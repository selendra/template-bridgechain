//! graphql-api — a read-mostly GraphQL front-end over the bridge signature store.
//!
//! It answers the questions an operator/dapp actually asks ("what transfers are
//! in flight A->C?", "is this submissionId ready to claim?", "how many are stuck
//! below threshold?") in one typed query, instead of fetching every record from
//! the sig-store and filtering client-side. It reads the same store the
//! validator/keeper share (a dir or the HTTP sig-store) and exposes one mutation
//! (`submitSignature`) that goes through the existing trust boundary.
//!
//!   GET  /            -> GraphiQL playground (interactive explorer)
//!   POST /graphql     -> GraphQL endpoint
//!   GET  /health      -> "ok"
//!
//! Read-only by default for safety; pass `--allow-mutations` to expose the
//! `submitSignature` mutation. Bind to localhost unless you front it with auth.
//!
//! ## No database credential, on purpose
//!
//! This is the only bridge service published to the internet, so it holds
//! exactly one credential: the sig-store's read-only bearer token. Everything it
//! serves — submissions, history, swap history, allowlists — comes back through
//! routes gated on `bridge_core::auth::Scope::Read`.
//!
//! It used to take a `--db-url` and connect to the indexer's Postgres with the
//! same full-privilege role the sig-store uses (and, via `Db::connect`, run the
//! schema migration). That put the most exposed component outside the scope
//! model entirely: compromise it and you could write signatures, rewrite the
//! allowlists, and forge the `refund_status` that the sig-store deliberately
//! exposes at NO scope, because a false `refunded` permanently hides a stuck
//! transfer from the recovery relayers. The flag is gone rather than made
//! optional, so it cannot be reintroduced by a config.

mod chain;
mod solana_pool;
mod schema;
mod swap;

use std::sync::Arc;

use async_graphql::http::GraphiQLSource;
use async_graphql::{EmptyMutation, Schema};
use async_graphql_axum::GraphQL;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post_service};
use axum::Router;
use bridge_core::backend::StoreBackend;
use bridge_core::ratelimit::{enforce as rate_limit, RateLimit};
use clap::Parser;
use tracing::{info, warn};

use chain::Chains;
use schema::{ApiState, Mutation, Query};
use swap::Swaps;

#[derive(Parser, Debug)]
#[command(about = "GraphQL API over the bridge signature store")]
struct Args {
    /// Address to bind, e.g. 127.0.0.1:8088
    #[arg(long, env = "GRAPHQL_BIND", default_value = "127.0.0.1:8088")]
    bind: String,
    /// Directory-backed store (file-per-id). Mutually exclusive with --store-url.
    #[arg(long, env = "GRAPHQL_STORE_DIR")]
    dir: Option<String>,
    /// HTTP sig-store base URL, e.g. http://127.0.0.1:8080.
    #[arg(long, env = "GRAPHQL_STORE_URL")]
    store_url: Option<String>,
    /// Keeper signature threshold, so the API can report `meetsThreshold`/`ready`.
    #[arg(long, env = "GRAPHQL_THRESHOLD")]
    threshold: Option<u64>,
    /// Destination gate(s) for on-chain `executed`/`status`, as `CHAINID=RPC,GATE`
    /// (repeatable), e.g. `--gate 1338=http://127.0.0.1:8546,0xGate...`. Without
    /// it, `executed` is null and `status` falls back to signatures only.
    #[arg(long = "gate", value_name = "CHAINID=RPC,GATE")]
    gates: Vec<String>,
    /// JSON file listing the network registry served to the UI via the `chains`
    /// query (an array of {chain_id,name,rpc_url?,public_rpc_url?,gate?,token?,
    /// tokens?,router?,swap_pool?} — snake_case, matching ChainInfo's serde field
    /// names). `rpc_url` is used server-side only (it may carry a provider key);
    /// `public_rpc_url` is what clients receive as `rpcUrl`. Each chain with a
    /// rpc_url+gate is also registered for `executed()` lookups — a base58 gate
    /// as a Solana gate — and each with a rpc_url+swap_pool for the pool views
    /// (`swap_pool` is `"ADDR"` or `{"address","from_block","max_block_range"}`).
    /// An explicit `--gate`/`--swap` for the same chain wins. Omit it =>
    /// `chains` returns `[]`.
    #[arg(long = "chains-file", env = "GRAPHQL_CHAINS_FILE", value_name = "PATH")]
    chains_file: Option<String>,
    /// Same-chain SwapPool(s) for the `pools`/`swapQuote` read view, as
    /// `CHAINID=RPC,POOL[,FROM_BLOCK[,MAX_RANGE]]` (repeatable), e.g.
    /// `--swap 1337=http://127.0.0.1:8545,0xPool...`. Prefer the registry's
    /// `swap_pool` key (keeps the RPC url off argv); this flag remains as a
    /// fallback and wins for its chain. Without either, `pools` and `swapQuote`
    /// return null. Read-only — no swaps are executed server-side.
    #[arg(long = "swap", value_name = "CHAINID=RPC,POOL")]
    swaps: Vec<String>,
    /// Expose the `submitSignature` mutation (off by default — read-only).
    #[arg(long, env = "GRAPHQL_ALLOW_MUTATIONS", default_value_t = false)]
    allow_mutations: bool,
    /// Harden for a public deployment: no GraphiQL playground, no introspection.
    ///
    /// This is the only bridge service published to the internet. The playground
    /// and a full introspection response are a development convenience that
    /// hands a stranger the complete shape of the API; the depth and complexity
    /// caps below bound abuse of a query, not enumeration of the schema.
    #[arg(long, env = "GRAPHQL_PRODUCTION", default_value_t = false)]
    production: bool,
    /// Sustained requests per second, per credential (or shared, when
    /// unauthenticated). Zero disables the limiter.
    #[arg(long, env = "GRAPHQL_RATE_PER_SECOND", default_value_t = 25.0)]
    rate_per_second: f64,
    /// How many requests may arrive back to back before the limit bites.
    #[arg(long, env = "GRAPHQL_RATE_BURST", default_value_t = 100)]
    rate_burst: u32,
    /// Largest accepted request body, in bytes.
    #[arg(long, env = "GRAPHQL_MAX_BODY_BYTES", default_value_t = 128 * 1024)]
    max_body_bytes: usize,
    /// Query complexity cap. List fields multiply by their page size and each
    /// chain-reading field (`executed`/`cancelled`/`status`) costs
    /// `schema::CHAIN_READ_COST` (20), so this bounds `eth_call` fan-out per
    /// request at roughly `max_complexity / 20`. The default admits a full
    /// 200-row page with `status`, and refuses one asking for all three.
    #[arg(long, env = "GRAPHQL_MAX_COMPLEXITY", default_value_t = 8000)]
    max_complexity: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "graphql_api=info".into()),
        )
        .init();

    let args = Args::parse();

    let backend = match (&args.dir, &args.store_url) {
        (Some(_), Some(_)) => anyhow::bail!("pass only one of --dir or --store-url"),
        (Some(dir), None) => StoreBackend::file(dir)?,
        // L-5: a read-only credential. This is the most exposed component, so it
        // must hold nothing that can write — the token, not the type, is what
        // enforces that server-side.
        (None, Some(url)) => StoreBackend::remote_for_role(url.clone(), "SIG_STORE_READER_TOKEN"),
        (None, None) => anyhow::bail!("need a store: pass --dir <path> or --store-url <url>"),
    };
    let described = backend.describe();

    let mut chains = Chains::new();
    for spec in &args.gates {
        chains.add_spec(spec)?;
    }

    // Load the UI-facing registry (if any) and fold each chain's gate into the
    // executed-gate map, so one --chains-file can drive both the `chains` query
    // and on-chain status without repeating every gate as a --gate flag.
    let registry = match &args.chains_file {
        Some(path) => chain::load_registry(path)?,
        None => Vec::new(),
    };
    // H-4: the `chains` query serves `public_rpc_url` as `rpcUrl` and NEVER the
    // (possibly keyed) `rpc_url`. A chain without a public one is served with
    // `rpcUrl: null` — legal, the UI falls back to the wallet — but worth a
    // warning per chain, and a refusal under --production where a null means
    // the operator has simply not finished the migration.
    let unpublished = chain::chains_without_public_rpc(&registry);
    for id in &unpublished {
        warn!(
            chain_id = id,
            "chain has no `public_rpc_url` in the registry: `chains.rpcUrl` will be null for it              (the private `rpc_url` is never served)"
        );
    }
    if args.production && !unpublished.is_empty() {
        anyhow::bail!(
            "--production: every chain in the registry needs a `public_rpc_url` (a keyless              endpoint safe to hand to browsers); missing for chain ids {unpublished:?}"
        );
    }
    // Base58 gates route to the Solana reader here (`Chains::add`), so the
    // Solana leg no longer needs its RPC on `--gate` argv either.
    for c in &registry {
        if let (Some(rpc), Some(gate)) = (&c.rpc_url, &c.gate) {
            chains.add(c.chain_id, rpc, gate)?;
        }
    }
    let chain_ids = chains.configured();
    let solana_ids = chains.configured_solana();

    let mut swaps = Swaps::new();
    // Hosted RPCs cap eth_getLogs and reject anything wider (Alchemy free tier:
    // 10 blocks), so the pool's token-list replay has to be chunked to fit.
    if let Ok(r) = std::env::var("GRAPHQL_MAX_BLOCK_RANGE").unwrap_or_default().parse::<u64>() {
        swaps.set_max_block_range(r);
    }
    for spec in &args.swaps {
        swaps.add_spec(spec)?;
    }
    // File form: a registry entry's `swap_pool`, read over its `rpc_url`. argv
    // above already claimed its chains, so those entries are no-ops.
    for c in &registry {
        swaps.add_from_registry(c)?;
    }
    // An SPL mint has no on-chain symbol (it lives in Metaplex metadata), so a
    // Solana pool takes its token names from the same registry the UI reads.
    // Without this the Swap view would list raw base58 addresses.
    for c in &registry {
        let symbols: std::collections::BTreeMap<String, String> =
            c.tokens.iter().map(|t| (t.address.clone(), t.symbol.clone())).collect();
        if !symbols.is_empty() {
            swaps.set_symbols(c.chain_id, symbols);
        }
    }
    let swap_ids = swaps.configured();

    let state = ApiState {
        backend: Arc::new(backend),
        threshold: args.threshold,
        chains,
        registry,
        swaps,
    };

    // Depth/complexity caps so one request can't fan out to hundreds of store
    // loads or destination-gate RPCs (e.g. an alias bomb). Generous enough for
    // legit queries and GraphiQL's introspection, tight enough to stop abuse.
    //
    // `production` additionally drops introspection and the playground. Those caps
    // bound what one QUERY can cost; they do nothing about a stranger reading the
    // whole schema off the most exposed service in the deployment.
    // The two branches build different concrete `GraphQL<..>` types, so the
    // routing is spelled out in each rather than shared through a binding.
    //
    // `production` drops introspection and the playground: the depth/complexity
    // caps bound what one QUERY can cost, and do nothing about a stranger reading
    // the whole schema off the most exposed service in the deployment. The
    // playground is a GET on /graphql (and /), so in production the endpoint
    // accepts POST only and there is nothing to serve a browser.
    let mut router = if args.allow_mutations {
        let mut schema = Schema::build(Query, Mutation, async_graphql::EmptySubscription)
            .limit_depth(15)
            .limit_complexity(args.max_complexity)
            .data(state);
        if args.production {
            schema = schema.disable_introspection();
        }
        let service = GraphQL::new(schema.finish());
        if args.production {
            Router::new().route("/graphql", post_service(service))
        } else {
            Router::new()
                .route("/graphql", get(graphiql).post_service(service))
                .route("/", get(graphiql))
        }
    } else {
        let mut schema = Schema::build(Query, EmptyMutation, async_graphql::EmptySubscription)
            .limit_depth(15)
            .limit_complexity(args.max_complexity)
            .data(state);
        if args.production {
            schema = schema.disable_introspection();
        }
        let service = GraphQL::new(schema.finish());
        if args.production {
            Router::new().route("/graphql", post_service(service))
        } else {
            Router::new()
                .route("/graphql", get(graphiql).post_service(service))
                .route("/", get(graphiql))
        }
    };

    if args.production {
        info!(
            "production mode: GraphiQL and introspection are OFF; the `chains` query serves \
             only `public_rpc_url` (never the server-side `rpc_url`)."
        );
    }

    // Same posture as the sig-store: bound what one caller can cost us. Keyed on
    // the bearer token when there is one, shared otherwise — this service is
    // usually unauthenticated and public, so the shared bucket is the common case.
    if args.rate_per_second > 0.0 {
        let limit = RateLimit::new(args.rate_burst, args.rate_per_second);
        info!(burst = args.rate_burst, per_second = args.rate_per_second, "rate limit active");
        router = router.route_layer(middleware::from_fn_with_state(limit, rate_limit));
    }

    let app = router
        .layer(DefaultBodyLimit::max(args.max_body_bytes))
        .route("/health", get(|| async { "ok" }));

    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    info!(
        bind = %args.bind,
        store = %described,
        threshold = ?args.threshold,
        mutations = args.allow_mutations,
        on_chain_status_for = ?chain_ids,
        solana_gates_for = ?solana_ids,
        swap_pools_for = ?swap_ids,
        production = args.production,
        // History lives behind the sig-store's read scope, so a dir-backed run
        // has none — say so at startup rather than at the first query.
        history = args.store_url.is_some(),
        "graphql-api listening (GraphiQL at /)"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

/// The interactive GraphiQL explorer, pointed at our /graphql endpoint.
async fn graphiql() -> impl IntoResponse {
    Html(GraphiQLSource::build().endpoint("/graphql").finish())
}
