//! sig-store — the bridge's HTTP gateway over the Postgres source of truth.
//!
//! Backed by `bridge-db` (Postgres): it owns transaction history (submissions +
//! signatures + lifecycle status) and the two allowlists. N validators POST
//! their signatures here; the keeper GETs merged records, then POSTs back the
//! claim tx; operators manage the allowlists. The DB enforces the same
//! trust boundary the old file store did (id<->params binding + signature auth).
//!
//!   GET    /health
//!
//!   # signature store / transaction history
//!   POST   /submissions                  -> upsert a record + its signature(s)
//!                                           (at most MAX_SIGS_PER_POST signatures)
//!   GET    /submissions?limit=&offset=   -> records (params + signatures), oldest
//!                                           first; limit defaults to and is capped
//!                                           at DEFAULT_PAGE
//!   GET    /submissions/:id              -> one record (404 if unknown)
//!   POST   /submissions/:id/claimed      -> the keeper's ADVISORY claim report
//!                                           (body: {"claim_tx": "0x.."}); writes
//!                                           `keeper_claim_tx` only — never `status`
//!   GET    /history?limit=&offset=       -> history view (status, counts, timestamps),
//!                                           newest first, paged like /submissions
//!   GET    /swaps?chain_id=&limit=       -> same-chain swap history (newest first)
//!
//!   # refund path (two-phase: burn on the destination, then repay on the source)
//!   POST   /submissions/:id/attestations -> a validator's cancel/refund signature
//!                                           (body: {"kind":"cancel"|"refund",
//!                                                   "signer":"0x..","signature":"0x.."})
//!   GET    /refund-candidates            -> submissions a refund relayer should
//!                                           examine (still requires on-chain checks)
//!
//! The lifecycle (`status`, `refund_status`) has NO write route at all: those
//! columns gate the claim and refund queues, so they are set only by the indexer
//! from observed on-chain `Claimed`/`Cancelled`/`Refunded` events, never on a
//! caller's word. `/claimed` used to be the exception (audit 2026-09-09, M-1): a
//! leaked keeper token could mark any transfer — including future ones, ids
//! being deterministic — claimed, hiding it from both queues forever.
//!
//!   # allowlists
//!   GET    /allowed/tokens               -> whitelisted tokens
//!   POST   /allowed/tokens               -> add (body: {"chain_id":..,"token":"0x..","symbol":".."})
//!   DELETE /allowed/tokens/:chain/:token -> remove
//!   GET    /allowed/chains               -> whitelisted source->target pairs
//!   POST   /allowed/chains               -> add (body: {"chain_id_from":..,"chain_id_to":..})
//!   DELETE /allowed/chains/:from/:to     -> remove

use axum::extract::{DefaultBodyLimit, Path, Query, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use bridge_core::allow::{
    AddTokenRequest, AllowedChain, AllowedToken, AttestationRequest, ClaimedRequest,
    SubmissionHistory, SwapRecord,
};
use bridge_core::auth::{require_scope, Auth, Scope};
use bridge_core::ratelimit::{enforce as rate_limit, RateLimit};
use bridge_core::store::{SigKind, SignerSig, SubmissionRecord};
use bridge_db::{Db, DbError};
use clap::Parser;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(about = "Postgres-backed signature store + allowlists for the bridge")]
struct Args {
    /// Address to bind, e.g. 0.0.0.0:8080
    #[arg(long, env = "SIG_STORE_BIND", default_value = "0.0.0.0:8080")]
    bind: String,
    /// Postgres connection string, e.g. postgres://bridge:bridge@localhost:5432/bridge
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    /// LEGACY all-scopes secret. Still honoured so existing deployments keep
    /// working, but it grants read + sign + relay + admin to whoever holds it —
    /// the blast radius finding L-5 is about. Prefer the per-service tokens below.
    #[arg(long, env = "SIG_STORE_TOKEN")]
    auth_token: Option<String>,
    /// Validators: read + deposit signatures/attestations. Cannot mark claimed or
    /// edit the allowlist.
    #[arg(long, env = "SIG_STORE_VALIDATOR_TOKEN")]
    validator_token: Option<String>,
    /// Keeper: read + record a claim tx. Cannot deposit signatures.
    #[arg(long, env = "SIG_STORE_KEEPER_TOKEN")]
    keeper_token: Option<String>,
    /// Read-only consumers (the GraphQL API). Grants nothing that writes — this is
    /// the whole point of the split, since it is the most exposed component.
    #[arg(long, env = "SIG_STORE_READER_TOKEN")]
    reader_token: Option<String>,
    /// Operators: allowlist mutations, itself a security control.
    #[arg(long, env = "SIG_STORE_ADMIN_TOKEN")]
    admin_token: Option<String>,
    /// Sustained write requests per second, per bearer token (L-1).
    #[arg(long, env = "SIG_STORE_RATE_PER_SECOND", default_value_t = 50.0)]
    rate_per_second: f64,
    /// How many write requests one credential may send back to back (L-1).
    #[arg(long, env = "SIG_STORE_RATE_BURST", default_value_t = 200)]
    rate_burst: u32,
    /// Largest accepted request body, in bytes.
    #[arg(long, env = "SIG_STORE_MAX_BODY_BYTES", default_value_t = 256 * 1024)]
    max_body_bytes: usize,
    /// Serve with NO authentication when no token is configured. Dev only.
    ///
    /// Without this the process refuses to bind rather than exposing an open
    /// store, because "no token" is far more often a lost secret mount than a
    /// deliberate choice — and the open failure mode is world-writable
    /// signatures, claim status, and the allowlist that IS the incident
    /// kill-switch. Requiring the operator to say it out loud makes the
    /// dangerous configuration the one that takes an extra argument.
    #[arg(long, env = "SIG_STORE_ALLOW_UNAUTHENTICATED", default_value_t = false)]
    allow_unauthenticated: bool,
}

impl Args {
    /// Assemble the scoped token set. Absent/empty tokens are dropped by
    /// [`Auth::new`], so an unset variable can never authenticate a request.
    fn auth(&self) -> Auth {
        let mut entries: Vec<(String, std::collections::HashSet<Scope>)> = Vec::new();
        if let Some(t) = self.auth_token.clone().filter(|t| !t.is_empty()) {
            warn!(
                "SIG_STORE_TOKEN grants ALL scopes to every holder (read+sign+relay+admin). \
                 Prefer SIG_STORE_{{VALIDATOR,KEEPER,READER,ADMIN}}_TOKEN so a leak from one \
                 component cannot write on behalf of the others."
            );
            entries.push((t, Scope::all()));
        }
        if let Some(t) = self.validator_token.clone() {
            entries.push((t, [Scope::Read, Scope::Sign].into_iter().collect()));
        }
        if let Some(t) = self.keeper_token.clone() {
            entries.push((t, [Scope::Read, Scope::Relay].into_iter().collect()));
        }
        if let Some(t) = self.reader_token.clone() {
            entries.push((t, [Scope::Read].into_iter().collect()));
        }
        if let Some(t) = self.admin_token.clone() {
            entries.push((t, [Scope::Read, Scope::Admin].into_iter().collect()));
        }
        Auth::new(entries)
    }
}

#[derive(Clone)]
struct AppState {
    db: Db,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sig_store=info,bridge_db=info".into()),
        )
        .init();

    let args = Args::parse();
    let auth = args.auth();
    let db = Db::connect(&args.database_url).await?;
    info!("connected to Postgres and applied schema");

    let state = AppState { db };

    // FAIL CLOSED. `Auth::new` drops empty tokens, so an unset (or wiped) secret
    // leaves nothing configured — and an unconfigured `Auth` grants every scope to
    // everyone. Warning about that and serving anyway meant one lost env var
    // silently opened the whole store; the log line was the only difference
    // between a correct deployment and an open one.
    require_credentials(&auth, args.allow_unauthenticated)?;

    let writes = RateLimit::new(args.rate_burst, args.rate_per_second);
    info!(
        burst = args.rate_burst,
        per_second = args.rate_per_second,
        max_body_bytes = args.max_body_bytes,
        "write rate limit active (per bearer token)"
    );
    let app = build_app(state, auth, writes, args.max_body_bytes);

    let listener = tokio::net::TcpListener::bind(&args.bind).await?;
    info!(bind = %args.bind, "sig-store listening");
    axum::serve(listener, app).await?;
    Ok(())
}

/// The whole HTTP surface: every route group under its scope and (for writers)
/// the per-credential rate limit. Split from `main` so tests can drive the REAL
/// handlers through the REAL auth layering with `oneshot`.
fn build_app(state: AppState, auth: Auth, writes: RateLimit, max_body_bytes: usize) -> Router {
    // L-5: each route group demands the NARROWEST scope that lets it work, so a
    // credential leaked from one component cannot act as another.
    //
    // NOTE: there is deliberately no write route for the lifecycle (`status`,
    // `refund_status`) at ANY scope. Those columns gate the claim and refund
    // queues, so a forged "claimed" or "refunded" would permanently hide a
    // transfer from the keeper and the relayers. They are written ONLY by the
    // indexer, from observed on-chain `Claimed`/`Cancelled`/`Refunded` events —
    // never on a caller's word. `/claimed` below is advisory (M-1).
    let read = Router::new()
        .route("/submissions", get(list_submissions))
        .route("/submissions/:id", get(get_submission))
        .route("/refund-candidates", get(get_refund_candidates))
        .route("/history", get(get_history))
        .route("/swaps", get(get_swaps))
        .route("/allowed/tokens", get(list_tokens))
        .route("/allowed/chains", get(list_chains))
        .route_layer(middleware::from_fn_with_state((auth.clone(), Scope::Read), require_scope));

    // L-1: a per-credential token bucket on every route that WRITES.
    //
    // The binding rules make a forged record impossible, but they do not require a
    // record to describe a transfer that ever happened on a chain — so a holder of
    // a `Sign`-scoped token could mint well-formed junk at line rate and grow the
    // table without limit. Keyed on the bearer token, because the thing worth
    // bounding is what ONE credential can do; every writer here is a service
    // holding a scoped token, and several of them may share an ingress address.

    // Validators deposit signatures and cancel/refund attestations.
    let sign = Router::new()
        .route("/submissions", post(post_submission))
        .route("/submissions/:id/attestations", post(post_attestation))
        .route_layer(middleware::from_fn_with_state(writes.clone(), rate_limit))
        .route_layer(middleware::from_fn_with_state((auth.clone(), Scope::Sign), require_scope));

    // The keeper records a claim tx. ADVISORY (M-1): it lands in
    // `keeper_claim_tx` and nothing else — see `post_claimed`.
    let relay = Router::new()
        .route("/submissions/:id/claimed", post(post_claimed))
        .route_layer(middleware::from_fn_with_state(writes.clone(), rate_limit))
        .route_layer(middleware::from_fn_with_state((auth.clone(), Scope::Relay), require_scope));

    // The allowlists are a security control, so they get their own scope.
    let admin = Router::new()
        .route("/allowed/tokens", post(add_token))
        .route("/allowed/tokens/:chain/:token", delete(remove_token))
        .route("/allowed/chains", post(add_chain))
        .route("/allowed/chains/:from/:to", delete(remove_chain))
        .route_layer(middleware::from_fn_with_state(writes.clone(), rate_limit))
        .route_layer(middleware::from_fn_with_state((auth.clone(), Scope::Admin), require_scope));

    Router::new()
        .route("/health", get(health))
        .merge(read)
        .merge(sign)
        .merge(relay)
        .merge(admin)
        // A submission with its signatures is a few kB; the default 2 MB let a
        // caller make the server allocate far more than any real request needs.
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .with_state(state)
}

async fn health() -> &'static str {
    "ok"
}

/// FAIL CLOSED: refuse to serve an unauthenticated store unless told to.
///
/// [`Auth::new`] drops empty tokens, so an unset — or wiped — secret leaves
/// nothing configured, and an unconfigured `Auth` grants EVERY scope to everyone.
/// This used to warn and serve anyway, which made one lost env var
/// indistinguishable from a correct deployment except in the log, with
/// world-writable signatures, claim status and the allowlist (the incident
/// kill-switch) as the result.
///
/// Compose passes the tokens as `${VAR:?}` so it could never reach this state; a
/// systemd unit, a bare binary or a Kubernetes manifest that loses a secret mount
/// absolutely could.
fn require_credentials(auth: &Auth, allow_unauthenticated: bool) -> anyhow::Result<()> {
    if auth.is_enforced() {
        info!(tokens = auth.token_count(), "auth enabled: scoped bearer tokens required");
        return Ok(());
    }
    if allow_unauthenticated {
        warn!(
            "--allow-unauthenticated: serving with NO authentication (signatures, claim \
             status and the allowlist are all world-writable). Never do this on a \
             networked deployment."
        );
        return Ok(());
    }
    anyhow::bail!(
        "refusing to start: no bearer token is configured, which would leave signatures, \
         claim status and the allowlist world-writable. Set at least one of \
         SIG_STORE_VALIDATOR_TOKEN / _KEEPER_TOKEN / _READER_TOKEN / _ADMIN_TOKEN (or the \
         legacy SIG_STORE_TOKEN), or pass --allow-unauthenticated to accept an open store \
         on a trusted local network."
    )
}

/// Map a DbError to an HTTP error, distinguishing caller faults (4xx) from
/// server faults (5xx) so a forged signature reads as 400, not 500.
fn db_err(e: DbError) -> (StatusCode, String) {
    let code = if e.is_client_error() {
        StatusCode::BAD_REQUEST
    } else {
        StatusCode::INTERNAL_SERVER_ERROR
    };
    (code, e.to_string())
}

// --- signature store / transaction history -------------------------------

/// Audit 2026-09-09, M-2: how many signatures one `POST /submissions` may carry.
///
/// An honest client sends exactly ONE — its own (`RemoteStore::upsert`). The body
/// limit alone still let a single request carry ~1,200 signatures, each of which
/// cost an ECDSA recovery plus a transaction, while the rate limiter counted it
/// as one request. Four leaves room for a batching client without leaving room
/// for that.
const MAX_SIGS_PER_POST: usize = 4;

/// Default and maximum page size for the unfiltered `GET /submissions` and
/// `GET /history` (audit 2026-09-09, item 10). Generous so today's consumers —
/// the GraphQL API sends no `limit` — see everything a small deployment has,
/// while a `Read` credential can no longer pull an arbitrarily large table in
/// one request. Larger sets are walked with `offset`.
const DEFAULT_PAGE: u64 = 5_000;

/// Resolve a caller's `limit`/`offset` into SQL-ready values: absent limit means
/// [`DEFAULT_PAGE`], anything above it is clamped, not refused.
fn page(limit: Option<u64>, offset: Option<u64>) -> (i64, i64) {
    let limit = limit.unwrap_or(DEFAULT_PAGE).min(DEFAULT_PAGE) as i64;
    let offset = offset.unwrap_or(0).min(i64::MAX as u64) as i64;
    (limit, offset)
}

/// Upsert a record. The body carries the submission params plus one (or more)
/// signatures in `signatures`; each is merged into the stored record, deduped
/// by signer. Returns the merged record.
async fn post_submission(
    State(s): State<AppState>,
    Json(record): Json<SubmissionRecord>,
) -> Result<Json<SubmissionRecord>, (StatusCode, String)> {
    if record.signatures.len() > MAX_SIGS_PER_POST {
        return Err((
            StatusCode::PAYLOAD_TOO_LARGE,
            format!(
                "too many signatures in one request ({}); at most {MAX_SIGS_PER_POST} — a \
                 validator posts its own signature only",
                record.signatures.len()
            ),
        ));
    }
    let sigs = record.signatures.clone();
    let mut base = record;
    base.signatures = Vec::new();

    if sigs.is_empty() {
        // No signature attached: just report the current state (if any).
        let existing = s.db.load(&base.submission_id).await.map_err(db_err)?;
        return Ok(Json(existing.unwrap_or(base)));
    }

    let mut merged = base;
    for sig in sigs {
        let signer = sig.signer.clone();
        merged = s.db.upsert_signature(merged, sig).await.map_err(db_err)?;
        info!(submission_id = %merged.submission_id, %signer, sigs = merged.signatures.len(), "stored signature");
    }
    Ok(Json(merged))
}

/// Query for [`list_submissions`].
///
/// With no parameters this returns the whole table, which is what the GraphQL API
/// and the operator tooling want. `pending` narrows it to a keeper's work queue,
/// filtered in SQL on the lifecycle the indexer maintains — see
/// `Db::pending_claims` for why polling the whole table every tick did not scale.
#[derive(serde::Deserialize)]
struct SubmissionQuery {
    /// `"claims"` (needs `chain_id_to`) or `"refunds"` (needs `chain_id_from`).
    pending: Option<String>,
    chain_id_to: Option<u64>,
    chain_id_from: Option<u64>,
    /// Page size for the unfiltered listing (default and max [`DEFAULT_PAGE`]).
    /// Ignored by the `pending` work queues, which are bounded by construction.
    limit: Option<u64>,
    offset: Option<u64>,
}

async fn list_submissions(
    State(s): State<AppState>,
    Query(q): Query<SubmissionQuery>,
) -> Result<Json<Vec<SubmissionRecord>>, (StatusCode, String)> {
    let records = match (q.pending.as_deref(), q.chain_id_to, q.chain_id_from) {
        (None, _, _) => {
            let (limit, offset) = page(q.limit, q.offset);
            s.db.load_page(limit, offset).await
        }
        (Some("claims"), Some(to), _) => s.db.pending_claims(to).await,
        (Some("refunds"), _, Some(from)) => s.db.pending_refunds(from).await,
        (Some(kind), _, _) => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!(
                    "pending={kind:?} needs its chain filter: \
                     pending=claims&chain_id_to=N, or pending=refunds&chain_id_from=N"
                ),
            ))
        }
    };
    Ok(Json(records.map_err(db_err)?))
}

async fn get_submission(
    State(s): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<SubmissionRecord>, (StatusCode, String)> {
    match s.db.load(&id).await.map_err(db_err)? {
        Some(rec) => Ok(Json(rec)),
        None => Err((StatusCode::NOT_FOUND, "unknown submissionId".into())),
    }
}

/// The keeper's report of its claim tx. **Advisory** (audit 2026-09-09, M-1).
///
/// This used to call `Db::mark_claimed` — the same authoritative write the
/// indexer makes on an observed on-chain `Claimed` — so a holder of the Relay
/// token could set `status='claimed'` on any id, clear its refund eligibility,
/// and park a marker for ids that did not exist yet. Every work queue filters on
/// `status`, and nothing ever writes it back, so the transfer vanished from both
/// the claim path and the refund path for good.
///
/// Now it records `keeper_claim_tx` and nothing else: the lifecycle moves only
/// when the indexer sees the `Claimed` event on-chain. The route is kept because
/// the keeper still calls it; the response is unchanged.
async fn post_claimed(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(body): Json<ClaimedRequest>,
) -> Result<StatusCode, (StatusCode, String)> {
    s.db.note_keeper_claim(&id, &body.claim_tx).await.map_err(db_err)?;
    info!(submission_id = %id, claim_tx = %body.claim_tx, "noted keeper claim report (advisory)");
    Ok(StatusCode::NO_CONTENT)
}

/// Query for [`get_history`]: an optional page, defaulting to [`DEFAULT_PAGE`].
#[derive(serde::Deserialize)]
struct PageQuery {
    limit: Option<u64>,
    offset: Option<u64>,
}

async fn get_history(
    State(s): State<AppState>,
    Query(q): Query<PageQuery>,
) -> Result<Json<Vec<SubmissionHistory>>, (StatusCode, String)> {
    let (limit, offset) = page(q.limit, q.offset);
    Ok(Json(s.db.history_page(limit, offset).await.map_err(db_err)?))
}

/// Query for [`get_swaps`]. Both fields optional: no `chain_id` means every
/// chain, and `limit` defaults to 100 and is capped so one request cannot ask
/// the database for the whole table.
#[derive(serde::Deserialize)]
struct SwapQuery {
    chain_id: Option<u64>,
    limit: Option<u64>,
}

/// Same-chain swap history. Read scope, like `/history` — it exists so the
/// GraphQL API can serve `swapHistory` with its read-only bearer token instead
/// of a Postgres credential of its own.
async fn get_swaps(
    State(s): State<AppState>,
    Query(q): Query<SwapQuery>,
) -> Result<Json<Vec<SwapRecord>>, (StatusCode, String)> {
    let limit = q.limit.unwrap_or(100).min(1000) as i64;
    Ok(Json(s.db.list_swaps(q.chain_id, limit).await.map_err(db_err)?))
}

// --- refund path ----------------------------------------------------------

/// Store one validator's cancel/refund attestation.
///
/// The signature is checked against the digest for `kind` specifically, so a
/// transfer signature posted here as a `cancel` recovers to the wrong address
/// and is rejected — the three quorums stay independent.
async fn post_attestation(
    State(s): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<AttestationRequest>,
) -> Result<Json<SubmissionRecord>, (StatusCode, String)> {
    let kind = SigKind::parse(&req.kind)
        .filter(|k| *k != SigKind::Transfer)
        .ok_or((StatusCode::BAD_REQUEST, format!("unknown attestation kind {:?}", req.kind)))?;

    let rec = s
        .db
        .upsert_attestation(&id, kind, SignerSig { signer: req.signer, signature: req.signature })
        .await
        .map_err(db_err)?;

    let count = match kind {
        SigKind::Cancel => rec.cancel_signatures.len(),
        SigKind::Refund => rec.refund_signatures.len(),
        SigKind::Transfer => unreachable!("filtered above"),
    };
    info!(submission_id = %rec.submission_id, kind = kind.as_str(), count, "stored attestation");
    Ok(Json(rec))
}

async fn get_refund_candidates(
    State(s): State<AppState>,
) -> Result<Json<Vec<SubmissionRecord>>, (StatusCode, String)> {
    Ok(Json(s.db.refund_candidates().await.map_err(db_err)?))
}

// `cancelled`/`refunded` are written only by the indexer from observed on-chain
// events (see the router note), so there are intentionally no HTTP handlers for
// them here.

// --- allowlists -----------------------------------------------------------

async fn list_tokens(
    State(s): State<AppState>,
) -> Result<Json<Vec<AllowedToken>>, (StatusCode, String)> {
    Ok(Json(s.db.list_allowed_tokens().await.map_err(db_err)?))
}

async fn add_token(
    State(s): State<AppState>,
    Json(req): Json<AddTokenRequest>,
) -> Result<Json<AllowedToken>, (StatusCode, String)> {
    let added = s
        .db
        .add_allowed_token(req.chain_id, &req.token, req.symbol.as_deref())
        .await
        .map_err(db_err)?;
    info!(chain_id = added.chain_id, token = %added.token, debridge_id = %added.debridge_id, "allowed token");
    Ok(Json(added))
}

async fn remove_token(
    State(s): State<AppState>,
    Path((chain, token)): Path<(u64, String)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let removed = s.db.remove_allowed_token(chain, &token).await.map_err(db_err)?;
    Ok(if removed { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND })
}

async fn list_chains(
    State(s): State<AppState>,
) -> Result<Json<Vec<AllowedChain>>, (StatusCode, String)> {
    Ok(Json(s.db.list_allowed_chains().await.map_err(db_err)?))
}

async fn add_chain(
    State(s): State<AppState>,
    Json(req): Json<AllowedChain>,
) -> Result<Json<AllowedChain>, (StatusCode, String)> {
    let added = s
        .db
        .add_allowed_chain(req.chain_id_from, req.chain_id_to)
        .await
        .map_err(db_err)?;
    info!(from = added.chain_id_from, to = added.chain_id_to, "allowed chain pair");
    Ok(Json(added))
}

async fn remove_chain(
    State(s): State<AppState>,
    Path((from, to)): Path<(u64, u64)>,
) -> Result<StatusCode, (StatusCode, String)> {
    let removed = s.db.remove_allowed_chain(from, to).await.map_err(db_err)?;
    Ok(if removed { StatusCode::NO_CONTENT } else { StatusCode::NOT_FOUND })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{header, Request};
    use axum::routing::post;
    use tower::ServiceExt; // for `oneshot`

    const VAL: &str = "val-token";
    const KEEP: &str = "keeper-token";
    const READ: &str = "reader-token";
    const ADMIN: &str = "admin-token";

    fn test_auth() -> Auth {
        Auth::new([
            (VAL.to_string(), [Scope::Read, Scope::Sign].into_iter().collect()),
            (KEEP.to_string(), [Scope::Read, Scope::Relay].into_iter().collect()),
            (READ.to_string(), [Scope::Read].into_iter().collect()),
            (ADMIN.to_string(), [Scope::Read, Scope::Admin].into_iter().collect()),
        ])
    }

    /// The same scope layering main() uses, with stub handlers so the test
    /// exercises the AUTH wiring rather than the database.
    fn app() -> Router {
        app_limited(RateLimit::new(1_000, 1_000.0))
    }

    fn app_limited(writes: RateLimit) -> Router {
        let auth = test_auth();
        let read = Router::new()
            .route("/submissions", get(|| async { "list" }))
            .route("/allowed/tokens", get(|| async { "tokens" }))
            .route_layer(middleware::from_fn_with_state(
                (auth.clone(), Scope::Read),
                require_scope,
            ));
        let sign = Router::new()
            .route("/submissions", post(|| async { "signed" }))
            .route_layer(middleware::from_fn_with_state(writes.clone(), rate_limit))
            .route_layer(middleware::from_fn_with_state(
                (auth.clone(), Scope::Sign),
                require_scope,
            ));
        let relay = Router::new()
            .route("/submissions/:id/claimed", post(|| async { "claimed" }))
            .route_layer(middleware::from_fn_with_state(
                (auth.clone(), Scope::Relay),
                require_scope,
            ));
        let admin = Router::new()
            .route("/allowed/tokens", post(|| async { "added" }))
            .route_layer(middleware::from_fn_with_state(
                (auth.clone(), Scope::Admin),
                require_scope,
            ));
        Router::new()
            .route("/health", get(health))
            .merge(read)
            .merge(sign)
            .merge(relay)
            .merge(admin)
    }

    async fn status(method: &str, uri: &str, bearer: Option<&str>) -> StatusCode {
        status_on(app(), method, uri, bearer).await
    }

    async fn status_on(app: Router, method: &str, uri: &str, bearer: Option<&str>) -> StatusCode {
        let mut b = Request::builder().method(method).uri(uri);
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        app.oneshot(b.body(Body::empty()).unwrap()).await.unwrap().status()
    }

    // --- L-1: a credential cannot write at line rate --------------------------

    /// The binding rules stop a FORGED record, not a well-formed useless one: an
    /// id must hash its own params and a signature must recover to its signer, but
    /// nothing requires the transfer to have happened on any chain. Without a rate
    /// limit a `Sign`-scoped token could grow the table without bound.
    #[tokio::test]
    async fn writes_are_rate_limited_per_credential() {
        let limit = RateLimit::new(2, 0.001); // two, then effectively none
        let app = app_limited(limit);

        assert_eq!(status_on(app.clone(), "POST", "/submissions", Some(VAL)).await, StatusCode::OK);
        assert_eq!(status_on(app.clone(), "POST", "/submissions", Some(VAL)).await, StatusCode::OK);
        assert_eq!(
            status_on(app.clone(), "POST", "/submissions", Some(VAL)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "a credential over its budget must be refused"
        );
    }

    /// Reads are not limited — the GraphQL API polls them and a read cannot grow
    /// the table.
    #[tokio::test]
    async fn reads_are_not_rate_limited() {
        let app = app_limited(RateLimit::new(1, 0.001));
        for _ in 0..5 {
            assert_eq!(status_on(app.clone(), "GET", "/submissions", Some(READ)).await, StatusCode::OK);
        }
    }

    /// The limiter sits INSIDE the auth layer, so an unauthenticated flood is
    /// rejected as 401 without consuming a legitimate credential's budget.
    #[tokio::test]
    async fn an_unauthenticated_flood_does_not_consume_a_real_budget() {
        let app = app_limited(RateLimit::new(2, 0.001));
        for _ in 0..10 {
            assert_eq!(
                status_on(app.clone(), "POST", "/submissions", Some("bogus")).await,
                StatusCode::UNAUTHORIZED
            );
        }
        assert_eq!(
            status_on(app.clone(), "POST", "/submissions", Some(VAL)).await,
            StatusCode::OK,
            "the real credential must still have its full budget"
        );
    }

    #[tokio::test]
    async fn health_needs_no_token() {
        assert_eq!(status("GET", "/health", None).await, StatusCode::OK);
    }

    #[tokio::test]
    async fn missing_or_wrong_token_is_rejected() {
        assert_eq!(status("GET", "/submissions", None).await, StatusCode::UNAUTHORIZED);
        assert_eq!(status("GET", "/submissions", Some("nope")).await, StatusCode::UNAUTHORIZED);
    }

    /// THE L-5 property, end to end through the router: the read-only credential
    /// the GraphQL API carries — the most exposed component — must be unable to
    /// write anything. Under the old single shared token it could do everything.
    #[tokio::test]
    async fn the_read_only_token_cannot_write_anything() {
        assert_eq!(status("GET", "/submissions", Some(READ)).await, StatusCode::OK);

        assert_eq!(
            status("POST", "/submissions", Some(READ)).await,
            StatusCode::UNAUTHORIZED,
            "a reader must not deposit signatures"
        );
        assert_eq!(
            status("POST", "/submissions/0xabc/claimed", Some(READ)).await,
            StatusCode::UNAUTHORIZED,
            "a reader must not mark transfers claimed"
        );
        assert_eq!(
            status("POST", "/allowed/tokens", Some(READ)).await,
            StatusCode::UNAUTHORIZED,
            "a reader must not edit the allowlist"
        );
    }

    /// Components cannot act as one another.
    #[tokio::test]
    async fn scopes_are_not_interchangeable_over_http() {
        // A validator signs, but does not relay or administer.
        assert_eq!(status("POST", "/submissions", Some(VAL)).await, StatusCode::OK);
        assert_eq!(
            status("POST", "/submissions/0xabc/claimed", Some(VAL)).await,
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(status("POST", "/allowed/tokens", Some(VAL)).await, StatusCode::UNAUTHORIZED);

        // The keeper relays, but cannot deposit signatures.
        assert_eq!(status("POST", "/submissions/0xabc/claimed", Some(KEEP)).await, StatusCode::OK);
        assert_eq!(status("POST", "/submissions", Some(KEEP)).await, StatusCode::UNAUTHORIZED);

        // The operator administers, but does not sign.
        assert_eq!(status("POST", "/allowed/tokens", Some(ADMIN)).await, StatusCode::OK);
        assert_eq!(status("POST", "/submissions", Some(ADMIN)).await, StatusCode::UNAUTHORIZED);
    }

    /// Every component still reads — the shared capability.
    #[tokio::test]
    async fn every_service_token_can_read() {
        for t in [VAL, KEEP, READ, ADMIN] {
            assert_eq!(status("GET", "/submissions", Some(t)).await, StatusCode::OK, "{t}");
        }
    }

    // --- M-1: the store must not come up open by accident ------------------

    /// THE regression. An unset (or wiped) token variable leaves `Auth`
    /// unenforced, and an unenforced `Auth` grants every scope to everyone. The
    /// process used to log a warning and serve, so a lost secret mount looked
    /// exactly like a healthy deployment.
    #[test]
    fn refuses_to_start_with_no_credentials() {
        let err = require_credentials(&Auth::new([]), false).unwrap_err().to_string();
        assert!(err.contains("refusing to start"), "{err}");
    }

    /// An unset variable must not become a usable empty credential either — that
    /// is the same open store by a different route.
    #[test]
    fn an_empty_token_is_not_a_credential() {
        let empty = Auth::new([(String::new(), Scope::all())]);
        assert!(require_credentials(&empty, false).is_err());
    }

    /// The dangerous configuration is the one that takes an extra argument.
    #[test]
    fn an_open_store_requires_saying_so_explicitly() {
        assert!(require_credentials(&Auth::new([]), true).is_ok());
    }

    #[test]
    fn a_configured_token_starts_normally() {
        assert!(require_credentials(&test_auth(), false).is_ok());
    }

    // `ct_eq` and the scope table itself are covered by bridge_core::auth's tests.

    // --- 2026-09-09 M-2: signatures per POST are capped ------------------------

    /// A `Db` that never connects: these tests must be refused BEFORE the handler
    /// reaches the database.
    fn lazy_state() -> AppState {
        AppState { db: Db::connect_lazy("postgres://nobody@127.0.0.1:1/never").unwrap() }
    }

    fn dummy_record(n_sigs: usize) -> SubmissionRecord {
        SubmissionRecord {
            submission_id: format!("0x{}", "ab".repeat(32)),
            bridge_domain: format!("0x{}", "d0".repeat(32)),
            debridge_id: format!("0x{}", "11".repeat(32)),
            amount: "1".into(),
            chain_id_from: 1,
            chain_id_to: 2,
            nonce: 0,
            receiver: format!("0x{}", "cd".repeat(20)),
            auto_params: "0x".into(),
            native_sender: "0x".into(),
            token: format!("0x{}", "ee".repeat(20)),
            signatures: (0..n_sigs)
                .map(|i| SignerSig {
                    signer: format!("0x{:040x}", i + 1),
                    signature: format!("0x{}", "00".repeat(65)),
                })
                .collect(),
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    async fn post_json(app: Router, uri: &str, bearer: Option<&str>, body: &impl serde::Serialize) -> axum::response::Response {
        let mut b = Request::builder()
            .method("POST")
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some(t) = bearer {
            b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
        }
        app.oneshot(b.body(Body::from(serde_json::to_vec(body).unwrap())).unwrap()).await.unwrap()
    }

    /// One POST used to carry ~1,200 signatures under the body limit, each costing
    /// an ECDSA recovery and a transaction, while the rate limiter saw one
    /// request. The real handler must refuse the batch up front — with no
    /// database in reach, so the assertion also proves no query ran.
    #[tokio::test]
    async fn a_post_with_too_many_signatures_is_refused_before_the_database() {
        let app = Router::new().route("/submissions", post(post_submission)).with_state(lazy_state());
        let res = post_json(app, "/submissions", None, &dummy_record(MAX_SIGS_PER_POST + 1)).await;
        assert_eq!(res.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    /// Sanity on the constant: an honest client sends one, so the cap must admit
    /// that and stay tiny.
    #[test]
    fn the_per_post_cap_admits_an_honest_client_and_little_more() {
        assert!(MAX_SIGS_PER_POST >= 1 && MAX_SIGS_PER_POST <= 8);
    }

    // --- 2026-09-09 item 10: paging ------------------------------------------

    #[test]
    fn paging_defaults_are_backward_compatible_and_clamped() {
        // No parameters: the generous default page, from the start — what the
        // GraphQL client (which sends nothing) gets today.
        assert_eq!(page(None, None), (DEFAULT_PAGE as i64, 0));
        // An explicit page is honoured...
        assert_eq!(page(Some(50), Some(100)), (50, 100));
        // ...and one over the cap is clamped rather than refused or unbounded.
        assert_eq!(page(Some(u64::MAX), None).0, DEFAULT_PAGE as i64);
        // An absurd offset cannot overflow the i64 bind.
        assert_eq!(page(None, Some(u64::MAX)).1, i64::MAX);
    }

    // --- 2026-09-09 M-1: a Relay token cannot hide a transfer -----------------
    //
    // Needs a live Postgres: `BRIDGE_TEST_DATABASE_URL=postgres://… cargo test`.
    // Skipped (passing, with a note) when the variable is unset, because the
    // unit-test suite must stay runnable without infrastructure.

    /// Live tests share one database and each runs `migrate()` on connect, and
    /// two concurrent `CREATE TABLE IF NOT EXISTS` on a fresh database race in
    /// Postgres (duplicate `pg_type` key). Serialise them.
    static LIVE_DB: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    fn live_db_url() -> Option<String> {
        match std::env::var("BRIDGE_TEST_DATABASE_URL") {
            Ok(u) if !u.is_empty() => Some(u),
            _ => {
                eprintln!("BRIDGE_TEST_DATABASE_URL unset — skipping live-Postgres test");
                None
            }
        }
    }

    /// A well-formed record (id == keccak(params), token hashes to debridge_id)
    /// with a nonce unique to this run so re-runs against one database do not
    /// collide, plus ONE valid signature from a fresh key.
    fn signed_record(chain_to: u64) -> SubmissionRecord {
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;
        use alloy_primitives::{Address, B256, U256};
        let token = Address::repeat_byte(0x11);
        let debridge_id = bridge_core::debridge_id(U256::from(1337u64), token);
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;
        let receiver = Address::repeat_byte(0xAB).to_vec();
        let domain = B256::repeat_byte(0xD0);
        let id = bridge_core::submission_id(
            domain,
            debridge_id,
            U256::from(100u64),
            U256::from(1337u64),
            U256::from(chain_to),
            U256::from(nonce),
            &receiver,
        );
        let signer = PrivateKeySigner::random();
        let sig = signer.sign_message_sync(id.as_slice()).unwrap();
        SubmissionRecord {
            submission_id: format!("{id:#x}"),
            bridge_domain: format!("{domain:#x}"),
            debridge_id: format!("{debridge_id:#x}"),
            amount: "100".into(),
            chain_id_from: 1337,
            chain_id_to: chain_to,
            nonce,
            receiver: format!("0x{}", hex::encode(&receiver)),
            auto_params: "0x".into(),
            native_sender: "0x".into(),
            token: format!("{token:#x}"),
            signatures: vec![SignerSig {
                signer: format!("{:#x}", signer.address()),
                signature: bridge_core::signer::encode_signature(&sig),
            }],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    async fn get_json<T: serde::de::DeserializeOwned>(app: Router, uri: &str, bearer: &str) -> T {
        let req = Request::builder()
            .method("GET")
            .uri(uri)
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .body(Body::empty())
            .unwrap();
        let res = app.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "GET {uri}");
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    /// THE M-1 property, end to end through the real router and a real database:
    /// the keeper's `POST /submissions/:id/claimed` must leave a READY transfer in
    /// the keeper's claim queue and in the history as `signed`, and must park
    /// nothing for an id that has no row yet. Only the indexer's `mark_claimed`
    /// (an observed on-chain event) may take it out of the queue.
    #[tokio::test]
    async fn a_relay_token_cannot_hide_a_transfer() {
        let Some(url) = live_db_url() else { return };
        let _serial = LIVE_DB.lock().await;
        let db = Db::connect(&url).await.expect("connect to BRIDGE_TEST_DATABASE_URL");
        let app = build_app(AppState { db: db.clone() }, test_auth(), RateLimit::new(1_000, 1_000.0), 256 * 1024);

        // A fresh chain_to per run keeps the pending-claims queue we inspect small.
        let chain_to = 900_000 + (std::process::id() as u64 % 90_000);
        let rec = signed_record(chain_to);
        let id = rec.submission_id.clone();
        let res = post_json(app.clone(), "/submissions", Some(VAL), &rec).await;
        assert_eq!(res.status(), StatusCode::OK, "validator upsert");

        let queue_uri = format!("/submissions?pending=claims&chain_id_to={chain_to}");
        let in_queue = |q: &Vec<SubmissionRecord>| q.iter().any(|r| r.submission_id.eq_ignore_ascii_case(&id));
        assert!(in_queue(&get_json(app.clone(), &queue_uri, KEEP).await), "premise: READY and queued");

        // The keeper reports a claim. Pre-fix this set status='claimed'.
        let claim = ClaimedRequest { claim_tx: format!("0x{}", "77".repeat(32)) };
        let res = post_json(app.clone(), &format!("/submissions/{}/claimed", &id[2..]), Some(KEEP), &claim).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);

        // Still in the claim queue; history still says `signed`, with the report
        // recorded where nothing reads it for control flow.
        assert!(
            in_queue(&get_json(app.clone(), &queue_uri, KEEP).await),
            "a Relay token must not remove a transfer from the claim queue"
        );
        let hist: Vec<SubmissionHistory> = get_json(app.clone(), "/history?limit=50", READ).await;
        let row = hist.iter().find(|h| h.submission_id.eq_ignore_ascii_case(&id)).expect("in history");
        assert_eq!(row.status, "signed");
        assert_eq!(row.claim_tx, None, "the authoritative claim_tx is untouched");
        assert_eq!(row.refund_status, "none");
        assert_eq!(row.keeper_claim_tx.as_deref(), Some(claim.claim_tx.as_str()));

        // A report for an id with no row must park NOTHING: when the row later
        // appears (indexer `Sent`), it must come up `signed` and queued.
        let future = signed_record(chain_to);
        let fid = future.submission_id.clone();
        let res = post_json(app.clone(), &format!("/submissions/{}/claimed", &fid[2..]), Some(KEEP), &claim).await;
        assert_eq!(res.status(), StatusCode::NO_CONTENT);
        let mut observed = future.clone();
        observed.signatures.clear();
        db.observe_submission(observed).await.unwrap();
        let q: Vec<SubmissionRecord> = get_json(app.clone(), &queue_uri, KEEP).await;
        assert!(q.iter().any(|r| r.submission_id.eq_ignore_ascii_case(&fid)), "pre-poisoning a future id must not work");
        let hist: Vec<SubmissionHistory> = get_json(app.clone(), "/history?limit=50", READ).await;
        let frow = hist.iter().find(|h| h.submission_id.eq_ignore_ascii_case(&fid)).unwrap();
        assert_eq!(frow.status, "signed");
        assert_eq!(frow.keeper_claim_tx, None, "nothing was parked for the unknown id");

        // Contrast: the indexer's observed on-chain `Claimed` IS authoritative.
        db.mark_claimed(&id, &claim.claim_tx).await.unwrap();
        assert!(!in_queue(&get_json(app.clone(), &queue_uri, KEEP).await), "an observed claim leaves the queue");
        let hist: Vec<SubmissionHistory> = get_json(app.clone(), "/history?limit=50", READ).await;
        let row = hist.iter().find(|h| h.submission_id.eq_ignore_ascii_case(&id)).unwrap();
        assert_eq!(row.status, "claimed");
        assert_eq!(row.claim_tx.as_deref(), Some(claim.claim_tx.as_str()));
    }

    /// Paging through the real router: `limit` bounds the page and `offset` walks
    /// it, with the default returning the same order an unbounded call would.
    #[tokio::test]
    async fn listing_is_paged() {
        let Some(url) = live_db_url() else { return };
        let _serial = LIVE_DB.lock().await;
        let db = Db::connect(&url).await.unwrap();
        let app = build_app(AppState { db }, test_auth(), RateLimit::new(1_000, 1_000.0), 256 * 1024);
        for _ in 0..3 {
            let res = post_json(app.clone(), "/submissions", Some(VAL), &signed_record(1338)).await;
            assert_eq!(res.status(), StatusCode::OK);
        }
        let all: Vec<SubmissionRecord> = get_json(app.clone(), "/submissions", READ).await;
        assert!(all.len() >= 3);
        let p1: Vec<SubmissionRecord> = get_json(app.clone(), "/submissions?limit=2", READ).await;
        assert_eq!(p1.len(), 2);
        let p2: Vec<SubmissionRecord> = get_json(app.clone(), "/submissions?limit=2&offset=2", READ).await;
        assert_eq!(p1[0].submission_id, all[0].submission_id);
        assert_eq!(p1[1].submission_id, all[1].submission_id);
        assert_eq!(p2[0].submission_id, all[2].submission_id);
        let h: Vec<SubmissionHistory> = get_json(app.clone(), "/history?limit=1", READ).await;
        assert_eq!(h.len(), 1);
    }
}
