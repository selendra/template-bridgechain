//! The GraphQL schema: a read view over the signature store plus a single
//! `submitSignature` mutation that goes through the same trust-boundary `upsert`.
//!
//! Nothing here talks to a chain — it reports what the validators have *signed*,
//! not what the keeper has executed on-chain. `meetsThreshold` therefore means
//! "has enough signatures for the keeper to claim", given the `--threshold` the
//! API was started with (omitted => `meetsThreshold` is null).

use std::sync::Arc;

use async_graphql::{ComplexObject, Context, Enum, InputObject, Object, SimpleObject};
use bridge_core::allow::{SubmissionHistory, SwapBridgeInfo, SwapRecord};
use bridge_core::backend::StoreBackend;
use bridge_core::store::{SignerSig, SubmissionRecord};

use crate::chain::{ChainInfo, Chains};
use crate::swap::{PoolInfo, PoolToken, Swaps};

/// Rows returned by a list query when the caller passes no `limit`.
pub const DEFAULT_PAGE: u64 = 50;
/// Hard ceiling on rows per list query, whatever `limit` says. Bounds the
/// per-row `eth_call` fan-out of `executed`/`cancelled`/`status` (M-8) together
/// with the `complexity` multipliers below.
pub const MAX_PAGE: u64 = 200;
/// Complexity charged for one field that costs an upstream RPC call
/// (`executed`, `cancelled`, `status`). With the list multipliers this is what
/// makes `limit_complexity` a bound on RPC fan-out rather than on JSON size.
pub const CHAIN_READ_COST: usize = 20;

/// Effective page size for a `limit` argument: default when absent, capped at
/// [`MAX_PAGE`], never zero.
pub fn page_size(limit: Option<u64>) -> usize {
    limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE) as usize
}

/// The `limit`/`offset` window over an already-loaded list.
///
/// The page is cut HERE, after the resolver's own filters, rather than asked of
/// the store. The sig-store now takes `limit`/`offset` on `GET /submissions` and
/// `GET /history` (`RemoteStore::load_page` / `history_page`, server default and
/// cap 5,000 rows) — but those routes take no `chain_id_from`/`chain_id_to`/
/// `stuck` filters, so a server-side window under a client-side filter would
/// return short, misaligned pages. Until the store filters too, the store's cap
/// bounds the load and this bounds the response; the finding's point — per-row
/// chain reads happen only for the rows RETURNED — holds either way, and the
/// wire shape will not change when the cut moves server-side.
pub fn paginate<T>(rows: Vec<T>, limit: Option<u64>, offset: Option<u64>) -> Vec<T> {
    let skip = offset.unwrap_or(0) as usize;
    rows.into_iter().skip(skip).take(page_size(limit)).collect()
}

/// Turn a store/backend failure into a client-facing GraphQL error.
///
/// `RemoteError`'s `Display` is reqwest's, and reqwest prints the request URL —
/// i.e. the sig-store's internal address (and, in a misconfigured deployment,
/// anything in its userinfo). That went straight into the `errors[]` of the one
/// service that faces the internet. The detail is logged here; the client gets
/// a fixed message. Store-side rejections (`StoreError`: bad id, signature
/// mismatch, ...) carry no URL and are still passed through — the caller needs
/// them to fix its input.
pub fn store_error(e: anyhow::Error) -> async_graphql::Error {
    if e.downcast_ref::<bridge_core::remote::RemoteError>().is_some()
        || e.downcast_ref::<reqwest::Error>().is_some()
    {
        tracing::warn!(error = ?e, "signature store request failed");
        return async_graphql::Error::new("signature store unavailable");
    }
    async_graphql::Error::new(e.to_string())
}

/// Shared, read-mostly state handed to every resolver via the schema's data.
pub struct ApiState {
    pub backend: Arc<StoreBackend>,
    /// Signature count the keeper requires to claim. `None` => unknown here, so
    /// `meetsThreshold`/`ready` are reported as null/zero.
    pub threshold: Option<u64>,
    /// Optional destination-gate RPCs, so `executed`/`status` can report on-chain
    /// delivery. Empty => those fields are null/UNKNOWN.
    pub chains: Chains,
    /// The network registry served to the UI via the `chains` query (so the
    /// frontend discovers configured chains instead of hardcoding them). Empty
    /// when the API wasn't started with `--chains-file`.
    pub registry: Vec<ChainInfo>,
    /// Optional same-chain `SwapPool` RPCs, so `pools`/`swapQuote` can report
    /// live pool state. Empty => those fields are null.
    pub swaps: Swaps,
    // NOTE: there is deliberately no database handle here. `history` and
    // `swapHistory` read the indexer's data through the sig-store's `Read`
    // scope, on the same read-only bearer token this service already carries.
    // A Postgres credential in THIS process — the only one published to the
    // internet — would sit outside `bridge_core::auth` entirely and could write
    // signatures, rewrite the allowlists, and forge the `refund_status` the
    // sig-store refuses to expose at any scope.
}

/// A network the bridge UI can target. Mirrors [`ChainInfo`] for the wire.
#[derive(SimpleObject)]
pub struct Chain {
    pub chain_id: u64,
    pub name: String,
    /// Browser-safe, KEYLESS read-only RPC for off-wallet reads
    /// (decimals/balances) — the registry's `public_rpc_url`. Null when the
    /// operator has not published one; the UI then reads through the wallet.
    /// The server-side `rpc_url` (which may carry a provider key) is never
    /// returned here.
    pub rpc_url: Option<String>,
    /// Deployed Gate on this chain, or null if it isn't pinned server-side.
    pub gate: Option<String>,
    /// Default ERC-20 to prefill when bridging from this chain. Null if unset.
    pub token: Option<String>,
    /// All ERC-20s that can be bridged from this chain (for the UI's token
    /// picker). Empty when the registry doesn't list any.
    pub tokens: Vec<Token>,
    /// Deployed `SwapRouter` on this chain, for cross-chain-swap. Null if unset.
    pub router: Option<String>,
}

/// One bridgeable token on a chain.
#[derive(SimpleObject)]
pub struct Token {
    pub symbol: String,
    /// `0x`-prefixed ERC-20 address on this chain.
    pub address: String,
}

impl From<ChainInfo> for Chain {
    fn from(c: ChainInfo) -> Self {
        Chain {
            chain_id: c.chain_id,
            name: c.name,
            // H-4: only the public endpoint ever crosses the wire.
            rpc_url: c.public_rpc_url,
            gate: c.gate,
            token: c.token,
            tokens: c
                .tokens
                .into_iter()
                .map(|t| Token { symbol: t.symbol, address: t.address })
                .collect(),
            router: c.router,
        }
    }
}

/// One listed token in a same-chain swap pool. Numeric fields are decimal
/// strings (uint256) to avoid JSON precision loss, like `Submission.amount`.
#[derive(SimpleObject)]
pub struct PoolTokenView {
    /// `0x`-prefixed token address (base58 mint on Solana).
    pub token: String,
    /// The pool's vault for this token — Solana only, `null` on EVM where the
    /// pool contract holds its own balances. A UI needs it to build the swap
    /// instruction; a wrong one fails the transaction rather than misdirecting
    /// it, since the program pins the vault in its own token record.
    pub vault: Option<String>,
    /// ERC-20 symbol (empty if the token doesn't expose one).
    pub symbol: String,
    pub decimals: u8,
    /// USD price, 1e18-scaled, decimal string.
    pub price: String,
    /// Current reserve (the swap lock), in token base units, decimal string.
    pub reserve: String,
    /// Max swap-out value in 1e18-scaled USD (`reserve*price/10^decimals`).
    pub max_swap_usd: String,
    /// True for the pool's core-price stablecoin.
    pub is_stable: bool,
    /// Unix seconds the current price was set (Solana only; null on EVM).
    /// `0` means never stamped, which the program treats as stale.
    pub price_set_at: Option<i64>,
    /// Whether the program would accept this price now (Solana only; null on
    /// EVM). `false` means a swap through this token reverts `StalePrice` and
    /// `swapQuote` returns null for it.
    pub price_fresh: Option<bool>,
}

/// What a browser needs to build a Solana gate `send`. See the resolver for why
/// none of it is trusted with the destination of the transfer.
#[derive(SimpleObject)]
pub struct SolanaGateContext {
    /// Base58 gate program id.
    pub program_id: String,
    /// `0x` + 64 hex — the deployment generation, hashed into the submissionId.
    pub bridge_domain: String,
    /// The gate's own chain id (deBridge's id for Solana).
    pub chain_id: u64,
    /// Next nonce for this destination corridor.
    pub nonce: u64,
    pub debridge_id: String,
    /// The registered vault the tokens are locked into.
    pub vault: String,
    /// The mint's decimals, for amount entry.
    pub decimals: u8,
    /// True when the gate's circuit breaker is tripped — a `send` would revert.
    pub paused: bool,
}

/// A configured same-chain swap pool: its contract address, core stablecoin,
/// and the tokens listed on it. The `address` is what a wallet sends
/// `approve`/`swap` to, so a UI can execute a swap end-to-end from this alone.
#[derive(SimpleObject)]
pub struct SwapPoolInfo {
    pub chain_id: u64,
    /// `0x`-prefixed SwapPool contract address.
    pub address: String,
    /// `0x`-prefixed core stablecoin (unit of account).
    pub stable: String,
    pub tokens: Vec<PoolTokenView>,
    /// Max age (seconds) of a token price the program will still swap at —
    /// the effective `max_price_age`. Solana only; null on EVM.
    pub max_price_age: Option<i64>,
}

impl SwapPoolInfo {
    fn build(chain_id: u64, info: PoolInfo) -> Self {
        SwapPoolInfo {
            chain_id,
            address: info.address,
            stable: info.stable,
            tokens: info.tokens.into_iter().map(Into::into).collect(),
            max_price_age: info.max_price_age,
        }
    }
}

impl From<PoolToken> for PoolTokenView {
    fn from(p: PoolToken) -> Self {
        PoolTokenView {
            vault: p.vault,
            token: p.token,
            symbol: p.symbol,
            decimals: p.decimals,
            price: p.price,
            reserve: p.reserve,
            max_swap_usd: p.max_swap_usd,
            is_stable: p.is_stable,
            price_set_at: p.price_set_at,
            price_fresh: p.price_fresh,
        }
    }
}

/// Lifecycle of a transfer, combining off-chain signatures with on-chain truth.
#[derive(Enum, Copy, Clone, Eq, PartialEq, Debug)]
pub enum SubmissionStatus {
    /// Fewer than `threshold` signatures collected — the keeper can't claim yet.
    Pending,
    /// Enough signatures to claim, but not yet executed on the destination chain.
    Ready,
    /// `executed(submissionId) == true` on the destination gate — delivered.
    Executed,
    /// Burned on the destination by `Gate.cancel` so the source could refund it.
    /// Also sets `executed`, hence the separate state: the funds went BACK, they
    /// did not arrive.
    Cancelled,
    /// Can't be determined (no `--threshold` and/or no destination RPC configured).
    Unknown,
}

/// One validator's signature over a submissionId.
#[derive(SimpleObject)]
pub struct Signature {
    /// Recovered signer address, `0x`-prefixed.
    pub signer: String,
    /// 65-byte ECDSA signature (r||s||v), `0x`-prefixed.
    pub signature: String,
}

impl From<SignerSig> for Signature {
    fn from(s: SignerSig) -> Self {
        Signature { signer: s.signer, signature: s.signature }
    }
}

/// A cross-chain transfer and the signatures collected for it so far.
///
/// The plain fields come straight from the store (cheap). `executed` and `status`
/// are resolved lazily — they only hit the destination chain when a client asks
/// for them, and only if the API was started with a `--gate` for `chainIdTo`.
#[derive(SimpleObject)]
#[graphql(complex)]
pub struct Submission {
    /// The sacred submissionId (`0x`-prefixed keccak of the transfer params).
    pub submission_id: String,
    pub debridge_id: String,
    /// uint256 as a decimal string (avoids JSON precision loss).
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    /// `0x`-prefixed raw receiver bytes.
    pub receiver: String,
    /// `0x`-prefixed execution payload (`0x` when none).
    pub auto_params: String,
    /// `0x`-prefixed packed source sender.
    pub native_sender: String,
    /// The source-chain ERC-20 that was locked (empty on rows predating the
    /// refund path). Needed to build `Gate.refund`.
    pub token: String,
    pub signatures: Vec<Signature>,
    /// Convenience: `signatures.len()`.
    pub signature_count: u64,
    /// `signatureCount >= threshold`, or null if the API has no threshold set.
    pub meets_threshold: Option<bool>,
    /// Validators attesting the DESTINATION burn (`Gate.cancel`). A separate
    /// quorum from `signatures` — a transfer signature can never count here.
    pub cancel_signature_count: u64,
    /// Validators attesting the SOURCE payout (`Gate.refund`). Only forms after
    /// the burn is observed on-chain.
    pub refund_signature_count: u64,
}

impl Submission {
    fn from_record(rec: SubmissionRecord, threshold: Option<u64>) -> Self {
        let signature_count = rec.signatures.len() as u64;
        let meets_threshold = threshold.map(|t| signature_count >= t);
        Submission {
            submission_id: rec.submission_id,
            debridge_id: rec.debridge_id,
            amount: rec.amount,
            chain_id_from: rec.chain_id_from,
            chain_id_to: rec.chain_id_to,
            nonce: rec.nonce,
            receiver: rec.receiver,
            auto_params: rec.auto_params,
            native_sender: rec.native_sender,
            token: rec.token,
            cancel_signature_count: rec.cancel_signatures.len() as u64,
            refund_signature_count: rec.refund_signatures.len() as u64,
            signatures: rec.signatures.into_iter().map(Into::into).collect(),
            signature_count,
            meets_threshold,
        }
    }
}

#[ComplexObject]
impl Submission {
    /// On-chain `executed(submissionId)` on the destination gate. `null` when the
    /// API has no `--gate` configured for `chainIdTo` (or the RPC call failed).
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn executed(&self, ctx: &Context<'_>) -> Option<bool> {
        state(ctx).chains.executed(self.chain_id_to, &self.submission_id).await
    }

    /// On-chain `cancelled(submissionId)`: the transfer was burned on the
    /// destination so it could be refunded on the source, rather than delivered.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn cancelled(&self, ctx: &Context<'_>) -> Option<bool> {
        state(ctx).chains.cancelled(self.chain_id_to, &self.submission_id).await
    }

    /// Combined lifecycle: CANCELLED if the destination burned it, EXECUTED if
    /// the destination gate confirms delivery, otherwise READY/PENDING from the
    /// signature count, or UNKNOWN if neither a threshold nor a destination RPC
    /// is configured.
    #[graphql(complexity = "CHAIN_READ_COST")]
    async fn status(&self, ctx: &Context<'_>) -> SubmissionStatus {
        let chains = &state(ctx).chains;
        if chains.executed(self.chain_id_to, &self.submission_id).await == Some(true) {
            // `cancel` sets `executed` too, so check which one it was before
            // telling anyone their funds were delivered.
            if chains.cancelled(self.chain_id_to, &self.submission_id).await == Some(true) {
                return SubmissionStatus::Cancelled;
            }
            return SubmissionStatus::Executed;
        }
        match self.meets_threshold {
            Some(true) => SubmissionStatus::Ready,
            Some(false) => SubmissionStatus::Pending,
            None => SubmissionStatus::Unknown,
        }
    }
}

/// Optional filters for `submissions`. All supplied fields must match (AND).
#[derive(InputObject, Default)]
pub struct SubmissionFilter {
    pub chain_id_from: Option<u64>,
    pub chain_id_to: Option<u64>,
    /// Keep only records with at least this many signatures.
    pub min_signatures: Option<u64>,
    /// `true` => only records that meet the keeper threshold; `false` => only
    /// those that don't. Requires the API to have been started with `--threshold`.
    pub ready: Option<bool>,
}

/// How many submissions flow along one source→destination route.
#[derive(SimpleObject)]
pub struct RouteCount {
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub count: u64,
}

/// Aggregate view of the whole store.
#[derive(SimpleObject)]
pub struct Stats {
    /// Total records in the store.
    pub total: u64,
    /// Records with at least one signature.
    pub signed: u64,
    /// Records that meet the threshold (0 if no threshold is configured).
    pub ready: u64,
    /// The configured keeper threshold, if any.
    pub threshold: Option<u64>,
    /// Per source→destination route counts, sorted by (from, to).
    pub routes: Vec<RouteCount>,
}

fn state<'c>(ctx: &Context<'c>) -> &'c ApiState {
    ctx.data_unchecked::<ApiState>()
}



/// The swap intent (and destination outcome, once known) of a
/// `SwapRouter.swapAndBridge` transfer — a plain bridge send has none.
#[derive(SimpleObject)]
pub struct SwapIntent {
    pub token_in: String,
    pub amount_in: String,
    pub stable_out: String,
    pub final_token: String,
    pub final_receiver: String,
    /// Destination-chain finalize tx, once the swap-back leg has run.
    pub finalize_tx: Option<String>,
    pub finalize_amount_out: Option<String>,
    /// True if the destination swap failed and the stable was delivered as-is.
    pub finalize_fallback: Option<bool>,
    pub finalized_at: Option<String>,
}

impl From<SwapBridgeInfo> for SwapIntent {
    fn from(i: SwapBridgeInfo) -> Self {
        SwapIntent {
            token_in: i.token_in,
            amount_in: i.amount_in,
            stable_out: i.stable_out,
            final_token: i.final_token,
            final_receiver: i.final_receiver,
            finalize_tx: i.finalize_tx,
            finalize_amount_out: i.finalize_amount_out,
            finalize_fallback: i.finalize_fallback,
            finalized_at: i.finalized_at,
        }
    }
}

/// One row of the database-backed transaction-history view: every bridge
/// transfer the `indexer` has observed, regardless of whether it ever got a
/// validator signature — unlike `submissions`/`submission` (signature-store
/// view), this is where a stuck/failed transfer is visible.
#[derive(SimpleObject)]
pub struct HistoryEntry {
    pub submission_id: String,
    pub debridge_id: String,
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: String,
    pub status: String,
    pub claim_tx: Option<String>,
    pub signature_count: u64,
    pub created_at: String,
    pub updated_at: String,
    /// True once this transfer has entered the refund lifecycle at all.
    pub stuck: bool,
    /// `none` | `eligible` | `cancelled` | `refunded`. `cancelled` means the
    /// destination was burned so the source could repay; `refunded` means the
    /// funds are back with the sender.
    pub refund_status: String,
    /// Source-chain `Gate.refund` tx hash.
    pub refund_tx: Option<String>,
    /// Destination-chain `Gate.cancel` tx hash.
    pub cancel_tx: Option<String>,
    /// The source-chain ERC-20 that was locked.
    pub token: Option<String>,
    /// Validators attesting the destination burn.
    pub cancel_signature_count: u64,
    /// Validators attesting the source payout.
    pub refund_signature_count: u64,
    /// Set when this transfer originated from `SwapRouter.swapAndBridge`.
    pub swap_intent: Option<SwapIntent>,
}

impl From<SubmissionHistory> for HistoryEntry {
    fn from(h: SubmissionHistory) -> Self {
        HistoryEntry {
            submission_id: h.submission_id,
            debridge_id: h.debridge_id,
            amount: h.amount,
            chain_id_from: h.chain_id_from,
            chain_id_to: h.chain_id_to,
            nonce: h.nonce,
            receiver: h.receiver,
            status: h.status,
            claim_tx: h.claim_tx,
            signature_count: h.signature_count as u64,
            created_at: h.created_at,
            updated_at: h.updated_at,
            stuck: h.stuck,
            refund_status: h.refund_status,
            refund_tx: h.refund_tx,
            cancel_tx: h.cancel_tx,
            token: h.token,
            cancel_signature_count: h.cancel_signature_count as u64,
            refund_signature_count: h.refund_signature_count as u64,
            swap_intent: h.swap_intent.map(Into::into),
        }
    }
}

/// Optional filters for `history`. All supplied fields must match (AND).
#[derive(InputObject, Default)]
pub struct HistoryFilter {
    pub chain_id_from: Option<u64>,
    pub chain_id_to: Option<u64>,
    /// Keep only transfers flagged stuck (refund-eligible).
    pub stuck_only: Option<bool>,
    /// Exact-match one submissionId (e.g. to look up refund/stuck status for a
    /// detail view already loaded via `submission`). Case-insensitive.
    pub submission_id: Option<String>,
}

/// One completed same-chain swap (`SwapPool.Swapped`), mirrored by the indexer.
#[derive(SimpleObject)]
pub struct SwapHistoryEntry {
    pub chain_id: u64,
    pub tx_hash: String,
    pub sender: String,
    pub receiver: String,
    pub token_in: String,
    pub token_out: String,
    pub amount_in: String,
    pub amount_out: String,
    pub block_number: u64,
    pub created_at: String,
}

impl From<SwapRecord> for SwapHistoryEntry {
    fn from(s: SwapRecord) -> Self {
        SwapHistoryEntry {
            chain_id: s.chain_id,
            tx_hash: s.tx_hash,
            sender: s.sender,
            receiver: s.receiver,
            token_in: s.token_in,
            token_out: s.token_out,
            amount_in: s.amount_in,
            amount_out: s.amount_out,
            block_number: s.block_number,
            created_at: s.created_at,
        }
    }
}

pub struct Query;

#[Object]
impl Query {
    /// Submissions matching `filter`, sorted by (chainIdFrom, chainIdTo, nonce)
    /// for a stable order, as one page: `limit` rows (default 50, at most 200)
    /// starting at `offset` (default 0). Both are optional, so existing clients
    /// keep working and simply receive the first page.
    #[graphql(complexity = "page_size(limit) * child_complexity")]
    async fn submissions(
        &self,
        ctx: &Context<'_>,
        filter: Option<SubmissionFilter>,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> async_graphql::Result<Vec<Submission>> {
        let st = state(ctx);
        let f = filter.unwrap_or_default();
        let threshold = st.threshold;

        let mut records = st.backend.load_all().await.map_err(store_error)?;
        records.sort_by(|a, b| {
            (a.chain_id_from, a.chain_id_to, a.nonce).cmp(&(
                b.chain_id_from,
                b.chain_id_to,
                b.nonce,
            ))
        });

        let out = records
            .into_iter()
            .filter(|r| f.chain_id_from.is_none_or(|c| r.chain_id_from == c))
            .filter(|r| f.chain_id_to.is_none_or(|c| r.chain_id_to == c))
            .filter(|r| f.min_signatures.is_none_or(|m| r.signatures.len() as u64 >= m))
            .filter(|r| match (f.ready, threshold) {
                (Some(want), Some(t)) => (r.signatures.len() as u64 >= t) == want,
                (Some(_), None) => false, // asked to filter by readiness but we can't judge
                (None, _) => true,
            })
            .map(|r| Submission::from_record(r, threshold))
            .collect();
        Ok(paginate(out, limit, offset))
    }

    /// A single submission by its `0x`-prefixed submissionId, or null if unknown.
    async fn submission(
        &self,
        ctx: &Context<'_>,
        submission_id: String,
    ) -> async_graphql::Result<Option<Submission>> {
        // Reject anything that isn't a 32-byte hex hash before it reaches a
        // backend, where it would otherwise build a file path (dir) or a URL
        // (remote) — path-traversal / URL-injection defense at the boundary.
        if !bridge_core::store::is_valid_submission_id(&submission_id) {
            return Err(async_graphql::Error::new(
                "submissionId must be a 32-byte hex hash (0x + 64 hex digits)",
            ));
        }
        let st = state(ctx);
        let rec = st.backend.load(&submission_id).await.map_err(store_error)?;
        Ok(rec.map(|r| Submission::from_record(r, st.threshold)))
    }

    /// The configured network registry, so the UI can discover chains (id, name,
    /// RPC, gate, token) from the backend instead of hardcoding them. Empty when
    /// the API was started without `--chains-file`.
    async fn chains(&self, ctx: &Context<'_>) -> Vec<Chain> {
        state(ctx).registry.iter().cloned().map(Chain::from).collect()
    }

    /// Live snapshot of a same-chain swap pool: every listed token with its
    /// price, reserve (the swap lock), and max-swap-out USD value. `null` when
    /// the API has no `--swap` configured for `chainId` (or the RPC read failed).
    async fn pools(&self, ctx: &Context<'_>, chain_id: u64) -> Option<Vec<PoolTokenView>> {
        state(ctx)
            .swaps
            .pools(chain_id)
            .await
            .map(|v| v.into_iter().map(Into::into).collect())
    }

    /// Full snapshot of a same-chain swap pool INCLUDING its contract address and
    /// core stablecoin, so a UI can execute a swap (approve + `swap`) against it.
    /// `null` when the API has no `--swap` for `chainId` (or the RPC read failed).
    async fn swap_pool(&self, ctx: &Context<'_>, chain_id: u64) -> Option<SwapPoolInfo> {
        state(ctx)
            .swaps
            .pool_info(chain_id)
            .await
            .map(|info| SwapPoolInfo::build(chain_id, info))
    }

    /// On-chain `quote` for a same-chain swap: the pegged output (net of fee,
    /// before the reserve cap) for swapping `amountIn` of `tokenIn` into
    /// `tokenOut`, as a decimal string. `null` when the chain isn't configured,
    /// an address/amount is malformed, a token isn't listed (call reverts), or —
    /// on Solana — a leg's price is older than the pool's `maxPriceAge`, which
    /// the program would reject as `StalePrice` (see `PoolTokenView.priceFresh`).
    async fn swap_quote(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        token_in: String,
        token_out: String,
        amount_in: String,
    ) -> Option<String> {
        state(ctx).swaps.quote(chain_id, &token_in, &token_out, &amount_in).await
    }

    /// Everything a browser needs to build a `send` on the Solana gate for one
    /// asset and destination: the deployment domain, the corridor's next nonce,
    /// and the registered vault.
    ///
    /// None of it can redirect a transfer — the receiver, amount and destination
    /// are packed into the instruction by the browser, and a wrong value here
    /// yields a submissionId the program does not derive, so the transaction
    /// fails rather than pays the wrong account.
    async fn solana_gate_context(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        // `symbol` is the asset as the registry lists it; the debridgeId is
        // derived from the DESTINATION chain's token for that symbol.
        symbol: String,
        chain_id_to: u64,
    ) -> Option<SolanaGateContext> {
        let st = state(ctx);
        let gate = st.chains.solana_gate(chain_id)?;
        // The debridgeId is DERIVED, not configured: it is `keccak(chainId,
        // token)` of the asset on the chain it is native to — here, the
        // destination. Deriving it from the registry means one less value that
        // can be stale, and the same value the destination gate will look up
        // when it claims.
        let dest = st.registry.iter().find(|c| c.chain_id == chain_id_to)?;
        let token = dest
            .tokens
            .iter()
            .find(|t| t.symbol.eq_ignore_ascii_case(&symbol))
            .map(|t| t.address.clone())?;
        let token: alloy_primitives::Address = token.parse().ok()?;
        let id = bridge_core::debridge_id(alloy_primitives::U256::from(chain_id_to), token);
        let debridge_id = format!("{id:#x}");
        match gate.send_context(&debridge_id, chain_id_to).await {
            Ok(c) => Some(SolanaGateContext {
                program_id: c.program_id,
                bridge_domain: c.bridge_domain,
                chain_id: c.chain_id,
                nonce: c.nonce,
                debridge_id: c.debridge_id,
                vault: c.vault,
                decimals: c.decimals,
                paused: c.paused,
            }),
            Err(e) => {
                tracing::warn!(chain_id, error = %e, "solana gate context unavailable");
                None
            }
        }
    }

    /// A recent blockhash for a Solana pool's cluster. The browser builds and
    /// signs its own swap transaction — this is the one piece it cannot derive,
    /// and passing it through here keeps the RPC credential server-side.
    /// `null` for an EVM chain or an unconfigured one.
    async fn solana_blockhash(&self, ctx: &Context<'_>, chain_id: u64) -> Option<String> {
        state(ctx).swaps.solana_blockhash(chain_id).await
    }

    /// SPL balance of a token account, as a decimal string ("0" when the
    /// account does not exist yet). The caller derives the address; this only
    /// reads it.
    async fn solana_token_balance(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        account: String,
    ) -> Option<String> {
        state(ctx).swaps.solana_token_balance(chain_id, &account).await
    }

    /// Confirmation state of a Solana transaction: `pending`, `processed`,
    /// `confirmed`, `finalized` or `failed`. `null` for an EVM chain.
    async fn solana_signature_status(
        &self,
        ctx: &Context<'_>,
        chain_id: u64,
        signature: String,
    ) -> Option<String> {
        state(ctx).swaps.solana_signature_status(chain_id, &signature).await
    }

    /// Aggregate counts across the whole store.
    async fn stats(&self, ctx: &Context<'_>) -> async_graphql::Result<Stats> {
        use std::collections::BTreeMap;
        let st = state(ctx);
        let records = st.backend.load_all().await.map_err(store_error)?;

        let mut signed = 0u64;
        let mut ready = 0u64;
        let mut routes: BTreeMap<(u64, u64), u64> = BTreeMap::new();
        for r in &records {
            let n = r.signatures.len() as u64;
            if n >= 1 {
                signed += 1;
            }
            if let Some(t) = st.threshold {
                if n >= t {
                    ready += 1;
                }
            }
            *routes.entry((r.chain_id_from, r.chain_id_to)).or_default() += 1;
        }

        Ok(Stats {
            total: records.len() as u64,
            signed,
            ready,
            threshold: st.threshold,
            routes: routes
                .into_iter()
                .map(|((from, to), count)| RouteCount {
                    chain_id_from: from,
                    chain_id_to: to,
                    count,
                })
                .collect(),
        })
    }

    /// Transaction history: every bridge transfer the `indexer` has observed
    /// on-chain, including ones stuck at zero signatures (which `submissions` can
    /// never show, since that view only exists once a validator has signed).
    /// Newest first.
    ///
    /// Read through the sig-store's `/history` route on this service's read-only
    /// bearer token — deliberately NOT straight from Postgres. This process is
    /// the one exposed to the internet, and a database credential here would
    /// bypass every scope in `bridge_core::auth`. Needs `--store-url`.
    ///
    /// One page: `limit` rows (default 50, at most 200) from `offset` (default
    /// 0), applied after `filter`.
    #[graphql(complexity = "page_size(limit) * child_complexity")]
    async fn history(
        &self,
        ctx: &Context<'_>,
        filter: Option<HistoryFilter>,
        limit: Option<u64>,
        offset: Option<u64>,
    ) -> async_graphql::Result<Vec<HistoryEntry>> {
        let f = filter.unwrap_or_default();
        let rows = state(ctx).backend.history().await.map_err(store_error)?;
        let rows: Vec<HistoryEntry> = rows
            .into_iter()
            .filter(|r| f.chain_id_from.is_none_or(|c| r.chain_id_from == c))
            .filter(|r| f.chain_id_to.is_none_or(|c| r.chain_id_to == c))
            .filter(|r| f.stuck_only.is_none_or(|want| r.stuck == want))
            .filter(|r| f.submission_id.as_deref().is_none_or(|id| r.submission_id.eq_ignore_ascii_case(id)))
            .map(Into::into)
            .collect();
        Ok(paginate(rows, limit, offset))
    }

    /// Same-chain swap history (`SwapPool.Swapped`), mirrored by the `indexer`.
    /// Newest first, optionally scoped to one chain. Served over the sig-store's
    /// read scope for the reason `history` documents. Needs `--store-url`.
    /// `limit` defaults to 50 and is capped at 200.
    #[graphql(complexity = "page_size(limit) * child_complexity")]
    async fn swap_history(
        &self,
        ctx: &Context<'_>,
        chain_id: Option<u64>,
        limit: Option<u64>,
    ) -> async_graphql::Result<Vec<SwapHistoryEntry>> {
        let rows = state(ctx)
            .backend
            .swaps(chain_id, page_size(limit) as u64)
            .await
            .map_err(store_error)?;
        Ok(rows.into_iter().map(Into::into).collect())
    }
}

/// Mirrors a `SubmissionRecord` plus exactly one signature to merge in.
#[derive(InputObject)]
pub struct SubmissionInput {
    pub submission_id: String,
    /// Deployment generation of the gate that emitted this transfer,
    /// `0x`-prefixed bytes32. Part of the submissionId preimage, so an absent or
    /// wrong value simply fails the server-side id check — it is not a way to
    /// smuggle a record in, only a way to be rejected.
    pub bridge_domain: String,
    pub debridge_id: String,
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: String,
    /// `0x` when there is no execution payload.
    pub auto_params: String,
    pub native_sender: String,
    /// The source-chain ERC-20 that was locked, `0x`-prefixed. Optional, but a
    /// record without it can never be refunded. Verified against `debridgeId`
    /// server-side, so it cannot be used to point a refund at another asset.
    pub token: Option<String>,
    /// The signer address for the attached signature, `0x`-prefixed.
    pub signer: String,
    /// 65-byte ECDSA signature (r||s||v), `0x`-prefixed.
    pub signature: String,
}

pub struct Mutation;

#[Object]
impl Mutation {
    /// Upsert a transfer record and merge in one validator signature. Rejected
    /// (by the same trust boundary the sig-store uses) unless the submissionId
    /// equals the keccak of the params and the signature recovers to `signer`.
    async fn submit_signature(
        &self,
        ctx: &Context<'_>,
        input: SubmissionInput,
    ) -> async_graphql::Result<Submission> {
        let st = state(ctx);
        let sig = SignerSig { signer: input.signer, signature: input.signature };
        let record = SubmissionRecord {
            submission_id: input.submission_id,
            bridge_domain: input.bridge_domain,
            debridge_id: input.debridge_id,
            amount: input.amount,
            chain_id_from: input.chain_id_from,
            chain_id_to: input.chain_id_to,
            nonce: input.nonce,
            receiver: input.receiver,
            auto_params: input.auto_params,
            native_sender: input.native_sender,
            token: input.token.unwrap_or_default(),
            signatures: Vec::new(),
            cancel_signatures: Vec::new(),
            refund_signatures: Vec::new(),
        };
        let merged = st.backend.upsert(record, sig).await.map_err(store_error)?;
        Ok(Submission::from_record(merged, st.threshold))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_size_defaults_and_caps() {
        assert_eq!(page_size(None), DEFAULT_PAGE as usize);
        assert_eq!(page_size(Some(0)), 1, "zero is not a way to ask for everything");
        assert_eq!(page_size(Some(7)), 7);
        assert_eq!(page_size(Some(u64::MAX)), MAX_PAGE as usize);
        assert_eq!(page_size(Some(MAX_PAGE + 1)), MAX_PAGE as usize);
    }

    /// M-8: with no args a caller gets the first DEFAULT_PAGE rows — never the
    /// whole table.
    #[test]
    fn paginate_windows_the_list() {
        let rows: Vec<u64> = (0..1000).collect();
        assert_eq!(paginate(rows.clone(), None, None).len(), DEFAULT_PAGE as usize);
        assert_eq!(paginate(rows.clone(), Some(10_000), None).len(), MAX_PAGE as usize);
        assert_eq!(paginate(rows.clone(), Some(3), Some(5)), vec![5, 6, 7]);
        assert!(paginate(rows.clone(), Some(3), Some(5_000)).is_empty(), "offset past the end");
        assert_eq!(paginate(rows, Some(5), Some(998)), vec![998, 999], "short last page");
    }

    /// The `chains` query must never carry the private endpoint (H-4).
    #[test]
    fn chain_view_serves_only_the_public_rpc() {
        let info = ChainInfo {
            chain_id: 1,
            name: "x".into(),
            rpc_url: Some("https://provider.example/v2/SECRETKEY".into()),
            public_rpc_url: Some("https://rpc.public.example".into()),
            gate: None,
            token: None,
            tokens: vec![],
            router: None,
            swap_pool: None,
        };
        let view = Chain::from(info.clone());
        assert_eq!(view.rpc_url.as_deref(), Some("https://rpc.public.example"));

        let view = Chain::from(ChainInfo { public_rpc_url: None, ..info });
        assert_eq!(view.rpc_url, None, "no public URL => null, never the private one");
    }

    /// A store transport failure must not leak the store's address to clients.
    #[tokio::test]
    async fn remote_errors_are_replaced_by_a_generic_message() {
        // A real transport error: port 1 on loopback refuses the connection.
        // reqwest's Display for it names the URL — exactly what used to reach
        // the client's `errors[]`.
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/internal-store/history")
            .send()
            .await
            .unwrap_err();
        let inner = bridge_core::remote::RemoteError::Http(err);
        let e = anyhow::Error::from(inner).context("history");
        assert!(e.to_string().contains("history"), "premise: detail exists: {e}");
        assert!(format!("{e:?}").contains("internal-store"), "premise: the URL is in the detail");

        let msg = store_error(e).message;
        assert_eq!(msg, "signature store unavailable");
        assert!(!msg.contains("internal-store"));
    }

    /// The complexity multiplier is what turns `limit_complexity` into a bound
    /// on `eth_call` fan-out. Before: `{ submissions { executed cancelled
    /// status } }` had complexity 4 whatever the table size.
    #[tokio::test]
    async fn list_complexity_scales_with_page_size_and_chain_reads() {
        let dir = std::env::temp_dir().join(format!("graphql-api-complexity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let state = ApiState {
            backend: Arc::new(StoreBackend::file(&dir).unwrap()),
            threshold: Some(2),
            chains: Chains::new(),
            registry: vec![],
            swaps: Swaps::new(),
        };
        let schema = async_graphql::Schema::build(
            Query,
            async_graphql::EmptyMutation,
            async_graphql::EmptySubscription,
        )
        .limit_complexity(8000)
        .data(state)
        .finish();

        // 200 rows x (1 + 3 x 20) = 12,200 > 8000: refused before any resolver runs.
        let res = schema
            .execute("{ submissions(limit: 200) { submissionId executed cancelled status } }")
            .await;
        assert!(!res.errors.is_empty(), "must be refused");
        assert!(res.errors[0].message.to_lowercase().contains("complex"), "{:?}", res.errors);

        // 200 rows x (1 + 20) = 4,200: admitted (and, on an empty store, empty).
        let res = schema.execute("{ submissions(limit: 200) { submissionId status } }").await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // The frontend's exact shape, default page: admitted.
        let res = schema
            .execute(
                "{ submissions { submissionId debridgeId amount chainIdFrom chainIdTo nonce receiver \
                   nativeSender signatureCount meetsThreshold status signatures { signer } } }",
            )
            .await;
        assert!(res.errors.is_empty(), "{:?}", res.errors);

        // `history` and `swapHistory` carry the same multiplier.
        let res = schema
            .execute("{ history(limit: 200) { submissionId status swapIntent { tokenIn } } }")
            .await;
        // (a dir-backed store has no history; the point is that it got PAST
        // validation and into the resolver, which errors on the backend.)
        assert!(res.errors.iter().all(|e| !e.message.to_lowercase().contains("complex")), "{:?}", res.errors);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...while a store-side validation error (no URL in it) stays informative.
    #[test]
    fn store_validation_errors_pass_through() {
        let e = anyhow::Error::from(bridge_core::store::StoreError::BadField("signer"));
        let msg = store_error(e).message;
        assert!(msg.contains("signer"), "got: {msg}");
    }
}
