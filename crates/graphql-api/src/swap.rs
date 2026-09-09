//! Optional on-chain read view over same-chain `SwapPool`s.
//!
//! Given a destination `chainId -> (rpc, pool)` mapping (from `--swap`), this
//! reads a pool's listed tokens, prices, and reserves so the UI can render a
//! swap screen and get a live `quote` without hardcoding pool state. It is
//! strictly read-only: no swaps are ever executed here (that happens from the
//! user's wallet in the frontend). Chains the API wasn't configured with simply
//! report `null`, and any RPC failure degrades to `null` rather than failing the
//! whole GraphQL query — same posture as the executed-gate lookups in `chain.rs`.

use anyhow::Context as _;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::str::FromStr;

use alloy::primitives::{Address, U256, U512};
use alloy::providers::{DynProvider, Provider};
use alloy::rpc::types::Filter;
use alloy::sol_types::SolEvent;
use bridge_core::abi::{IERC20Mintable, SwapPool};

use crate::chain::{provider_for, split_spec, ChainInfo};

/// One listed token in a pool, flattened for the wire. Numeric fields are
/// decimal strings (uint256) to avoid JSON precision loss, mirroring how
/// `Submission.amount` is carried.
#[derive(Clone, Debug)]
pub struct PoolToken {
    /// The pool's vault for this token (Solana only; `None` on EVM, where the
    /// pool contract holds its own balances). Passing a wrong one fails the
    /// transaction — the program pins the vault in its token record — so this
    /// is a convenience, not a trust anchor.
    pub vault: Option<String>,
    /// `0x`-prefixed token address.
    pub token: String,
    /// ERC-20 symbol (best-effort; empty if the token doesn't expose one).
    pub symbol: String,
    pub decimals: u8,
    /// USD price, PRICE_ONE(1e18)-scaled, as a decimal string.
    pub price: String,
    /// Current reserve (the swap lock), in token base units, decimal string.
    pub reserve: String,
    /// `reserve * price / 10^decimals` — the max swap OUT value in
    /// PRICE_ONE-scaled USD, decimal string. This is the "max swap up to lock".
    pub max_swap_usd: String,
    /// True for the pool's core-price stablecoin (price pinned to 1.0).
    pub is_stable: bool,
    /// Unix seconds at which the CURRENT price was set. Solana only (`None` on
    /// EVM, whose `tokens()` getter does not expose it). `0` = never stamped
    /// (a record predating the field), which the guard treats as stale.
    pub price_set_at: Option<i64>,
    /// Whether the program would accept this token's price right now
    /// (`PoolState::price_is_fresh`). Solana only. A `false` leg means `swap`
    /// would revert `StalePrice` and `swapQuote` returns null for it.
    pub price_fresh: Option<bool>,
}

/// A configured pool's address + core stablecoin + its listed tokens. The
/// `address` is what the UI sends `approve`/`swap` transactions to (the `pools`
/// token list alone can't be swapped against without it).
#[derive(Clone, Debug)]
pub struct PoolInfo {
    /// `0x`-prefixed SwapPool contract address.
    pub address: String,
    /// `0x`-prefixed core stablecoin (the unit of account).
    pub stable: String,
    pub tokens: Vec<PoolToken>,
    /// The staleness bound the program enforces, in seconds (the effective
    /// value: a pool initialized before the field existed reports the
    /// default). Solana only; `None` on EVM.
    pub max_price_age: Option<i64>,
}

/// Same-chain swap pools the API can read from. Cheap to clone (each
/// `DynProvider` is an `Arc` internally); share freely across resolvers.
#[derive(Clone)]
pub struct Swaps {
    /// chain_id -> the pool on that chain, EVM or Solana. Two VMs, one view:
    /// the resolvers below are the only place that needs to know which.
    pools: BTreeMap<u64, Backend>,
    /// Default blocks per `eth_getLogs`, used by pools that do not carry their
    /// own. Hosted RPCs cap this and reject anything wider (Alchemy's free tier:
    /// 10), so it must be configurable per deployment.
    ///
    /// One global value is not enough for a mesh: the cap is a property of the
    /// ENDPOINT, and the strictest one would then throttle every other chain.
    /// That is fatal, not merely slow, on a fast chain — a pool on a 0.2s-block
    /// chain produces blocks faster than a 10-block chunk size can replay them,
    /// so its token list never finishes backfilling and the Swap view stays
    /// empty forever. Hence the per-pool override in [`Swaps::add_spec`].
    max_range: u64,
    /// Memoised token-list state per chain, so each query scans only the blocks
    /// produced since the last one. Without this, every `swapPool` query
    /// re-replays the pool's whole history: at a 10-block chunk size that is one
    /// RPC round trip per 10 blocks, per query, growing forever — enough to
    /// rate-limit the API into returning intermittent nulls while the frontend
    /// polls every 10s.
    cache: Arc<Mutex<BTreeMap<u64, TokenListState>>>,
}

/// A configured pool. The EVM side reads through alloy; the Solana side reads
/// accounts over JSON-RPC and prices with `swap-math` — the same crate its
/// program links, so the quote and the payout cannot disagree.
#[derive(Clone)]
enum Backend {
    Evm {
        provider: DynProvider,
        pool: Address,
        /// First block worth scanning (the pool's deployment height).
        from_block: u64,
        /// Blocks per `eth_getLogs` for THIS endpoint.
        max_range: u64,
    },
    Solana(crate::solana_pool::SolanaPool),
}

/// Replayed listing state plus how far it has been scanned.
#[derive(Clone, Default)]
struct TokenListState {
    /// First-seen order, for stable UI output.
    order: Vec<Address>,
    /// Current listed/delisted flag per token.
    live: BTreeMap<Address, bool>,
    /// Highest block already applied (`None` = nothing scanned yet).
    scanned_to: Option<u64>,
}

impl Default for Swaps {
    fn default() -> Self {
        Self {
            pools: BTreeMap::new(),
            max_range: DEFAULT_MAX_BLOCK_RANGE,
            cache: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

/// Suits a local node. Live deployments behind a hosted RPC must lower this.
const DEFAULT_MAX_BLOCK_RANGE: u64 = 1000;

impl Swaps {
    pub fn new() -> Self {
        Self::default()
    }

    /// Override the `eth_getLogs` chunk size (see [`Swaps::max_range`]).
    pub fn set_max_block_range(&mut self, range: u64) {
        if range > 0 {
            self.max_range = range;
        }
    }

    /// Register a pool from a `CHAINID=RPC,POOL[,FROM_BLOCK[,MAX_RANGE]]` spec, e.g.
    /// `1337=http://127.0.0.1:8545,0xPool...` or
    /// `11155111=https://…,0xPool…,11456300`. The HTTP provider is built eagerly
    /// (no network I/O yet); the first query is what hits the chain.
    ///
    /// `FROM_BLOCK` should be the pool's deployment height. It defaults to 0,
    /// which is correct for a local chain but must be set on a live one — see
    /// [`Swaps::listed_tokens`] for why scanning from genesis fails outright.
    ///
    /// `MAX_RANGE` is this endpoint's `eth_getLogs` cap; omit it to use the
    /// global default.
    pub fn add_spec(&mut self, spec: &str) -> anyhow::Result<u64> {
        let (chain_id, rpc, rest) = split_spec(spec, "--swap")?;
        let mut parts = rest.splitn(3, ',');
        let pool_s = parts.next().unwrap_or(rest);
        let from_block = match parts.next() {
            Some(blk) => blk
                .trim()
                .parse::<u64>()
                .with_context(|| format!("bad FROM_BLOCK in --swap {spec:?}"))?,
            None => 0,
        };
        let max_range = match parts.next() {
            Some(r) => {
                let r = r
                    .trim()
                    .parse::<u64>()
                    .with_context(|| format!("bad MAX_RANGE in --swap {spec:?}"))?;
                anyhow::ensure!(r > 0, "MAX_RANGE must be > 0 in --swap {spec:?}");
                r
            }
            None => self.max_range,
        };
        self.insert(chain_id, rpc, pool_s, from_block, max_range, &format!("--swap {spec:?}"))?;
        Ok(chain_id)
    }

    /// Register a pool from a `--chains-file` entry's `swap_pool`, read over that
    /// chain's `rpc_url` — the file form of [`Swaps::add_spec`], so the pool's
    /// (possibly keyed) RPC never has to appear on argv. A no-op when the chain
    /// already has a pool (an explicit `--swap` wins), or when the entry has no
    /// `swap_pool`. Returns whether a pool was registered.
    pub fn add_from_registry(&mut self, c: &ChainInfo) -> anyhow::Result<bool> {
        let Some(sp) = &c.swap_pool else { return Ok(false) };
        if self.pools.contains_key(&c.chain_id) {
            return Ok(false);
        }
        let rpc = c
            .rpc_url
            .as_deref()
            .map(str::trim)
            .filter(|u| !u.is_empty())
            .with_context(|| format!("chain {} has a swap_pool but no rpc_url", c.chain_id))?;
        if let Some(0) = sp.max_block_range() {
            anyhow::bail!("chain {}: swap_pool.max_block_range must be > 0", c.chain_id);
        }
        self.insert(
            c.chain_id,
            rpc,
            sp.address(),
            sp.from_block().unwrap_or(0),
            sp.max_block_range().unwrap_or(self.max_range),
            &format!("chain {} swap_pool", c.chain_id),
        )?;
        Ok(true)
    }

    /// The one place a pool is built, whichever form it was configured in.
    fn insert(
        &mut self,
        chain_id: u64,
        rpc: &str,
        pool_s: &str,
        from_block: u64,
        max_range: u64,
        ctx: &str,
    ) -> anyhow::Result<()> {
        // A `0x…` pool is an EVM contract; anything else is a base58 Solana
        // PROGRAM id. Distinguishing on the address form keeps one flag out of
        // the spec and cannot be got wrong by an operator.
        if !pool_s.trim().starts_with("0x") {
            let program = pool_s.trim().to_string();
            anyhow::ensure!(
                crate::solana_pool::from_b58(&program).is_some(),
                "{ctx}: pool is neither an 0x address nor a base58 Solana program id"
            );
            self.pools.insert(
                chain_id,
                Backend::Solana(crate::solana_pool::SolanaPool::new(rpc.trim(), program)),
            );
            return Ok(());
        }
        let (provider, pool) = provider_for(pool_s, rpc, ctx)?;
        self.pools.insert(chain_id, Backend::Evm { provider, pool, from_block, max_range });
        Ok(())
    }

    #[cfg(test)]
    fn evm_params(&self, chain_id: u64) -> Option<(u64, u64)> {
        match self.pools.get(&chain_id)? {
            Backend::Evm { from_block, max_range, .. } => Some((*from_block, *max_range)),
            Backend::Solana(_) => None,
        }
    }

    /// Teach a Solana pool the symbols its mints are known by. SPL mints carry
    /// no on-chain symbol, so without this the UI would show raw addresses.
    pub fn set_symbols(&mut self, chain_id: u64, symbols: BTreeMap<String, String>) {
        if let Some(Backend::Solana(p)) = self.pools.get_mut(&chain_id) {
            p.symbols = symbols;
        }
    }

    /// The chainIds this API can report pool state for.
    pub fn configured(&self) -> Vec<u64> {
        self.pools.keys().copied().collect()
    }

    /// Discover the currently-listed token set for a pool by replaying its
    /// `TokenListed` / `TokenDelisted` logs in chain order. Returns addresses in
    /// discovery order (stable first, since it's listed in the constructor).
    ///
    /// **The scan is bounded and chunked, and has to be.** This used to filter
    /// `from_block(0)`, which is fine against a local anvil and fatal against a
    /// live chain: Sepolia is past 11.4M blocks, and hosted RPCs cap
    /// `eth_getLogs` and REJECT a wider range rather than truncating it —
    /// Alchemy's free tier allows 10 blocks. The genesis-to-tip filter therefore
    /// returned a hard error, `pools()` swallowed it into `None`, and the whole
    /// Swap view rendered empty with nothing in the log to explain why.
    ///
    /// `from_block` is the pool's deployment height (configured per pool) and
    /// the range is walked in `max_range` chunks.
    async fn listed_tokens(
        &self,
        chain_id: u64,
        provider: &DynProvider,
        pool: Address,
        from_block: u64,
        max_range: u64,
    ) -> anyhow::Result<Vec<Address>> {
        let tip = provider.get_block_number().await?;

        // Resume where the last scan stopped; only the new blocks are fetched.
        let mut state = {
            // Recover from poisoning rather than propagating it: this is a
            // read-through cache, so the worst a poisoned entry costs is a
            // re-scan. Panicking here would turn one unrelated panic into a
            // permanently broken Swap view for every later request.
            let guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
            guard.get(&chain_id).cloned().unwrap_or_default()
        };
        let mut start = match state.scanned_to {
            Some(done) => done.saturating_add(1),
            None => from_block,
        };

        // A chunk that fails (rate limit, transient RPC error) must not throw
        // away the chunks that already succeeded — otherwise a long backfill
        // behind a rate-limited endpoint never converges, because every retry
        // restarts from the deployment block and fails at the same place.
        // Bounded work PER CALL. Chasing the tip in one query is O(backlog):
        // 2600 blocks at a 10-block cap is 260 round trips, which re-triggers the
        // rate limiting this cache exists to avoid — and makes a single UI poll
        // take minutes. Spend a fixed budget instead and let successive polls
        // advance the cursor; at this budget a caller catches up far faster than
        // the chain produces blocks, so it converges while every query stays cheap.
        const MAX_CHUNKS_PER_CALL: usize = 20;
        let mut chunks = 0usize;

        let mut events: Vec<(u64, u64, bool, Address)> = Vec::new();
        let mut reached = state.scanned_to;
        let mut scan_err = None;
        while start <= tip {
            if chunks >= MAX_CHUNKS_PER_CALL {
                break;
            }
            chunks += 1;
            let end = core::cmp::min(start.saturating_add(max_range - 1), tip);
            let listed_f = Filter::new()
                .address(pool)
                .event_signature(SwapPool::TokenListed::SIGNATURE_HASH)
                .from_block(start)
                .to_block(end);
            let delisted_f = Filter::new()
                .address(pool)
                .event_signature(SwapPool::TokenDelisted::SIGNATURE_HASH)
                .from_block(start)
                .to_block(end);
            if let Err(e) = Self::collect_chunk(provider, &listed_f, &delisted_f, &mut events).await
            {
                scan_err = Some(e);
                break;
            }
            reached = Some(end);
            start = end.saturating_add(1);
        }

        // Apply the new events in chain order on top of the carried state.
        events.sort_by_key(|(b, i, _, _)| (*b, *i));
        for (_, _, is_listed, token) in events {
            if is_listed {
                if !state.live.get(&token).copied().unwrap_or(false)
                    && !state.order.contains(&token)
                {
                    state.order.push(token);
                }
                state.live.insert(token, true);
            } else {
                state.live.insert(token, false);
            }
        }
        state.scanned_to = reached;

        let listed: Vec<Address> = state
            .order
            .iter()
            .copied()
            .filter(|t| state.live.get(t).copied().unwrap_or(false))
            .collect();
        self.cache.lock().unwrap_or_else(|e| e.into_inner()).insert(chain_id, state);

        // A truncated scan still yields a usable answer, and serving it beats
        // serving nothing. Listings happen at deployment, so they land in the
        // FIRST chunk — whereas catching up to the tip behind a 10-block cap can
        // take hundreds of round trips, during which a strict error would blank
        // the whole Swap view. The cost is bounded and one-directional: a token
        // DELISTED in the not-yet-scanned tail keeps showing until the backfill
        // reaches it. Only fail when the scan produced nothing at all.
        if let Some(e) = scan_err {
            if listed.is_empty() {
                return Err(e);
            }
            tracing::warn!(
                chain_id,
                error = %e,
                tokens = listed.len(),
                "pool scan truncated; serving the tokens discovered so far"
            );
        }
        Ok(listed)
    }

    /// One chunk of the listed/delisted replay, appended to `events`.
    async fn collect_chunk(
        provider: &DynProvider,
        listed_f: &Filter,
        delisted_f: &Filter,
        events: &mut Vec<(u64, u64, bool, Address)>,
    ) -> anyhow::Result<()> {
        for log in provider.get_logs(listed_f).await? {
            if let Ok(d) = SwapPool::TokenListed::decode_log(&log.inner) {
                events.push((
                    log.block_number.unwrap_or(0),
                    log.log_index.unwrap_or(0),
                    true,
                    d.data.token,
                ));
            }
        }
        for log in provider.get_logs(delisted_f).await? {
            if let Ok(d) = SwapPool::TokenDelisted::decode_log(&log.inner) {
                events.push((
                    log.block_number.unwrap_or(0),
                    log.log_index.unwrap_or(0),
                    false,
                    d.data.token,
                ));
            }
        }
        Ok(())
    }

    /// Full pool snapshot: every listed token with its price, reserve, and
    /// max-swap USD value. `None` when the chain isn't configured or the RPC
    /// read fails (never propagates an error into the GraphQL response).
    pub async fn pools(&self, chain_id: u64) -> Option<Vec<PoolToken>> {
        let (provider, pool_addr, from_block, max_range) = match self.pools.get(&chain_id)? {
            Backend::Solana(sol) => return self.solana_pools(chain_id, sol).await,
            Backend::Evm { provider, pool, from_block, max_range } => {
                (provider, pool, from_block, max_range)
            }
        };
        let pool = SwapPool::new(*pool_addr, provider);

        let stable = pool.stable().call().await.ok()?;
        let tokens = self
            .listed_tokens(chain_id, provider, *pool_addr, *from_block, *max_range)
            .await
            .inspect_err(|e| tracing::warn!(chain_id, error = %e, "pool token scan failed"))
            .ok()?;

        let mut out = Vec::with_capacity(tokens.len());
        for token in tokens {
            let info = pool.tokens(token).call().await.ok()?;
            let decimals = info.decimals;
            let price = info.price;
            let reserve = info.reserve;
            // reserve * price / 10^decimals (PRICE_ONE-scaled USD). Compute the
            // product at full 512-bit width — matching the contract's mulDiv — so a
            // large reserve*price that overflows U256 before the divide still
            // yields the correct value instead of collapsing to 0 (which would
            // under-report the swap ceiling for a deep pool). Saturate only if the
            // final quotient itself exceeds U256 (not physically reachable).
            let scale = U256::from(10u64).pow(U256::from(decimals));
            let wide = U512::from(reserve) * U512::from(price) / U512::from(scale);
            let max_swap_usd = if wide > U512::from(U256::MAX) {
                U256::MAX
            } else {
                // low 256 bits are the entire value once we know it fits
                U256::from_le_slice(&wide.to_le_bytes::<64>()[..32])
            };

            let symbol = IERC20Mintable::new(token, provider)
                .symbol()
                .call()
                .await
                .unwrap_or_default();

            out.push(PoolToken {
                vault: None,
                token: format!("{token:#x}"),
                symbol,
                decimals,
                price: price.to_string(),
                price_set_at: None,
                price_fresh: None,
                reserve: reserve.to_string(),
                max_swap_usd: max_swap_usd.to_string(),
                is_stable: token == stable,
            });
        }
        Some(out)
    }

    /// A recent blockhash for the Solana chain's pool, so the browser can build
    /// a transaction. `None` for an EVM chain (a wallet supplies its own nonce).
    pub async fn solana_blockhash(&self, chain_id: u64) -> Option<String> {
        match self.pools.get(&chain_id)? {
            Backend::Solana(sol) => sol.latest_blockhash().await.ok(),
            Backend::Evm { .. } => None,
        }
    }

    /// SPL balance of a token account on the Solana chain.
    pub async fn solana_token_balance(&self, chain_id: u64, account: &str) -> Option<String> {
        match self.pools.get(&chain_id)? {
            Backend::Solana(sol) => sol.token_balance(account).await.ok(),
            Backend::Evm { .. } => None,
        }
    }

    /// Confirmation state of a Solana signature.
    pub async fn solana_signature_status(&self, chain_id: u64, signature: &str) -> Option<String> {
        match self.pools.get(&chain_id)? {
            Backend::Solana(sol) => sol.signature_status(signature).await.ok(),
            Backend::Evm { .. } => None,
        }
    }

    /// The Solana view of [`pools`](Self::pools): one `getProgramAccounts` and
    /// the shared layouts, with no log replay — the pool's state IS its
    /// accounts, so there is no history to walk and no scan floor to get wrong.
    async fn solana_pools(
        &self,
        chain_id: u64,
        sol: &crate::solana_pool::SolanaPool,
    ) -> Option<Vec<PoolToken>> {
        let snap = sol
            .snapshot()
            .await
            .inspect_err(|e| tracing::warn!(chain_id, error = %e, "solana pool read failed"))
            .ok()?;
        Some(Self::solana_tokens(sol, &snap, crate::solana_pool::unix_now()))
    }

    /// Flatten a decoded Solana snapshot into the wire shape, stamping each
    /// token with the program's own freshness verdict at `now`.
    fn solana_tokens(
        sol: &crate::solana_pool::SolanaPool,
        snap: &crate::solana_pool::Snapshot,
        now: i64,
    ) -> Vec<PoolToken> {
        let mut out = Vec::with_capacity(snap.tokens.len());
        for t in &snap.tokens {
            let mint = crate::solana_pool::b58(&t.mint);
            // Same USD figure the EVM branch reports: reserve priced at the
            // token's own decimals. `usd_value` is the shared implementation.
            let max_swap_usd = swap_math::usd_value(t.reserve, t.price, t.decimals)
                .map(|v| v.to_string())
                .unwrap_or_else(|| "0".into());
            out.push(PoolToken {
                vault: Some(crate::solana_pool::b58(&t.vault)),
                symbol: sol.symbol_of(&mint),
                token: mint,
                decimals: t.decimals,
                price: t.price.to_string(),
                reserve: t.reserve.to_string(),
                max_swap_usd,
                is_stable: t.mint == snap.pool.hub_mint,
                price_set_at: Some(t.price_set_at),
                price_fresh: Some(snap.pool.price_is_fresh(t, now)),
            });
        }
        out
    }

    /// The Solana view of [`quote`](Self::quote). Computed here rather than
    /// asked of the chain — there is no view instruction — with the same
    /// `swap-math` the program executes, so the two agree by construction.
    async fn solana_quote(
        &self,
        sol: &crate::solana_pool::SolanaPool,
        token_in: &str,
        token_out: &str,
        amount_in: &str,
    ) -> Option<String> {
        let mint_in = crate::solana_pool::from_b58(token_in)?;
        let mint_out = crate::solana_pool::from_b58(token_out)?;
        let amount: u64 = amount_in.trim().parse().ok()?;
        let snap = sol.snapshot().await.ok()?;
        // `Snapshot::quote` applies the program's `StalePrice` guard as well as
        // its arithmetic: a stale leg yields no quote rather than a number the
        // chain will refuse.
        match snap.quote(&mint_in, &mint_out, amount, crate::solana_pool::unix_now()) {
            Ok(v) => Some(v.to_string()),
            Err(e) => {
                tracing::warn!(token_in, token_out, error = %e, "solana quote refused");
                None
            }
        }
    }

    /// Pool metadata (address + stable) alongside the full token snapshot, so a
    /// UI can build swap/approve transactions against a discovered pool. `None`
    /// on the same conditions as [`pools`](Self::pools).
    pub async fn pool_info(&self, chain_id: u64) -> Option<PoolInfo> {
        // On Solana the "pool address" a UI sends its instruction to is the
        // PROGRAM id; the pool account itself is a PDA the program derives.
        let (address, tokens, max_price_age) = match self.pools.get(&chain_id)? {
            Backend::Evm { pool, .. } => (format!("{pool:#x}"), self.pools(chain_id).await?, None),
            Backend::Solana(sol) => {
                // One snapshot for both the token list and the pool's bound, so
                // the two describe the same slot.
                let snap = sol
                    .snapshot()
                    .await
                    .inspect_err(|e| tracing::warn!(chain_id, error = %e, "solana pool read failed"))
                    .ok()?;
                let tokens = Self::solana_tokens(sol, &snap, crate::solana_pool::unix_now());
                (sol.program.clone(), tokens, Some(snap.pool.effective_max_price_age()))
            }
        };
        // The stable is the (only) token flagged is_stable; derive it from the
        // snapshot rather than re-reading `stable()` off-chain.
        let stable = tokens
            .iter()
            .find(|t| t.is_stable)
            .map(|t| t.token.clone())
            .unwrap_or_default();
        Some(PoolInfo { address, stable, tokens, max_price_age })
    }

    /// On-chain `quote(tokenIn, tokenOut, amountIn)` — the pegged output for a
    /// swap, net of fee, WITHOUT the reserve-cap check (matches the contract's
    /// `quote`). Returns the amount as a decimal string, or `None` if the chain
    /// isn't configured, an address/amount is malformed, or the call reverts
    /// (e.g. a token isn't listed).
    pub async fn quote(
        &self,
        chain_id: u64,
        token_in: &str,
        token_out: &str,
        amount_in: &str,
    ) -> Option<String> {
        let (provider, pool_addr) = match self.pools.get(&chain_id)? {
            Backend::Solana(sol) => {
                return self.solana_quote(sol, token_in, token_out, amount_in).await
            }
            Backend::Evm { provider, pool, .. } => (provider, pool),
        };
        let ti = Address::from_str(token_in.trim()).ok()?;
        let to = Address::from_str(token_out.trim()).ok()?;
        let amt = U256::from_str(amount_in.trim()).ok()?;
        let pool = SwapPool::new(*pool_addr, provider);
        let out = pool.quote(ti, to, amt).call().await.ok()?;
        Some(out.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{parse_registry, SwapPoolCfg};

    /// base58 of 32 x 0x07 — a well-formed program id.
    const SOL_PROGRAM: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";

    fn info(chain_id: u64, rpc: Option<&str>, sp: Option<SwapPoolCfg>) -> ChainInfo {
        ChainInfo {
            chain_id,
            name: "x".into(),
            rpc_url: rpc.map(str::to_owned),
            public_rpc_url: None,
            gate: None,
            token: None,
            tokens: vec![],
            router: None,
            swap_pool: sp,
        }
    }

    /// The file form registers exactly what the argv form would, per VM.
    #[test]
    fn swap_pool_from_the_registry_registers_evm_and_solana_pools() {
        let mut swaps = Swaps::new();
        swaps.set_max_block_range(500);
        // Bare address: defaults, like `--swap cid=rpc,pool`.
        let evm = info(1337, Some("http://127.0.0.1:8545"),
            Some(SwapPoolCfg::Address("0x0000000000000000000000000000000000000002".into())));
        assert!(swaps.add_from_registry(&evm).unwrap());
        assert_eq!(swaps.evm_params(1337), Some((0, 500)));
        // Object: from_block + this endpoint's own getLogs cap.
        let live = info(11155111, Some("https://x.example/v2/KEY"),
            Some(SwapPoolCfg::Full {
                address: "0x0000000000000000000000000000000000000003".into(),
                from_block: Some(11456300),
                max_block_range: Some(10),
            }));
        assert!(swaps.add_from_registry(&live).unwrap());
        assert_eq!(swaps.evm_params(11155111), Some((11456300, 10)));
        // Solana: base58 program, read from accounts.
        let sol = info(7565164, Some("https://sol.example"),
            Some(SwapPoolCfg::Address(SOL_PROGRAM.into())));
        assert!(swaps.add_from_registry(&sol).unwrap());
        assert!(matches!(swaps.pools.get(&7565164), Some(Backend::Solana(p)) if p.program == SOL_PROGRAM));
        assert_eq!(swaps.configured(), vec![1337, 7565164, 11155111]);
        // No swap_pool: nothing happens.
        assert!(!swaps.add_from_registry(&info(5, Some("http://h"), None)).unwrap());
    }

    /// argv `--swap` for the same chain wins; the registry entry is ignored.
    #[test]
    fn argv_swap_wins_over_the_registry() {
        let mut swaps = Swaps::new();
        swaps.add_spec("1337=http://127.0.0.1:8545,0x0000000000000000000000000000000000000009,77").unwrap();
        let reg = info(1337, Some("http://other"),
            Some(SwapPoolCfg::Address("0x0000000000000000000000000000000000000002".into())));
        assert!(!swaps.add_from_registry(&reg).unwrap(), "already configured from argv");
        assert_eq!(swaps.evm_params(1337), Some((77, DEFAULT_MAX_BLOCK_RANGE)));
    }

    #[test]
    fn swap_pool_without_rpc_url_is_an_error() {
        let mut swaps = Swaps::new();
        let bad = info(1, None,
            Some(SwapPoolCfg::Address("0x0000000000000000000000000000000000000002".into())));
        assert!(swaps.add_from_registry(&bad).is_err());
    }

    /// End to end from JSON, the way main.rs wires it.
    #[test]
    fn registry_json_to_pools() {
        let raw = r#"[{"chain_id": 1337, "name": "a", "rpc_url": "http://127.0.0.1:8545",
                       "gate": "0x0000000000000000000000000000000000000001",
                       "swap_pool": {"address": "0x0000000000000000000000000000000000000002", "from_block": 12}}]"#;
        let reg = parse_registry(raw, "chains.json").unwrap();
        let mut swaps = Swaps::new();
        for c in &reg {
            swaps.add_from_registry(c).unwrap();
        }
        assert_eq!(swaps.evm_params(1337), Some((12, DEFAULT_MAX_BLOCK_RANGE)));
    }
}
