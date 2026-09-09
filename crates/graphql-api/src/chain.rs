//! Optional on-chain execution lookups for destination gates.
//!
//! The signature store only knows what validators have *signed*; it cannot say
//! whether the keeper has actually delivered a transfer. Given a destination
//! `chainId -> (rpc, gate)` mapping, this asks the gate's `executed(submissionId)`
//! so the API can distinguish "enough signatures" (READY) from "claimed on-chain"
//! (EXECUTED). Chains the API wasn't configured with simply report `null`.

use std::collections::{BTreeMap, HashMap};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::client::RpcClient;
use anyhow::Context;
use bridge_core::abi::Gate;
use serde::{Deserialize, Serialize};

/// Time to establish a TCP/TLS connection to any upstream (RPC node, Solana
/// endpoint). A provider that is down should fail a resolver in seconds, not
/// hold a request slot until the client gives up.
pub(crate) const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total budget for one upstream request, headers to last body byte.
pub(crate) const HTTP_TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// The one `reqwest::Client` every Solana JSON-RPC call in this process shares.
///
/// One client means one connection pool (the per-call `reqwest::Client::new()`
/// the Solana proxies used to do opened a fresh TLS session per GraphQL field),
/// and one place where the timeouts are set — a client without them turns one
/// unresponsive provider into a pile of hung requests on the only service in
/// the deployment that faces the internet.
pub(crate) fn http_client() -> reqwest::Client {
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .timeout(HTTP_TOTAL_TIMEOUT)
                .build()
                .expect("reqwest client with static config")
        })
        .clone()
}

/// Same client, same timeouts, for the EVM providers. Alloy's HTTP transport is
/// built on its own `reqwest` (a different major than the workspace's), so the
/// two types cannot be one value; the configuration is.
fn alloy_http_client() -> alloy::transports::http::reqwest::Client {
    use alloy::transports::http::reqwest as areq;
    static CLIENT: OnceLock<areq::Client> = OnceLock::new();
    CLIENT
        .get_or_init(|| {
            areq::Client::builder()
                .connect_timeout(HTTP_CONNECT_TIMEOUT)
                .timeout(HTTP_TOTAL_TIMEOUT)
                .build()
                .expect("reqwest client with static config")
        })
        .clone()
}

/// A network the bridge UI can target, served to the frontend via the `chains`
/// query so it discovers configured networks instead of hardcoding them.
///
/// Only `chain_id` and `name` are required; `gate`/`token` are deployed fresh by
/// the local scripts each run, so they're optional here and may be supplied (or
/// overridden) from the UI. When `rpc_url` + `gate` are present, the API also
/// registers the gate for on-chain `executed()` lookups (see [`Chains::add`]).
///
/// ## Two RPC fields, on purpose (H-4)
///
/// `rpc_url` is the SERVER-SIDE endpoint: it is what this process calls for
/// `executed()`/`cancelled()`/pool reads, and on a hosted provider it carries
/// the operator's API key in the path. It is never serialised to a client.
/// `public_rpc_url` is what the browser may use for its own reads (decimals,
/// balances) — a keyless public endpoint. The `chains` query returns ONLY the
/// latter as `rpcUrl`; a chain without one gets `null`, and the UI falls back to
/// the wallet's provider. Both launchers used to put the keyed URL in the one
/// field there was, and the API handed it to every anonymous visitor.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChainInfo {
    pub chain_id: u64,
    pub name: String,
    /// Server-side RPC (may carry a provider key). NEVER sent to clients.
    #[serde(default)]
    pub rpc_url: Option<String>,
    /// Browser-safe, keyless RPC served to clients as `rpcUrl`. Optional; the
    /// server warns at startup for every chain lacking one and refuses to start
    /// under `--production`.
    #[serde(default)]
    pub public_rpc_url: Option<String>,
    #[serde(default)]
    pub gate: Option<String>,
    /// Default ERC-20 to prefill when bridging from this chain (the primary
    /// asset). Kept for back-compat; `tokens[0]` supersedes it when present.
    #[serde(default)]
    pub token: Option<String>,
    /// All ERC-20s that can be bridged from this chain, so the UI can offer a
    /// token picker instead of a single prefilled address. Empty when unset.
    #[serde(default)]
    pub tokens: Vec<TokenInfo>,
    /// Deployed `SwapRouter` on this chain, for cross-chain-swap (Phase F). Like
    /// `gate`/`token`, optional and re-deployed fresh by local scripts each run.
    #[serde(default)]
    pub router: Option<String>,
    /// Same-chain swap pool to serve through `pools`/`swapPool`/`swapQuote` —
    /// the file form of `--swap CHAINID=RPC,POOL[,FROM_BLOCK[,MAX_RANGE]]`, read
    /// with this chain's `rpc_url` so the (possibly keyed) url stays in the 0600
    /// registry instead of on argv. Either a bare address string or an object;
    /// see [`SwapPoolCfg`]. An explicit `--swap` for the same chain wins.
    #[serde(default)]
    pub swap_pool: Option<SwapPoolCfg>,
}

/// A chain's swap pool in the registry: `"swap_pool": "0x…"` (or a base58
/// Solana program id) or `"swap_pool": {"address": "…", "from_block": N,
/// "max_block_range": M}`. `from_block` is the pool's deployment height (EVM
/// only; must be set on a live chain), `max_block_range` that endpoint's
/// `eth_getLogs` cap. Both default as the argv form does.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum SwapPoolCfg {
    Address(String),
    Full {
        address: String,
        #[serde(default)]
        from_block: Option<u64>,
        #[serde(default)]
        max_block_range: Option<u64>,
    },
}

impl SwapPoolCfg {
    pub fn address(&self) -> &str {
        match self {
            SwapPoolCfg::Address(a) | SwapPoolCfg::Full { address: a, .. } => a.trim(),
        }
    }
    pub fn from_block(&self) -> Option<u64> {
        match self {
            SwapPoolCfg::Full { from_block, .. } => *from_block,
            SwapPoolCfg::Address(_) => None,
        }
    }
    pub fn max_block_range(&self) -> Option<u64> {
        match self {
            SwapPoolCfg::Full { max_block_range, .. } => *max_block_range,
            SwapPoolCfg::Address(_) => None,
        }
    }
}

/// Is this a base58 Solana address (program id) rather than an `0x` EVM one?
/// The VM is told apart by the address form everywhere in this crate (`--gate`,
/// `--swap`, and now the registry), so an operator never declares it twice.
pub fn is_solana_address(s: &str) -> bool {
    let t = s.trim();
    !t.starts_with("0x") && crate::solana_pool::from_b58(t).is_some()
}

/// One bridgeable token on a chain (symbol + address), served to the UI.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TokenInfo {
    pub symbol: String,
    /// `0x`-prefixed ERC-20 address on this chain.
    pub address: String,
}

/// Load the chain registry from a JSON file (an array of [`ChainInfo`]).
pub fn load_registry(path: &str) -> anyhow::Result<Vec<ChainInfo>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading chains file {path}"))?;
    parse_registry(&raw, path)
}

/// Parse + validate a registry document. `path` is for error context only.
/// Split from [`load_registry`] so the rules are unit-testable.
pub fn parse_registry(raw: &str, path: &str) -> anyhow::Result<Vec<ChainInfo>> {
    let chains: Vec<ChainInfo> =
        serde_json::from_str(raw).with_context(|| format!("parsing chains file {path}"))?;
    for c in &chains {
        if let Some(g) = &c.gate {
            // A base58 gate is a Solana program; only a 0x one is an EVM address.
            if g.trim().starts_with("0x") {
                Address::from_str(g.trim()).with_context(|| {
                    format!("bad gate address for chain {} in {path}", c.chain_id)
                })?;
            } else {
                anyhow::ensure!(
                    is_solana_address(g),
                    "gate for chain {} in {path} is neither an 0x address nor a base58 Solana program id",
                    c.chain_id
                );
            }
        }
        if let Some(sp) = &c.swap_pool {
            let a = sp.address();
            if a.starts_with("0x") {
                Address::from_str(a).with_context(|| {
                    format!("bad swap_pool address for chain {} in {path}", c.chain_id)
                })?;
            } else {
                anyhow::ensure!(
                    is_solana_address(a),
                    "swap_pool for chain {} in {path} is neither an 0x address nor a base58 Solana program id",
                    c.chain_id
                );
            }
            if let Some(0) = sp.max_block_range() {
                anyhow::bail!("swap_pool.max_block_range for chain {} in {path} must be > 0", c.chain_id);
            }
            // The pool is read over this chain's own rpc_url; without one there
            // is nothing to read it with, and failing here beats a pool that is
            // silently absent from the Swap view.
            anyhow::ensure!(
                c.rpc_url.as_deref().map(str::trim).is_some_and(|u| !u.is_empty()),
                "chain {} in {path} has a swap_pool but no rpc_url to read it through",
                c.chain_id
            );
        }
        if let Some(u) = &c.public_rpc_url {
            let url: reqwest::Url = u
                .trim()
                .parse()
                .with_context(|| format!("bad public_rpc_url for chain {} in {path}", c.chain_id))?;
            anyhow::ensure!(
                matches!(url.scheme(), "http" | "https" | "ws" | "wss"),
                "public_rpc_url for chain {} in {path} must be http(s)/ws(s)",
                c.chain_id
            );
            // The whole point of the field is that it is safe to hand out. If it
            // is byte-identical to the private endpoint, the operator has pasted
            // the keyed URL into both, and we would be serving the key again.
            if c.rpc_url.as_deref().map(str::trim) == Some(u.trim()) && looks_keyed(u) {
                anyhow::bail!(
                    "chain {} in {path}: public_rpc_url equals rpc_url and looks like it carries \
                     a provider key — the public URL must be a keyless endpoint",
                    c.chain_id
                );
            }
        }
    }
    Ok(chains)
}

/// Heuristic for "this URL embeds a credential": a hosted-provider path segment
/// that is a long opaque token, or userinfo / a key-ish query parameter.
///
/// Only a heuristic — it can never PROVE a URL is safe — so it is used solely to
/// refuse the obvious mistake of the same keyed URL in both fields, and never
/// to wave a URL through.
fn looks_keyed(u: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(u.trim()) else { return false };
    if !url.username().is_empty() || url.password().is_some() {
        return true;
    }
    if url.query_pairs().any(|(k, _)| {
        let k = k.to_ascii_lowercase();
        k.contains("key") || k.contains("token") || k.contains("secret")
    }) {
        return true;
    }
    // e.g. https://eth-sepolia.g.alchemy.com/v2/<32 opaque chars>
    url.path_segments()
        .into_iter()
        .flatten()
        .any(|seg| seg.len() >= 20 && seg.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'))
}

/// Chain ids in `registry` that have no `public_rpc_url`. The browser can still
/// use them through its wallet's provider; the server just cannot offer a
/// read-only endpoint for them.
pub fn chains_without_public_rpc(registry: &[ChainInfo]) -> Vec<u64> {
    registry
        .iter()
        .filter(|c| c.public_rpc_url.as_deref().map(str::trim).is_none_or(str::is_empty))
        .map(|c| c.chain_id)
        .collect()
}

/// Split a `CHAINID=RPC,ADDR` spec (the shape both `--gate` and `--swap` use)
/// into its parts. `flag` names the flag in error messages.
pub(crate) fn split_spec<'s>(spec: &'s str, flag: &str) -> anyhow::Result<(u64, &'s str, &'s str)> {
    let (id_s, rest) = spec
        .split_once('=')
        .with_context(|| format!("{flag} must be CHAINID=RPC,ADDR, got {spec:?}"))?;
    let (rpc, addr_s) = rest
        .split_once(',')
        .with_context(|| format!("{flag} must be CHAINID=RPC,ADDR, got {spec:?}"))?;
    let chain_id: u64 =
        id_s.trim().parse().with_context(|| format!("bad chainId in {flag} {spec:?}"))?;
    Ok((chain_id, rpc, addr_s))
}

/// Parse an address + RPC url and build an (erased) HTTP provider. `ctx` names
/// the source in error messages (e.g. `"--gate 1338=...,0xabc"` or `"chain 1338"`).
pub(crate) fn provider_for(addr: &str, rpc: &str, ctx: &str) -> anyhow::Result<(DynProvider, Address)> {
    let address: Address =
        addr.trim().parse().with_context(|| format!("bad address in {ctx}"))?;
    let url = rpc.trim().parse().with_context(|| format!("bad rpc url in {ctx}"))?;
    // Through the shared, timeout-bearing client — `connect_http` would build a
    // reqwest client with no timeouts at all.
    let rpc_client = RpcClient::new_http_with_client(alloy_http_client(), url);
    let provider = ProviderBuilder::new().connect_client(rpc_client).erased();
    Ok((provider, address))
}

/// Memo of the two TERMINAL gate flags per `(chain, submissionId)`.
///
/// `executed` and `cancelled` are write-once on the Gate: `claim` and `cancel`
/// both set `executed`, `cancel` also sets `cancelled`, and neither can ever be
/// unset. So once either reads `true`, every later `eth_call` for that id would
/// return the same answer — and the API was making it anyway, once per row per
/// request, forever (M-8). A `false`, by contrast, is NOT cached: the transfer
/// may still be claimed or cancelled a block later.
///
/// `cancelled == false` is also final once `executed == true` (the id was
/// claimed, and a claimed id cannot be cancelled), so that pair is memoised too.
#[derive(Clone, Default)]
pub struct TerminalCache {
    inner: Arc<Mutex<HashMap<(u64, String), Terminal>>>,
}

#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
struct Terminal {
    executed: bool,
    /// `Some` only once known for certain.
    cancelled: Option<bool>,
}

impl TerminalCache {
    /// Upper bound on remembered ids. Every entry is a settled transfer, so this
    /// grows with history; on overflow the whole memo is dropped and rebuilt —
    /// a cache, not a ledger.
    const MAX_ENTRIES: usize = 100_000;

    fn key(chain_id: u64, submission_id: &str) -> (u64, String) {
        (chain_id, submission_id.to_ascii_lowercase())
    }

    /// `Some(true)` if this id is known to be executed; `None` if unknown.
    pub fn executed(&self, chain_id: u64, submission_id: &str) -> Option<bool> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&Self::key(chain_id, submission_id)).filter(|t| t.executed).map(|_| true)
    }

    /// `Some(v)` if this id's `cancelled` flag is settled; `None` if unknown.
    pub fn cancelled(&self, chain_id: u64, submission_id: &str) -> Option<bool> {
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&Self::key(chain_id, submission_id)).and_then(|t| t.cancelled)
    }

    /// Record a fresh `executed` read. Only `true` is terminal.
    pub fn note_executed(&self, chain_id: u64, submission_id: &str, value: bool) {
        if !value {
            return;
        }
        self.update(chain_id, submission_id, |t| t.executed = true);
    }

    /// Record a fresh `cancelled` read. `true` is terminal (and implies
    /// `executed`); `false` is terminal only if the id is already known executed.
    pub fn note_cancelled(&self, chain_id: u64, submission_id: &str, value: bool) {
        self.update(chain_id, submission_id, |t| {
            if value {
                t.executed = true;
                t.cancelled = Some(true);
            } else if t.executed {
                t.cancelled = Some(false);
            }
        });
    }

    fn update(&self, chain_id: u64, submission_id: &str, f: impl FnOnce(&mut Terminal)) {
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = Self::key(chain_id, submission_id);
        if !map.contains_key(&key) && map.len() >= Self::MAX_ENTRIES {
            map.clear();
        }
        let entry = map.entry(key).or_default();
        f(entry);
        // Never keep an entry that says nothing terminal.
        if !entry.executed && entry.cancelled.is_none() {
            map.remove(&Self::key(chain_id, submission_id));
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().len()
    }
}

/// Destination gates the API can read execution status from. Cheap to clone
/// (each `DynProvider` is an `Arc` internally); share freely across resolvers.
#[derive(Clone, Default)]
pub struct Chains {
    gates: BTreeMap<u64, (DynProvider, Address)>,
    /// Solana gates, which are programs read over JSON-RPC rather than
    /// contracts called through a provider.
    solana_gates: BTreeMap<u64, crate::solana_pool::SolanaGate>,
    /// Settled `executed`/`cancelled` answers, so a delivered transfer costs
    /// zero `eth_call`s on every later request.
    terminal: TerminalCache,
}

impl Chains {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register a destination from a `CHAINID=RPC,GATE` spec, e.g.
    /// `1338=http://127.0.0.1:8546,0xabc...`. The HTTP provider is built eagerly
    /// (no network I/O yet); the first `executed()` call is what hits the chain.
    pub fn add_spec(&mut self, spec: &str) -> anyhow::Result<u64> {
        let (chain_id, rpc, gate_s) = split_spec(spec, "--gate")?;
        // A base58 gate is a Solana PROGRAM, not an EVM contract: it is read
        // through JSON-RPC account fetches rather than an alloy provider, so it
        // is kept aside instead of being forced into one. Same rule as --swap,
        // so an operator never has to declare which VM a chain is.
        if !gate_s.trim().starts_with("0x") {
            self.solana_gates.insert(
                chain_id,
                crate::solana_pool::SolanaGate::new(rpc.trim(), gate_s.trim()),
            );
            return Ok(chain_id);
        }
        let (provider, gate) = provider_for(gate_s, rpc, &format!("--gate {spec:?}"))?;
        self.gates.insert(chain_id, (provider, gate));
        Ok(chain_id)
    }

    /// The Solana gate configured for a chain, if any.
    pub fn solana_gate(&self, chain_id: u64) -> Option<&crate::solana_pool::SolanaGate> {
        self.solana_gates.get(&chain_id)
    }

    /// Register a destination gate from already-parsed parts (used to fold the
    /// `--chains-file` registry into the executed-gate map). A no-op if this
    /// chain already has a gate (an explicit `--gate` wins).
    ///
    /// Routes on the address form exactly as [`Chains::add_spec`] does: a base58
    /// gate is a Solana program and goes to the JSON-RPC reader, so the Solana
    /// leg's (keyed) RPC can live in the registry file like every EVM chain's,
    /// instead of on argv.
    pub fn add(&mut self, chain_id: u64, rpc: &str, gate: &str) -> anyhow::Result<()> {
        if self.gates.contains_key(&chain_id) || self.solana_gates.contains_key(&chain_id) {
            return Ok(());
        }
        if is_solana_address(gate) {
            self.solana_gates.insert(
                chain_id,
                crate::solana_pool::SolanaGate::new(rpc.trim(), gate.trim()),
            );
            return Ok(());
        }
        let (provider, gate) = provider_for(gate, rpc, &format!("chain {chain_id}"))?;
        self.gates.insert(chain_id, (provider, gate));
        Ok(())
    }

    /// The destination chainIds this API can report execution status for (EVM).
    pub fn configured(&self) -> Vec<u64> {
        self.gates.keys().copied().collect()
    }

    /// The chainIds with a Solana gate registered (for `solanaGateContext`).
    pub fn configured_solana(&self) -> Vec<u64> {
        self.solana_gates.keys().copied().collect()
    }

    /// `executed(submissionId)` on the destination gate. `None` when `chain_id_to`
    /// isn't configured, the id is malformed, or the RPC call fails — a flaky RPC
    /// must never fail the whole GraphQL query, only leave status unknown.
    pub async fn executed(&self, chain_id_to: u64, submission_id: &str) -> Option<bool> {
        let (provider, gate) = self.gates.get(&chain_id_to)?;
        if let Some(v) = self.terminal.executed(chain_id_to, submission_id) {
            return Some(v);
        }
        let id = B256::from_str(submission_id).ok()?;
        let v = Gate::new(*gate, provider).executed(id).call().await.ok()?;
        self.terminal.note_executed(chain_id_to, submission_id, v);
        Some(v)
    }

    /// `cancelled(submissionId)` on the destination gate.
    ///
    /// `executed` alone cannot distinguish "delivered" from "burned so it could
    /// be refunded" — `cancel` sets the same flag. Reporting a cancelled
    /// transfer as EXECUTED would tell a user their funds arrived when in fact
    /// they were returned on the source chain, so the two are read together.
    pub async fn cancelled(&self, chain_id_to: u64, submission_id: &str) -> Option<bool> {
        let (provider, gate) = self.gates.get(&chain_id_to)?;
        if let Some(v) = self.terminal.cancelled(chain_id_to, submission_id) {
            return Some(v);
        }
        let id = B256::from_str(submission_id).ok()?;
        let v = Gate::new(*gate, provider).cancelled(id).call().await.ok()?;
        self.terminal.note_cancelled(chain_id_to, submission_id, v);
        Some(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEYED: &str = "https://eth-sepolia.g.alchemy.com/v2/AbCdEfGhIjKlMnOpQrStUvWxYz012345";

    fn one(extra: &str) -> String {
        format!(
            r#"[{{"chain_id": 11155111, "name": "Sepolia", "rpc_url": "{KEYED}",
                 "gate": "0x0000000000000000000000000000000000000001" {extra}}}]"#
        )
    }

    /// H-4: the field is optional and absent by default — an old chains.json
    /// still parses, it just has nothing public to serve.
    #[test]
    fn registry_without_public_rpc_parses_and_is_reported() {
        let reg = parse_registry(&one(""), "chains.json").unwrap();
        assert_eq!(reg[0].public_rpc_url, None);
        assert_eq!(reg[0].rpc_url.as_deref(), Some(KEYED), "the private URL stays for server-side use");
        assert_eq!(chains_without_public_rpc(&reg), vec![11155111]);
    }

    #[test]
    fn public_rpc_url_is_read_and_satisfies_the_check() {
        let reg = parse_registry(
            &one(r#", "public_rpc_url": "https://rpc.sepolia.org""#),
            "chains.json",
        )
        .unwrap();
        assert_eq!(reg[0].public_rpc_url.as_deref(), Some("https://rpc.sepolia.org"));
        assert!(chains_without_public_rpc(&reg).is_empty());
    }

    /// An empty string is "not set", not "set to nothing".
    #[test]
    fn blank_public_rpc_url_counts_as_missing() {
        let reg = parse_registry(&one(r#", "public_rpc_url": "  ""#), "chains.json");
        // An empty string is not a URL, so parsing rejects it outright...
        assert!(reg.is_err());
        // ...and a registry built in memory with a blank one is reported missing.
        let mut c = parse_registry(&one(""), "x").unwrap();
        c[0].public_rpc_url = Some("   ".into());
        assert_eq!(chains_without_public_rpc(&c), vec![11155111]);
    }

    /// The exact mistake the finding describes: the keyed URL pasted into the
    /// public field too. Refuse rather than serve the key under a new name.
    #[test]
    fn keyed_url_copied_into_the_public_field_is_rejected() {
        let err = parse_registry(&one(&format!(r#", "public_rpc_url": "{KEYED}""#)), "chains.json")
            .unwrap_err()
            .to_string();
        assert!(err.contains("public_rpc_url equals rpc_url"), "got: {err}");
    }

    /// A local dev chain has no key anywhere; the same URL in both is fine.
    #[test]
    fn identical_keyless_urls_are_allowed() {
        let raw = r#"[{"chain_id": 1337, "name": "anvil",
                       "rpc_url": "http://127.0.0.1:8545", "public_rpc_url": "http://127.0.0.1:8545"}]"#;
        assert!(parse_registry(raw, "x").is_ok());
    }

    #[test]
    fn non_http_public_rpc_url_is_rejected() {
        let err = parse_registry(&one(r#", "public_rpc_url": "javascript:alert(1)""#), "x")
            .unwrap_err()
            .to_string();
        assert!(err.contains("must be http"), "got: {err}");
    }

    #[test]
    fn keyed_heuristic() {
        assert!(looks_keyed(KEYED));
        assert!(looks_keyed("https://mainnet.infura.io/v3/0123456789abcdef0123456789abcdef"));
        assert!(looks_keyed("https://rpc.example.com/?apiKey=abc"));
        assert!(looks_keyed("https://user:pw@rpc.example.com/"));
        assert!(!looks_keyed("https://rpc.sepolia.org"));
        assert!(!looks_keyed("http://127.0.0.1:8545"));
        assert!(!looks_keyed("https://ethereum-sepolia-rpc.publicnode.com"));
    }

    // --- file forms for the Solana gate and swap pools ------------------------

    /// base58 of 32 x 0x07 — a well-formed program id.
    const SOL_PROGRAM: &str = "US517G5965aydkZ46HS38QLi7UQiSojurfbQfKCELFx";

    /// A base58 gate in the registry is a Solana program: it parses, and
    /// `Chains::add` routes it to the Solana reader instead of failing to parse
    /// it as an EVM address (which is what forced it onto `--gate` argv).
    #[test]
    fn base58_gate_in_the_registry_is_a_solana_gate() {
        let raw = format!(
            r#"[{{"chain_id": 7565164, "name": "Solana", "rpc_url": "https://sol.example/v2/KEY",
                  "gate": "{SOL_PROGRAM}", "tokens": []}}]"#
        );
        let reg = parse_registry(&raw, "chains.json").unwrap();
        let mut chains = Chains::new();
        chains.add(reg[0].chain_id, reg[0].rpc_url.as_deref().unwrap(), reg[0].gate.as_deref().unwrap()).unwrap();
        assert!(chains.solana_gate(7565164).is_some(), "routed to the Solana reader");
        assert!(chains.configured().is_empty(), "not an EVM gate");
        assert_eq!(chains.configured_solana(), vec![7565164]);
        assert_eq!(chains.solana_gate(7565164).unwrap().program, SOL_PROGRAM);
    }

    #[test]
    fn a_gate_that_is_neither_0x_nor_base58_is_rejected() {
        let raw = r#"[{"chain_id": 1, "name": "x", "gate": "not a gate!"}]"#;
        let err = parse_registry(raw, "chains.json").unwrap_err().to_string();
        assert!(err.contains("neither an 0x address nor a base58"), "got: {err}");
    }

    /// An explicit `--gate` still wins over the file for the same chain.
    #[test]
    fn argv_gate_wins_over_the_registry() {
        let mut chains = Chains::new();
        chains.add_spec(&format!("9=http://127.0.0.1:8899,{SOL_PROGRAM}")).unwrap();
        chains.add(9, "http://other", "0x0000000000000000000000000000000000000001").unwrap();
        assert!(chains.solana_gate(9).is_some() && chains.configured().is_empty());
    }

    /// `swap_pool` — both spellings the scripts may emit.
    #[test]
    fn swap_pool_parses_as_string_or_object() {
        let raw = format!(
            r#"[{{"chain_id": 1337, "name": "a", "rpc_url": "http://127.0.0.1:8545",
                  "swap_pool": "0x0000000000000000000000000000000000000002"}},
                {{"chain_id": 11155111, "name": "b", "rpc_url": "https://x.example/v2/KEY",
                  "swap_pool": {{"address": "0x0000000000000000000000000000000000000003",
                                 "from_block": 11456300, "max_block_range": 10}}}},
                {{"chain_id": 7565164, "name": "sol", "rpc_url": "https://sol.example",
                  "swap_pool": {{"address": "{SOL_PROGRAM}"}}}}]"#
        );
        let reg = parse_registry(&raw, "chains.json").unwrap();
        let sp = reg[0].swap_pool.as_ref().unwrap();
        assert_eq!(sp.address(), "0x0000000000000000000000000000000000000002");
        assert_eq!((sp.from_block(), sp.max_block_range()), (None, None));
        let sp = reg[1].swap_pool.as_ref().unwrap();
        assert_eq!((sp.from_block(), sp.max_block_range()), (Some(11456300), Some(10)));
        let sp = reg[2].swap_pool.as_ref().unwrap();
        assert_eq!(sp.address(), SOL_PROGRAM);
        assert!(reg[0].tokens.is_empty() && reg[0].gate.is_none(), "other fields still optional");
    }

    #[test]
    fn swap_pool_needs_an_rpc_url_and_a_sane_range() {
        let raw = r#"[{"chain_id": 1, "name": "x", "swap_pool": "0x0000000000000000000000000000000000000002"}]"#;
        let err = parse_registry(raw, "c").unwrap_err().to_string();
        assert!(err.contains("no rpc_url"), "got: {err}");

        let raw = r#"[{"chain_id": 1, "name": "x", "rpc_url": "http://h",
                       "swap_pool": {"address": "0x0000000000000000000000000000000000000002", "max_block_range": 0}}]"#;
        let err = parse_registry(raw, "c").unwrap_err().to_string();
        assert!(err.contains("max_block_range"), "got: {err}");

        let raw = r#"[{"chain_id": 1, "name": "x", "rpc_url": "http://h", "swap_pool": "0xnope"}]"#;
        assert!(parse_registry(raw, "c").is_err());
    }

    // --- TerminalCache (M-8) ------------------------------------------------

    #[test]
    fn false_is_never_cached_but_true_is() {
        let c = TerminalCache::default();
        c.note_executed(1, "0xAB", false);
        assert_eq!(c.executed(1, "0xab"), None, "a false may flip later");
        assert_eq!(c.len(), 0);

        c.note_executed(1, "0xAB", true);
        assert_eq!(c.executed(1, "0xab"), Some(true), "case-insensitive key");
        assert_eq!(c.executed(2, "0xab"), None, "per chain");
    }

    #[test]
    fn cancelled_true_implies_executed() {
        let c = TerminalCache::default();
        c.note_cancelled(1, "0x01", true);
        assert_eq!(c.cancelled(1, "0x01"), Some(true));
        assert_eq!(c.executed(1, "0x01"), Some(true));
    }

    /// `cancelled == false` is only settled once we know the id executed (it was
    /// claimed, and a claimed id can no longer be cancelled).
    #[test]
    fn cancelled_false_is_final_only_after_executed() {
        let c = TerminalCache::default();
        c.note_cancelled(1, "0x02", false);
        assert_eq!(c.cancelled(1, "0x02"), None, "still cancellable");
        assert_eq!(c.len(), 0, "nothing terminal to keep");

        c.note_executed(1, "0x02", true);
        c.note_cancelled(1, "0x02", false);
        assert_eq!(c.cancelled(1, "0x02"), Some(false), "claimed, so never cancelled");
    }
}
