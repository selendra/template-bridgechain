//! Multi-RPC failover (mirrors this repo's `ChainProvider` + `Web3Service`).
//!
//! Holds an ordered list of RPC endpoints. Every call tries the currently
//! active endpoint first, then rotates through the rest on error, sticking to
//! the first one that answers. A `chainId` guard at startup drops endpoints
//! that report the wrong chain (the classic "pointed at the wrong network" bug).

use alloy::providers::{DynProvider, Provider, ProviderBuilder};
use alloy::rpc::types::{Filter, Log};
use bridge_core::config::redact_url;
use tracing::warn;

struct Endpoint {
    /// The endpoint as it may appear in a log line: scheme + host only. Hosted
    /// RPC keys live in the path/query, and every `warn!` here used to print the
    /// full URL (audit 2026-09-09, "keyed RPC URLs logged"). The full URL is
    /// consumed by the provider at construction and kept nowhere else.
    url: String,
    provider: DynProvider,
}

pub struct Failover {
    endpoints: Vec<Endpoint>,
    active: usize,
}

/// Connect to the first endpoint that answers AND reports `expected_chain_id`.
///
/// Used by the refund loop, which needs a plain provider for `eth_call` reads of
/// gate state rather than the log-scanning surface [`Failover`] exposes. The
/// chainId guard matters more here than anywhere: attesting a refund on the
/// strength of a *different* chain's `executed` flag would be exactly the
/// mistake that lets a delivered transfer also be refunded.
pub async fn connect_checked(urls: &[String], expected_chain_id: u64) -> anyhow::Result<DynProvider> {
    probe(urls, expected_chain_id, true)
        .await
        .into_iter()
        .next()
        .map(|e| e.provider)
        .ok_or_else(|| anyhow::anyhow!("no healthy RPC endpoints for chain {expected_chain_id}"))
}

/// Build a provider for every url that parses, and keep those whose
/// `eth_chainId` matches, in the order given. Endpoints that fail either check
/// are logged and dropped. `stop_at_first` returns as soon as one is healthy,
/// for callers that only ever use a single provider.
///
/// The chainId guard is the whole point and is why this is one function rather
/// than two: a silently-wrong-network endpoint reads plausible state for a
/// DIFFERENT chain, which is how a validator ends up attesting against gate
/// state it never actually saw.
async fn probe(urls: &[String], expected_chain_id: u64, stop_at_first: bool) -> Vec<Endpoint> {
    let mut healthy = Vec::new();
    for full_url in urls {
        let url = redact_url(full_url);
        let provider = match full_url.parse() {
            Ok(parsed) => ProviderBuilder::new().connect_http(parsed).erased(),
            Err(e) => {
                warn!(%url, error = %e, "skipping unparseable RPC url");
                continue;
            }
        };
        match provider.get_chain_id().await {
            Ok(id) if id == expected_chain_id => {
                healthy.push(Endpoint { url, provider });
                if stop_at_first {
                    return healthy;
                }
            }
            Ok(id) => warn!(%url, got = id, want = expected_chain_id, "skipping RPC: chainId mismatch"),
            Err(e) => warn!(%url, error = %e, "skipping RPC: unreachable"),
        }
    }
    healthy
}

/// The last block a scan window may safely extend to on ONE endpoint, given the
/// head THAT endpoint reports.
///
/// `None` means the endpoint has nothing confirmed at or past `from_block` — a
/// node lagging behind whichever endpoint we last read the head from — and the
/// caller must not scan (or advance the cursor) on it at all this tick.
/// Otherwise the window is the requested `to_block`, clamped to what this
/// endpoint has actually finalised. Pure, so it is unit-tested directly.
pub fn clamp_scan_window(from_block: u64, to_block: u64, endpoint_head: u64, confirmations: u64) -> Option<u64> {
    let confirmed = endpoint_head.saturating_sub(confirmations);
    if confirmed < from_block {
        return None;
    }
    Some(to_block.min(confirmed))
}

impl Failover {
    /// Connect to every URL, keep only those whose `eth_chainId` matches
    /// `expected_chain_id`. Errors if none survive.
    pub async fn connect(urls: &[String], expected_chain_id: u64) -> anyhow::Result<Self> {
        let endpoints = probe(urls, expected_chain_id, false).await;
        anyhow::ensure!(
            !endpoints.is_empty(),
            "no healthy RPC endpoints for chain {expected_chain_id}"
        );
        Ok(Self { endpoints, active: 0 })
    }

    /// The active endpoint, REDACTED (scheme + host). Safe to log.
    pub fn active_url(&self) -> &str {
        &self.endpoints[self.active].url
    }

    /// Run an async provider op across endpoints, rotating on failure and
    /// pinning `active` to the first that succeeds.
    async fn with_failover<T, F, Fut>(&mut self, what: &str, mut op: F) -> anyhow::Result<T>
    where
        F: FnMut(DynProvider) -> Fut,
        Fut: std::future::Future<Output = Result<T, alloy::transports::TransportError>>,
    {
        let n = self.endpoints.len();
        let mut last_err = None;
        for attempt in 0..n {
            let idx = (self.active + attempt) % n;
            let provider = self.endpoints[idx].provider.clone();
            match op(provider).await {
                Ok(v) => {
                    if idx != self.active {
                        warn!(from = %self.endpoints[self.active].url, to = %self.endpoints[idx].url, "RPC failover");
                        self.active = idx;
                    }
                    return Ok(v);
                }
                Err(e) => {
                    warn!(url = %self.endpoints[idx].url, op = what, error = %e, "RPC call failed; rotating");
                    last_err = Some(e);
                }
            }
        }
        Err(anyhow::anyhow!(
            "all {n} RPC endpoints failed for {what}: {}",
            last_err.map(|e| e.to_string()).unwrap_or_default()
        ))
    }

    /// A clone of the currently-active provider, for one-off contract reads that
    /// do not warrant a dedicated failover wrapper (e.g. the startup read of
    /// `Gate.bridgeDomain()`). Callers own the retry: this hands back whichever
    /// endpoint is active right now and does not rotate on failure.
    pub fn active_provider(&self) -> DynProvider {
        self.endpoints[self.active].provider.clone()
    }

    pub async fn get_block_number(&mut self) -> anyhow::Result<u64> {
        self.with_failover("get_block_number", |p| async move { p.get_block_number().await })
            .await
    }

    /// `eth_getLogs` for `[from_block, to_block]`, with the window clamped to the
    /// head reported by the SAME endpoint that serves the logs. There is
    /// deliberately no unbounded `get_logs` here any more: the scan loop must not
    /// be able to pair a head from one endpoint with logs from another.
    ///
    /// ## Why (audit 2026-09-09, "failover can advance the cursor past unscanned blocks")
    ///
    /// The scan loop reads `latest` once, computes `to_block` from it, then calls
    /// `get_logs`. Those are two separate failover calls: `latest` may have come
    /// from endpoint A and, after a rotation, the logs from endpoint B. If B lags
    /// A — a different node behind the same load balancer, a replica still
    /// syncing — B simply returns no logs for blocks it has not seen yet, the
    /// call succeeds, and the loop persists `last_block = to_block`. Every `Sent`
    /// in the gap is skipped for good (and the nonce gap then pauses the
    /// validator on the NEXT event, blaming a missed nonce the RPC caused).
    ///
    /// So both reads happen against one provider inside one failover attempt:
    /// ask THIS endpoint for its head, clamp the window to its own confirmed
    /// depth, and only then fetch logs. The caller advances the cursor to the
    /// returned `scanned_to`, never to the `to_block` it asked for. If this
    /// endpoint has nothing confirmed at `from_block` yet, `Ok(None)`: nothing was
    /// scanned, nothing may advance.
    ///
    /// This costs one `eth_blockNumber` per window on top of the `eth_getLogs`
    /// (a cheap call, and the price of the two being coherent); the scan loop's
    /// cached-head optimisation still bounds the REQUESTED window, so catch-up
    /// throughput is otherwise unchanged.
    ///
    /// `filter` must carry the address/topic selection only; the block range is
    /// set here.
    pub async fn get_logs_confirmed(
        &mut self,
        filter: &Filter,
        from_block: u64,
        to_block: u64,
        confirmations: u64,
    ) -> anyhow::Result<Option<(Vec<Log>, u64)>> {
        let filter = filter.clone();
        self.with_failover("get_logs_confirmed", move |p| {
            let filter = filter.clone();
            async move {
                let head = p.get_block_number().await?;
                let Some(scanned_to) = clamp_scan_window(from_block, to_block, head, confirmations) else {
                    return Ok(None);
                };
                let f = filter.from_block(from_block).to_block(scanned_to);
                let logs = p.get_logs(&f).await?;
                Ok(Some((logs, scanned_to)))
            }
        })
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The pre-fix behaviour was `to_block` regardless of what the serving node
    /// knew. Every case here is one the old loop got wrong or right for the
    /// wrong reason.
    #[test]
    fn scan_window_is_clamped_to_the_serving_endpoints_head() {
        // Endpoint is at/ahead of the cached head: the requested window stands.
        assert_eq!(clamp_scan_window(100, 199, 210, 10), Some(199));
        assert_eq!(clamp_scan_window(100, 199, 209, 10), Some(199));
        // Endpoint lags: the window shrinks to what IT has confirmed.
        assert_eq!(clamp_scan_window(100, 199, 160, 10), Some(150));
        // Endpoint has nothing confirmed at from_block yet: do not scan at all.
        assert_eq!(clamp_scan_window(100, 199, 109, 10), None);
        assert_eq!(clamp_scan_window(100, 199, 5, 10), None, "saturating, not wrapping");
        // Exactly one block available.
        assert_eq!(clamp_scan_window(100, 199, 110, 10), Some(100));
        // Zero confirmations (dev chains) clamp to the head itself.
        assert_eq!(clamp_scan_window(100, 199, 150, 0), Some(150));
    }
}
