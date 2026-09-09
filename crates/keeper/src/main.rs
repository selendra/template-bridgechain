//! Minimal keeper / executor (Phase 5).
//!
//! One claim loop *per configured target chain*: read the signature store, and
//! for every record destined for that chain that has >= threshold signatures and
//! isn't yet executed, build and submit `claim()` (signatures sorted by signer
//! ascending, as the Gate requires). Configuring several `[[targets]]` lets a
//! single keeper deliver A->B and A->C transfers from the same source.
//!
//! It also relays the two-phase refund, which runs on both sides:
//!   * on a `[[targets]]` chain, a **cancel** quorum burns a stranded transfer
//!     (`cancel()`), taking precedence over claiming it;
//!   * on a `[[sources]]` chain, a **refund** quorum returns the locked funds
//!     (`refund()`).
//!
//! The keeper decides nothing here — it only relays quorums the validators
//! formed after checking both chains themselves. It holds no authority the
//! signatures don't already carry.

mod config;

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use alloy::network::EthereumWallet;
use alloy::primitives::{Address, Bytes, B256, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use anyhow::Context;
use bridge_core::abi::Gate;
use bridge_core::backend::StoreBackend;
use bridge_core::store::{SigKind, SignerSig, SubmissionRecord};
use config::{ChainCfg, Config};
use std::collections::HashSet;
use tracing::{debug, info, warn};

/// Upper bound on waiting for a submitted tx's receipt. A tx that never confirms
/// within this window (stuck/underpriced/replaced) makes `get_receipt` return a
/// typed [`ReceiptTimeout`] instead of blocking the whole per-chain loop forever.
/// The loop remembers the hash in [`PendingTxs`] and, on later ticks, polls it
/// BEFORE considering a resubmit — a duplicate goes out only once the original
/// is gone from the mempool or has mined and reverted. Each `try_*` still
/// re-checks on-chain state first, so a retry after a tx actually landed is a no-op.
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(120);

/// How often [`GateView`] re-reads `threshold`, `validatorCount` and validator
/// membership from the gate.
///
/// These used to be a startup snapshot (`threshold`) or a memo that never expired
/// (membership), so an on-chain validator-set change needed a keeper restart to
/// take effect. That is not merely stale reporting: a cached `true` for a
/// validator that has since been removed lets the built signature array exceed
/// the CURRENT `validatorCount`, which `Gate._verifySignatures` rejects outright.
const GATE_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "keeper=info".into()),
        )
        .init();

    let cfg_path = std::env::args().nth(1).unwrap_or_else(|| "keeper.toml".into());
    let cfg = Config::load(&cfg_path)?;

    let signer = cfg.keeper.load("keeper").context("loading keeper signer")?;
    // Shared across every per-target loop (one HTTP client / one dir handle).
    // L-5: read + mark-claimed only — it cannot deposit signatures.
    let source = Arc::new(StoreBackend::from_config(&cfg.store, "SIG_STORE_KEEPER_TOKEN")?);

    info!(
        keeper = %signer.address(),
        targets = cfg.targets.len(),
        sources = cfg.sources.len(),
        source = %source.describe(),
        "keeper started"
    );

    // A chain listed as BOTH a claim target and a refund source (a bidirectional
    // corridor) gets two loops submitting from the same account on the same chain
    // concurrently. Each has its own fresh-nonce provider, so under simultaneous
    // load they can fetch the same pending nonce and one tx is rejected
    // (nonce-too-low) — self-healing on the next tick, but worth flagging. For a
    // busy bidirectional keeper, run the target and source roles as separate
    // processes (or separate signer accounts) to avoid the contention.
    for t in &cfg.targets {
        if cfg.sources.iter().any(|s| s.chain_id == t.chain_id) {
            warn!(
                chain_id = t.chain_id,
                "chain is both a claim target and a refund source; the two loops share one \
                 account and may briefly contend on nonces under load (self-healing). Consider \
                 separate keeper processes for the two roles."
            );
        }
    }

    // Spawn one independent claim loop per destination chain. A loop only returns
    // on a permanent misconfig (e.g. wrong chainId); transient RPC failures are
    // retried inside it. We isolate a dead loop so one bad chain can't take down
    // delivery to the others — only when EVERY loop has exited do we error out.
    let mut tasks = tokio::task::JoinSet::new();
    for target in cfg.targets {
        let signer = signer.clone();
        let source = source.clone();
        tasks.spawn(async move { run_target(target, signer, source).await });
    }

    // And one refund loop per SOURCE chain. Refunds pay out where the funds were
    // locked, so they belong to the source side, not the claim targets.
    for src in cfg.sources {
        let signer = signer.clone();
        let store = source.clone();
        tasks.spawn(async move { run_source_refunds(src, signer, store).await });
    }

    let total = tasks.len();
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => warn!("a target loop exited on its own (other chains keep running)"),
            Ok(Err(e)) => warn!(error = %e, "a target loop failed (other chains keep running)"),
            Err(e) => warn!(error = %e, "a target task panicked (other chains keep running)"),
        }
    }
    anyhow::bail!("all {total} target loops have exited");
}

/// Connect to one chain and read its gate's parameters — the identical prologue
/// every submit loop needs (claims on a target, refunds on a source).
///
/// Returns the signing provider plus the initial [`GateView`]. Transient RPC
/// failures retry here rather than killing the loop; only a wrong `chainId` is
/// fatal, because that is a permanent misconfiguration and submitting to the
/// wrong network is not something to keep retrying.
async fn connect_gate(
    chain: &ChainCfg,
    signer: &PrivateKeySigner,
    role: &'static str,
) -> anyhow::Result<(impl Provider + Clone, Address, GateView)> {
    let wallet = EthereumWallet::from(signer.clone());
    let gate_addr: Address = chain.gate.parse().context("bad gate address")?;
    let retry = Duration::from_millis(chain.poll_interval_ms.max(1000));

    // SimpleNonceManager fetches the pending nonce from the chain for every tx,
    // instead of the default CachedNonceManager which keeps a local counter.
    //
    // The cached manager is unsafe here: a tx whose gas estimation reverts (e.g.
    // a claim for an asset the destination hasn't registered — exactly the
    // stranded transfers this keeper is meant to cancel) still advances the
    // cached nonce before failing to send. After a run of such failures the
    // cache sits far ahead of the chain, so the NEXT real tx (a cancel, say)
    // broadcasts with a gap and hangs pending forever. The keeper submits txs
    // one at a time and awaits each receipt, so a fresh per-tx fetch is correct.
    let provider = ProviderBuilder::new()
        .wallet(wallet)
        .with_simple_nonce_management()
        .connect_http(chain.rpc.parse()?);

    // Verify the RPC is on the expected chain. Unreachable => transient, retry.
    // Wrong chainId => permanent misconfig, return Err (isolated; siblings live).
    loop {
        match provider.get_chain_id().await {
            Ok(id) if id == chain.chain_id => break,
            Ok(id) => {
                anyhow::bail!("RPC chainId {id} != configured {} for {}", chain.chain_id, chain.rpc)
            }
            Err(e) => {
                warn!(chain_id = chain.chain_id, error = %e, "get_chain_id failed; retrying");
                tokio::time::sleep(retry).await;
            }
        }
    }

    let view = loop {
        match GateView::load(&Gate::new(gate_addr, &provider)).await {
            Ok(v) => break v,
            Err(e) => {
                warn!(chain_id = chain.chain_id, error = %e, "read gate params failed; retrying");
                tokio::time::sleep(retry).await;
            }
        }
    };

    info!(
        keeper = %signer.address(),
        gate = %gate_addr,
        chain_id = chain.chain_id,
        threshold = view.threshold,
        validator_count = view.validator_count,
        "{role} loop started"
    );
    Ok((provider, gate_addr, view))
}

/// Claim loop for a single destination chain.
async fn run_target(
    target: ChainCfg,
    signer: PrivateKeySigner,
    source: Arc<StoreBackend>,
) -> anyhow::Result<()> {
    let retry = Duration::from_millis(target.poll_interval_ms.max(1000));
    let (provider, gate_addr, mut view) = connect_gate(&target, &signer, "target").await?;
    let gate = Gate::new(gate_addr, &provider);

    // Submissions already reported UNCLAIMABLE on this chain. Bounded in practice
    // by the number of simultaneously-stranded transfers, and entries are dropped
    // as soon as one becomes claimable or executed.
    let mut stranded = StrandedLog::default();
    // Claims/cancels whose receipt timed out and may still be in the mempool.
    let mut pending = PendingTxs::default();

    loop {
        view.refresh_if_stale(&gate).await;
        // Allowlist for this tick. Fail-closed: if the sig-store is unreachable,
        // skip the tick rather than claim on a stale view. None => file mode
        // (no central allowlist, enforcement disabled).
        let allowlist = match source.fetch_allowlist().await {
            Ok(a) => a,
            Err(e) => {
                warn!(chain_id = target.chain_id, error = %e, "allowlist fetch failed; skipping tick");
                tokio::time::sleep(retry).await;
                continue;
            }
        };

        // The server-side work queue, not the whole table. Polling `load_all` cost
        // one `eth_call` per historically-delivered transfer per tick, forever,
        // because `SubmissionRecord` carries no lifecycle and a settled row is
        // indistinguishable from a pending one until the chain is asked. See
        // `bridge_db::Db::pending_claims`.
        //
        // Still only a hint: every `try_*` below re-checks the chain before it
        // submits, so the filter can never cause a wrong claim — at worst it
        // delays one until the row's lifecycle catches up.
        //
        // A store error used to be `unwrap_or_default()` — an empty queue — so a
        // 401 (rotated token) or a 500 meant claims and cancels silently stopped
        // with nothing in the log. Skip the tick loudly instead.
        let records = match source.pending_claims(target.chain_id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(chain_id = target.chain_id, error = %e, "pending_claims read failed; skipping tick");
                tokio::time::sleep(retry).await;
                continue;
            }
        };
        // Every id the queue handed us this tick. Anything the per-submission
        // memos (`stranded`, `pending`) remember that is NOT in here has left the
        // queue for good — cancelled, or claimed by another keeper — and must be
        // forgotten, or the memo grows by one entry per such transfer forever.
        let seen: HashSet<String> = records.iter().map(|r| r.submission_id.clone()).collect();
        for rec in records {
            // File-mode backends have no lifecycle to filter on and hand back
            // everything, so the corridor check stays.
            if rec.chain_id_to != target.chain_id {
                continue;
            }
            // Cancels are handled BEFORE the transfer-threshold and allowlist
            // gates, and deliberately so. Both of those exist to protect payouts,
            // and a cancel is the opposite of a payout — it releases nothing and
            // only burns the transfer so the source can repay the sender.
            //
            // Checking them first would strand precisely the transfers that need
            // refunding most: a transfer the allowlist rejects never collects
            // transfer signatures at all, so it would fail the threshold check,
            // never reach this branch, and its funds would stay locked forever.
            let cancel_sigs = view
                .member_signatures(&gate, &rec.submission_id, SigKind::Cancel, &rec.cancel_signatures)
                .await;
            if cancel_sigs.len() as u64 >= view.threshold {
                if !pending.may_submit(&provider, &rec.submission_id, SigKind::Cancel).await {
                    continue;
                }
                match try_cancel(&gate, &rec, &cancel_sigs).await {
                    // The DB `refund_status` is advanced by the indexer when it
                    // observes the resulting `Cancelled` event on-chain, not
                    // reported here — the keeper's word is not authoritative for a
                    // state that gates the refund-candidate list.
                    Ok(Some(_tx)) => {}
                    Ok(None) => {} // already executed (claimed or cancelled)
                    Err(e) => {
                        pending.note_failure(&rec.submission_id, SigKind::Cancel, &e);
                        warn!(
                            chain_id = target.chain_id,
                            submission_id = %rec.submission_id,
                            error = %e,
                            "cancel failed"
                        )
                    }
                }
                continue;
            }

            let claim_sigs = view
                .member_signatures(&gate, &rec.submission_id, SigKind::Transfer, &rec.signatures)
                .await;
            if (claim_sigs.len() as u64) < view.threshold {
                continue;
            }
            // Second enforcement gate (validators are the first): never submit a
            // claim for a non-whitelisted token or chain pair.
            if let Some(allow) = &allowlist {
                if !allow.token_allowed(&rec.debridge_id)
                    || !allow.chain_allowed(rec.chain_id_from, rec.chain_id_to)
                {
                    warn!(
                        chain_id = target.chain_id,
                        submission_id = %rec.submission_id,
                        "BLOCKED by allowlist — refusing to claim"
                    );
                    continue;
                }
            }

            if !pending.may_submit(&provider, &rec.submission_id, SigKind::Transfer).await {
                continue;
            }
            match try_claim(&gate, &rec, &claim_sigs).await {
                Ok(ClaimOutcome::Submitted(tx)) => {
                    stranded.clear(&rec.submission_id);
                    if let Err(e) = source.mark_claimed(&rec.submission_id, &tx).await {
                        warn!(
                            chain_id = target.chain_id,
                            submission_id = %rec.submission_id,
                            error = %e,
                            "claimed on-chain but failed to record status"
                        );
                    }
                }
                Ok(ClaimOutcome::AlreadyExecuted) => {
                    stranded.clear(&rec.submission_id);
                }
                // A transfer this gate can never pay out. Reported ONCE per
                // submission, at WARN.
                //
                // It used to be dropped silently (or at DEBUG, which nobody
                // enables in production), because warning every tick floods the
                // log for as long as the transfer sits unclaimed — at minimum a
                // whole refund timeout. But silence is the wrong trade: the
                // operator's only signal was a row stuck at READY forever with
                // nothing anywhere explaining why, and both real instances of
                // this — an unregistered corridor return path, and a receiver of
                // the wrong width — looked identical to "the keeper is asleep".
                //
                // Warn once, remember, and forget again the moment the transfer
                // becomes claimable or is executed, so a later strand of the same
                // id is reported afresh.
                Ok(ClaimOutcome::Stranded(reason)) => {
                    if stranded.should_report(&rec.submission_id) {
                        warn!(
                            chain_id = target.chain_id,
                            submission_id = %rec.submission_id,
                            debridge_id = %rec.debridge_id,
                            chain_id_from = rec.chain_id_from,
                            reason,
                            "UNCLAIMABLE — this gate can never pay this transfer out; \
                             it must be recovered via cancel/refund"
                        );
                    }
                }
                Err(e) => {
                    pending.note_failure(&rec.submission_id, SigKind::Transfer, &e);
                    warn!(
                        chain_id = target.chain_id,
                        submission_id = %rec.submission_id,
                        error = %e,
                        "claim failed"
                    )
                }
            }
        }
        // A stranded transfer that is later CANCELLED leaves the queue through the
        // cancel branch's `continue`, never through `clear`; without this its
        // entry would live for the life of the process.
        stranded.retain_seen(&seen);
        pending.retain_seen(&seen);
        tokio::time::sleep(Duration::from_millis(target.poll_interval_ms)).await;
    }
}

/// Refund loop for a single SOURCE chain: submit `refund()` for transfers whose
/// destination has already been burned and which have a refund quorum.
///
/// The keeper does not decide anything here — it only relays quorums the
/// validators formed. Both the "was it really burned?" and "was it really sent
/// from this gate?" questions are answered by the validators' on-chain checks
/// and by the Gate's own `sentBy` guard respectively.
async fn run_source_refunds(
    src: ChainCfg,
    signer: PrivateKeySigner,
    store: Arc<StoreBackend>,
) -> anyhow::Result<()> {
    let retry = Duration::from_millis(src.poll_interval_ms.max(1000));
    let (provider, gate_addr, mut view) = connect_gate(&src, &signer, "source refund").await?;
    let gate = Gate::new(gate_addr, &provider);
    let mut pending = PendingTxs::default();

    loop {
        view.refresh_if_stale(&gate).await;
        // Refunds that a validator quorum has actually attested — see
        // `bridge_db::Db::pending_refunds`. Same reasoning as the claim loop,
        // including the store-error handling: a silent empty queue here meant
        // refunds silently never happened.
        let records = match store.pending_refunds(src.chain_id).await {
            Ok(r) => r,
            Err(e) => {
                warn!(chain_id = src.chain_id, error = %e, "pending_refunds read failed; skipping tick");
                tokio::time::sleep(retry).await;
                continue;
            }
        };
        let seen: HashSet<String> = records.iter().map(|r| r.submission_id.clone()).collect();
        for rec in records {
            if rec.chain_id_from != src.chain_id {
                continue;
            }
            let refund_sigs = view
                .member_signatures(&gate, &rec.submission_id, SigKind::Refund, &rec.refund_signatures)
                .await;
            if (refund_sigs.len() as u64) < view.threshold {
                continue;
            }
            if !pending.may_submit(&provider, &rec.submission_id, SigKind::Refund).await {
                continue;
            }
            match try_refund(&gate, &rec, &refund_sigs).await {
                // As with cancel, the indexer records `refund_status = refunded`
                // from the observed on-chain `Refunded` event; the keeper does not
                // report a state that gates the candidate list.
                Ok(Some(_tx)) => {}
                Ok(None) => {} // already refunded, or never sent from this gate
                Err(e) => {
                    pending.note_failure(&rec.submission_id, SigKind::Refund, &e);
                    warn!(
                        chain_id = src.chain_id,
                        submission_id = %rec.submission_id,
                        error = %e,
                        "refund failed"
                    )
                }
            }
        }
        pending.retain_seen(&seen);
        tokio::time::sleep(Duration::from_millis(src.poll_interval_ms)).await;
    }
}

/// Can an EVM `claim` decode this receiver at all?
///
/// `Gate._toAddress` requires EXACTLY 20 bytes and reverts `BadReceiver`
/// otherwise. A 32-byte receiver is not a malformed 20-byte one — it is an
/// address for another VM (a Solana SPL token account, say) that was routed to
/// an EVM chain, and no amount of retrying will make it claimable here.
fn evm_receiver_decodable(receiver: &str) -> bool {
    receiver.strip_prefix("0x").unwrap_or(receiver).len() / 2 == 20
}

/// Remembers which submissions have already been reported unclaimable, so the
/// warning fires once per strand instead of once per poll tick.
///
/// The alternative to remembering is one of two bad options: warn every tick
/// (~1.5 lines/second per stranded transfer, for at least a whole refund
/// timeout, burying every other log line) or stay quiet and leave the operator
/// with a row stuck at READY and no explanation anywhere.
#[derive(Default)]
struct StrandedLog(HashSet<String>);

impl StrandedLog {
    /// True the FIRST time this submission is seen stranded, false while it
    /// stays that way.
    fn should_report(&mut self, submission_id: &str) -> bool {
        self.0.insert(submission_id.to_owned())
    }

    /// Forget it: the transfer progressed, so a LATER strand of the same id is
    /// news again rather than a duplicate. Registering a missing corridor is
    /// exactly this case — every stranded transfer on it becomes claimable at
    /// once, and if one strands again afterwards the operator must hear about it.
    fn clear(&mut self, submission_id: &str) {
        self.0.remove(submission_id);
    }

    /// Forget every id that is NOT in `seen` — the ids the work queue returned
    /// this tick. A transfer that leaves the queue by any route other than
    /// `clear` (cancelled, or claimed by another keeper) would otherwise stay in
    /// the set for the life of the process: a tiny leak per transfer, but one
    /// that also suppresses the report should the same id ever strand again.
    fn retain_seen(&mut self, seen: &HashSet<String>) {
        self.0.retain(|id| seen.contains(id));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

// ---------------------------------------------------------------------------
// Pending-tx tracking: what to do when a receipt does not arrive in time.
// ---------------------------------------------------------------------------

/// `confirm` gave up waiting for this tx's receipt. Carried as a typed error so
/// the loop can remember the hash and poll it next tick instead of blindly
/// submitting a duplicate.
///
/// Without this the pattern was: tx stuck/underpriced -> receipt times out ->
/// `executed()` still false next tick -> a SECOND tx is queued at nonce+1 ->
/// and a third, and a fourth, one per tick. The moment the first one mined,
/// every duplicate reverted `AlreadyExecuted` and each paid its gas.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReceiptTimeout {
    hash: B256,
}

impl std::fmt::Display for ReceiptTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "no receipt for tx {:#x} within {}s; it is remembered and polled before any resubmit",
            self.hash,
            RECEIPT_TIMEOUT.as_secs()
        )
    }
}

impl std::error::Error for ReceiptTimeout {}

/// What the chain says about a remembered tx hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TxProbe {
    /// A receipt exists: the tx is in a block.
    Mined { reverted: bool },
    /// No receipt, but the node still knows the tx — it is waiting in the pool.
    InMempool,
    /// No receipt and the node has never heard of it: dropped or replaced.
    Gone,
    /// The RPC could not answer.
    Unknown,
}

/// The loop's decision for one remembered tx.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingAction {
    /// It mined successfully; forget it. The `try_*` on-chain re-check makes the
    /// follow-up a no-op.
    Landed,
    /// Still in flight (or unknowable this tick); do NOT submit another.
    Wait,
    /// It will never mine (gone) or it mined and reverted; forget it and let
    /// the tick submit afresh.
    Resubmit,
}

/// The pure rule. Fail-closed on `Unknown`: an RPC blip must not become a
/// duplicate tx, and waiting one more tick costs nothing.
fn resolve_pending(probe: TxProbe) -> PendingAction {
    match probe {
        TxProbe::Mined { reverted: false } => PendingAction::Landed,
        TxProbe::Mined { reverted: true } | TxProbe::Gone => PendingAction::Resubmit,
        TxProbe::InMempool | TxProbe::Unknown => PendingAction::Wait,
    }
}

/// Hashes of submitted txs whose receipt did not arrive within
/// [`RECEIPT_TIMEOUT`], keyed by `(submission_id, kind)` — one claim, one
/// cancel and one refund can each be in flight for the same id, but never two
/// of the same kind.
///
/// The keeper keeps `SimpleNonceManager` (a fresh pending-nonce fetch per tx):
/// this memo is what stops the fresh nonce from being used to queue a
/// duplicate behind a tx that is merely slow.
#[derive(Default)]
struct PendingTxs(HashMap<(String, &'static str), B256>);

impl PendingTxs {
    fn key(submission_id: &str, kind: SigKind) -> (String, &'static str) {
        (submission_id.to_owned(), kind.as_str())
    }

    fn track(&mut self, submission_id: &str, kind: SigKind, hash: B256) {
        self.0.insert(Self::key(submission_id, kind), hash);
    }

    fn hash(&self, submission_id: &str, kind: SigKind) -> Option<B256> {
        self.0.get(&Self::key(submission_id, kind)).copied()
    }

    fn clear(&mut self, submission_id: &str, kind: SigKind) {
        self.0.remove(&Self::key(submission_id, kind));
    }

    /// Apply a probe result for a remembered tx: forget it unless it is still in
    /// flight, and say whether a new submission may go out. Pure — the I/O is in
    /// [`PendingTxs::may_submit`].
    fn apply(&mut self, submission_id: &str, kind: SigKind, probe: TxProbe) -> PendingAction {
        let action = resolve_pending(probe);
        if action != PendingAction::Wait {
            self.clear(submission_id, kind);
        }
        action
    }

    /// If a `kind` tx for this id is remembered, ask the chain about it first.
    /// Returns `true` when the tick may go ahead and (re)submit, `false` when it
    /// must leave the id alone this tick.
    async fn may_submit<P: Provider>(
        &mut self,
        provider: &P,
        submission_id: &str,
        kind: SigKind,
    ) -> bool {
        let Some(hash) = self.hash(submission_id, kind) else { return true };
        let probe = probe_tx(provider, hash).await;
        match self.apply(submission_id, kind, probe) {
            PendingAction::Landed => {
                info!(submission_id, tx = %hash, kind = kind.as_str(), "earlier tx landed after its receipt timed out");
                true
            }
            PendingAction::Resubmit => {
                warn!(submission_id, tx = %hash, kind = kind.as_str(), ?probe, "earlier tx will not land; resubmitting");
                true
            }
            PendingAction::Wait => {
                debug!(submission_id, tx = %hash, kind = kind.as_str(), ?probe, "earlier tx still in flight; not resubmitting");
                false
            }
        }
    }

    /// Remember the hash if `err` is a [`ReceiptTimeout`]; any other failure
    /// means nothing was left in flight.
    fn note_failure(&mut self, submission_id: &str, kind: SigKind, err: &anyhow::Error) {
        if let Some(t) = err.downcast_ref::<ReceiptTimeout>() {
            self.track(submission_id, kind, t.hash);
        }
    }

    /// Same bound as [`StrandedLog::retain_seen`].
    fn retain_seen(&mut self, seen: &HashSet<String>) {
        self.0.retain(|(id, _), _| seen.contains(id));
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.0.len()
    }
}

/// Ask the chain what became of `hash`. Receipt first (cheap, and the only
/// thing that settles it), then the pool.
async fn probe_tx<P: Provider>(provider: &P, hash: B256) -> TxProbe {
    match provider.get_transaction_receipt(hash).await {
        Ok(Some(receipt)) => TxProbe::Mined { reverted: !receipt.status() },
        Ok(None) => match provider.get_transaction_by_hash(hash).await {
            Ok(Some(_)) => TxProbe::InMempool,
            Ok(None) => TxProbe::Gone,
            Err(e) => {
                warn!(tx = %hash, error = %e, "get_transaction_by_hash failed; treating the tx as in flight");
                TxProbe::Unknown
            }
        },
        Err(e) => {
            warn!(tx = %hash, error = %e, "get_transaction_receipt failed; treating the tx as in flight");
            TxProbe::Unknown
        }
    }
}

/// What one `try_claim` attempt concluded.
///
/// The two non-submitting outcomes used to share a bare `None`, which is how a
/// permanently-undeliverable transfer became indistinguishable from a settled
/// one: both were "nothing to do", and neither said anything. Naming them apart
/// lets the caller stay quiet about the ordinary case and speak up exactly once
/// about the pathological one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClaimOutcome {
    /// A `claim()` was submitted and confirmed; carries the tx hash.
    Submitted(String),
    /// Already delivered — by this keeper on an earlier tick, or another keeper.
    AlreadyExecuted,
    /// This gate can NEVER pay this transfer out, whatever the quorum. Carries
    /// the operator-facing reason. Recovery is the two-phase cancel/refund.
    Stranded(&'static str),
}

/// Submit `claim()` for one record. See [`ClaimOutcome`] for what the non-error
/// results mean.
///
/// `sigs` MUST already be filtered to the gate's on-chain validator set (see
/// [`GateView::member_signatures`]). The record's own `signatures` field is
/// deliberately NOT read here: it may contain signatures from any key at all, and
/// forwarding those is what makes a transfer permanently unclaimable.
async fn try_claim<P: Provider>(
    gate: &Gate::GateInstance<P>,
    rec: &SubmissionRecord,
    sigs: &[SignerSig],
) -> anyhow::Result<ClaimOutcome> {
    let submission_id = B256::from_str(&rec.submission_id).context("bad submission_id")?;

    // An EVM `claim` decodes `receiver` as an address and requires EXACTLY 20
    // bytes (it used to truncate anything longer, silently paying an unowned
    // address). A 32-byte receiver here means the transfer was addressed for a
    // non-EVM VM but routed to an EVM chain, so the claim is certain to revert
    // `BadReceiver`. Report it as stranded rather than burn a tx and an RPC round
    // trip every tick — this is exactly the case the two-phase refund recovers,
    // same posture as the `tokenOf == 0` guard below.
    //
    // The CALLER decides how loudly to say so, and says it once per submission;
    // that is why this returns a reason instead of logging here. Logging at this
    // level meant either a WARN every tick (~1.5 lines/second per stranded
    // transfer, burying everything else) or a DEBUG nobody reads.
    if !evm_receiver_decodable(&rec.receiver) {
        return Ok(ClaimOutcome::Stranded(
            "receiver is not a 20-byte EVM address (a 32-byte one is addressed for \
             another VM and reverts BadReceiver here)",
        ));
    }

    if gate.executed(submission_id).call().await? {
        return Ok(ClaimOutcome::AlreadyExecuted); // by us or another keeper
    }

    let debridge_id = B256::from_str(&rec.debridge_id).context("bad debridge_id")?;

    // Skip a claim that would certainly revert with UnknownAsset: if the
    // destination gate has no local token registered for this debridgeId, there
    // is nothing to release. This is exactly the stranded-transfer case the
    // refund path handles — without this guard the keeper would re-attempt the
    // claim every tick, hammering the RPC and flooding the logs, until the
    // transfer is cancelled. If the asset is registered later, the claim resumes
    // (and the caller drops its "already warned" entry, so a later strand of the
    // same id is reported again).
    //
    // A whole corridor can land here: `run.sh` wires `setLocalToken` only between
    // the EVM chains in its own config, so a corridor added out-of-band — the
    // Solana leg, say — has no return-path mapping until someone registers it.
    if gate.tokenOf(debridge_id).call().await? == Address::ZERO {
        return Ok(ClaimOutcome::Stranded(
            "destination gate has no local token registered for this debridgeId \
             (UnknownAsset) — call setLocalToken for this corridor",
        ));
    }

    let amount = U256::from_str(&rec.amount).context("bad amount")?;
    let receiver = bytes_of(&rec.receiver)?;
    let auto_params = bytes_of(&rec.auto_params)?;
    let native_sender = bytes_of(&rec.native_sender)?;

    // signatures MUST be ordered by signer address, strictly ascending
    let signatures = sorted_signatures(sigs)?;

    info!(submission_id = %rec.submission_id, sigs = signatures.len(), "submitting claim()");

    let call = gate.claim(
        debridge_id,
        amount,
        U256::from(rec.chain_id_from),
        U256::from(rec.nonce),
        receiver,
        auto_params,
        native_sender,
        signatures,
    );
    confirm(call, "claim", &rec.submission_id, "CLAIMED").await.map(ClaimOutcome::Submitted)
}

/// Send a prepared gate call, await its receipt, and refuse to report a
/// mined-but-REVERTED transaction as success.
///
/// That last part is the reason this is one helper rather than three copies. A
/// reverted `claim` reported as success makes the caller run `mark_claimed`,
/// which also clears the `eligible` refund flag — permanently hiding a stranded
/// transfer from recovery. A reverted `cancel` reported as success mis-sequences
/// the two-phase refund, and a reverted `refund` claims funds were returned when
/// they were not. Failing instead leaves the tick to retry, and each `try_*`
/// re-checks on-chain state first, so a retry after a tx really landed is a no-op.
///
/// `verb` names the call in the error; `done` is the log line on success.
async fn confirm<P: Provider>(
    call: alloy::contract::CallBuilder<P, impl alloy::contract::CallDecoder>,
    verb: &str,
    submission_id: &str,
    done: &str,
) -> anyhow::Result<String> {
    let pending = call.send().await.with_context(|| format!("send {verb}"))?;
    let hash = *pending.tx_hash();
    let receipt = match pending.with_timeout(Some(RECEIPT_TIMEOUT)).get_receipt().await {
        Ok(r) => r,
        // The watcher gave up, not the chain: the tx may still mine. Hand the
        // hash back as a typed error so the loop remembers it (see
        // `PendingTxs`) instead of queueing a duplicate next tick.
        Err(alloy::providers::PendingTransactionError::TxWatcher(
            alloy::providers::WatchTxError::Timeout,
        )) => return Err(ReceiptTimeout { hash }.into()),
        Err(e) => return Err(anyhow::Error::from(e).context("await receipt")),
    };
    if !receipt.status() {
        anyhow::bail!(
            "{verb} tx {:#x} reverted (status 0) for submission {submission_id}; \
             not recording it as successful",
            receipt.transaction_hash,
        );
    }
    info!(submission_id, tx = %receipt.transaction_hash, "{done}");
    Ok(format!("{:#x}", receipt.transaction_hash))
}

/// Submit `cancel()` on the destination. `None` if it is already executed
/// (claimed or cancelled) — either way there is nothing to burn.
///
/// `sigs` MUST already be validator-filtered — see [`try_claim`].
async fn try_cancel<P: Provider>(
    gate: &Gate::GateInstance<P>,
    rec: &SubmissionRecord,
    sigs: &[SignerSig],
) -> anyhow::Result<Option<String>> {
    let submission_id = B256::from_str(&rec.submission_id).context("bad submission_id")?;
    if gate.executed(submission_id).call().await? {
        return Ok(None);
    }

    let debridge_id = B256::from_str(&rec.debridge_id).context("bad debridge_id")?;
    let amount = U256::from_str(&rec.amount).context("bad amount")?;

    info!(
        submission_id = %rec.submission_id,
        sigs = sigs.len(),
        "submitting cancel() — burning the transfer on the destination"
    );

    let call = gate.cancel(
        debridge_id,
        amount,
        U256::from(rec.chain_id_from),
        U256::from(rec.nonce),
        bytes_of(&rec.receiver)?,
        bytes_of(&rec.auto_params)?,
        bytes_of(&rec.native_sender)?,
        sorted_signatures(sigs)?,
    );
    confirm(call, "cancel", &rec.submission_id, "CANCELLED").await.map(Some)
}

/// Submit `refund()` on the source. `None` if already refunded, if this gate
/// never emitted the id, or if we don't know which token was locked.
///
/// `sigs` MUST already be validator-filtered — see [`try_claim`].
async fn try_refund<P: Provider>(
    gate: &Gate::GateInstance<P>,
    rec: &SubmissionRecord,
    sigs: &[SignerSig],
) -> anyhow::Result<Option<String>> {
    let submission_id = B256::from_str(&rec.submission_id).context("bad submission_id")?;

    if gate.refunded(submission_id).call().await? {
        return Ok(None);
    }
    // `sentBy` is the gate's own record that it locked these funds; zero means
    // there is nothing to return (and `refund()` would revert with NotSent).
    if gate.sentBy(submission_id).call().await? == Address::ZERO {
        return Ok(None);
    }

    // The locked ERC-20 is not derivable from debridgeId (a one-way hash), so it
    // is carried on the record — and re-checked on-chain, which is why supplying
    // it from the store is safe: a wrong token reverts rather than paying out.
    if rec.token.is_empty() {
        warn!(
            submission_id = %rec.submission_id,
            "refund quorum reached but the locked token is unknown for this record \
             (pre-refund-path row); re-index its Sent event to populate it"
        );
        return Ok(None);
    }
    let token = Address::from_str(&rec.token).context("bad token")?;
    let debridge_id = B256::from_str(&rec.debridge_id).context("bad debridge_id")?;
    let amount = U256::from_str(&rec.amount).context("bad amount")?;

    info!(
        submission_id = %rec.submission_id,
        sigs = sigs.len(),
        "submitting refund() — returning locked funds on the source"
    );

    let call = gate.refund(
        token,
        debridge_id,
        amount,
        U256::from(rec.chain_id_to),
        U256::from(rec.nonce),
        bytes_of(&rec.receiver)?,
        bytes_of(&rec.auto_params)?,
        bytes_of(&rec.native_sender)?,
        sorted_signatures(sigs)?,
    );
    confirm(call, "refund", &rec.submission_id, "REFUNDED").await.map(Some)
}

/// The keeper's live view of one gate: the signature `threshold`, the
/// `validatorCount` that bounds how long a signature array may be, and a
/// per-signer membership memo.
///
/// ## Why the array must be filtered, not merely counted
///
/// The sig-store verifies only that a signature recovers to its claimed signer —
/// NOT that the signer is a validator. Anyone able to write to the store (any
/// validator, the keeper, or any holder of the shared token) can therefore
/// deposit structurally valid signatures from throwaway keys.
///
/// Counting only members was necessary but not sufficient. The keeper used to
/// count members for the quorum decision and then forward the record's ENTIRE
/// signature list as calldata. `Gate._verifySignatures` rejects any array longer
/// than `validatorCount`, so two junk signatures against a 3-validator gate made
/// every submission revert `TooManySignatures` — forever, since the off-chain
/// quorum still read as satisfied and the tick retried. The transfer became
/// permanently unclaimable.
///
/// So membership is now a FILTER, and the filtered list is the only thing that
/// ever reaches calldata. Signatures are first RECOVERED and deduplicated by the
/// recovered address (the store's `signer` label is not trusted — see
/// [`authenticate_signatures`]), and members are a subset of the on-chain set, so
/// the resulting array can never exceed `validatorCount` — `TooManySignatures`
/// is unreachable.
struct GateView {
    threshold: u64,
    /// Bounds the signature array `Gate._verifySignatures` will accept.
    validator_count: usize,
    /// Per-signer membership, refreshed on [`GATE_REFRESH_INTERVAL`].
    members: HashMap<Address, bool>,
    refreshed_at: Instant,
}

impl GateView {
    async fn load<P: Provider>(gate: &Gate::GateInstance<P>) -> anyhow::Result<Self> {
        let threshold = gate.threshold().call().await?;
        let validator_count = gate.validatorCount().call().await?;
        Ok(GateView {
            threshold: threshold.try_into().unwrap_or(u64::MAX),
            validator_count: validator_count.try_into().unwrap_or(usize::MAX),
            members: HashMap::new(),
            refreshed_at: Instant::now(),
        })
    }

    /// Re-read the gate's parameters once the memo is older than
    /// [`GATE_REFRESH_INTERVAL`], dropping the membership cache with them.
    ///
    /// A read failure leaves the previous (still usable) view in place and retries
    /// on the next tick — the alternative, treating an RPC blip as "no validators",
    /// would stall delivery entirely.
    async fn refresh_if_stale<P: Provider>(&mut self, gate: &Gate::GateInstance<P>) {
        if self.refreshed_at.elapsed() < GATE_REFRESH_INTERVAL {
            return;
        }
        match GateView::load(gate).await {
            Ok(fresh) => *self = fresh,
            Err(e) => {
                warn!(error = %e, "refreshing gate params failed; keeping the previous view");
                // Back off a full interval rather than retrying every tick.
                self.refreshed_at = Instant::now();
            }
        }
    }

    /// Those `sigs` that (a) genuinely recover to their labelled signer over
    /// `kind`'s digest of `submission_id`, deduplicated by RECOVERED address, and
    /// (b) are signed by a member of the gate's on-chain validator set.
    ///
    /// Step (a) is what keeps the store's `signer` label advisory. The keeper
    /// used to take it on trust: a row labelled with a member's address but
    /// carrying another key's bytes (or the same member's bytes twice under two
    /// labels) counted toward quorum and reached calldata, where `Gate` recovered
    /// a non-member / a duplicate and reverted — at estimateGas, every tick,
    /// forever. Recovering here means the calldata can only ever hold distinct
    /// member signatures.
    ///
    /// Fail-closed: an `isValidator` read error drops that signer for this tick
    /// (we wait rather than submit a doomed tx) and is not cached.
    async fn member_signatures<P: Provider>(
        &mut self,
        gate: &Gate::GateInstance<P>,
        submission_id: &str,
        kind: SigKind,
        sigs: &[SignerSig],
    ) -> Vec<SignerSig> {
        let Ok(id) = B256::from_str(submission_id) else {
            warn!(submission_id, "malformed submission_id in store row; ignoring its signatures");
            return Vec::new();
        };
        let authentic = authenticate_signatures(id, kind, sigs);
        let mut resolved = Vec::with_capacity(authentic.len());
        for (addr, s) in authentic {
            let member = match self.members.get(&addr) {
                Some(&m) => m,
                None => match gate.isValidator(addr).call().await {
                    Ok(m) => {
                        self.members.insert(addr, m);
                        m
                    }
                    Err(e) => {
                        warn!(signer = %s.signer, error = %e, "isValidator read failed; dropping this signer for this tick");
                        continue;
                    }
                },
            };
            resolved.push((addr, member, s));
        }
        filter_members(resolved, self.validator_count)
    }
}

/// Recover each signature over `kind`'s digest of `id`, drop any whose
/// recovered address is not the store's `signer` label (or that do not recover
/// at all), and keep ONE signature per recovered address.
///
/// The returned `SignerSig.signer` is the RECOVERED address in canonical
/// `0x`-lowercase form, not the label — downstream ordering keys on it.
///
/// Pure (no I/O), so the rule is unit-testable with real keys.
fn authenticate_signatures(id: B256, kind: SigKind, sigs: &[SignerSig]) -> Vec<(Address, SignerSig)> {
    let mut seen: HashSet<Address> = HashSet::with_capacity(sigs.len());
    let mut out = Vec::with_capacity(sigs.len());
    for s in sigs {
        match bridge_core::store::verify_attestation(id, kind, s) {
            Ok(recovered) => {
                if !seen.insert(recovered) {
                    debug!(signer = %s.signer, "duplicate signature for one recovered signer; keeping the first");
                    continue;
                }
                out.push((
                    recovered,
                    SignerSig { signer: format!("{recovered:#x}"), signature: s.signature.clone() },
                ));
            }
            Err(e) => warn!(
                submission_id = %id,
                kind = kind.as_str(),
                signer = %s.signer,
                error = %e,
                "store row does not recover to its signer label; dropping it"
            ),
        }
    }
    out
}

/// Keep only member signatures, then cap the result at `validator_count`.
///
/// Split from the I/O so the rule is unit-testable. The cap is belt-and-braces:
/// distinct members can only exceed `validator_count` when the memo is stale
/// (a validator removed on-chain within the refresh window). Truncating after the
/// caller sorts would break the ascending-order requirement, so we cap here and
/// let [`sorted_signatures`] order what survives — a short array reverts
/// `NotEnoughSignatures`, which is retryable, rather than `TooManySignatures`,
/// which was not.
fn filter_members(
    resolved: Vec<(Address, bool, SignerSig)>,
    validator_count: usize,
) -> Vec<SignerSig> {
    let mut kept: Vec<(Address, SignerSig)> = resolved
        .into_iter()
        .filter(|(_, member, _)| *member)
        .map(|(addr, _, s)| (addr, s))
        .collect();
    kept.sort_by(|a, b| a.0.cmp(&b.0));
    kept.truncate(validator_count);
    kept.into_iter().map(|(_, s)| s).collect()
}

/// Signatures ordered by recovered signer ascending, as every Gate entry point
/// requires (the ordering is what dedupes signers on-chain), each re-encoded in
/// the only form the Gate accepts.
///
/// The canonicalisation is a HEAL, not the primary fix: the sig-store now stores
/// low-`s`/`v∈{27,28}` bytes on the way in, but rows written before that change
/// (and any store an operator restores from backup) can still hold a high-`s`
/// entry. One of those in the array reverts `claim`, `cancel` AND `refund` with
/// `ECDSAInvalidSignatureS`, and the off-chain quorum still reads as satisfied, so
/// the tick retries the same doomed calldata forever. Normalising here costs
/// nothing and cannot change which address a signature recovers to, so the
/// ascending order the caller relies on is preserved.
fn sorted_signatures(sigs: &[SignerSig]) -> anyhow::Result<Vec<Bytes>> {
    let mut sigs = sigs.to_vec();
    sigs.sort_by(|a, b| {
        let aa = Address::from_str(&a.signer).unwrap_or(Address::ZERO);
        let bb = Address::from_str(&b.signer).unwrap_or(Address::ZERO);
        aa.cmp(&bb)
    });
    sigs.iter()
        .map(|s| {
            // Fall back to the stored bytes when they cannot be parsed at all: the
            // store authenticates every signature on the way in, so this should be
            // unreachable, and forwarding is exactly the old behaviour — the Gate
            // gets the final say either way. Refusing here would let one
            // unparseable row block a quorum that is otherwise fine.
            match bridge_core::store::canonical_signature(s) {
                Ok(canonical) => bytes_of(&canonical.signature),
                Err(e) => {
                    warn!(signer = %s.signer, error = %e, "signature has no canonical form; forwarding as stored");
                    bytes_of(&s.signature)
                }
            }
        })
        .collect()
}

fn bytes_of(hex_str: &str) -> anyhow::Result<Bytes> {
    let s = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    if s.is_empty() {
        return Ok(Bytes::new());
    }
    Ok(Bytes::from(hex::decode(s)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signer whose address is `byte` repeated — lets tests control ordering.
    fn sig(byte: u8) -> SignerSig {
        SignerSig {
            signer: format!("{:#x}", Address::repeat_byte(byte)),
            signature: format!("0x{}", hex::encode([byte; 65])),
        }
    }

    /// What `member_signatures` hands to `filter_members` after its RPC reads.
    fn resolved(pairs: &[(&SignerSig, bool)]) -> Vec<(Address, bool, SignerSig)> {
        pairs
            .iter()
            .map(|(s, member)| (Address::from_str(&s.signer).unwrap(), *member, (*s).clone()))
            .collect()
    }

    /// THE regression. Before the fix the keeper counted only validators toward
    /// quorum but forwarded the record's ENTIRE signature list as calldata. Two
    /// signatures from throwaway keys pushed the array past `validatorCount`, and
    /// `Gate._verifySignatures` reverted `TooManySignatures` on every retry —
    /// permanently unclaimable.
    #[test]
    fn junk_signatures_never_reach_the_calldata() {
        let (v1, v2) = (sig(0x11), sig(0x22));
        let (junk1, junk2) = (sig(0xAA), sig(0xBB));
        // A 3-validator / threshold-2 gate; the store holds 2 real + 2 forged.
        let validator_count = 3;

        // The pre-fix path: forward `rec.signatures` verbatim. Pin the defect so
        // this test fails loudly if anyone reintroduces it.
        let unfiltered = [&v1, &junk1, &v2, &junk2].len();
        assert!(
            unfiltered > validator_count,
            "premise of this regression: the unfiltered array overflows the gate's cap"
        );

        let kept = filter_members(
            resolved(&[(&v1, true), (&junk1, false), (&v2, true), (&junk2, false)]),
            validator_count,
        );

        assert_eq!(kept.len(), 2, "only validator signatures may be submitted");
        assert!(
            kept.iter().all(|s| s.signer != junk1.signer && s.signer != junk2.signer),
            "a non-validator signature reached the calldata"
        );
        // The Gate's own cap must now be unreachable from the keeper.
        assert!(
            kept.len() <= validator_count,
            "array would revert TooManySignatures at the gate"
        );
        // ...and quorum is still met, so the transfer is claimable.
        assert!(kept.len() >= 2, "junk signatures must not deny a real quorum");
    }

    /// The stale-memo guard: if validators are removed on-chain inside the refresh
    /// window, a cached `true` could otherwise build an array longer than the
    /// CURRENT `validatorCount`. Capping turns that into a retryable
    /// `NotEnoughSignatures` instead of a permanent `TooManySignatures`.
    #[test]
    fn array_is_capped_at_the_current_validator_count() {
        let sigs: Vec<SignerSig> = (1u8..=4).map(sig).collect();
        let pairs: Vec<(&SignerSig, bool)> = sigs.iter().map(|s| (s, true)).collect();

        let kept = filter_members(resolved(&pairs), 2);

        assert_eq!(kept.len(), 2, "must not exceed the gate's validatorCount");
    }

    /// The Gate requires strictly ascending signers; capping must not disturb the
    /// ordering `sorted_signatures` then relies on.
    #[test]
    fn survivors_stay_in_ascending_signer_order() {
        let (a, b, c) = (sig(0x33), sig(0x11), sig(0x22));
        let kept = filter_members(resolved(&[(&a, true), (&b, true), (&c, true)]), 3);

        let addrs: Vec<Address> =
            kept.iter().map(|s| Address::from_str(&s.signer).unwrap()).collect();
        let mut sorted = addrs.clone();
        sorted.sort();
        assert_eq!(addrs, sorted, "signers must be strictly ascending");

        // And the encoded array the gate actually receives round-trips.
        let encoded = sorted_signatures(&kept).expect("valid hex signatures");
        assert_eq!(encoded.len(), 3);
    }

    /// The heal for rows written before the sig-store canonicalised on the way in.
    ///
    /// A high-`s` signature authenticates off-chain (alloy normalises before
    /// recovering) and reverts `ECDSAInvalidSignatureS` in `ECDSA.recover`. Since
    /// the whole quorum goes to the Gate as one array, one such entry reverted
    /// `claim`, `cancel` and `refund` on every retry — the off-chain quorum still
    /// read as satisfied, so the tick never gave up and never varied the calldata.
    #[test]
    fn calldata_is_canonical_even_when_the_store_holds_a_high_s_row() {
        use alloy::signers::local::PrivateKeySigner;
        use alloy::signers::SignerSync;
        use alloy::primitives::U256;

        const N: U256 = U256::from_limbs([
            0xBFD25E8CD0364141,
            0xBAAEDCE6AF48A03B,
            0xFFFFFFFFFFFFFFFE,
            0xFFFFFFFFFFFFFFFF,
        ]);
        const HALF_N: U256 = U256::from_limbs([
            0xDFE92F46681B20A0,
            0x5D576E7357A4501D,
            0xFFFFFFFFFFFFFFFF,
            0x7FFFFFFFFFFFFFFF,
        ]);

        let signer = PrivateKeySigner::random();
        let id = B256::repeat_byte(0x42);
        let raw = bridge_core::signer::signature_bytes(
            &signer.sign_message_sync(id.as_slice()).unwrap(),
        );

        // The malleated twin: same signer, `s -> n - s`, parity flipped.
        let mut poisoned = raw;
        let s_high = N - U256::from_be_slice(&raw[32..64]);
        poisoned[32..64].copy_from_slice(&s_high.to_be_bytes::<32>());
        poisoned[64] = if raw[64] == 27 { 28 } else { 27 };
        assert!(
            U256::from_be_slice(&poisoned[32..64]) > HALF_N,
            "premise: the Gate reverts on this encoding"
        );

        let stored = SignerSig {
            signer: format!("{:#x}", signer.address()),
            signature: format!("0x{}", hex::encode(poisoned)),
        };

        let calldata = sorted_signatures(&[stored]).expect("canonicalises");
        assert_eq!(
            calldata[0].as_ref(),
            &raw[..],
            "the keeper must submit the low-`s` form, not the bytes it was handed"
        );
    }

    // ---------------------------------------------------------------------
    // The store's `signer` label is advisory. Recover, then dedupe by what the
    // bytes actually recover to.
    // ---------------------------------------------------------------------

    fn signed(signer: &PrivateKeySigner, id: B256, kind: SigKind) -> SignerSig {
        use alloy::signers::SignerSync;
        let sig = signer.sign_message_sync(kind.digest(id).as_slice()).unwrap();
        SignerSig {
            signer: format!("{:#x}", signer.address()),
            signature: format!("0x{}", hex::encode(bridge_core::signer::signature_bytes(&sig))),
        }
    }

    /// THE regression: a row whose bytes belong to key X but whose label is a
    /// member's address. Trusting the label counted X toward quorum and put X's
    /// signature in the calldata, where the Gate recovered a non-member and
    /// reverted every tick at estimateGas.
    #[test]
    fn a_row_mislabelled_with_a_member_address_is_dropped() {
        let id = B256::repeat_byte(0x11);
        let member = PrivateKeySigner::random();
        let junk = PrivateKeySigner::random();

        let mut forged = signed(&junk, id, SigKind::Transfer);
        forged.signer = format!("{:#x}", member.address()); // lie about who signed

        let kept = authenticate_signatures(id, SigKind::Transfer, &[forged]);
        assert!(kept.is_empty(), "a signature must count for the key that MADE it, never its label");
    }

    /// The same member's bytes filed twice — once under the checksummed label,
    /// once lowercase — must collapse to ONE signature, or the Gate's strict
    /// ascending check sees a duplicate and reverts.
    #[test]
    fn duplicate_rows_for_one_recovered_signer_collapse_to_one() {
        let id = B256::repeat_byte(0x22);
        let v = PrivateKeySigner::random();
        let a = signed(&v, id, SigKind::Transfer);
        let mut b = a.clone();
        b.signer = alloy::primitives::Address::from_str(&a.signer).unwrap().to_checksum(None);
        assert_ne!(a.signer, b.signer, "premise: two spellings of one label");

        let kept = authenticate_signatures(id, SigKind::Transfer, &[a.clone(), b]);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].0, v.address());
        assert_eq!(kept[0].1.signer, format!("{:#x}", v.address()), "label is the recovered address");
    }

    /// A transfer signature is not a cancel attestation: it recovers to a
    /// different address over `cancel_id(id)` and so fails the label check.
    #[test]
    fn a_transfer_signature_does_not_authenticate_as_a_cancel() {
        let id = B256::repeat_byte(0x33);
        let v = PrivateKeySigner::random();
        let transfer = signed(&v, id, SigKind::Transfer);
        assert!(authenticate_signatures(id, SigKind::Cancel, &[transfer.clone()]).is_empty());
        assert!(authenticate_signatures(id, SigKind::Refund, &[transfer]).is_empty());

        let cancel = signed(&v, id, SigKind::Cancel);
        assert_eq!(authenticate_signatures(id, SigKind::Cancel, &[cancel]).len(), 1);
    }

    /// Recovery must not reject a signature the signer really did make just
    /// because the store holds it high-`s` (see `sorted_signatures`).
    #[test]
    fn a_high_s_row_still_recovers_to_its_signer() {
        let id = B256::repeat_byte(0x44);
        let v = PrivateKeySigner::random();
        let good = signed(&v, id, SigKind::Transfer);
        let raw: [u8; 65] = hex::decode(&good.signature[2..]).unwrap().try_into().unwrap();
        let n = U256::from_str_radix(
            "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141",
            16,
        )
        .unwrap();
        let mut high = raw;
        let s_high = n - U256::from_be_slice(&raw[32..64]);
        high[32..64].copy_from_slice(&s_high.to_be_bytes::<32>());
        high[64] = if raw[64] == 27 { 28 } else { 27 };
        let row = SignerSig { signer: good.signer.clone(), signature: format!("0x{}", hex::encode(high)) };

        let kept = authenticate_signatures(id, SigKind::Transfer, &[row]);
        assert_eq!(kept.len(), 1, "same signer, non-canonical encoding — still theirs");
        // ...and the calldata path canonicalises it.
        let encoded = sorted_signatures(&[kept[0].1.clone()]).unwrap();
        assert_eq!(encoded[0].as_ref(), &raw[..]);
    }

    /// Unparseable bytes and an unparseable label are both dropped, not
    /// forwarded.
    #[test]
    fn garbage_rows_are_dropped() {
        let id = B256::repeat_byte(0x55);
        let rows = [
            SignerSig { signer: "not-an-address".into(), signature: format!("0x{}", hex::encode([1u8; 65])) },
            SignerSig { signer: format!("{:#x}", Address::repeat_byte(1)), signature: "0xzz".into() },
            SignerSig { signer: format!("{:#x}", Address::repeat_byte(1)), signature: format!("0x{}", hex::encode([0u8; 65])) },
        ];
        assert!(authenticate_signatures(id, SigKind::Transfer, &rows).is_empty());
    }

    /// End-to-end through the pure pipeline: recover -> dedupe -> members ->
    /// sorted. Two members (one filed twice), one forged row, one non-member.
    #[test]
    fn recovered_and_deduped_signatures_then_filter_to_members_ascending() {
        let id = B256::repeat_byte(0x66);
        let (v1, v2, outsider) =
            (PrivateKeySigner::random(), PrivateKeySigner::random(), PrivateKeySigner::random());
        let members: HashSet<Address> = [v1.address(), v2.address()].into_iter().collect();

        let mut forged = signed(&outsider, id, SigKind::Transfer);
        forged.signer = format!("{:#x}", v1.address());
        let rows = [
            signed(&v2, id, SigKind::Transfer),
            forged,
            signed(&v1, id, SigKind::Transfer),
            signed(&v1, id, SigKind::Transfer), // duplicate
            signed(&outsider, id, SigKind::Transfer), // honest non-member
        ];

        let authentic = authenticate_signatures(id, SigKind::Transfer, &rows);
        assert_eq!(authentic.len(), 3, "v1 once, v2 once, outsider once");

        let resolved: Vec<(Address, bool, SignerSig)> =
            authentic.into_iter().map(|(a, s)| (a, members.contains(&a), s)).collect();
        let kept = filter_members(resolved, 3);
        let addrs: Vec<Address> = kept.iter().map(|s| Address::from_str(&s.signer).unwrap()).collect();
        let mut expect = vec![v1.address(), v2.address()];
        expect.sort();
        assert_eq!(addrs, expect, "exactly the two members, ascending");
    }

    // ---------------------------------------------------------------------
    // Pending-tx tracking: a receipt timeout must not become a duplicate tx.
    // ---------------------------------------------------------------------

    #[test]
    fn a_tx_still_in_the_mempool_blocks_a_resubmit() {
        assert_eq!(resolve_pending(TxProbe::InMempool), PendingAction::Wait);
        // and an RPC we cannot ask is treated the same way — fail closed.
        assert_eq!(resolve_pending(TxProbe::Unknown), PendingAction::Wait);
    }

    #[test]
    fn a_dropped_or_reverted_tx_allows_a_resubmit() {
        assert_eq!(resolve_pending(TxProbe::Gone), PendingAction::Resubmit);
        assert_eq!(resolve_pending(TxProbe::Mined { reverted: true }), PendingAction::Resubmit);
    }

    #[test]
    fn a_mined_tx_is_forgotten_and_the_tick_proceeds_to_its_noop_recheck() {
        assert_eq!(resolve_pending(TxProbe::Mined { reverted: false }), PendingAction::Landed);
    }

    /// The memo only fills from a typed `ReceiptTimeout`; every other failure
    /// (send rejected, estimateGas revert) left nothing in flight.
    #[test]
    fn only_a_receipt_timeout_is_remembered() {
        let mut p = PendingTxs::default();
        let hash = B256::repeat_byte(0xAB);
        p.note_failure("0xid", SigKind::Transfer, &anyhow::anyhow!("send claim: nonce too low"));
        assert_eq!(p.hash("0xid", SigKind::Transfer), None);

        let err: anyhow::Error = ReceiptTimeout { hash }.into();
        p.note_failure("0xid", SigKind::Transfer, &err);
        assert_eq!(p.hash("0xid", SigKind::Transfer), Some(hash));
        // ...and survives a `.context()` wrapper, as `try_*` may add one.
        let mut q = PendingTxs::default();
        let wrapped = anyhow::Error::from(ReceiptTimeout { hash }).context("claim");
        q.note_failure("0xid", SigKind::Transfer, &wrapped);
        assert_eq!(q.hash("0xid", SigKind::Transfer), Some(hash));
    }

    /// The state machine over the memo: Wait keeps the entry; Landed/Resubmit
    /// clear it, so the NEXT tick's `may_submit` is unconditional.
    #[test]
    fn apply_clears_the_memo_except_while_waiting() {
        let hash = B256::repeat_byte(0xCD);
        for (probe, action, still_tracked) in [
            (TxProbe::InMempool, PendingAction::Wait, true),
            (TxProbe::Unknown, PendingAction::Wait, true),
            (TxProbe::Gone, PendingAction::Resubmit, false),
            (TxProbe::Mined { reverted: true }, PendingAction::Resubmit, false),
            (TxProbe::Mined { reverted: false }, PendingAction::Landed, false),
        ] {
            let mut p = PendingTxs::default();
            p.track("0xid", SigKind::Cancel, hash);
            assert_eq!(p.apply("0xid", SigKind::Cancel, probe), action, "{probe:?}");
            assert_eq!(p.hash("0xid", SigKind::Cancel).is_some(), still_tracked, "{probe:?}");
        }
    }

    /// A claim and a cancel for the same id are separate in-flight txs.
    #[test]
    fn pending_is_keyed_by_kind_as_well_as_id() {
        let mut p = PendingTxs::default();
        p.track("0xid", SigKind::Transfer, B256::repeat_byte(1));
        assert_eq!(p.hash("0xid", SigKind::Cancel), None);
        p.track("0xid", SigKind::Cancel, B256::repeat_byte(2));
        assert_eq!(p.len(), 2);
        p.clear("0xid", SigKind::Transfer);
        assert_eq!(p.hash("0xid", SigKind::Cancel), Some(B256::repeat_byte(2)));
    }

    #[test]
    fn pending_entries_for_ids_that_left_the_queue_are_dropped() {
        let mut p = PendingTxs::default();
        p.track("0xgone", SigKind::Transfer, B256::repeat_byte(1));
        p.track("0xhere", SigKind::Refund, B256::repeat_byte(2));
        p.retain_seen(&["0xhere".to_string()].into_iter().collect());
        assert_eq!(p.len(), 1);
        assert_eq!(p.hash("0xhere", SigKind::Refund), Some(B256::repeat_byte(2)));
    }

    /// A record carrying nothing but forged signatures must not reach quorum.
    #[test]
    fn all_junk_yields_no_quorum() {
        let (j1, j2, j3) = (sig(0xAA), sig(0xBB), sig(0xCC));
        let kept = filter_members(resolved(&[(&j1, false), (&j2, false), (&j3, false)]), 3);
        assert!(kept.is_empty(), "no forged signature may count toward quorum");
    }

    // ---------------------------------------------------------------------
    // Unclaimable transfers must be VISIBLE.
    //
    // Both of these were found on a live testnet, and both presented the same
    // way: a transfer parked at READY with a full quorum and not one line in any
    // log. One was a corridor whose return path had never been registered
    // (`tokenOf == 0`); the other was a Solana->EVM transfer carrying a 32-byte
    // receiver. The keeper was skipping each silently, so "the corridor is
    // misconfigured" looked exactly like "the keeper is asleep".
    // ---------------------------------------------------------------------

    #[test]
    fn a_20_byte_receiver_is_decodable_and_a_32_byte_one_is_not() {
        // What `Gate._toAddress` accepts, and what it reverts BadReceiver on.
        assert!(evm_receiver_decodable("0xaDDd30479698216B0C2eE967cBC115917EeFE243"));
        assert!(evm_receiver_decodable("aDDd30479698216B0C2eE967cBC115917EeFE243"), "0x is optional");

        // A left-padded EVM address is the trap: it LOOKS like the right account
        // and is what a naive Solana->EVM send produces.
        assert!(!evm_receiver_decodable(
            "0x000000000000000000000000addd30479698216b0c2ee967cbc115917eefe243"
        ));
        // A genuine SPL token account.
        assert!(!evm_receiver_decodable(
            "0x6d15932c9d8a32313d2b4fa5a26d36bce1ca678ccb2dc670cc6762b489988dea"
        ));
        assert!(!evm_receiver_decodable("0x"), "an empty receiver is not an address");
    }

    /// THE property: say it once, not once per tick. A stranded transfer sits
    /// unclaimable for at least a whole refund timeout, and at a ~4s poll that is
    /// hundreds of identical lines that bury everything else.
    #[test]
    fn a_stranded_transfer_is_reported_once_not_every_tick() {
        let mut log = StrandedLog::default();
        assert!(log.should_report("0xabc"), "the first sighting must be reported");
        for tick in 0..50 {
            assert!(!log.should_report("0xabc"), "tick {tick} must stay quiet");
        }
    }

    /// ...but a transfer that RECOVERS and strands again is news a second time.
    /// Registering a missing corridor unsticks every transfer on it at once; if
    /// one of them strands again afterwards the operator has to hear about it.
    #[test]
    fn recovery_rearms_the_report() {
        let mut log = StrandedLog::default();
        assert!(log.should_report("0xabc"));
        assert!(!log.should_report("0xabc"));

        log.clear("0xabc"); // claimed, or found already executed
        assert!(log.should_report("0xabc"), "a later strand must be reported afresh");
    }

    /// The audit nit: a stranded transfer that is later CANCELLED leaves the work
    /// queue via the cancel branch, never via `clear`, so its entry lived for the
    /// life of the process. Retaining only the ids the queue returned this tick
    /// closes that — and re-arms the report if the same id ever strands again.
    #[test]
    fn a_cancelled_transfer_leaves_the_stranded_set() {
        let mut log = StrandedLog::default();
        assert!(log.should_report("0xcancelled"));
        assert!(log.should_report("0xstill_stuck"));
        assert_eq!(log.len(), 2);

        // Next tick: the queue no longer returns the cancelled one.
        log.retain_seen(&["0xstill_stuck".to_string()].into_iter().collect());
        assert_eq!(log.len(), 1);
        assert!(!log.should_report("0xstill_stuck"), "the one still queued stays quiet");
        assert!(log.should_report("0xcancelled"), "a fresh strand of a forgotten id is news");
    }

    #[test]
    fn submissions_are_tracked_independently() {
        let mut log = StrandedLog::default();
        assert!(log.should_report("0xaaa"));
        assert!(log.should_report("0xbbb"), "a different transfer is its own event");
        log.clear("0xaaa");
        assert!(!log.should_report("0xbbb"), "clearing one must not rearm another");
    }

    /// The three outcomes must stay distinguishable. They were once collapsed
    /// into `Option<String>`, which is what made "delivered" and "can never be
    /// delivered" the same value.
    #[test]
    fn the_outcomes_are_distinct() {
        assert_ne!(ClaimOutcome::AlreadyExecuted, ClaimOutcome::Stranded("x"));
        assert_ne!(
            ClaimOutcome::Submitted("0xtx".into()),
            ClaimOutcome::AlreadyExecuted
        );
        assert_ne!(ClaimOutcome::Stranded("a"), ClaimOutcome::Stranded("b"));
    }
}
