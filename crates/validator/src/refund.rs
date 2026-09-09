//! Refund attestation loop — the off-chain half of the two-phase refund.
//!
//! A transfer can strand: the destination gate may have no liquidity for the
//! asset, the corridor may be de-listed after the funds were locked, or the
//! target chain may be down long enough that nobody ever claims. The locked
//! funds have to be recoverable, but a refund that merely waits out a timeout is
//! a double-spend — the transfer's claim signatures still exist, so a keeper can
//! deliver on the destination in the same window the source pays the refund.
//!
//! So the refund is ordered, and this loop is what enforces the ordering:
//!
//!   1. The transfer is unclaimed past the timeout, and the DESTINATION gate
//!      still reports `executed == false`. Attest a **cancel**.
//!   2. A keeper submits `cancel()` there, permanently burning the transfer —
//!      `claim()` can never succeed for it again.
//!   3. Only once the destination reports `cancelled == true` do we attest a
//!      **refund**.
//!
//! Step 3 is the load-bearing one. The source gate cannot read the destination,
//! so nothing on-chain stops a refund quorum from paying out early — the
//! guarantee is that this quorum never forms until the burn is an observed
//! on-chain fact. Which is the same trust assumption the bridge already makes
//! for `Sent`: validators attest to what they independently read on a chain.
//!
//! Every decision below is made from on-chain reads at a confirmed block. The
//! store's `refund_status`/timeout only *nominates* candidates; it never
//! authorises anything, so a wrong or manipulated timestamp there can at most
//! cause a wasted look.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::Duration;

use alloy::eips::BlockNumberOrTag;
use alloy::primitives::{Address, B256};
use alloy::providers::{DynProvider, Provider};
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use anyhow::Context;
use bridge_core::abi::Gate;
use bridge_core::backend::StoreBackend;
use bridge_core::signer::encode_signature;
use bridge_core::store::{SigKind, SignerSig, SubmissionRecord};
use tracing::{info, warn};

use crate::config::RefundConfig;
use crate::provider;

/// One chain this validator can independently read gate state from.
struct GateReader {
    chain_id: u64,
    gate: Address,
    provider: DynProvider,
    block_confirmation: u64,
}

impl GateReader {
    async fn connect(
        chain_id: u64,
        gate: &str,
        endpoints: &[String],
        block_confirmation: u64,
    ) -> anyhow::Result<Self> {
        let provider = provider::connect_checked(endpoints, chain_id).await?;
        Ok(GateReader {
            chain_id,
            gate: gate.parse().context("bad gate address")?,
            provider,
            block_confirmation,
        })
    }

    /// The newest block we are willing to trust. Reading `executed` at the chain
    /// tip would let a reorg make a claimed transfer look unclaimed — and this
    /// loop would then attest a cancel for a transfer that was actually paid.
    async fn confirmed_block(&self) -> anyhow::Result<u64> {
        let latest = self.provider.get_block_number().await?;
        Ok(latest.saturating_sub(self.block_confirmation))
    }

    /// Destination-side view of a submission at a confirmed block.
    async fn destination_state(&self, id: B256) -> anyhow::Result<DestinationState> {
        let block = self.confirmed_block().await?;
        let at = BlockNumberOrTag::Number(block).into();
        let gate = Gate::new(self.gate, &self.provider);
        Ok(DestinationState {
            executed: gate.executed(id).block(at).call().await?,
            cancelled: gate.cancelled(id).block(at).call().await?,
        })
    }

    /// Source-side view: who locked the funds (zero once refunded or if this gate
    /// never emitted the id at all), and whether it has already been paid back.
    async fn source_state(&self, id: B256) -> anyhow::Result<SourceState> {
        let block = self.confirmed_block().await?;
        let at = BlockNumberOrTag::Number(block).into();
        let gate = Gate::new(self.gate, &self.provider);
        Ok(SourceState {
            sent_by: gate.sentBy(id).block(at).call().await?,
            refunded: gate.refunded(id).block(at).call().await?,
        })
    }

    /// A block that is provably at least `timeout_secs` old, measured against the
    /// chain's OWN head timestamp rather than our wall clock (a validator with a
    /// skewed clock must not be able to attest early, and block timestamps are
    /// what the chain actually agrees on).
    ///
    /// Conservative by construction: any block old enough will do, so we step back
    /// exponentially until the timestamp condition holds rather than binary-
    /// searching for the newest such block. Overshooting only makes the effective
    /// timeout longer, which is the safe direction. Typically one or two calls,
    /// because block times are stable.
    ///
    /// `Ok(None)` means the chain has no block that old yet (a fresh dev chain),
    /// in which case nothing may be attested.
    async fn aged_block(&self, timeout_secs: i64) -> anyhow::Result<Option<u64>> {
        let head_num = self.confirmed_block().await?;
        let head = self
            .provider
            .get_block_by_number(BlockNumberOrTag::Number(head_num))
            .await?
            .context("confirmed head block vanished")?;
        let target = (head.header.timestamp as i64).saturating_sub(timeout_secs);

        // Start from a 12s/block estimate, then double until we are far enough
        // back. Bounded so a pathological chain cannot spin here.
        let mut step: u64 = ((timeout_secs.max(1) as u64) / 12).max(1);
        for _ in 0..24 {
            let Some(candidate) = head_num.checked_sub(step) else { return Ok(None) };
            let block = self
                .provider
                .get_block_by_number(BlockNumberOrTag::Number(candidate))
                .await?
                .context("candidate block vanished")?;
            if (block.header.timestamp as i64) <= target {
                return Ok(Some(candidate));
            }
            step = step.saturating_mul(2);
        }
        Ok(None)
    }

    /// Was `id` already locked on this gate as of `block`?
    ///
    /// `sentBy` is written by `send` in the same transaction that locks the funds,
    /// so a non-zero value at a historical height is the chain's own statement
    /// that the deposit existed by then. Reading it at an aged block is therefore
    /// an *authenticated* age check — no timestamp from the store, no schema
    /// change, one `eth_call`.
    async fn was_sent_by_block(&self, id: B256, block: u64) -> anyhow::Result<bool> {
        let at = BlockNumberOrTag::Number(block).into();
        let gate = Gate::new(self.gate, &self.provider);
        Ok(gate.sentBy(id).block(at).call().await? != Address::ZERO)
    }
}

struct DestinationState {
    executed: bool,
    cancelled: bool,
}

struct SourceState {
    sent_by: Address,
    refunded: bool,
}

/// What this validator should do about one candidate, after reading both chains.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Destination is unclaimed and past the timeout — attest the burn.
    AttestCancel,
    /// Destination is burned — attest the payout.
    AttestRefund,
    /// Nothing to do (delivered, already refunded, already attested by us, or a
    /// chain we don't watch). Carries a reason for the log.
    Skip(&'static str),
}

/// Decide from on-chain facts alone. Split out from the I/O so the safety rules
/// are unit-testable.
///
/// `aged_out` is this validator's OWN answer to "has the unclaimed timeout
/// elapsed?", derived from `sentBy` at a historical block (see
/// [`GateReader::was_sent_by_block`]) — never from the store's `refund_status`.
///
/// ## Why the timeout has to be checked here (finding H-2)
///
/// The store only nominates candidates: `sweep_refund_eligible` flips
/// `refund_status` to `'eligible'` after `refund_timeout_secs`. This loop used to
/// treat "it is on the candidate list" as "the timeout has elapsed", so the
/// entire unclaimed-timeout rested on a database column — a value no validator
/// verified, and one the module docs wrongly described as unable to authorise
/// anything.
///
/// It authorised plenty: a wrong `created_at`, clock skew, a misconfigured sweep
/// interval, or write access to the DB nominates healthy in-flight transfers, and
/// within one poll interval the validators attest cancels for all of them.
/// `cancel` is irreversible and permanently forecloses the payout, so that turns
/// a DB fault into a fleet-wide forced-refund of everything in flight.
///
/// The destination check (`executed == false`) never stopped it, because a
/// transfer that is merely *in flight* has not been claimed yet either — that is
/// precisely the window an early cancel steals.
///
/// ## A source this validator cannot read (audit round 4, M-4)
///
/// `src` is `None` when there is no reader for `chain_id_from` — today that means
/// the source is Solana, which no EVM validator can read. The CANCEL leg is then
/// impossible here, because the age can only be established on the source, and
/// `aged_out` MUST be `false` for such a candidate (the caller guarantees it;
/// this function refuses regardless). The REFUND leg is different: it follows a
/// burn this validator observed on a destination it CAN read, at a confirmed
/// block, and the source-side checks it skips (`sentBy`, `refunded`) only guard
/// against a wasted attestation — the Solana program's `process_refund` refuses
/// `NotSent` and a spent record on-chain. Skipping refunds too, as this loop
/// used to (`return` on a missing source reader), left every stuck Solana→EVM
/// transfer unrefundable.
fn decide(
    src: Option<&SourceState>,
    dst: &DestinationState,
    aged_out: bool,
    already_attested_cancel: bool,
    already_attested_refund: bool,
) -> Decision {
    // The destination was DELIVERED. Never attest anything: a refund on top of a
    // claim is the double-spend this whole design exists to prevent.
    if dst.executed && !dst.cancelled {
        return Decision::Skip("delivered on destination");
    }
    match src {
        // Source has already paid it back.
        Some(src) if src.refunded || src.sent_by == Address::ZERO => {
            return Decision::Skip("already refunded, or not sent from this gate");
        }
        Some(_) => {}
        // No source reader: only the refund leg can proceed (see above).
        None if !dst.cancelled => {
            return Decision::Skip("source chain unreadable — cancel cannot be attested here");
        }
        None => {}
    }
    // A burn that is already on-chain is a settled fact — the refund leg does not
    // re-litigate the timeout, it only follows the destination.
    if dst.cancelled {
        return if already_attested_refund {
            Decision::Skip("refund already attested by us")
        } else {
            Decision::AttestRefund
        };
    }
    if already_attested_cancel {
        return Decision::Skip("cancel already attested by us");
    }
    // Burning a transfer the keeper may still be about to deliver is not ours to
    // do until the window we independently verified has actually passed.
    if !aged_out {
        return Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)");
    }
    Decision::AttestCancel
}

/// Poll the store for stuck transfers and attest cancels/refunds for them.
pub async fn run(
    cfg: RefundConfig,
    sources: Vec<(u64, String, Vec<String>)>, // (chain_id, gate, endpoints)
    signer: PrivateKeySigner,
    sink: std::sync::Arc<StoreBackend>,
) -> anyhow::Result<()> {
    let signer_addr = signer.address();
    let retry = Duration::from_millis(cfg.poll_interval_ms.max(1000));

    // Connect every chain up front. A validator that cannot read a chain must not
    // vote on transfers touching it, so we don't paper over a bad endpoint — but a
    // transient RPC hiccup at startup must not permanently kill the loop (it would
    // stay dead until the process is bounced, stranding refunds). Retry connect,
    // exactly as the transfer scanner does.
    let connect = |chain_id: u64, gate: String, endpoints: Vec<String>| async move {
        loop {
            match GateReader::connect(chain_id, &gate, &endpoints, cfg.block_confirmation).await {
                Ok(reader) => break reader,
                Err(e) => {
                    warn!(chain_id, error = %e, "refund loop: connecting RPC failed; retrying");
                    tokio::time::sleep(retry).await;
                }
            }
        }
    };

    let mut source_readers: BTreeMap<u64, GateReader> = BTreeMap::new();
    for (chain_id, gate, endpoints) in &sources {
        source_readers.insert(*chain_id, connect(*chain_id, gate.clone(), endpoints.clone()).await);
    }

    let mut dest_readers: BTreeMap<u64, GateReader> = BTreeMap::new();
    for dest in &cfg.destinations {
        let endpoints = dest.endpoints()?;
        dest_readers.insert(dest.chain_id, connect(dest.chain_id, dest.gate.clone(), endpoints).await);
    }

    info!(
        validator = %signer_addr,
        sources = source_readers.len(),
        destinations = dest_readers.len(),
        timeout_secs = cfg.timeout_secs,
        "refund attestation loop started"
    );

    loop {
        let candidates = match sink.refund_candidates().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "fetching refund candidates failed; retrying");
                tokio::time::sleep(retry).await;
                continue;
            }
        };

        for rec in candidates {
            if let Err(e) = handle_candidate(
                &rec,
                &source_readers,
                &dest_readers,
                &signer,
                signer_addr,
                &sink,
                cfg.timeout_secs,
            )
            .await
            {
                warn!(submission_id = %rec.submission_id, error = %e, "refund attestation failed");
            }
        }

        tokio::time::sleep(Duration::from_millis(cfg.poll_interval_ms)).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_candidate(
    rec: &SubmissionRecord,
    source_readers: &BTreeMap<u64, GateReader>,
    dest_readers: &BTreeMap<u64, GateReader>,
    signer: &PrivateKeySigner,
    signer_addr: Address,
    sink: &StoreBackend,
    timeout_secs: i64,
) -> anyhow::Result<()> {
    // The DESTINATION must be readable: whether a transfer was delivered is the
    // one fact no attestation may take from the store. A destination we cannot
    // read is a corridor we do not vote on.
    let Some(dst) = dest_readers.get(&rec.chain_id_to) else { return Ok(()) };
    // The SOURCE may be unreadable (round 4, M-4: a Solana source). Then only the
    // refund leg is possible — `decide` enforces that — and the age is never
    // claimed: `aged_out` stays false.
    let src = source_readers.get(&rec.chain_id_from);

    let id = B256::from_str(&rec.submission_id).context("bad submission_id")?;

    let dst_state = dst.destination_state(id).await.context("reading destination gate")?;
    let src_state = match src {
        Some(s) => Some(s.source_state(id).await.context("reading source gate")?),
        None => None,
    };

    // H-2: establish the unclaimed timeout OURSELVES, from the source chain, and
    // never from the store's nomination. Only needed on the cancel leg — once the
    // destination is burned the refund follows an on-chain fact, not a timer — so
    // skip the reads when they cannot change the outcome.
    let aged_out = match (src, dst_state.cancelled) {
        (_, true) => true,
        (None, false) => false, // cannot be shown; `decide` skips the cancel anyway
        (Some(src), false) => {
            match src.aged_block(timeout_secs).await.context("locating an aged source block")? {
                Some(block) => src
                    .was_sent_by_block(id, block)
                    .await
                    .context("reading historical sentBy")?,
                // The chain has no block old enough yet: nothing can have aged out.
                None => false,
            }
        }
    };

    let mine = |sigs: &[SignerSig]| sigs.iter().any(|s| s.signer.eq_ignore_ascii_case(&format!("{signer_addr:#x}")));
    let decision = decide(
        src_state.as_ref(),
        &dst_state,
        aged_out,
        mine(&rec.cancel_signatures),
        mine(&rec.refund_signatures),
    );

    let kind = match decision {
        Decision::Skip(reason) => {
            tracing::debug!(submission_id = %rec.submission_id, reason, "no attestation");
            return Ok(());
        }
        Decision::AttestCancel => SigKind::Cancel,
        Decision::AttestRefund => SigKind::Refund,
    };

    let digest = kind.digest(id);
    let sig = signer.sign_message(digest.as_slice()).await?;
    let sig = SignerSig {
        signer: format!("{signer_addr:#x}"),
        signature: encode_signature(&sig),
    };

    sink.upsert_attestation(&rec.submission_id, kind, sig).await?;

    info!(
        submission_id = %rec.submission_id,
        kind = kind.as_str(),
        chain_from = rec.chain_id_from,
        chain_to = rec.chain_id_to,
        source_readable = src.is_some(),
        dest_chain = dst.chain_id,
        "ATTESTED"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sender() -> Address {
        Address::repeat_byte(0x11)
    }

    fn src(refunded: bool) -> SourceState {
        SourceState { sent_by: sender(), refunded }
    }

    /// This validator verified, on-chain, that the unclaimed timeout has elapsed.
    const AGED: bool = true;

    #[test]
    fn never_attests_a_delivered_transfer() {
        // THE safety rule. A claimed transfer must never earn a cancel or refund
        // attestation, whatever the store says about timeouts.
        let dst = DestinationState { executed: true, cancelled: false };
        assert!(matches!(decide(Some(&src(false)), &dst, AGED, false, false), Decision::Skip(_)));
    }

    #[test]
    fn attests_cancel_when_destination_is_untouched_and_aged_out() {
        let dst = DestinationState { executed: false, cancelled: false };
        assert_eq!(decide(Some(&src(false)), &dst, AGED, false, false), Decision::AttestCancel);
    }

    /// THE H-2 rule. Appearing on the store's candidate list is not evidence of
    /// anything: the validator establishes the age itself against the source
    /// chain, and until that passes it will not burn a transfer the keeper may
    /// still be about to deliver.
    #[test]
    fn never_attests_a_cancel_before_the_timeout_it_verified_itself() {
        let untouched = DestinationState { executed: false, cancelled: false };
        assert_eq!(
            decide(Some(&src(false)), &untouched, false, false, false),
            Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)"),
            "a store nomination alone must not authorise a burn"
        );
        // The same candidate becomes attestable once it has genuinely aged.
        assert_eq!(
            decide(Some(&src(false)), &untouched, AGED, false, false),
            Decision::AttestCancel
        );
    }

    /// The finding's actual attack: a DB that flags everything eligible the moment
    /// it is created must not be able to force a fleet-wide cancel of healthy
    /// in-flight transfers. Note the destination check never caught this — an
    /// in-flight transfer is unclaimed too, which is exactly the window a
    /// premature cancel steals.
    #[test]
    fn a_compromised_store_cannot_shorten_the_window() {
        let in_flight = DestinationState { executed: false, cancelled: false };
        for already_cancel in [false, true] {
            let d = decide(Some(&src(false)), &in_flight, false, already_cancel, false);
            assert!(
                matches!(d, Decision::Skip(_)),
                "a not-yet-aged transfer must never be cancelled, got {d:?}"
            );
        }
    }

    /// The refund leg follows an on-chain burn rather than a timer, so it does not
    /// re-check the age: by then the destination is provably foreclosed.
    #[test]
    fn a_burned_destination_still_earns_a_refund_without_an_age_check() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(decide(Some(&src(false)), &burned, false, true, false), Decision::AttestRefund);
    }

    #[test]
    fn attests_refund_only_after_the_burn_is_on_chain() {
        let untouched = DestinationState { executed: false, cancelled: false };
        assert_eq!(
            decide(Some(&src(false)), &untouched, AGED, true, false),
            Decision::Skip("cancel already attested by us")
        );

        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(decide(Some(&src(false)), &burned, AGED, true, false), Decision::AttestRefund);
    }

    #[test]
    fn stops_once_the_source_has_paid_out() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert!(matches!(decide(Some(&src(true)), &burned, AGED, true, true), Decision::Skip(_)));
    }

    #[test]
    fn refuses_a_submission_this_gate_never_sent() {
        // A quorum must not form for a transfer that was never locked here.
        let burned = DestinationState { executed: true, cancelled: true };
        let ghost = SourceState { sent_by: Address::ZERO, refunded: false };
        assert!(matches!(decide(Some(&ghost), &burned, AGED, false, false), Decision::Skip(_)));
    }

    #[test]
    fn does_not_re_attest() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(
            decide(Some(&src(false)), &burned, AGED, true, true),
            Decision::Skip("refund already attested by us")
        );
    }

    // --- an unreadable source (round 4, M-4: Solana-origin transfers) --------

    /// THE M-4 fix. This validator can read the EVM destination but not the
    /// Solana source. It used to return before deciding anything, so a burned
    /// Solana->EVM transfer never collected refund attestations from the EVM
    /// validators and stayed stuck. A burn observed at a confirmed block is
    /// enough for the refund leg; the source gate enforces the rest on-chain.
    #[test]
    fn a_burn_on_a_readable_destination_earns_a_refund_even_without_a_source_reader() {
        let burned = DestinationState { executed: true, cancelled: true };
        assert_eq!(decide(None, &burned, false, false, false), Decision::AttestRefund);
        assert_eq!(
            decide(None, &burned, false, false, true),
            Decision::Skip("refund already attested by us")
        );
    }

    /// The cancel leg needs the age, and the age lives on the source. No reader
    /// => no cancel, however the candidate was nominated and even if the caller
    /// somehow passed `aged_out = true`.
    #[test]
    fn no_source_reader_never_yields_a_cancel() {
        let untouched = DestinationState { executed: false, cancelled: false };
        for aged in [false, true] {
            for already in [false, true] {
                assert_eq!(
                    decide(None, &untouched, aged, already, false),
                    Decision::Skip("source chain unreadable — cancel cannot be attested here")
                );
            }
        }
    }

    /// Delivered stays delivered, reader or not.
    #[test]
    fn a_delivered_transfer_is_never_attested_without_a_source_reader_either() {
        let delivered = DestinationState { executed: true, cancelled: false };
        assert!(matches!(decide(None, &delivered, true, false, false), Decision::Skip(_)));
    }
}
