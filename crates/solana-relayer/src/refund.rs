//! Refund attestation for transfers that touch Solana at EITHER end.
//!
//! The two-phase refund needs someone to vouch, from on-chain facts, that a
//! stuck transfer may be burned and then repaid. `crates/validator`'s refund
//! loop does that for corridors whose both ends are EVM chains. This attester
//! covers the two corridors that have a Solana end:
//!
//!   * **EVM → Solana** (Solana is the DESTINATION). The burn/no-burn facts are
//!     read from the Solana `["executed", id]` marker. The AGE — "has this been
//!     unclaimed for the timeout?" — is read from the EVM SOURCE gate: `sentBy(id)`
//!     at a block that is provably `timeout_secs` old by that chain's own clock,
//!     exactly as `validator/src/refund.rs` does (its H-2 fix). Audit round 4
//!     (M-13) found this attester taking the age from the store's
//!     `refund_candidates()` nomination instead, which let anyone who could flip
//!     `refund_status` get validators to burn a fresh, deliverable transfer.
//!   * **Solana → EVM** (Solana is the SOURCE). Round 4's M-4: nothing attested
//!     these at all — the EVM validator skips a source it cannot read, and this
//!     process handled only Solana destinations — so a stuck Solana→EVM transfer
//!     was unrefundable. Now the burn facts come from the EVM DESTINATION gate
//!     (`executed`/`cancelled` at a confirmed block, over raw JSON-RPC in
//!     [`crate::evm`]) and the age from the Solana `["sent", id]` record's
//!     `locked_at`, measured against the cluster's Clock sysvar.
//!
//! ## The rules that never bend
//!
//!   * A transfer DELIVERED on its destination earns nothing. A refund on top of
//!     a claim is the double-spend the whole design exists to prevent.
//!   * A CANCEL is attested only once THIS process has shown, on-chain, that the
//!     transfer is older than the timeout. If it cannot show that — no reader for
//!     the source chain, no `[refund]` block, the chain too young — it does not
//!     vote. The store's word is never evidence.
//!   * A REFUND follows an observed burn, not a timer, so it needs no age check.
//!
//! Every read is at the commitment / confirmation depth the operator configured
//! for signing, because a rolled-back "not executed" would let us attest a burn
//! for a transfer that was in fact paid.

use std::collections::{BTreeMap, HashSet};
use std::str::FromStr;
use std::sync::Mutex;
use std::time::Duration;

use solana_client::nonblocking::rpc_client::RpcClient;
use solana_sdk::pubkey::Pubkey;
use tracing::{info, warn};

use crate::config::{RefundConfig, SourceChain};
use crate::evm::GateReader;
use crate::gate::{
    commitment, domain_id, hex32, sign, CANCEL_PREFIX, MARKER_CANCELLED, REFUND_PREFIX,
};
use crate::store::{SignerSig, Store};

/// What a DESTINATION gate says about a submission (either VM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DestinationState {
    /// The submission is spent there, one way or the other.
    pub executed: bool,
    /// …and it was BURNED rather than delivered.
    pub cancelled: bool,
}

/// What a SOURCE gate says about a submission (either VM).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourceState {
    /// The gate really locked funds for this id (Solana: a live `["sent", id]`
    /// record; EVM: `sentBy != 0`).
    pub sent: bool,
    /// Already paid back (Solana: the record was zeroed; EVM: `refunded`).
    pub refunded: bool,
}

/// What to do about one candidate.
#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    /// Destination is untouched and the transfer is provably aged — attest the burn.
    AttestCancel,
    /// Destination is burned — attest the payout.
    AttestRefund,
    Skip(&'static str),
}

/// Decide from on-chain facts alone. Split from the I/O so the safety rules are
/// unit-testable, exactly as the EVM loop does it.
///
/// * `src` is `None` when this process has no reader for the source chain. The
///   source-side checks guard against WASTED attestations, not against loss (the
///   source gate itself refuses `NotSent`/`AlreadyRefunded`), so a missing reader
///   does not block the refund leg — but it does block the cancel leg, through
///   `aged_out`.
/// * `aged_out` is this process's OWN on-chain answer to "has the unclaimed
///   timeout elapsed?": `Some(true)`/`Some(false)` when it could be established,
///   `None` when it could not. `None` never yields a cancel. This is M-13.
pub fn decide(
    src: Option<&SourceState>,
    dst: &DestinationState,
    aged_out: Option<bool>,
    already_attested_cancel: bool,
    already_attested_refund: bool,
) -> Decision {
    // THE safety rule. A delivered transfer must never earn a cancel or refund
    // attestation, whatever the store says about timeouts.
    if dst.executed && !dst.cancelled {
        return Decision::Skip("delivered on destination");
    }
    if let Some(src) = src {
        if src.refunded || !src.sent {
            return Decision::Skip("already refunded, or not sent from that gate");
        }
    }
    // A burn already on-chain is a settled fact — the refund leg follows the
    // destination, it does not re-litigate the timeout.
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
    match aged_out {
        None => Decision::Skip("unclaimed timeout cannot be verified on-chain; not attesting"),
        Some(false) => Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)"),
        Some(true) => Decision::AttestCancel,
    }
}

/// Pure Solana age rule (host-testable): has a transfer locked at cluster time
/// `locked_at` been unclaimed for `timeout_secs`, as of cluster time `now`?
///
/// Both timestamps come from the chain — `locked_at` from the `["sent", id]`
/// record `process_send` wrote, `now` from the Clock sysvar — never from this
/// host's wall clock, so a skewed validator cannot attest early.
pub fn solana_aged_out(locked_at: i64, now: i64, timeout_secs: i64) -> bool {
    // A record with no lock time (pre-round-4 layout, or a zeroed field) can
    // never be shown aged: fail closed.
    locked_at > 0 && now.saturating_sub(locked_at) >= timeout_secs
}

/// The Solana source record, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SolanaSourceRecord {
    pub state: SourceState,
    /// `locked_at` from the record; 0 when there is no live record.
    pub locked_at: i64,
}

/// Interpret a `["sent", id]` account (pure, host-testable). `owner_is_program`
/// and `data` come from a plain `getAccountInfo`.
pub fn solana_source_record(account: Option<(bool, &[u8])>) -> SolanaSourceRecord {
    use bridge_solana::relayer::decode_sent_record;

    let not_sent = SolanaSourceRecord { state: SourceState { sent: false, refunded: false }, locked_at: 0 };
    let Some((owner_is_program, data)) = account else { return not_sent };
    // Only a PDA the PROGRAM owns counts: anyone can park an account there.
    if !owner_is_program {
        return not_sent;
    }
    // Both the current and the pre-round-4 layout; the latter has no lock time,
    // so it decodes with `locked_at == 0` and can never be shown aged.
    let Some(rec) = decode_sent_record(data) else { return not_sent };
    // `process_refund` zeroes the record on payout.
    if rec.amount == 0 && rec.debridge_id == [0u8; 32] {
        return SolanaSourceRecord { state: SourceState { sent: true, refunded: true }, locked_at: 0 };
    }
    SolanaSourceRecord { state: SourceState { sent: true, refunded: false }, locked_at: rec.locked_at }
}

/// Read the Solana destination marker for a submission.
async fn solana_destination_state(
    rpc: &RpcClient,
    program_id: &Pubkey,
    id: &[u8; 32],
) -> anyhow::Result<DestinationState> {
    let (executed, _) = Pubkey::find_program_address(&[b"executed", id], program_id);
    let acct = rpc.get_account_with_commitment(&executed, rpc.commitment()).await?.value;
    Ok(match acct {
        // Only a PDA the PROGRAM owns counts. An account someone else parked at
        // that address proves nothing about this gate's state.
        Some(a) if a.owner == *program_id && !a.data.is_empty() => DestinationState {
            executed: true,
            cancelled: a.data[0] == MARKER_CANCELLED,
        },
        _ => DestinationState::default(),
    })
}

/// Read the Solana `["sent", id]` origin record.
async fn solana_source_state(
    rpc: &RpcClient,
    program_id: &Pubkey,
    id: &[u8; 32],
) -> anyhow::Result<SolanaSourceRecord> {
    let (sent, _) = Pubkey::find_program_address(&[b"sent", id], program_id);
    let acct = rpc.get_account_with_commitment(&sent, rpc.commitment()).await?.value;
    Ok(solana_source_record(acct.as_ref().map(|a| (a.owner == *program_id, a.data.as_slice()))))
}

/// The cluster's own notion of now, from the Clock sysvar at the signing
/// commitment.
async fn solana_now(rpc: &RpcClient) -> anyhow::Result<i64> {
    let acct = rpc
        .get_account_with_commitment(&solana_sdk::sysvar::clock::id(), rpc.commitment())
        .await?
        .value
        .ok_or_else(|| anyhow::anyhow!("clock sysvar missing"))?;
    let clock: solana_sdk::clock::Clock = solana_sdk::account::from_account(&acct)
        .ok_or_else(|| anyhow::anyhow!("clock sysvar does not decode"))?;
    Ok(clock.unix_timestamp)
}

pub struct Attester {
    rpc: RpcClient,
    program_id: Pubkey,
    chain_id: u64,
    secret: libsecp256k1::SecretKey,
    signer_address: String,
    poll: Duration,
    store: Store,
    /// `None` => no `[refund]` block: refunds only, never cancels.
    timeout_secs: Option<i64>,
    evm: BTreeMap<u64, GateReader>,
    /// Corridors already warned about (no reader / no timeout), so the log says
    /// it once per submission rather than every poll.
    warned: Mutex<HashSet<String>>,
}

impl Attester {
    pub fn new(
        cfg: &SourceChain,
        refund: Option<&RefundConfig>,
        secret_key: [u8; 32],
        signer_address: String,
        store: Store,
    ) -> anyhow::Result<Self> {
        let mut evm = BTreeMap::new();
        if let Some(r) = refund {
            for e in &r.evm {
                evm.insert(e.chain_id, GateReader::new(e)?);
            }
        }
        Ok(Attester {
            // Refund decisions release real funds, so read them at the same
            // commitment the scanner signs at — a rolled-back "not executed"
            // would let us attest a burn for a transfer that was in fact paid.
            rpc: RpcClient::new_with_commitment(cfg.rpc.clone(), commitment(&cfg.commitment)),
            program_id: Pubkey::from_str(&cfg.program_id)
                .map_err(|_| anyhow::anyhow!("program_id is not a valid pubkey"))?,
            chain_id: cfg.chain_id,
            secret: libsecp256k1::SecretKey::parse(&secret_key)
                .map_err(|_| anyhow::anyhow!("signer key is not a valid secp256k1 scalar"))?,
            signer_address,
            poll: Duration::from_millis(cfg.poll_interval_ms.max(1000)),
            store,
            timeout_secs: refund.map(|r| r.timeout_secs),
            evm,
            warned: Mutex::new(HashSet::new()),
        })
    }

    pub async fn run(self) -> anyhow::Result<()> {
        info!(
            validator = %self.signer_address,
            chain_id = self.chain_id,
            evm_readers = self.evm.len(),
            timeout_secs = ?self.timeout_secs,
            "solana refund attester started"
        );
        if self.timeout_secs.is_none() {
            warn!(
                "no [refund] block — this attester will vote REFUND for observed burns but \
                 NEVER cancel: a cancel needs an on-chain age proof (timeout_secs + an EVM \
                 reader for the source or destination gate)"
            );
        }
        loop {
            if let Err(e) = self.tick().await {
                warn!(error = %e, "refund attestation tick failed; retrying");
            }
            tokio::time::sleep(self.poll).await;
        }
    }

    fn warn_once(&self, key: String, msg: &str) {
        let mut seen = self.warned.lock().unwrap_or_else(|p| p.into_inner());
        if seen.insert(key.clone()) {
            warn!(submission_id = %key, "{msg}");
        }
    }

    async fn tick(&self) -> anyhow::Result<()> {
        for rec in self.store.refund_candidates().await? {
            let Ok(id) = hex32(&rec.submission_id) else { continue };

            let facts = if rec.chain_id_to == self.chain_id {
                self.evm_to_solana_facts(&rec.submission_id, &id, rec.chain_id_from).await
            } else if rec.chain_id_from == self.chain_id {
                self.solana_to_evm_facts(&rec.submission_id, &id, rec.chain_id_to).await
            } else {
                continue; // an EVM<->EVM corridor; the EVM validators own it
            };
            let Some((src, dst, aged_out)) = (match facts {
                Ok(f) => f,
                Err(e) => {
                    // Never guess. An unreadable chain means no vote.
                    warn!(submission_id = %rec.submission_id, error = %e, "cannot read chain state; not attesting");
                    continue;
                }
            }) else {
                continue;
            };

            let mine = |sigs: &[SignerSig]| {
                sigs.iter().any(|s| s.signer.eq_ignore_ascii_case(&self.signer_address))
            };
            let decision = decide(
                src.as_ref(),
                &dst,
                aged_out,
                mine(&rec.cancel_signatures),
                mine(&rec.refund_signatures),
            );

            let (kind, prefix) = match decision {
                Decision::AttestCancel => ("cancel", CANCEL_PREFIX),
                Decision::AttestRefund => ("refund", REFUND_PREFIX),
                Decision::Skip(reason) => {
                    tracing::debug!(submission_id = %rec.submission_id, reason, "no attestation");
                    continue;
                }
            };

            let signature = sign(&self.secret, &domain_id(prefix, &id));
            match self
                .store
                .post_attestation(&rec.submission_id, kind, &self.signer_address, &signature)
                .await
            {
                Ok(()) => info!(
                    submission_id = %rec.submission_id,
                    kind,
                    chain_from = rec.chain_id_from,
                    chain_to = rec.chain_id_to,
                    "ATTESTED"
                ),
                Err(e) => warn!(submission_id = %rec.submission_id, kind, error = %e, "attestation rejected"),
            }
        }
        Ok(())
    }

    /// Solana is the DESTINATION. Burn facts from the Solana marker; age (and the
    /// wasted-work guards) from the EVM source gate when we have a reader for it.
    async fn evm_to_solana_facts(
        &self,
        sid: &str,
        id: &[u8; 32],
        chain_id_from: u64,
    ) -> anyhow::Result<Option<(Option<SourceState>, DestinationState, Option<bool>)>> {
        let dst = solana_destination_state(&self.rpc, &self.program_id, id).await?;
        let (src, aged_out) = match (self.timeout_secs, self.evm.get(&chain_id_from)) {
            (Some(timeout), Some(reader)) => {
                let s = reader.source_state(id).await?;
                let aged = if dst.cancelled { None } else { Some(reader.aged_out(id, timeout).await?) };
                (Some(SourceState { sent: s.sent, refunded: s.refunded }), aged)
            }
            _ => {
                if !dst.cancelled {
                    self.warn_once(
                        sid.to_string(),
                        &format!(
                            "EVM->Solana candidate from chain {chain_id_from}: no [[refund.evm]] reader \
                             (or no [refund].timeout_secs) for the SOURCE gate, so its age cannot be \
                             verified on-chain — cancel will NOT be attested (M-13)"
                        ),
                    );
                }
                (None, None)
            }
        };
        Ok(Some((src, dst, aged_out)))
    }

    /// Solana is the SOURCE (M-4). Burn facts from the EVM destination gate —
    /// without a reader for it we cannot see the destination at all and must not
    /// vote — age from the Solana `["sent", id]` record against the cluster clock.
    async fn solana_to_evm_facts(
        &self,
        sid: &str,
        id: &[u8; 32],
        chain_id_to: u64,
    ) -> anyhow::Result<Option<(Option<SourceState>, DestinationState, Option<bool>)>> {
        let Some(reader) = self.evm.get(&chain_id_to) else {
            self.warn_once(
                sid.to_string(),
                &format!(
                    "Solana->EVM candidate to chain {chain_id_to}: no [[refund.evm]] reader for the \
                     DESTINATION gate, so neither cancel nor refund can be attested by this process"
                ),
            );
            return Ok(None);
        };
        let d = reader.destination_state(id).await?;
        let dst = DestinationState { executed: d.executed, cancelled: d.cancelled };
        let src = solana_source_state(&self.rpc, &self.program_id, id).await?;
        let aged_out = match self.timeout_secs {
            Some(timeout) if !dst.cancelled && src.state.sent && !src.state.refunded => {
                Some(solana_aged_out(src.locked_at, solana_now(&self.rpc).await?, timeout))
            }
            Some(_) => None,
            None => None,
        };
        Ok(Some((Some(src.state), dst, aged_out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered() -> DestinationState {
        DestinationState { executed: true, cancelled: false }
    }
    fn burned() -> DestinationState {
        DestinationState { executed: true, cancelled: true }
    }
    fn untouched() -> DestinationState {
        DestinationState::default()
    }
    fn live_source() -> SourceState {
        SourceState { sent: true, refunded: false }
    }
    /// This process verified, on-chain, that the timeout has elapsed.
    const AGED: Option<bool> = Some(true);
    const FRESH: Option<bool> = Some(false);
    const UNKNOWN: Option<bool> = None;

    /// THE rule. A delivered transfer must never earn either attestation — a
    /// refund on top of a claim is the double-spend the two-phase design exists
    /// to prevent, and no timeout or store state may override an on-chain payout.
    #[test]
    fn a_delivered_transfer_is_never_attested() {
        for (c, r) in [(false, false), (true, false), (false, true), (true, true)] {
            for aged in [AGED, FRESH, UNKNOWN] {
                assert_eq!(
                    decide(Some(&live_source()), &delivered(), aged, c, r),
                    Decision::Skip("delivered on destination")
                );
                assert_eq!(decide(None, &delivered(), aged, c, r), Decision::Skip("delivered on destination"));
            }
        }
    }

    #[test]
    fn an_untouched_destination_earns_a_cancel_once_aged_on_chain() {
        assert_eq!(decide(Some(&live_source()), &untouched(), AGED, false, false), Decision::AttestCancel);
        assert_eq!(decide(None, &untouched(), AGED, false, false), Decision::AttestCancel);
    }

    /// THE M-13 rule. Appearing on the store's candidate list is not evidence of
    /// anything: until THIS process has established the age on-chain, it will not
    /// burn a transfer the keeper may still be about to deliver.
    #[test]
    fn a_store_nomination_alone_never_authorises_a_cancel() {
        assert_eq!(
            decide(Some(&live_source()), &untouched(), FRESH, false, false),
            Decision::Skip("unclaimed timeout has not elapsed (verified on-chain)")
        );
        // The same candidate becomes attestable once it has genuinely aged.
        assert_eq!(decide(Some(&live_source()), &untouched(), AGED, false, false), Decision::AttestCancel);
    }

    /// No reader for the source chain => the age is unknowable => no cancel. A
    /// process that cannot verify does not vote, whatever the store says.
    #[test]
    fn an_unverifiable_age_never_authorises_a_cancel() {
        assert_eq!(
            decide(None, &untouched(), UNKNOWN, false, false),
            Decision::Skip("unclaimed timeout cannot be verified on-chain; not attesting")
        );
        assert_eq!(
            decide(Some(&live_source()), &untouched(), UNKNOWN, false, false),
            Decision::Skip("unclaimed timeout cannot be verified on-chain; not attesting")
        );
    }

    /// The finding's actual attack: a DB that flags everything eligible the
    /// moment it is created must not be able to force a fleet-wide cancel of
    /// healthy in-flight transfers.
    #[test]
    fn a_compromised_store_cannot_shorten_the_window() {
        for already_cancel in [false, true] {
            for aged in [FRESH, UNKNOWN] {
                let d = decide(Some(&live_source()), &untouched(), aged, already_cancel, false);
                assert!(matches!(d, Decision::Skip(_)), "a not-yet-aged transfer must never be cancelled, got {d:?}");
            }
        }
    }

    /// Refund follows an on-chain burn rather than a timer, so it does not
    /// re-check the age — and it does not need a source reader either: the source
    /// gate itself refuses `NotSent`/`AlreadyRefunded`, so the worst case without
    /// one is a wasted attestation. This is what lets the EVM validators and this
    /// process each vote REFUND for a Solana->EVM burn (M-4).
    #[test]
    fn a_burned_destination_earns_a_refund_without_an_age_check_or_source_reader() {
        assert_eq!(decide(Some(&live_source()), &burned(), FRESH, true, false), Decision::AttestRefund);
        assert_eq!(decide(None, &burned(), UNKNOWN, false, false), Decision::AttestRefund);
    }

    #[test]
    fn refund_requires_the_burn_to_be_on_chain_first() {
        assert_eq!(
            decide(Some(&live_source()), &untouched(), AGED, true, false),
            Decision::Skip("cancel already attested by us")
        );
        assert_eq!(decide(Some(&live_source()), &burned(), AGED, true, false), Decision::AttestRefund);
    }

    #[test]
    fn we_do_not_re_attest_our_own_vote() {
        assert_eq!(
            decide(Some(&live_source()), &untouched(), AGED, true, false),
            Decision::Skip("cancel already attested by us")
        );
        assert_eq!(
            decide(Some(&live_source()), &burned(), AGED, false, true),
            Decision::Skip("refund already attested by us")
        );
    }

    /// Source-side guards, when a reader exists: already repaid, or never locked
    /// there at all (a forged candidate), earn nothing.
    #[test]
    fn a_refunded_or_never_sent_source_earns_nothing() {
        let repaid = SourceState { sent: true, refunded: true };
        let ghost = SourceState { sent: false, refunded: false };
        for src in [repaid, ghost] {
            for dst in [untouched(), burned()] {
                assert!(matches!(decide(Some(&src), &dst, AGED, false, false), Decision::Skip(_)));
            }
        }
    }

    /// A marker PDA owned by anyone but the program proves nothing — treating it
    /// as state would let a squatter fake "delivered" and block a legitimate
    /// refund forever.
    #[test]
    fn only_a_program_owned_marker_counts() {
        let foreign = DestinationState::default();
        assert!(!foreign.executed, "a non-program-owned account is not state");
        assert_eq!(decide(Some(&live_source()), &foreign, AGED, false, false), Decision::AttestCancel);
    }

    // --- the Solana age rule (M-4 / M-13) -----------------------------------

    #[test]
    fn solana_age_is_measured_in_cluster_time() {
        let locked = 1_700_000_000;
        assert!(!solana_aged_out(locked, locked + 3599, 3600), "one second short is short");
        assert!(solana_aged_out(locked, locked + 3600, 3600));
        assert!(solana_aged_out(locked, locked + 999_999, 3600));
        // A clock that appears to run backwards (or a record from the future)
        // is never "aged".
        assert!(!solana_aged_out(locked, locked - 1, 3600));
    }

    /// A record with no lock time — the pre-round-4 layout, or a zeroed field —
    /// cannot be shown aged. Fail closed rather than treat 0 as "1970, so
    /// ancient".
    #[test]
    fn a_record_without_a_lock_time_is_never_aged() {
        assert!(!solana_aged_out(0, 1_700_000_000, 3600));
        assert!(!solana_aged_out(-5, 1_700_000_000, 3600));
    }

    // --- the ["sent", id] record interpretation -----------------------------

    fn record_bytes(amount: u64, locked_at: i64) -> Vec<u8> {
        use borsh::BorshSerialize;
        let rec = bridge_solana::relayer::SentRecord {
            debridge_id: if amount == 0 { [0u8; 32] } else { [9u8; 32] },
            sender: [1u8; 32],
            source_token: [2u8; 32],
            mint: [3u8; 32],
            amount,
            locked_at,
        };
        let mut out = Vec::new();
        rec.serialize(&mut out).unwrap();
        out
    }

    #[test]
    fn a_live_sent_record_is_sent_and_carries_its_lock_time() {
        let data = record_bytes(500, 1_700_000_000);
        let r = solana_source_record(Some((true, &data)));
        assert_eq!(r.state, SourceState { sent: true, refunded: false });
        assert_eq!(r.locked_at, 1_700_000_000);
    }

    /// `process_refund` zeroes the record on payout: that is "refunded", and it
    /// must not be mistaken for "never sent" (which would be a forged candidate)
    /// nor for a live record.
    #[test]
    fn a_zeroed_sent_record_is_refunded() {
        let zeroed = vec![0u8; bridge_solana::relayer::SENT_RECORD_LEN];
        let r = solana_source_record(Some((true, &zeroed)));
        assert_eq!(r.state, SourceState { sent: true, refunded: true });
        assert_eq!(r.locked_at, 0);
    }

    /// A record from before the upgrade proves the lock but not WHEN: it is
    /// `sent`, and its age can never be shown, so it earns a refund (after an
    /// observed burn) but never a cancel from this process.
    #[test]
    fn a_legacy_record_is_sent_but_never_aged() {
        let data = record_bytes(500, 1_700_000_000);
        let legacy = &data[..bridge_solana::relayer::LEGACY_SENT_RECORD_LEN];
        let r = solana_source_record(Some((true, legacy)));
        assert_eq!(r.state, SourceState { sent: true, refunded: false });
        assert_eq!(r.locked_at, 0);
        assert!(!solana_aged_out(r.locked_at, i64::MAX, 1), "unknown lock time is never aged");
    }

    /// No account, a foreign-owned account, or a wrong-sized one: this gate never
    /// sent it. Only program-owned state of a known layout is evidence.
    #[test]
    fn missing_foreign_or_malformed_records_are_not_sent() {
        let data = record_bytes(500, 1_700_000_000);
        for account in [None, Some((false, data.as_slice())), Some((true, &data[..data.len() - 9]))] {
            let r = solana_source_record(account);
            assert_eq!(r.state, SourceState { sent: false, refunded: false });
            assert_eq!(r.locked_at, 0);
        }
    }
}
