//! Off-chain relayer adapters for the Solana leg.
//!
//! Two directions, two adapters:
//!   * **Solana → EVM (source):** a Solana gate program emits its `Sent` event as
//!     a tagged program log; the validator's Solana source scans transaction logs
//!     for [`SENT_LOG_TAG`], parses it back into a [`Sent`], recomputes the id and
//!     signs — the same path the EVM source already runs.
//!   * **EVM → Solana (sink):** the keeper builds a Borsh `Claim` instruction
//!     ([`build_claim_instruction`]) — signatures sorted ascending by signer, as
//!     the gate requires — and submits it to the Solana program.
//!
//! The wire fields here are hex/decimal strings, matching the off-chain
//! `SubmissionRecord` shape, so a Solana-origin transfer drops straight into the
//! existing sig-store / keeper machinery.

use base64::Engine as _;
use borsh::{BorshDeserialize, BorshSerialize};

use crate::gate::Sent;
use crate::hash::AutoParams;
use crate::instruction::AutoParamsWire;
#[cfg(feature = "recover")]
use crate::instruction::{ClaimArgs, GateInstruction};
#[cfg(feature = "recover")]
use crate::verify::{eth_signed_digest, recover_evm_address};

/// First field of the Solana gate's `Sent` program-data event — lets the
/// validator's Solana source pick our event out of a transaction's program data.
/// Kept as the historical `BRIDGE_SENT` bytes so existing tooling recognises it.
pub const SENT_EVENT_TAG: &[u8] = b"BRIDGE_SENT";

/// Wire-format version of [`SentEvent`]. Bump on any layout change so a decoder
/// can reject an event it wasn't built to read instead of silently misreading it.
pub const SENT_EVENT_VERSION: u8 = 1;

/// The line prefix Solana's runtime prints for `sol_log_data(...)` — the program
/// emits its `Sent` event through that syscall, so this is where we find it.
pub const PROGRAM_DATA_PREFIX: &str = "Program data:";

/// Back-compat alias for the human-readable tag (the string form of
/// [`SENT_EVENT_TAG`]). Retained so older references keep resolving.
pub const SENT_LOG_TAG: &str = "BRIDGE_SENT";

/// The single, versioned on-chain `Sent` event — finding H5.
///
/// PROBLEM (H5): the deployed program emitted `sol_log_data([b"BRIDGE_SENT", id
/// || debridge_id])` (two hash-bound fields, binary), while the off-chain relayer
/// looked for a *text* line `BRIDGE_SENT {json}` carrying the *whole* transfer.
/// Neither the framing nor the field set matched, so Solana→EVM scanning could
/// never work and a validator could not reconstruct the submissionId.
///
/// FIX: one Borsh struct, versioned, carrying every field the submissionId hashes
/// over **plus the locked asset identity** (`mint`), emitted via `sol_log_data`
/// and decoded from the real `Program data:` base64 line. The program
/// (`crates/solana-gate`) mirrors this exact layout byte-for-byte; the round-trip
/// through the genuine log framing is tested here (see `tests`/`e2e.rs`).
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SentEvent {
    /// [`SENT_EVENT_VERSION`]; a decoder rejects anything it doesn't understand.
    pub version: u8,
    pub submission_id: [u8; 32],
    pub debridge_id: [u8; 32],
    /// The locked SPL mint on the Solana side — the asset identity bound to the
    /// transfer (a validator/relayer can check it against the debridgeId).
    pub mint: [u8; 32],
    pub amount: u64,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: Vec<u8>,
    pub native_sender: Vec<u8>,
    pub auto: Option<AutoParamsWire>,
}

impl SentEvent {
    /// Build the event a source-side `send` emits. `mint` is the locked SPL mint.
    pub fn from_sent(s: &Sent, mint: [u8; 32]) -> Self {
        SentEvent {
            version: SENT_EVENT_VERSION,
            submission_id: s.submission_id,
            debridge_id: s.debridge_id,
            mint,
            amount: s.amount,
            chain_id_from: s.chain_id_from,
            chain_id_to: s.chain_id_to,
            nonce: s.nonce,
            receiver: s.receiver.clone(),
            native_sender: s.native_sender.clone(),
            auto: s.auto.as_ref().map(auto_to_wire),
        }
    }

    /// Reconstruct the `Sent` the validator/keeper machinery consumes. The
    /// auto-params' `native_sender` is the event's single `native_sender` — the
    /// same value the submissionId hashes over — so a recompute matches.
    pub fn to_sent(&self) -> anyhow::Result<Sent> {
        if self.version != SENT_EVENT_VERSION {
            anyhow::bail!(
                "unsupported SentEvent version {} (expected {})",
                self.version,
                SENT_EVENT_VERSION
            );
        }
        let auto = self.auto.as_ref().map(|w| wire_to_auto(w, &self.native_sender));
        Ok(Sent {
            submission_id: self.submission_id,
            debridge_id: self.debridge_id,
            amount: self.amount,
            chain_id_from: self.chain_id_from,
            chain_id_to: self.chain_id_to,
            receiver: self.receiver.clone(),
            nonce: self.nonce,
            native_sender: self.native_sender.clone(),
            auto,
        })
    }

    /// Borsh bytes of this event — the second field the program passes to
    /// `sol_log_data`. The program serializes the identical layout.
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("borsh serialize SentEvent")
    }

    pub fn try_from_bytes(b: &[u8]) -> anyhow::Result<Self> {
        Ok(borsh::from_slice(b)?)
    }
}

/// Encode a `SentEvent` exactly as it appears in a Solana transaction's logs:
/// `Program data: <base64(tag)> <base64(borsh(event))>`. This is the string the
/// runtime prints for `sol_log_data(&[SENT_EVENT_TAG, &event.to_bytes()])`, so a
/// test can feed it straight back through [`parse_sent_event_line`].
pub fn sent_event_to_program_data_line(event: &SentEvent) -> String {
    let b64 = base64::engine::general_purpose::STANDARD;
    format!(
        "{PROGRAM_DATA_PREFIX} {} {}",
        b64.encode(SENT_EVENT_TAG),
        b64.encode(event.to_bytes())
    )
}

/// Parse a Solana `Program data:` log line into a [`SentEvent`]. Returns `None`
/// for any line that isn't a tagged bridge event (the validator skips those);
/// `Some(Err(..))` if it's ours but malformed (a fault the caller must surface,
/// per finding H3 — never a silent skip).
pub fn parse_sent_event_line(line: &str) -> Option<anyhow::Result<SentEvent>> {
    let rest = line.trim().strip_prefix(PROGRAM_DATA_PREFIX)?.trim();
    let b64 = base64::engine::general_purpose::STANDARD;
    let mut fields = rest.split_whitespace();
    let tag_b64 = fields.next()?;
    // Decode the first field; only claim this line if it's our tag.
    let tag = b64.decode(tag_b64).ok()?;
    if tag != SENT_EVENT_TAG {
        return None;
    }
    Some((|| {
        let payload_b64 = fields
            .next()
            .ok_or_else(|| anyhow::anyhow!("BRIDGE_SENT program data missing its payload field"))?;
        let bytes = b64.decode(payload_b64)?;
        SentEvent::try_from_bytes(&bytes)
    })())
}

/// Parse a Solana program-log line back into a `Sent`. Returns `None` for any
/// line that isn't our tagged event (the validator skips those); `Some(Err(..))`
/// if it is ours but won't decode.
///
/// **This says nothing about WHO emitted the line.** A transaction's log stream
/// is the concatenation of every program that ran in it, so a caller that feeds
/// arbitrary lines here is trusting any program in the transaction. Use
/// [`gate_program_data_lines`] to select the lines the gate itself emitted
/// before parsing — see the security note there.
pub fn parse_sent_log_line(line: &str) -> Option<anyhow::Result<Sent>> {
    match parse_sent_event_line(line)? {
        Ok(ev) => Some(ev.to_sent()),
        Err(e) => Some(Err(e)),
    }
}

/// Select the `Program data:` lines that `program_id` itself emitted.
///
/// ## Why this exists (the log-forgery vector)
///
/// `getSignaturesForAddress(gate)` returns every transaction that *mentions* the
/// gate in its `accountKeys` — merely listing it as a read-only account is
/// enough, and so is a one-unit real `send`. The `log_messages` of such a
/// transaction contain the output of EVERY program that ran, not just ours.
///
/// A scanner that parses all of them will accept a `BRIDGE_SENT` payload emitted
/// by an ATTACKER'S program. Neither of the checks downstream catches that: the
/// id recomputation only proves the attacker hashed their own chosen fields
/// correctly, and `chain_id_from` is a field in the forged payload. The validator
/// then signs a transfer that never happened, and a threshold of those signatures
/// releases real liquidity on the destination gate.
///
/// So attribution is not a nicety — it is the difference between "the gate said
/// this" and "somebody said this in a transaction the gate was mentioned in".
///
/// ## How
///
/// The runtime brackets each program's output with `Program <id> invoke [depth]`
/// and a terminating `Program <id> success` / `Program <id> failed: …`, nesting
/// on CPI. Tracking that stack tells us which program was executing when a given
/// `Program data:` line was printed; we keep only the lines emitted while
/// `program_id` is innermost.
///
/// Note this is *necessary but not sufficient*: logs can be truncated, and a
/// hostile RPC can return whatever it likes. The scanner additionally verifies
/// the event against the gate's own `["sent", submissionId]` PDA, which is the
/// authoritative check. This one keeps obviously-foreign events out cheaply.
pub fn gate_program_data_lines<'a>(logs: &'a [String], program_id: &str) -> Vec<&'a str> {
    let mut stack: Vec<&str> = Vec::new();
    let mut out = Vec::new();

    for line in logs {
        let line = line.trim();
        if let Some(who) = parse_invoke(line) {
            stack.push(who);
            continue;
        }
        if parse_terminator(line).is_some() {
            stack.pop();
            continue;
        }
        // Attribute program data to whichever program is currently innermost.
        if line.starts_with(PROGRAM_DATA_PREFIX) && stack.last() == Some(&program_id) {
            out.push(line);
        }
    }
    out
}

/// `Program <pubkey> invoke [<depth>]` -> the pubkey.
fn parse_invoke(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("Program ")?;
    let (who, tail) = rest.split_once(' ')?;
    // `invoke [N]` — require the bracket so a program literally named "invoke"
    // in some other message shape can't be mistaken for a frame.
    if tail.starts_with("invoke [") {
        Some(who)
    } else {
        None
    }
}

/// `Program <pubkey> success` / `Program <pubkey> failed: …` -> the pubkey.
///
/// Deliberately does NOT match `Program <pubkey> consumed …`, which the runtime
/// prints just before the terminator and would otherwise pop the frame early.
fn parse_terminator(line: &str) -> Option<&str> {
    let rest = line.strip_prefix("Program ")?;
    let (who, tail) = rest.split_once(' ')?;
    if tail == "success" || tail.starts_with("failed") {
        Some(who)
    } else {
        None
    }
}

/// The gate's source-side origin proof, written by `process_send` into the
/// program-owned PDA `["sent", submissionId]`.
///
/// Layout MUST match `solana_gate::SentRecord` byte-for-byte. That program is
/// excluded from the workspace (it builds for BPF), so the shape is mirrored here
/// rather than imported; [`SENT_RECORD_LEN`] pins the size against drift.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SentRecord {
    pub debridge_id: [u8; 32],
    /// The signer that locked the funds.
    pub sender: [u8; 32],
    /// The SPL token account debited — where `refund` returns the funds.
    pub source_token: [u8; 32],
    pub mint: [u8; 32],
    pub amount: u64,
    /// Cluster unix time the funds were locked (round 4, M-4/M-13). The refund
    /// attester reads this — never the store's nomination — to establish that a
    /// Solana-source transfer has been unclaimed for the timeout.
    pub locked_at: i64,
}

/// Borsh size of a [`SentRecord`]: four pubkey-width fields plus two 8-byte words.
pub const SENT_RECORD_LEN: usize = 32 + 32 + 32 + 32 + 8 + 8;
/// The pre-round-4 size (no `locked_at`). Still accepted — see [`decode_sent_record`].
pub const LEGACY_SENT_RECORD_LEN: usize = SENT_RECORD_LEN - 8;

/// Decode a `["sent", id]` record body, accepting the legacy layout with an
/// unknown (zero) `locked_at`. `None` for any other length or a malformed body.
///
/// The program applies the same rule, so an in-flight transfer locked before the
/// upgrade stays refundable; its age simply cannot be shown, and every age check
/// treats `locked_at == 0` as "not aged".
pub fn decode_sent_record(data: &[u8]) -> Option<SentRecord> {
    match data.len() {
        SENT_RECORD_LEN => SentRecord::try_from_slice(data).ok(),
        LEGACY_SENT_RECORD_LEN => {
            let mut padded = data.to_vec();
            padded.extend_from_slice(&[0u8; 8]);
            SentRecord::try_from_slice(&padded).ok()
        }
        _ => None,
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SentRecordError {
    #[error("no [\"sent\", id] record: this gate never emitted that submissionId")]
    Missing,
    #[error("[\"sent\", id] account is not owned by the gate program")]
    NotProgramOwned,
    #[error("[\"sent\", id] record is {0} bytes, expected {SENT_RECORD_LEN} (or the legacy {LEGACY_SENT_RECORD_LEN})")]
    BadLength(usize),
    #[error("[\"sent\", id] record does not decode as a SentRecord")]
    Malformed,
    #[error("record was zeroed (already refunded), so it authorises nothing")]
    Retired,
    #[error("record disagrees with the event on {field}")]
    Mismatch { field: &'static str },
}

/// Decode a `["sent", submissionId]` account and check it corroborates `event`.
///
/// This is the authoritative answer to "did the gate really emit this?". Logs are
/// a rendering; this account is program state that only `process_send` can write.
/// A forged `BRIDGE_SENT` — from a foreign program, a hostile RPC, or a replayed
/// line — has no such record, and one that names different values fails here.
///
/// `owner_is_program` and `data` come from a plain `getAccountInfo` on the PDA the
/// caller derived; keeping the I/O out makes the rule testable.
pub fn verify_sent_record(
    account: Option<(bool, &[u8])>,
    event: &SentEvent,
) -> Result<SentRecord, SentRecordError> {
    let Some((owner_is_program, data)) = account else {
        return Err(SentRecordError::Missing);
    };
    if !owner_is_program {
        return Err(SentRecordError::NotProgramOwned);
    }
    if data.is_empty() {
        return Err(SentRecordError::Missing);
    }
    if data.len() != SENT_RECORD_LEN && data.len() != LEGACY_SENT_RECORD_LEN {
        return Err(SentRecordError::BadLength(data.len()));
    }
    let record = decode_sent_record(data).ok_or(SentRecordError::Malformed)?;

    // `process_refund` zeroes the record on payout. An all-zero record proves the
    // transfer was already repaid on the source, so it must not corroborate a
    // fresh signature — and a zeroed record would otherwise "match" a forged
    // event that also named zeros.
    if record.amount == 0 && record.debridge_id == [0u8; 32] {
        return Err(SentRecordError::Retired);
    }

    if record.debridge_id != event.debridge_id {
        return Err(SentRecordError::Mismatch { field: "debridge_id" });
    }
    if record.amount != event.amount {
        return Err(SentRecordError::Mismatch { field: "amount" });
    }
    if record.mint != event.mint {
        return Err(SentRecordError::Mismatch { field: "mint" });
    }
    Ok(record)
}

/// Convert the hash-form auto-params into the Borsh instruction/event form.
pub fn auto_to_wire(a: &AutoParams) -> AutoParamsWire {
    let mut fee = [0u8; 16];
    fee.copy_from_slice(&a.execution_fee[16..]);
    let mut flags = [0u8; 8];
    flags.copy_from_slice(&a.flags[24..]);
    AutoParamsWire {
        execution_fee: u128::from_be_bytes(fee),
        flags: u64::from_be_bytes(flags),
        fallback_address: a.fallback_address.clone(),
        data: a.data.clone(),
    }
}

/// Inverse of [`auto_to_wire`]: widen the Borsh scalars back to the 32-byte hash
/// words and attach `native_sender` (the field the submissionId hashes over).
pub fn wire_to_auto(w: &AutoParamsWire, native_sender: &[u8]) -> AutoParams {
    let mut execution_fee = [0u8; 32];
    execution_fee[16..].copy_from_slice(&w.execution_fee.to_be_bytes());
    let mut flags = [0u8; 32];
    flags[24..].copy_from_slice(&w.flags.to_be_bytes());
    AutoParams {
        execution_fee,
        flags,
        fallback_address: w.fallback_address.clone(),
        data: w.data.clone(),
        native_sender: native_sender.to_vec(),
    }
}

// ---------------------------------------------------------------------------
// EVM `autoParams` -> Borsh `AutoParamsWire` (audit round 4, LOW "relayer
// ignores auto_params").
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AutoParamsError {
    #[error("autoParams blob is not a valid abi.encode(AutoParamsTo): {0}")]
    Malformed(&'static str),
    /// The value exists on the EVM side but this VM cannot represent it: the
    /// program hashes `execution_fee` as a `u128` and `flags` as a `u64`, so a
    /// wider value produces an id the gate can never reproduce (see the I-1 note
    /// on `submission_id` in `solana-gate`). Such a transfer is unclaimable AND
    /// uncancellable on Solana; the source must be refunded by other means.
    #[error("autoParams {field} exceeds what the Solana gate can encode")]
    Unrepresentable { field: &'static str },
}

/// Read one 32-byte ABI word at `at`.
fn abi_word(data: &[u8], at: usize) -> Result<[u8; 32], AutoParamsError> {
    data.get(at..at + 32)
        .and_then(|w| w.try_into().ok())
        .ok_or(AutoParamsError::Malformed("truncated word"))
}

/// A word that must fit `usize` (an offset or a length).
fn abi_usize(data: &[u8], at: usize) -> Result<usize, AutoParamsError> {
    let w = abi_word(data, at)?;
    if w[..24].iter().any(|b| *b != 0) {
        return Err(AutoParamsError::Malformed("offset/length too large"));
    }
    Ok(u64::from_be_bytes(w[24..].try_into().unwrap()) as usize)
}

/// A dynamic `bytes` whose head word (at `head`) holds its offset relative to
/// `base`.
fn abi_bytes(data: &[u8], base: usize, head: usize) -> Result<Vec<u8>, AutoParamsError> {
    let off = base
        .checked_add(abi_usize(data, head)?)
        .ok_or(AutoParamsError::Malformed("offset overflow"))?;
    let len = abi_usize(data, off)?;
    let start = off + 32;
    data.get(start..start.checked_add(len).ok_or(AutoParamsError::Malformed("length overflow"))?)
        .map(|b| b.to_vec())
        .ok_or(AutoParamsError::Malformed("bytes run past the blob"))
}

/// Decode the `abi.encode(AutoParamsTo)` blob a `Sent` event carries into the
/// Borsh form the Solana gate hashes.
///
/// `AutoParamsTo` is `(uint256 executionFee, uint256 flags, bytes fallbackAddress,
/// bytes data)`. Because the struct has dynamic members, `abi.encode` emits ONE
/// head word — the offset of the tuple (always 0x20) — followed by the tuple:
/// two static words, two offset words (relative to the tuple start), then the
/// two length-prefixed byte strings.
///
/// `Ok(None)` is "no execution payload" (an empty blob) — the store already
/// treats `0x` this way. An `Err` MUST be handled by skipping the transfer, never
/// by folding to `None`: the plain and with-auto ids for the same transfer are
/// different hashes, so a claim built with `auto: None` for a with-auto record
/// fails `NotEnoughSignatures` on-chain every poll, burning fees forever. That
/// is exactly what the relayer used to do.
///
/// Hand-rolled because this crate is alloy-free by design (see `Cargo.toml`);
/// the test suite pins it against alloy's own `abi_encode` of the same struct.
pub fn decode_evm_auto_params(blob: &[u8]) -> Result<Option<AutoParamsWire>, AutoParamsError> {
    if blob.is_empty() {
        return Ok(None);
    }
    let base = abi_usize(blob, 0)?;
    if base != 32 {
        return Err(AutoParamsError::Malformed("tuple offset is not 0x20"));
    }
    let fee = abi_word(blob, base)?;
    let flags = abi_word(blob, base + 32)?;
    if fee[..16].iter().any(|b| *b != 0) {
        return Err(AutoParamsError::Unrepresentable { field: "executionFee" });
    }
    if flags[..24].iter().any(|b| *b != 0) {
        return Err(AutoParamsError::Unrepresentable { field: "flags" });
    }
    let fallback_address = abi_bytes(blob, base, base + 64)?;
    let data = abi_bytes(blob, base, base + 96)?;
    Ok(Some(AutoParamsWire {
        execution_fee: u128::from_be_bytes(fee[16..].try_into().unwrap()),
        flags: u64::from_be_bytes(flags[24..].try_into().unwrap()),
        fallback_address,
        data,
    }))
}

/// Build the Borsh `Claim` instruction the keeper submits to the Solana gate.
///
/// Signatures are sorted by recovered signer address strictly ascending — exactly
/// the order the gate's `verify` step requires.
#[cfg(feature = "recover")]
pub fn build_claim_instruction(
    sent: &Sent,
    mut signatures: Vec<Vec<u8>>,
) -> anyhow::Result<Vec<u8>> {
    let digest = eth_signed_digest(&sent.submission_id);
    // Sort by recovered signer; a malformed signature sorts last deterministically.
    signatures.sort_by_key(|s| recover_evm_address(&digest, s).unwrap_or([0xff; 20]));

    let ix = GateInstruction::Claim(ClaimArgs {
        debridge_id: sent.debridge_id,
        amount: sent.amount,
        chain_id_from: sent.chain_id_from,
        nonce: sent.nonce,
        receiver: sent.receiver.clone(),
        auto: sent.auto.as_ref().map(auto_to_wire),
        native_sender: sent.native_sender.clone(),
        signatures,
    });
    Ok(ix.to_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::AutoParams;

    fn sample_sent(auto: Option<AutoParams>) -> Sent {
        Sent {
            submission_id: [0x11; 32],
            debridge_id: [0x22; 32],
            amount: 42_000,
            chain_id_from: crate::SOLANA_CHAIN_ID,
            chain_id_to: 1337,
            receiver: vec![0xEE; 20],
            nonce: 7,
            native_sender: vec![0x33; 32],
            auto,
        }
    }

    // H5: the exact `Program data:` line the runtime prints for
    // `sol_log_data([tag, borsh])` must round-trip back to the same Sent, both
    // with and without auto-params, and must carry the locked mint.
    #[test]
    fn program_data_line_round_trips() {
        for auto in [
            None,
            Some(AutoParams {
                execution_fee: {
                    let mut f = [0u8; 32];
                    f[16..].copy_from_slice(&1_234u128.to_be_bytes());
                    f
                },
                flags: {
                    let mut f = [0u8; 32];
                    f[24..].copy_from_slice(&5u64.to_be_bytes());
                    f
                },
                fallback_address: vec![0xAB; 20],
                data: vec![1, 2, 3, 4],
                native_sender: vec![0x33; 32],
            }),
        ] {
            let sent = sample_sent(auto);
            let mint = [0x55u8; 32];
            let line = sent_event_to_program_data_line(&SentEvent::from_sent(&sent, mint));
            assert!(line.starts_with("Program data: "), "must use sol_log_data framing");

            let event = parse_sent_event_line(&line).expect("our line").expect("decodes");
            assert_eq!(event.version, SENT_EVENT_VERSION);
            assert_eq!(event.mint, mint, "locked asset identity must survive");

            let back = parse_sent_log_line(&line).expect("our line").expect("decodes");
            assert_eq!(back, sent, "round-trip must be lossless");
        }
    }

    // Lines that aren't our tagged program data are skipped (None), so the
    // validator's scan ignores unrelated program output.
    #[test]
    fn non_bridge_lines_are_skipped() {
        for line in [
            "Program log: instruction: Send",
            "Program consumed 4242 compute units",
            "Program data: aGVsbG8=", // base64("hello"), not our tag
            "Program invoke [1]",
            "",
        ] {
            assert!(parse_sent_log_line(line).is_none(), "should skip: {line:?}");
            assert!(parse_sent_event_line(line).is_none(), "should skip: {line:?}");
        }
    }

    // A tagged-but-malformed payload is a hard error (Some(Err)), never a silent
    // skip — a corrupt event must surface, not vanish (finding H3 posture).
    #[test]
    fn tagged_but_malformed_payload_errors() {
        let b64 = base64::engine::general_purpose::STANDARD;
        // Correct tag, but the payload isn't valid Borsh for SentEvent.
        let line = format!(
            "Program data: {} {}",
            b64.encode(SENT_EVENT_TAG),
            b64.encode([0xFFu8; 3])
        );
        let r = parse_sent_event_line(&line).expect("recognised as ours");
        assert!(r.is_err(), "malformed payload must error, not skip");
    }

    const GATE: &str = "GateProg11111111111111111111111111111111111";
    const EVIL: &str = "EvilProg11111111111111111111111111111111111";

    fn data_line(sent: &Sent) -> String {
        sent_event_to_program_data_line(&SentEvent::from_sent(sent, [0x55; 32]))
    }

    /// THE C-1 attack, as a regression test.
    ///
    /// An attacker's program emits a perfectly well-formed `BRIDGE_SENT` payload
    /// inside a transaction that merely mentions the gate. Every downstream check
    /// passes on it — the id recomputes, the chain id is whatever the attacker
    /// wrote — so attribution is the only thing standing between that log line
    /// and a validator signature over a transfer that never happened.
    #[test]
    fn a_foreign_programs_bridge_sent_is_not_attributed_to_the_gate() {
        let forged = sample_sent(None);
        let logs: Vec<String> = vec![
            format!("Program {EVIL} invoke [1]"),
            "Program log: totally normal".into(),
            data_line(&forged), // <- emitted by EVIL, not the gate
            format!("Program {EVIL} consumed 1234 of 200000 compute units"),
            format!("Program {EVIL} success"),
        ];

        // The line itself parses fine — that is exactly why this was exploitable.
        assert!(parse_sent_log_line(&data_line(&forged)).is_some());

        // But it is not the gate's, so the scanner must never see it.
        assert!(
            gate_program_data_lines(&logs, GATE).is_empty(),
            "a foreign program's BRIDGE_SENT must not be attributed to the gate"
        );
    }

    /// The gate's own event, in the same transaction as a foreign one, is kept —
    /// and only that one. This is the mixed case an attacker would actually build
    /// (a real 1-unit send, to make the tx unambiguously involve the gate,
    /// alongside a forged event from their own program).
    #[test]
    fn only_the_gates_own_event_survives_a_mixed_transaction() {
        let mut real = sample_sent(None);
        real.amount = 1;
        let mut forged = sample_sent(None);
        forged.amount = 999_999_999;

        let logs: Vec<String> = vec![
            format!("Program {EVIL} invoke [1]"),
            data_line(&forged),
            format!("Program {GATE} invoke [2]"), // real CPI into the gate
            data_line(&real),
            format!("Program {GATE} consumed 500 of 190000 compute units"),
            format!("Program {GATE} success"),
            format!("Program {EVIL} success"),
        ];

        let kept = gate_program_data_lines(&logs, GATE);
        assert_eq!(kept.len(), 1, "exactly the gate's own event");
        let got = parse_sent_log_line(kept[0]).unwrap().unwrap();
        assert_eq!(got.amount, 1, "the forged event must not be the one kept");
    }

    /// `consumed` lines sit between a program's output and its terminator. Popping
    /// the frame on one would mis-attribute every later line in that frame.
    #[test]
    fn a_consumed_line_does_not_close_the_frame() {
        let sent = sample_sent(None);
        let logs: Vec<String> = vec![
            format!("Program {GATE} invoke [1]"),
            format!("Program {GATE} consumed 10 of 200000 compute units"),
            data_line(&sent),
            format!("Program {GATE} success"),
        ];
        assert_eq!(gate_program_data_lines(&logs, GATE).len(), 1);
    }

    /// A failed inner CPI pops its frame like a successful one, so output after it
    /// belongs to the caller again — not to the program that failed.
    #[test]
    fn a_failed_frame_pops_and_does_not_swallow_later_lines() {
        let sent = sample_sent(None);
        let logs: Vec<String> = vec![
            format!("Program {GATE} invoke [1]"),
            format!("Program {EVIL} invoke [2]"),
            format!("Program {EVIL} failed: custom program error: 0x1"),
            data_line(&sent), // back in the gate's frame
            format!("Program {GATE} success"),
        ];
        assert_eq!(gate_program_data_lines(&logs, GATE).len(), 1);
    }

    /// Nothing outside a frame is ever attributed (defensive: a truncated or
    /// reordered log stream must not default to "ours").
    #[test]
    fn data_outside_any_frame_is_dropped() {
        let sent = sample_sent(None);
        let logs: Vec<String> = vec![data_line(&sent)];
        assert!(gate_program_data_lines(&logs, GATE).is_empty());
    }

    // -----------------------------------------------------------------
    // The ["sent", id] origin proof — the authoritative anti-forgery check
    // -----------------------------------------------------------------

    fn event_and_record() -> (SentEvent, SentRecord) {
        let mint = [0x55u8; 32];
        let event = SentEvent::from_sent(&sample_sent(None), mint);
        let record = SentRecord {
            debridge_id: event.debridge_id,
            sender: [0x77; 32],
            source_token: [0x88; 32],
            mint,
            amount: event.amount,
            locked_at: 1_700_000_000,
        };
        (event, record)
    }

    #[test]
    fn a_matching_record_corroborates_the_event() {
        let (event, record) = event_and_record();
        let data = borsh::to_vec(&record).unwrap();
        assert_eq!(data.len(), SENT_RECORD_LEN, "layout must match the program's");
        assert_eq!(verify_sent_record(Some((true, &data)), &event).unwrap(), record);
    }

    /// The forged-event case: an attacker's log names a real corridor and a huge
    /// amount, but the gate never wrote a record for that id, so there is nothing
    /// on-chain to corroborate it.
    #[test]
    fn a_forged_event_has_no_origin_proof() {
        let (event, _) = event_and_record();
        assert_eq!(verify_sent_record(None, &event), Err(SentRecordError::Missing));
        assert_eq!(
            verify_sent_record(Some((true, &[])), &event),
            Err(SentRecordError::Missing)
        );
    }

    /// An account squatted at the derived address proves nothing — only the
    /// program can write program-owned state.
    #[test]
    fn a_foreign_owned_account_is_not_an_origin_proof() {
        let (event, record) = event_and_record();
        let data = borsh::to_vec(&record).unwrap();
        assert_eq!(
            verify_sent_record(Some((false, &data)), &event),
            Err(SentRecordError::NotProgramOwned)
        );
    }

    /// The inflation attack: a real 1-unit send exists, and the attacker replays
    /// its id with a bigger amount. The record pins the amount.
    #[test]
    fn an_inflated_amount_is_refused() {
        let (mut event, record) = event_and_record();
        event.amount = record.amount + 1_000_000;
        let data = borsh::to_vec(&record).unwrap();
        assert_eq!(
            verify_sent_record(Some((true, &data)), &event),
            Err(SentRecordError::Mismatch { field: "amount" })
        );
    }

    /// Swapping the asset for a more valuable one is pinned the same way.
    #[test]
    fn a_substituted_asset_is_refused() {
        let (event, record) = event_and_record();
        let data = borsh::to_vec(&record).unwrap();

        let mut wrong_corridor = event.clone();
        wrong_corridor.debridge_id = [0xAB; 32];
        assert_eq!(
            verify_sent_record(Some((true, &data)), &wrong_corridor),
            Err(SentRecordError::Mismatch { field: "debridge_id" })
        );

        let mut wrong_mint = event.clone();
        wrong_mint.mint = [0xCD; 32];
        assert_eq!(
            verify_sent_record(Some((true, &data)), &wrong_mint),
            Err(SentRecordError::Mismatch { field: "mint" })
        );
    }

    /// `process_refund` zeroes the record on payout. A zeroed record must not
    /// corroborate anything — least of all a forged event that also names zeros.
    #[test]
    fn a_refunded_record_authorises_nothing() {
        let (mut event, _) = event_and_record();
        let zeroed = vec![0u8; SENT_RECORD_LEN];
        event.debridge_id = [0u8; 32];
        event.amount = 0;
        assert_eq!(
            verify_sent_record(Some((true, &zeroed)), &event),
            Err(SentRecordError::Retired)
        );
    }

    /// A record written before `locked_at` existed still corroborates the event
    /// (the lock happened) and reads an unknown lock time as 0.
    #[test]
    fn a_legacy_record_is_accepted_with_an_unknown_lock_time() {
        let (event, record) = event_and_record();
        let full = borsh::to_vec(&record).unwrap();
        let legacy = &full[..LEGACY_SENT_RECORD_LEN];
        let got = verify_sent_record(Some((true, legacy)), &event).expect("legacy decodes");
        assert_eq!(got.amount, record.amount);
        assert_eq!(got.locked_at, 0);
        assert_eq!(decode_sent_record(&full).unwrap().locked_at, record.locked_at);
        assert!(decode_sent_record(&full[..50]).is_none());
    }

    #[test]
    fn a_wrong_sized_record_is_refused() {
        let (event, _) = event_and_record();
        let short = vec![0u8; SENT_RECORD_LEN - 1];
        assert_eq!(
            verify_sent_record(Some((true, &short)), &event),
            Err(SentRecordError::BadLength(SENT_RECORD_LEN - 1))
        );
    }

    // A future version the decoder wasn't built for is rejected rather than
    // silently misread.
    #[test]
    fn unknown_version_is_rejected() {
        let mut ev = SentEvent::from_sent(&sample_sent(None), [0x55; 32]);
        ev.version = SENT_EVENT_VERSION + 1;
        let line = sent_event_to_program_data_line(&ev);
        // The bytes decode into a SentEvent, but converting to a Sent rejects it.
        let ev2 = parse_sent_event_line(&line).unwrap().unwrap();
        assert!(ev2.to_sent().is_err(), "unknown version must be rejected");
    }

    // -----------------------------------------------------------------
    // EVM autoParams -> AutoParamsWire (round 4, LOW)
    // -----------------------------------------------------------------

    /// Pinned against alloy's own encoder: whatever `abi.encode(AutoParamsTo)`
    /// produces on the EVM side, this decoder must read back the same fields —
    /// and the id recomputed from them must be the id the EVM gate emitted.
    #[test]
    fn evm_auto_params_decode_matches_alloy_encoding() {
        use alloy::sol_types::SolValue;
        use bridge_core::abi::AutoParamsTo;

        for (fee, flags, fallback, data) in [
            (0u128, 0u64, vec![], vec![]),
            (1_000_000, 1, vec![0xAAu8; 20], vec![1, 2, 3]),
            (u128::MAX, u64::MAX, vec![0xBB; 32], vec![0u8; 100]),
            (7, 2, vec![], vec![0xCC; 33]), // non-word-aligned lengths
        ] {
            let encoded = AutoParamsTo {
                executionFee: alloy_primitives::U256::from(fee),
                flags: alloy_primitives::U256::from(flags),
                fallbackAddress: fallback.clone().into(),
                data: data.clone().into(),
            }
            .abi_encode();

            let wire = decode_evm_auto_params(&encoded).expect("decodes").expect("is Some");
            assert_eq!(wire.execution_fee, fee);
            assert_eq!(wire.flags, flags);
            assert_eq!(wire.fallback_address, fallback);
            assert_eq!(wire.data, data);

            // And the round trip through the hash form reproduces the EVM id.
            let native_sender = vec![0x11u8; 20];
            let auto = wire_to_auto(&wire, &native_sender);
            let ours = crate::hash::submission_id_with_auto(
                &[0xD0; 32], &[9; 32], &crate::hash::amount_word(500), 1337, 7565164, 3,
                &[0xAB; 32], &auto,
            );
            let theirs = bridge_core::submission_id_with_auto(
                alloy_primitives::B256::from([0xD0; 32]),
                alloy_primitives::B256::from([9u8; 32]),
                alloy_primitives::U256::from(500u64),
                alloy_primitives::U256::from(1337u64),
                alloy_primitives::U256::from(7565164u64),
                alloy_primitives::U256::from(3u64),
                &[0xAB; 32],
                &bridge_core::decode_auto_params(&encoded, &native_sender).unwrap().unwrap(),
            );
            assert_eq!(ours, theirs.0, "id from decoded auto-params diverged from bridge-core");
        }
    }

    #[test]
    fn an_empty_blob_is_no_payload() {
        assert_eq!(decode_evm_auto_params(&[]), Ok(None));
    }

    /// A payload the Solana gate cannot hash (fee >= 2^128, flags >= 2^64) is an
    /// ERROR, not `None` — folding it to `None` would build a claim for a
    /// different id and fail on-chain every poll.
    #[test]
    fn unrepresentable_values_are_errors_not_none() {
        use alloy::sol_types::SolValue;
        use bridge_core::abi::AutoParamsTo;

        let wide_fee = AutoParamsTo {
            executionFee: alloy_primitives::U256::from(u128::MAX) + alloy_primitives::U256::from(1u8),
            flags: alloy_primitives::U256::ZERO,
            fallbackAddress: vec![].into(),
            data: vec![].into(),
        }
        .abi_encode();
        assert_eq!(
            decode_evm_auto_params(&wide_fee),
            Err(AutoParamsError::Unrepresentable { field: "executionFee" })
        );

        let wide_flags = AutoParamsTo {
            executionFee: alloy_primitives::U256::ZERO,
            flags: alloy_primitives::U256::from(u64::MAX) + alloy_primitives::U256::from(1u8),
            fallbackAddress: vec![].into(),
            data: vec![].into(),
        }
        .abi_encode();
        assert_eq!(
            decode_evm_auto_params(&wide_flags),
            Err(AutoParamsError::Unrepresentable { field: "flags" })
        );
    }

    /// Garbage must be refused loudly, never read as an empty payload.
    #[test]
    fn a_malformed_blob_is_an_error() {
        assert!(matches!(decode_evm_auto_params(&[0u8; 31]), Err(AutoParamsError::Malformed(_))));
        assert!(matches!(decode_evm_auto_params(&[0u8; 64]), Err(AutoParamsError::Malformed(_))));
        // A plausible head whose byte strings run off the end.
        let mut truncated = vec![0u8; 32];
        truncated[31] = 0x20;
        truncated.extend_from_slice(&[0u8; 64]); // fee, flags
        let mut off = [0u8; 32];
        off[31] = 0x80;
        truncated.extend_from_slice(&off); // fallback offset
        truncated.extend_from_slice(&off); // data offset
        let mut len = [0u8; 32];
        len[31] = 200; // claims 200 bytes that are not there
        truncated.extend_from_slice(&len);
        assert!(matches!(decode_evm_auto_params(&truncated), Err(AutoParamsError::Malformed(_))));
    }
}
