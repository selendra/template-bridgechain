//! A dead-simple, file-backed signature store: one JSON file per submissionId.
//!
//! This is the local-dev stand-in for the deBridge API / Arweave. The validator
//! upserts its signature into `<dir>/<submissionId>.json`; the keeper reads the
//! directory, and once a record has >= threshold signatures, submits `claim()`.
//! Phase 7 replaces this with the HTTP `sig-store` service (same record shape).
//!
//! ## Trust boundary (security)
//!
//! In Phase 7 this store is fronted by an **unauthenticated** HTTP service, so
//! `upsert_signature` is a trust boundary: callers are untrusted. It therefore
//! enforces three invariants (the `abi` feature is required for the cryptographic
//! ones — every real caller, validator/keeper/sig-store, enables it):
//!
//!   1. **id ⇄ params binding** — `submission_id` MUST equal the canonical
//!      `keccak256` of the record's own parameters. An attacker cannot pin a real
//!      submissionId onto forged params (and vice-versa).
//!   2. **immutable params** — once a submissionId is stored, its parameters can
//!      never be changed; only new signatures may be merged in. This stops a
//!      poisoning attack that overwrites a legitimate record's `amount`/`receiver`
//!      while keeping the genuine validator signatures.
//!   3. **authentic signatures** — each signature must actually recover to its
//!      claimed `signer` over the EIP-191 digest of the submissionId, so junk
//!      signatures can't inflate the count past the threshold.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// One validator's signature over a submissionId.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignerSig {
    /// Recovered/known signer address, `0x`-prefixed.
    pub signer: String,
    /// 65-byte ECDSA signature (r||s||v, v in {27,28}), `0x`-prefixed.
    pub signature: String,
}

/// Everything the keeper needs to rebuild and submit a `claim()`, plus the
/// collected validator signatures. Numeric fields are stringly-typed to avoid
/// precision loss for `amount` (uint256).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionRecord {
    pub submission_id: String,
    /// `0x`-prefixed bytes32 — the deployment generation this transfer belongs
    /// to, read from the emitting gate's `bridgeDomain()`. Part of the
    /// submissionId preimage, so [`canonical_submission_id`] needs it to
    /// reproduce the id at all.
    ///
    /// `#[serde(default)]` for records written before the domain existed: those
    /// deserialize to the empty string, which is not valid hex, so they fail the
    /// id-binding check rather than being silently recomputed under a zero
    /// domain. A pre-domain record belongs to a superseded generation and must
    /// not be resurrected — that is precisely the replay this field prevents.
    #[serde(default)]
    pub bridge_domain: String,
    pub debridge_id: String,
    /// decimal string (uint256)
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    /// `0x`-prefixed hex; raw bytes of the receiver
    pub receiver: String,
    /// `0x`-prefixed hex; `0x` (empty) when there is no execution payload
    pub auto_params: String,
    /// `0x`-prefixed hex; packed source sender
    pub native_sender: String,
    /// `0x`-prefixed source-chain ERC-20 that was locked. NOT part of the
    /// submissionId — `debridge_id` is a one-way hash of it — so it is carried
    /// alongside for the refund relayer, and pinned by [`verify_token_binding`]
    /// (`debridge_id == keccak(chain_id_from, token)`) rather than trusted.
    ///
    /// Empty for records written before the refund path existed; such a record
    /// simply can't be refunded until the indexer re-observes its `Sent`.
    #[serde(default)]
    pub token: String,
    pub signatures: Vec<SignerSig>,
    /// Validator attestations authorising `Gate.cancel` on the DESTINATION chain
    /// (signed over `cancel_id`, a separate domain from the transfer signatures).
    #[serde(default)]
    pub cancel_signatures: Vec<SignerSig>,
    /// Validator attestations authorising `Gate.refund` on the SOURCE chain
    /// (signed over `refund_id`). A quorum here only forms after the destination
    /// `Cancelled` event is on-chain — that ordering is what makes the refund
    /// safe against a concurrent claim.
    #[serde(default)]
    pub refund_signatures: Vec<SignerSig>,
}

/// Construction from an on-chain `Gate.Sent` event — the ONE place the event's
/// fields are mapped onto the store record.
///
/// Every off-chain component that observes `Sent` (the validator, which signs
/// it; the indexer, which mirrors it) needs exactly this mapping, and a copy that
/// drifts is invisible: two components would compute two different
/// submissionIds for the same transfer and simply never agree, with no error
/// anywhere.
#[cfg(feature = "abi")]
impl SubmissionRecord {
    /// `None` when a chainId or the nonce exceeds `u64`.
    ///
    /// Those three are re-encoded as `U256` when a claim is rebuilt, so a value
    /// that only fits by saturating would reconstruct a DIFFERENT submissionId
    /// (and alias two distinct chains or nonces into one corridor). A real gate
    /// never emits them; callers skip such an event rather than record or sign it.
    pub fn from_sent_event(
        ev: &crate::abi::Gate::Sent,
        bridge_domain: alloy_primitives::B256,
    ) -> Option<Self> {
        let (chain_id_from, chain_id_to, nonce) = sent_event_u64s(ev)?;
        Some(SubmissionRecord {
            submission_id: format!("{:#x}", ev.submissionId),
            bridge_domain: format!("{bridge_domain:#x}"),
            debridge_id: format!("{:#x}", ev.debridgeId),
            amount: ev.amount.to_string(),
            chain_id_from,
            chain_id_to,
            nonce,
            receiver: format!("0x{}", hex::encode(&ev.receiver)),
            auto_params: format!("0x{}", hex::encode(&ev.autoParams)),
            native_sender: format!("0x{}", hex::encode(&ev.nativeSender)),
            // The locked asset, for the refund path. Not covered by the
            // submissionId, so the store re-derives debridgeId from it before
            // accepting (see `verify_token_binding`).
            token: format!("{:#x}", ev.token),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        })
    }
}

/// The event's `(chainIdFrom, chainIdTo, nonce)` as `u64`s, or `None` if any of
/// them overflows. See [`SubmissionRecord::from_sent_event`] for why that is a
/// refusal rather than a saturating cast.
#[cfg(feature = "abi")]
fn sent_event_u64s(ev: &crate::abi::Gate::Sent) -> Option<(u64, u64, u64)> {
    match (u64::try_from(ev.chainIdFrom), u64::try_from(ev.chainIdTo), u64::try_from(ev.nonce)) {
        (Ok(from), Ok(to), Ok(nonce)) => Some((from, to, nonce)),
        _ => None,
    }
}

/// Which digest domain a signature authorises. Each maps to a different
/// on-chain effect, so they are stored and counted separately — a transfer
/// quorum must never be usable as a cancel or refund quorum.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SigKind {
    /// Authorises `claim()` — signed over the raw submissionId.
    Transfer,
    /// Authorises `cancel()` on the destination — signed over `cancel_id`.
    Cancel,
    /// Authorises `refund()` on the source — signed over `refund_id`.
    Refund,
}

impl SigKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SigKind::Transfer => "transfer",
            SigKind::Cancel => "cancel",
            SigKind::Refund => "refund",
        }
    }

    pub fn parse(s: &str) -> Option<SigKind> {
        match s {
            "transfer" => Some(SigKind::Transfer),
            "cancel" => Some(SigKind::Cancel),
            "refund" => Some(SigKind::Refund),
            _ => None,
        }
    }

    /// The 32-byte message a validator actually signs for this domain, given the
    /// transfer's submissionId.
    #[cfg(feature = "abi")]
    pub fn digest(self, submission_id: alloy_primitives::B256) -> alloy_primitives::B256 {
        match self {
            SigKind::Transfer => submission_id,
            SigKind::Cancel => crate::cancel_id(submission_id),
            SigKind::Refund => crate::refund_id(submission_id),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("malformed field: {0}")]
    BadField(&'static str),
    #[error("submission_id {claimed} does not match the recomputed id {computed} for these params")]
    IdMismatch { claimed: String, computed: String },
    #[error("params conflict: submissionId {0} is already stored with different parameters (params are immutable)")]
    ParamsConflict(String),
    #[error("signature is not recoverable / invalid")]
    BadSignature,
    #[error("signature recovers to {recovered}, not the claimed signer {claimed}")]
    SignerMismatch { claimed: String, recovered: String },
    #[error("token {token} does not hash to debridgeId {debridge_id} on chain {chain_id}")]
    TokenMismatch { token: String, debridge_id: String, chain_id: u64 },
    /// Audit 2026-09-09, M-2: the per-submission signer cap for this domain
    /// (`transfer` | `cancel` | `refund`) is full and the signer is new.
    #[error(
        "refusing signature: submission already holds {MAX_SIGNATURES_PER_SUBMISSION} {0} signers, \
         which exceeds any real validator set"
    )]
    TooManySignatures(&'static str),
}

/// Audit 2026-09-09, M-2: how many DISTINCT signers one submission may hold per
/// domain (`transfer`, `cancel`, `refund`), in the file store and in bridge-db.
///
/// A quorum is `threshold` out of a validator set that is a handful of
/// addresses; 64 is an order of magnitude beyond any deployment, yet small
/// enough that the keeper's per-tick `pending_claims` payload and its
/// one-`isValidator`-call-per-unknown-signer memo stay bounded. Every signature
/// still has to recover to its claimed signer, so the only thing the cap ever
/// refuses is a leaked `Sign` credential minting throwaway keys to bloat a
/// record. A signer already on the record is always accepted (idempotent
/// re-POST), so an honest validator can never be locked out by junk.
pub const MAX_SIGNATURES_PER_SUBMISSION: usize = 64;

/// Merge `sig` into `bucket` deduped by signer, enforcing
/// [`MAX_SIGNATURES_PER_SUBMISSION`]. `kind` names the domain in the error.
fn push_capped(bucket: &mut Vec<SignerSig>, sig: SignerSig, kind: &'static str) -> Result<(), StoreError> {
    if bucket.iter().any(|s| s.signer.eq_ignore_ascii_case(&sig.signer)) {
        return Ok(());
    }
    if bucket.len() >= MAX_SIGNATURES_PER_SUBMISSION {
        return Err(StoreError::TooManySignatures(kind));
    }
    bucket.push(sig);
    Ok(())
}

/// True iff `s` is a well-formed submissionId: an optional `0x` followed by
/// exactly 64 hex digits (a 32-byte hash).
///
/// **Security:** the submissionId is used to build a filesystem path
/// (`file_path`) and a sig-store URL (`remote`). Both `load` and
/// `upsert_signature` guard with this *before* touching the filesystem, so an
/// untrusted id like `../../etc/foo` can never escape the store directory (path
/// traversal). Callers that forward ids to a remote store should guard too.
pub fn is_valid_submission_id(s: &str) -> bool {
    let s = s.strip_prefix("0x").unwrap_or(s);
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn file_path(dir: &Path, submission_id: &str) -> PathBuf {
    let id = submission_id.strip_prefix("0x").unwrap_or(submission_id);
    dir.join(format!("{id}.json"))
}

/// Ensure the store directory exists.
pub fn ensure_dir(dir: &Path) -> Result<(), StoreError> {
    std::fs::create_dir_all(dir)?;
    Ok(())
}

/// True iff two records carry identical transfer parameters (everything but the
/// collected signatures). Hex/hash fields are compared case-insensitively.
///
/// Callers comparing against a normalized/stored `submission_id` (e.g. one
/// that's always `0x`-prefixed) should normalize both sides the same way first
/// — this does a literal case-insensitive compare of the field as given.
pub fn same_params(a: &SubmissionRecord, b: &SubmissionRecord) -> bool {
    a.submission_id.eq_ignore_ascii_case(&b.submission_id)
        && a.debridge_id.eq_ignore_ascii_case(&b.debridge_id)
        && a.amount == b.amount
        && a.chain_id_from == b.chain_id_from
        && a.chain_id_to == b.chain_id_to
        && a.nonce == b.nonce
        && a.receiver.eq_ignore_ascii_case(&b.receiver)
        && a.auto_params.eq_ignore_ascii_case(&b.auto_params)
        && a.native_sender.eq_ignore_ascii_case(&b.native_sender)
}

#[cfg(feature = "abi")]
fn hex_bytes(field: &'static str, s: &str) -> Result<Vec<u8>, StoreError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s).map_err(|_| StoreError::BadField(field))
}

/// Recompute the canonical `submissionId` from a record's parameters, exactly as
/// the Gate contract would on `claim()`. This is THE check that binds an id to its
/// params: if the record's `submission_id` doesn't equal this, the record is forged.
#[cfg(feature = "abi")]
pub fn canonical_submission_id(rec: &SubmissionRecord) -> Result<alloy_primitives::B256, StoreError> {
    use alloy_primitives::{B256, U256};
    use std::str::FromStr;

    let bridge_domain =
        B256::from_str(&rec.bridge_domain).map_err(|_| StoreError::BadField("bridge_domain"))?;
    let debridge_id = B256::from_str(&rec.debridge_id).map_err(|_| StoreError::BadField("debridge_id"))?;
    let amount = U256::from_str(&rec.amount).map_err(|_| StoreError::BadField("amount"))?;
    let receiver = hex_bytes("receiver", &rec.receiver)?;
    let auto_params = hex_bytes("auto_params", &rec.auto_params)?;
    let native_sender = hex_bytes("native_sender", &rec.native_sender)?;
    let chain_from = U256::from(rec.chain_id_from);
    let chain_to = U256::from(rec.chain_id_to);
    let nonce = U256::from(rec.nonce);

    let auto = crate::decode_auto_params(&auto_params, &native_sender)
        .map_err(|_| StoreError::BadField("auto_params"))?;
    let id = match auto {
        None => {
            crate::submission_id(bridge_domain, debridge_id, amount, chain_from, chain_to, nonce, &receiver)
        }
        Some(auto) => crate::submission_id_with_auto(
            bridge_domain,
            debridge_id,
            amount,
            chain_from,
            chain_to,
            nonce,
            &receiver,
            &auto,
        ),
    };
    Ok(id)
}

/// Verify a signature genuinely recovers to its claimed signer over the EIP-191
/// digest of `submission_id` (the same digest the validator signs and the Gate
/// verifies). Returns the recovered address on success.
///
/// Authentication only — it deliberately accepts a non-canonical ENCODING, because
/// rejecting one would drop a signature the signer really did produce. Every write
/// path pairs this with [`canonical_signature`], which is what makes the accepted
/// bytes safe to hand to the Gate. See that function for why.
#[cfg(feature = "abi")]
pub fn verify_signature(
    submission_id: alloy_primitives::B256,
    sig: &SignerSig,
) -> Result<alloy_primitives::Address, StoreError> {
    use alloy_primitives::{Address, Signature};
    use std::str::FromStr;

    let claimed = Address::from_str(&sig.signer).map_err(|_| StoreError::BadField("signer"))?;
    let raw = hex_bytes("signature", &sig.signature)?;
    let signature = Signature::try_from(raw.as_slice()).map_err(|_| StoreError::BadSignature)?;
    let recovered = signature
        .recover_address_from_msg(submission_id.as_slice())
        .map_err(|_| StoreError::BadSignature)?;
    if recovered != claimed {
        return Err(StoreError::SignerMismatch {
            claimed: format!("{claimed:#x}"),
            recovered: format!("{recovered:#x}"),
        });
    }
    Ok(recovered)
}

/// Re-encode a signature in the ONE form every Gate entry point accepts: low-`s`,
/// with `v` in {27,28}.
///
/// ## Why this exists
///
/// The off-chain verifier and the on-chain one disagreed about what a valid
/// signature *encoding* is, and the disagreement was a one-validator kill switch.
///
/// [`verify_signature`] authenticates through alloy's `recover_address_from_msg`,
/// which silently calls `normalized_s()` first and passes `v` through
/// `normalize_v`. So a high-`s` signature — or one with `v` in {0,1} — recovers to
/// the right validator and used to be stored verbatim. `Gate._verifySignatures`
/// uses OpenZeppelin's `ECDSA.recover`, which REVERTS on both
/// (`ECDSAInvalidSignatureS` / `ECDSAInvalidSignature`).
///
/// The keeper submits every member signature in one array, so a single such entry
/// reverted the whole `claim` — and the same array-building code serves `cancel`
/// and `refund`, so the transfer could not be recovered either. One validator out
/// of N could freeze the bridge, which is exactly what a threshold is supposed to
/// make impossible. An honest third-party validator whose ECDSA library does not
/// normalise `s` would have done it by accident.
///
/// Canonicalising rather than rejecting is deliberate: the signature is genuine,
/// so dropping it would cost a real quorum vote. `s` and `n - s` verify to the same
/// signer, and flipping the parity alongside keeps the recovery id correct — the
/// re-encoded bytes are the same attestation, in the form the Gate reads.
#[cfg(feature = "abi")]
pub fn canonical_signature(sig: &SignerSig) -> Result<SignerSig, StoreError> {
    use alloy_primitives::Signature;

    let raw = hex_bytes("signature", &sig.signature)?;
    let parsed = Signature::try_from(raw.as_slice()).map_err(|_| StoreError::BadSignature)?;
    // `normalized_s` flips `y_parity` when it lowers `s`, and `as_bytes` always
    // emits `27 + y_parity` — so this fixes both non-canonical forms at once.
    let bytes = parsed.normalized_s().as_bytes();
    Ok(SignerSig {
        signer: sig.signer.clone(),
        signature: format!("0x{}", hex::encode(bytes)),
    })
}

/// Pin a record's `token` to its `debridge_id`.
///
/// The source gate always emits `debridgeId = keccak256(chainIdFrom, token)`, so
/// this recomputes that and rejects any other value. It makes `token`
/// self-certifying: although it is not covered by the submissionId, a caller
/// still cannot substitute a different (more valuable) asset — which matters
/// because `token` is what the keeper feeds to `Gate.refund`.
///
/// An empty `token` is accepted as "not recorded" (pre-refund-path records); the
/// refund relayer treats such a record as un-refundable rather than guessing.
#[cfg(feature = "abi")]
pub fn verify_token_binding(rec: &SubmissionRecord) -> Result<(), StoreError> {
    use alloy_primitives::{Address, B256, U256};
    use std::str::FromStr;

    if rec.token.is_empty() {
        return Ok(());
    }
    let token = Address::from_str(&rec.token).map_err(|_| StoreError::BadField("token"))?;
    let debridge_id = B256::from_str(&rec.debridge_id).map_err(|_| StoreError::BadField("debridge_id"))?;
    let computed = crate::debridge_id(U256::from(rec.chain_id_from), token);
    if computed != debridge_id {
        return Err(StoreError::TokenMismatch {
            token: format!("{token:#x}"),
            debridge_id: format!("{debridge_id:#x}"),
            chain_id: rec.chain_id_from,
        });
    }
    Ok(())
}

/// Verify an attestation for a given domain: the signature must recover to its
/// claimed signer over `kind`'s digest, not merely over the submissionId.
///
/// This is what keeps the three quorums independent. Feeding a validator's
/// transfer signature in as a cancel attestation fails here, because a cancel is
/// signed over `cancel_id(submissionId)` — a different message entirely.
#[cfg(feature = "abi")]
pub fn verify_attestation(
    submission_id: alloy_primitives::B256,
    kind: SigKind,
    sig: &SignerSig,
) -> Result<alloy_primitives::Address, StoreError> {
    verify_signature(kind.digest(submission_id), sig)
}

/// Insert or update a record, merging in `sig` (deduped by signer, case-insensitive).
/// Returns the resulting record (with all known signatures).
///
/// This is an untrusted-input trust boundary — see the module docs. With the `abi`
/// feature it rejects (1) records whose `submission_id` doesn't match their params,
/// (2) attempts to change the params of an already-stored submissionId, and (3)
/// signatures that don't recover to their claimed signer.
pub fn upsert_signature(
    dir: &Path,
    mut record: SubmissionRecord,
    #[allow(unused_mut)] mut sig: SignerSig,
) -> Result<SubmissionRecord, StoreError> {
    // Guard the id BEFORE it becomes a file path (path-traversal defense). With
    // the `abi` feature the canonical-id check below would also catch a non-hash
    // id, but this protects the non-abi build and fails fast with a clear error.
    if !is_valid_submission_id(&record.submission_id) {
        return Err(StoreError::BadField("submission_id"));
    }
    ensure_dir(dir)?;

    // (1) Bind id <-> params, and (3) authenticate the incoming signature.
    #[cfg(feature = "abi")]
    {
        use std::str::FromStr;
        let computed = canonical_submission_id(&record)?;
        let claimed = alloy_primitives::B256::from_str(&record.submission_id)
            .map_err(|_| StoreError::BadField("submission_id"))?;
        if computed != claimed {
            return Err(StoreError::IdMismatch {
                claimed: format!("{claimed:#x}"),
                computed: format!("{computed:#x}"),
            });
        }
        verify_signature(computed, &sig)?;
        // Store the form the Gate accepts, never the caller's encoding — see
        // `canonical_signature`. A high-`s` entry here reverts every claim.
        sig = canonical_signature(&sig)?;
        // (4) `token` isn't covered by the submissionId, so pin it separately.
        verify_token_binding(&record)?;
    }

    let path = file_path(dir, &record.submission_id);

    if path.exists() {
        let existing: SubmissionRecord = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
        // (2) Params are immutable once stored: reject any conflicting overwrite,
        // otherwise keep the genuine accumulated signatures.
        if !same_params(&existing, &record) {
            return Err(StoreError::ParamsConflict(record.submission_id.clone()));
        }
        record.signatures = existing.signatures;
        // Attestations are never supplied through this path — preserve whatever
        // `upsert_attestation` has collected.
        record.cancel_signatures = existing.cancel_signatures;
        record.refund_signatures = existing.refund_signatures;
        // `token` is verified above, so a previously-empty one may be filled in;
        // a stored non-empty value is immutable like the rest of the params.
        if !existing.token.is_empty() {
            record.token = existing.token;
        }
    }

    push_capped(&mut record.signatures, sig, "transfer")?;

    std::fs::write(&path, serde_json::to_string_pretty(&record)?)?;
    Ok(record)
}

/// Merge a cancel/refund attestation into an already-stored record.
///
/// Unlike [`upsert_signature`] this never creates a record: an attestation is
/// only meaningful for a transfer we have already seen, and refusing to
/// bootstrap one from attestation data alone keeps the id⇄params binding the
/// sole way a record can come into existence.
pub fn upsert_attestation(
    dir: &Path,
    submission_id: &str,
    kind: SigKind,
    #[allow(unused_mut)] mut sig: SignerSig,
) -> Result<SubmissionRecord, StoreError> {
    if !is_valid_submission_id(submission_id) {
        return Err(StoreError::BadField("submission_id"));
    }
    let path = file_path(dir, submission_id);
    if !path.exists() {
        return Err(StoreError::BadField("submission_id"));
    }
    let mut record: SubmissionRecord = serde_json::from_str(&std::fs::read_to_string(&path)?)?;

    // Authenticate against THIS domain's digest — a transfer signature replayed
    // here recovers to the wrong address and is rejected.
    #[cfg(feature = "abi")]
    {
        use std::str::FromStr;
        let id = alloy_primitives::B256::from_str(&record.submission_id)
            .map_err(|_| StoreError::BadField("submission_id"))?;
        verify_attestation(id, kind, &sig)?;
        // Cancel and refund reach the same `ECDSA.recover` a claim does, so they
        // need the same canonical encoding — otherwise a poisoned attestation
        // takes out the recovery path too.
        sig = canonical_signature(&sig)?;
    }

    let bucket = match kind {
        SigKind::Transfer => &mut record.signatures,
        SigKind::Cancel => &mut record.cancel_signatures,
        SigKind::Refund => &mut record.refund_signatures,
    };
    push_capped(bucket, sig, kind.as_str())?;

    std::fs::write(&path, serde_json::to_string_pretty(&record)?)?;
    Ok(record)
}

/// Load a single record by submissionId, if present.
pub fn load(dir: &Path, submission_id: &str) -> Result<Option<SubmissionRecord>, StoreError> {
    // A malformed id can't name a real record; reject it before it ever becomes a
    // file path, so `../foo`-style ids can't read outside the store (traversal).
    if !is_valid_submission_id(submission_id) {
        return Ok(None);
    }
    let path = file_path(dir, submission_id);
    if !path.exists() {
        return Ok(None);
    }
    Ok(Some(serde_json::from_str(&std::fs::read_to_string(&path)?)?))
}

/// Load every record in the store directory.
pub fn load_all(dir: &Path) -> Result<Vec<SubmissionRecord>, StoreError> {
    let mut out = Vec::new();
    if !dir.exists() {
        return Ok(out);
    }
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("json") {
            out.push(serde_json::from_str(&std::fs::read_to_string(&path)?)?);
        }
    }
    Ok(out)
}

#[cfg(all(test, feature = "abi"))]
mod tests {
    use super::*;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::signers::SignerSync;
    use alloy_primitives::{Address, B256, U256};
    use crate::signer::encode_signature as encode_sig;
    use std::str::FromStr;

    /// The ERC-20 `make_record` pretends was locked on chain 1337.
    fn token() -> Address {
        Address::repeat_byte(0x11)
    }

    // Build a well-formed record (id == keccak(params)) for a plain transfer.
    fn make_record() -> SubmissionRecord {
        let debridge_id = crate::debridge_id(U256::from(1337u64), token());
        let amount = U256::from(100u64);
        let chain_from = U256::from(1337u64);
        let chain_to = U256::from(1338u64);
        let nonce = U256::from(0u64);
        let receiver = Address::repeat_byte(0xAB).to_vec();
        let domain = B256::repeat_byte(0xD0);
        let id =
            crate::submission_id(domain, debridge_id, amount, chain_from, chain_to, nonce, &receiver);
        SubmissionRecord {
            submission_id: format!("{id:#x}"),
            bridge_domain: format!("{domain:#x}"),
            debridge_id: format!("{debridge_id:#x}"),
            amount: amount.to_string(),
            chain_id_from: 1337,
            chain_id_to: 1338,
            nonce: 0,
            receiver: format!("0x{}", hex::encode(&receiver)),
            auto_params: "0x".to_string(),
            native_sender: "0x".to_string(),
            token: format!("{:#x}", token()),
            signatures: vec![],
            cancel_signatures: vec![],
            refund_signatures: vec![],
        }
    }

    fn sign(signer: &PrivateKeySigner, id_hex: &str) -> SignerSig {
        let id = B256::from_str(id_hex).unwrap();
        let sig = signer.sign_message_sync(id.as_slice()).unwrap();
        SignerSig { signer: format!("{:#x}", signer.address()), signature: encode_sig(&sig) }
    }

    /// Sign the digest for a specific domain (what the validator does for a
    /// cancel/refund attestation).
    fn sign_kind(signer: &PrivateKeySigner, id_hex: &str, kind: SigKind) -> SignerSig {
        let id = B256::from_str(id_hex).unwrap();
        let sig = signer.sign_message_sync(kind.digest(id).as_slice()).unwrap();
        SignerSig { signer: format!("{:#x}", signer.address()), signature: encode_sig(&sig) }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut d = std::env::temp_dir();
        d.push(format!("bridge-store-test-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// M-2: the file store refuses a 65th DISTINCT signer but still accepts a
    /// re-POST from any signer already on the record.
    #[test]
    fn signer_count_per_submission_is_capped() {
        let dir = tmp_dir("sig-cap");
        let record = make_record();
        let id = record.submission_id.clone();
        let mut signers = Vec::new();
        for _ in 0..MAX_SIGNATURES_PER_SUBMISSION {
            let s = PrivateKeySigner::random();
            upsert_signature(&dir, record.clone(), sign(&s, &id)).unwrap();
            signers.push(s);
        }
        let stored = load(&dir, &id).unwrap().unwrap();
        assert_eq!(stored.signatures.len(), MAX_SIGNATURES_PER_SUBMISSION);

        // One more distinct signer is refused...
        let extra = PrivateKeySigner::random();
        let err = upsert_signature(&dir, record.clone(), sign(&extra, &id)).unwrap_err();
        assert!(matches!(err, StoreError::TooManySignatures("transfer")), "{err}");
        assert_eq!(load(&dir, &id).unwrap().unwrap().signatures.len(), MAX_SIGNATURES_PER_SUBMISSION);

        // ...but an existing signer re-posting is still fine (idempotent).
        upsert_signature(&dir, record.clone(), sign(&signers[3], &id)).unwrap();

        // Attestation domains are capped independently of the transfer set.
        for _ in 0..MAX_SIGNATURES_PER_SUBMISSION {
            let s = PrivateKeySigner::random();
            upsert_attestation(&dir, &id, SigKind::Cancel, sign_kind(&s, &id, SigKind::Cancel)).unwrap();
        }
        let err = upsert_attestation(&dir, &id, SigKind::Cancel, sign_kind(&extra, &id, SigKind::Cancel))
            .unwrap_err();
        assert!(matches!(err, StoreError::TooManySignatures("cancel")), "{err}");
        // A refund attestation is a different domain and is not blocked by it.
        upsert_attestation(&dir, &id, SigKind::Refund, sign_kind(&extra, &id, SigKind::Refund)).unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn happy_path_two_validators_merge_and_dedupe() {
        let dir = tmp_dir("happy");
        let v1: PrivateKeySigner = PrivateKeySigner::random();
        let v2: PrivateKeySigner = PrivateKeySigner::random();
        let rec = make_record();

        let r = upsert_signature(&dir, rec.clone(), sign(&v1, &rec.submission_id)).unwrap();
        assert_eq!(r.signatures.len(), 1);
        // same validator again -> deduped
        let r = upsert_signature(&dir, rec.clone(), sign(&v1, &rec.submission_id)).unwrap();
        assert_eq!(r.signatures.len(), 1);
        // second validator -> merged
        let r = upsert_signature(&dir, rec.clone(), sign(&v2, &rec.submission_id)).unwrap();
        assert_eq!(r.signatures.len(), 2);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_id_param_mismatch() {
        // V1 root cause: a record whose submission_id is NOT the hash of its params.
        let dir = tmp_dir("idmismatch");
        let v1 = PrivateKeySigner::random();
        let mut rec = make_record();
        // tamper the amount but keep the (now stale) submission_id
        rec.amount = "999999".to_string();
        let err = upsert_signature(&dir, rec.clone(), sign(&v1, &rec.submission_id)).unwrap_err();
        assert!(matches!(err, StoreError::IdMismatch { .. }), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_param_poisoning_of_existing_record() {
        // The headline attack: legit record gets real sigs, then an attacker POSTs
        // the SAME submission_id with different params. Must be rejected, leaving
        // the genuine record intact.
        let dir = tmp_dir("poison");
        let v1 = PrivateKeySigner::random();
        let rec = make_record();
        upsert_signature(&dir, rec.clone(), sign(&v1, &rec.submission_id)).unwrap();

        // attacker reuses the id but lies about the receiver; with a forged sig
        let mut evil = rec.clone();
        evil.receiver = format!("0x{}", hex::encode(Address::repeat_byte(0xEE).to_vec()));
        // keep submission_id pointing at the real file
        let attacker = PrivateKeySigner::random();
        let err = upsert_signature(&dir, evil.clone(), sign(&attacker, &evil.submission_id))
            .unwrap_err();
        // recompute(evil params) != submission_id -> IdMismatch (id<->param binding)
        assert!(matches!(err, StoreError::IdMismatch { .. }), "got {err:?}");

        // the genuine record on disk is untouched
        let on_disk = load(&dir, &rec.submission_id).unwrap().unwrap();
        assert_eq!(on_disk.receiver, rec.receiver);
        assert_eq!(on_disk.signatures.len(), 1);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_forged_signature() {
        // V2: signer field says V1 but the signature is from someone else.
        let dir = tmp_dir("forged");
        let v1 = PrivateKeySigner::random();
        let other = PrivateKeySigner::random();
        let rec = make_record();

        let mut bad = sign(&other, &rec.submission_id);
        bad.signer = format!("{:#x}", v1.address()); // claim to be V1
        let err = upsert_signature(&dir, rec.clone(), bad).unwrap_err();
        assert!(matches!(err, StoreError::SignerMismatch { .. }), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_token_not_matching_debridge_id() {
        // `token` rides outside the submissionId, so it gets its own binding:
        // swapping in a different (e.g. more valuable) asset must be rejected,
        // or the keeper would build a refund against the wrong token.
        let dir = tmp_dir("tokenbind");
        let v1 = PrivateKeySigner::random();
        let mut rec = make_record();
        rec.token = format!("{:#x}", Address::repeat_byte(0x22));
        let err = upsert_signature(&dir, rec.clone(), sign(&v1, &rec.submission_id)).unwrap_err();
        assert!(matches!(err, StoreError::TokenMismatch { .. }), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn attestations_are_domain_separated() {
        // THE refund-path invariant: a validator's transfer signature must not be
        // usable as a cancel (which burns the transfer on the destination) or as a
        // refund (which pays out on the source). Each domain is its own quorum.
        let dir = tmp_dir("domains");
        let v1 = PrivateKeySigner::random();
        let rec = make_record();
        upsert_signature(&dir, rec.clone(), sign(&v1, &rec.submission_id)).unwrap();

        for kind in [SigKind::Cancel, SigKind::Refund] {
            // the transfer signature replayed into another domain
            let replay = sign(&v1, &rec.submission_id);
            let err = upsert_attestation(&dir, &rec.submission_id, kind, replay).unwrap_err();
            assert!(
                matches!(err, StoreError::SignerMismatch { .. } | StoreError::BadSignature),
                "{kind:?} accepted a replayed transfer signature: {err:?}"
            );

            // the correctly-domained signature is accepted
            let good = sign_kind(&v1, &rec.submission_id, kind);
            let out = upsert_attestation(&dir, &rec.submission_id, kind, good.clone()).unwrap();
            let bucket = match kind {
                SigKind::Cancel => &out.cancel_signatures,
                SigKind::Refund => &out.refund_signatures,
                SigKind::Transfer => unreachable!(),
            };
            assert_eq!(bucket.len(), 1, "{kind:?} attestation not stored");

            // and deduped by signer
            let again = upsert_attestation(&dir, &rec.submission_id, kind, good).unwrap();
            let bucket = match kind {
                SigKind::Cancel => &again.cancel_signatures,
                SigKind::Refund => &again.refund_signatures,
                SigKind::Transfer => unreachable!(),
            };
            assert_eq!(bucket.len(), 1, "{kind:?} attestation not deduped");
        }

        // a cancel attestation must not count as a refund attestation either
        let cancel_sig = sign_kind(&v1, &rec.submission_id, SigKind::Cancel);
        let err = upsert_attestation(&dir, &rec.submission_id, SigKind::Refund, cancel_sig);
        // v1 already has a refund attestation stored, so dedupe would mask a
        // failure — assert on a fresh signer instead.
        drop(err);
        let v2 = PrivateKeySigner::random();
        let cancel_sig = sign_kind(&v2, &rec.submission_id, SigKind::Cancel);
        let err = upsert_attestation(&dir, &rec.submission_id, SigKind::Refund, cancel_sig).unwrap_err();
        assert!(
            matches!(err, StoreError::SignerMismatch { .. } | StoreError::BadSignature),
            "a cancel attestation was accepted as a refund: {err:?}"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn attestation_requires_an_existing_record() {
        // An attestation must never bootstrap a record: the id<->params binding
        // is the only way one comes into existence.
        let dir = tmp_dir("noboot");
        let v1 = PrivateKeySigner::random();
        let rec = make_record();
        let sig = sign_kind(&v1, &rec.submission_id, SigKind::Cancel);
        let err = upsert_attestation(&dir, &rec.submission_id, SigKind::Cancel, sig).unwrap_err();
        assert!(matches!(err, StoreError::BadField("submission_id")), "got {err:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn rejects_garbage_signature() {
        let dir = tmp_dir("garbage");
        let v1 = PrivateKeySigner::random();
        let rec = make_record();
        let junk = SignerSig {
            signer: format!("{:#x}", v1.address()),
            signature: format!("0x{}", hex::encode([7u8; 65])),
        };
        let err = upsert_signature(&dir, rec.clone(), junk).unwrap_err();
        assert!(
            matches!(err, StoreError::BadSignature | StoreError::SignerMismatch { .. }),
            "got {err:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ---------------------------------------------------------------------
    // Signature canonicalisation (the one-validator halt)
    // ---------------------------------------------------------------------

    /// secp256k1 group order, for building the malleated `n - s` twin.
    const SECP256K1_N: U256 = U256::from_limbs([
        0xBFD25E8CD0364141,
        0xBAAEDCE6AF48A03B,
        0xFFFFFFFFFFFFFFFE,
        0xFFFFFFFFFFFFFFFF,
    ]);
    /// OpenZeppelin `ECDSA.sol`'s rejection threshold: `s > n/2` reverts.
    const SECP256K1_HALF_N: U256 = U256::from_limbs([
        0xDFE92F46681B20A0,
        0x5D576E7357A4501D,
        0xFFFFFFFFFFFFFFFF,
        0x7FFFFFFFFFFFFFFF,
    ]);

    /// Re-encode `sig` in a form that recovers to the same signer but that the
    /// Gate's `ECDSA.recover` refuses: high `s` with the parity flipped to match.
    fn malleate(sig: &SignerSig) -> SignerSig {
        let raw = hex::decode(sig.signature.trim_start_matches("0x")).unwrap();
        let s_low = U256::from_be_slice(&raw[32..64]);
        let s_high = SECP256K1_N - s_low;
        let mut out = raw.clone();
        out[32..64].copy_from_slice(&s_high.to_be_bytes::<32>());
        out[64] = if raw[64] == 27 { 28 } else { 27 };
        SignerSig { signer: sig.signer.clone(), signature: format!("0x{}", hex::encode(out)) }
    }

    /// Re-encode `sig` with `v` in {0,1} — the other form alloy accepts off-chain
    /// and `ECDSA.recover` rejects on-chain.
    fn v_zero_one(sig: &SignerSig) -> SignerSig {
        let mut raw = hex::decode(sig.signature.trim_start_matches("0x")).unwrap();
        raw[64] -= 27;
        SignerSig { signer: sig.signer.clone(), signature: format!("0x{}", hex::encode(raw)) }
    }

    fn s_word(sig: &SignerSig) -> U256 {
        let raw = hex::decode(sig.signature.trim_start_matches("0x")).unwrap();
        U256::from_be_slice(&raw[32..64])
    }

    fn v_byte(sig: &SignerSig) -> u8 {
        let raw = hex::decode(sig.signature.trim_start_matches("0x")).unwrap();
        raw[64]
    }

    /// The premise: both malformed encodings still AUTHENTICATE. That is why the
    /// defect existed at all — `verify_signature` never had a reason to complain.
    #[test]
    fn non_canonical_encodings_still_authenticate() {
        let v1 = PrivateKeySigner::random();
        let rec = make_record();
        let id = B256::from_str(&rec.submission_id).unwrap();
        let good = sign(&v1, &rec.submission_id);

        for variant in [malleate(&good), v_zero_one(&good)] {
            assert!(
                verify_signature(id, &variant).is_ok(),
                "alloy normalises before recovering, so this authenticates"
            );
        }
    }

    /// THE regression. A high-`s` signature recovers to its signer off-chain and
    /// reverts `ECDSAInvalidSignatureS` on-chain, and the keeper submits every
    /// member signature in ONE array — so one such entry used to make `claim`,
    /// `cancel` and `refund` revert forever. One validator out of N could freeze
    /// the bridge, which is precisely what a threshold exists to prevent.
    #[test]
    fn a_high_s_signature_is_stored_in_the_form_the_gate_accepts() {
        let dir = tmp_dir("canon-high-s");
        let v1 = PrivateKeySigner::random();
        let rec = make_record();

        let good = sign(&v1, &rec.submission_id);
        let poisoned = malleate(&good);
        assert!(s_word(&poisoned) > SECP256K1_HALF_N, "premise: the Gate would revert on this");

        let stored = upsert_signature(&dir, rec.clone(), poisoned).unwrap();
        let kept = &stored.signatures[0];

        assert!(s_word(kept) <= SECP256K1_HALF_N, "stored signature must be low-`s`");
        assert!(matches!(v_byte(kept), 27 | 28), "stored `v` must be 27/28");
        assert_eq!(kept.signature, good.signature, "and it is the signer's own canonical form");

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The `v ∈ {0,1}` twin of the above, rejected on-chain as
    /// `ECDSAInvalidSignature` rather than `...SignatureS`, same consequence.
    #[test]
    fn a_v_zero_one_signature_is_stored_in_the_form_the_gate_accepts() {
        let dir = tmp_dir("canon-v01");
        let v1 = PrivateKeySigner::random();
        let rec = make_record();

        let good = sign(&v1, &rec.submission_id);
        let stored = upsert_signature(&dir, rec.clone(), v_zero_one(&good)).unwrap();

        assert_eq!(stored.signatures[0].signature, good.signature);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Cancel and refund reach the same on-chain verifier, so a poisoned
    /// attestation would take out the recovery path the claim halt is supposed to
    /// leave open. Both domains get the same treatment.
    #[test]
    fn attestations_are_canonicalised_too() {
        let dir = tmp_dir("canon-attest");
        let v1 = PrivateKeySigner::random();
        let rec = make_record();
        upsert_signature(&dir, rec.clone(), sign(&v1, &rec.submission_id)).unwrap();

        for kind in [SigKind::Cancel, SigKind::Refund] {
            let good = sign_kind(&v1, &rec.submission_id, kind);
            let out =
                upsert_attestation(&dir, &rec.submission_id, kind, malleate(&good)).unwrap();
            let bucket = match kind {
                SigKind::Cancel => &out.cancel_signatures,
                SigKind::Refund => &out.refund_signatures,
                SigKind::Transfer => unreachable!(),
            };
            assert_eq!(bucket[0].signature, good.signature, "{} attestation", kind.as_str());
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Canonicalising must never change WHO signed — the keeper sorts by recovered
    /// signer and the Gate dedupes on that ordering.
    #[test]
    fn canonicalising_preserves_the_recovered_signer() {
        let v1 = PrivateKeySigner::random();
        let rec = make_record();
        let id = B256::from_str(&rec.submission_id).unwrap();
        let good = sign(&v1, &rec.submission_id);

        for variant in [good.clone(), malleate(&good), v_zero_one(&good)] {
            let canonical = canonical_signature(&variant).unwrap();
            assert_eq!(verify_signature(id, &canonical).unwrap(), v1.address());
        }
    }

    /// A signature that is not 65 bytes (or carries an impossible `v`) has no
    /// canonical form; it must error rather than be silently reshaped.
    #[test]
    fn canonicalising_refuses_a_malformed_signature() {
        let short = SignerSig {
            signer: format!("{:#x}", Address::repeat_byte(1)),
            signature: "0xdeadbeef".into(),
        };
        assert!(canonical_signature(&short).is_err());
    }
}
