//! Allowlists — which tokens and which source→target chain pairs may bridge.
//!
//! These types are the on-wire shape shared by the Postgres-backed `sig-store`
//! (server) and the `RemoteStore` HTTP client the validator/keeper use to fetch
//! the lists. The DB (`bridge-db`) is the source of truth; everyone else mirrors
//! it into an in-memory [`Allowlist`] for fast membership checks.
//!
//! ## Semantics: the allowlist is OPT-IN
//!
//! An *empty* token list means "no token restriction configured" — every token
//! is allowed. The first row you add flips it to deny-by-default: only listed
//! tokens pass. The chain list behaves the same way, independently. This keeps
//! every existing end-to-end script working until an operator deliberately seeds
//! the lists, then enforcement turns on with no code change.
//!
//! The sharp edge is the way back out, which is why `bridge_db` refuses to
//! delete the LAST row of either list. Pruning row by row would otherwise cross
//! from deny-by-default to allow-everything the moment the final row went — no
//! error, no log, and both enforcement points (the validator before it signs,
//! the keeper before it claims) turned off at once, since they build their view
//! from the same fetch. Turning enforcement off stays possible; it just has to
//! be done to the table, not stumbled into one DELETE at a time.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// One whitelisted ERC-20, keyed by `(chain_id, token)`. `debridge_id` is the
/// `keccak256(chainId, token)` the Gate emits in `Sent` — precomputed so the
/// validator/keeper can match an event by a single hash lookup.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedToken {
    pub chain_id: u64,
    /// `0x`-prefixed token address (lowercased).
    pub token: String,
    /// `0x`-prefixed `keccak256(abi.encodePacked(chain_id, token))` (lowercased).
    pub debridge_id: String,
    #[serde(default)]
    pub symbol: Option<String>,
}

/// One whitelisted directed chain pair: transfers from `chain_id_from` to
/// `chain_id_to` are permitted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AllowedChain {
    pub chain_id_from: u64,
    pub chain_id_to: u64,
}

/// Request body to add a token to the allowlist; the `debridge_id` is derived
/// server-side so a caller can't pin a token onto the wrong hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AddTokenRequest {
    pub chain_id: u64,
    pub token: String,
    #[serde(default)]
    pub symbol: Option<String>,
}

/// Request body to mark a submission claimed (keeper → sig-store).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimedRequest {
    /// `0x`-prefixed claim transaction hash on the target chain.
    pub claim_tx: String,
}

/// Request body to post a cancel/refund attestation (validator → sig-store).
/// The signature is verified against `kind`'s own digest server-side, so a
/// mislabelled or replayed signature is rejected rather than miscounted.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AttestationRequest {
    /// `cancel` | `refund`.
    pub kind: String,
    pub signer: String,
    pub signature: String,
}


/// A submission as it appears in the transaction-history view: the transfer
/// parameters plus its lifecycle status and timing. Distinct from
/// [`crate::store::SubmissionRecord`] (which carries the raw signatures the
/// keeper needs) so history queries stay cheap and read-only.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubmissionHistory {
    pub submission_id: String,
    pub debridge_id: String,
    pub amount: String,
    pub chain_id_from: u64,
    pub chain_id_to: u64,
    pub nonce: u64,
    pub receiver: String,
    /// `signed` once the transfer has been observed (regardless of signature
    /// count — see the indexer, which inserts on `Sent` before any validator has
    /// acted) or at least one validator has attested; `claimed` after a keeper
    /// executes `claim()` on the target chain.
    pub status: String,
    /// Target-chain claim tx hash, once claimed.
    pub claim_tx: Option<String>,
    pub signature_count: i64,
    /// RFC-3339 timestamps.
    pub created_at: String,
    pub updated_at: String,
    /// True once this transfer has entered the refund lifecycle at all — i.e.
    /// `refund_status != "none"`. A nomination, not an authorisation.
    #[serde(default)]
    pub stuck: bool,
    /// Refund lifecycle: `none` | `eligible` | `cancelled` | `refunded`.
    ///
    /// `eligible` — past the timeout and still unclaimed, so validators may
    /// attest a cancel. `cancelled` — burned on the destination chain, which is
    /// what unlocks refund attestations. `refunded` — funds returned on the
    /// source chain. Cleared back to `none` if a stuck transfer is claimed after
    /// all.
    #[serde(default = "default_refund_status")]
    pub refund_status: String,
    /// Source-chain `Gate.refund` tx hash, once refunded.
    #[serde(default)]
    pub refund_tx: Option<String>,
    /// Destination-chain `Gate.cancel` tx hash, once burned.
    #[serde(default)]
    pub cancel_tx: Option<String>,
    /// The source-chain ERC-20 that was locked (needed to build `Gate.refund`).
    #[serde(default)]
    pub token: Option<String>,
    /// How many validators have attested the destination cancel.
    #[serde(default)]
    pub cancel_signature_count: i64,
    /// How many validators have attested the source refund.
    #[serde(default)]
    pub refund_signature_count: i64,
    /// If this transfer was a `SwapRouter.swapAndBridge` (swap-then-bridge) rather
    /// than a plain bridge send, its swap intent/outcome.
    #[serde(default)]
    pub swap_intent: Option<SwapBridgeInfo>,
    /// The keeper's OWN report of the claim tx it submitted (M-1, audit
    /// 2026-09-09). Advisory only: `status`/`claim_tx` above come from the
    /// indexer's on-chain observation, and no queue reads this field. Useful to
    /// spot a keeper that believes it claimed something the chain never saw.
    #[serde(default)]
    pub keeper_claim_tx: Option<String>,
}

fn default_refund_status() -> String {
    "none".to_string()
}

/// One same-chain swap (`SwapPool.Swapped`), mirrored into the DB by the indexer.
/// Same-chain swaps are atomic (revert on failure), so unlike a bridge transfer
/// there is no "stuck" state to track here — only completed swaps are ever emitted.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapRecord {
    pub chain_id: u64,
    /// `0x`-prefixed transaction hash.
    pub tx_hash: String,
    pub log_index: i64,
    pub sender: String,
    pub receiver: String,
    pub token_in: String,
    pub token_out: String,
    /// decimal strings (uint256)
    pub amount_in: String,
    pub amount_out: String,
    pub block_number: u64,
    /// RFC-3339 timestamp.
    pub created_at: String,
}

/// The swap intent (source leg) and outcome (destination leg) of a
/// `SwapRouter.swapAndBridge` transfer, keyed by the bridge `submissionId`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SwapBridgeInfo {
    pub token_in: String,
    pub amount_in: String,
    pub stable_out: String,
    pub final_token: String,
    pub final_receiver: String,
    /// Set once the destination leg has run (`Finalized`/`FinalizeFallback`).
    pub finalize_tx: Option<String>,
    pub finalize_amount_out: Option<String>,
    /// True if the destination swap failed and the router fell back to
    /// delivering the stable itself (`FinalizeFallback`).
    pub finalize_fallback: Option<bool>,
    pub finalized_at: Option<String>,
}

/// In-memory mirror of the allowlists, built from the fetched rows for O(1)
/// membership checks on the hot path (validator signing / keeper claiming).
#[derive(Clone, Debug, Default)]
pub struct Allowlist {
    /// Allowed `debridge_id`s (lowercased `0x`-hex).
    debridge_ids: HashSet<String>,
    /// Allowed `(chain_id_from, chain_id_to)` pairs.
    chains: HashSet<(u64, u64)>,
}

impl Allowlist {
    /// Build from the lists fetched from the store.
    pub fn from_parts(tokens: &[AllowedToken], chains: &[AllowedChain]) -> Self {
        Allowlist {
            debridge_ids: tokens.iter().map(|t| t.debridge_id.to_ascii_lowercase()).collect(),
            chains: chains.iter().map(|c| (c.chain_id_from, c.chain_id_to)).collect(),
        }
    }

    /// Opt-in semantics: an empty token list allows everything; otherwise only
    /// listed `debridge_id`s pass. `debridge_id` is matched case-insensitively.
    pub fn token_allowed(&self, debridge_id: &str) -> bool {
        self.debridge_ids.is_empty() || self.debridge_ids.contains(&debridge_id.to_ascii_lowercase())
    }

    /// Opt-in semantics: an empty chain list allows every pair; otherwise only
    /// listed `(from, to)` pairs pass.
    pub fn chain_allowed(&self, from: u64, to: u64) -> bool {
        self.chains.is_empty() || self.chains.contains(&(from, to))
    }
}
