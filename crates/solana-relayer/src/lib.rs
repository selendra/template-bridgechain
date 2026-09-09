//! solana-relayer — the Solana leg's off-chain runner (finding M-3).
//!
//! Runs as its OWN process rather than inside `validator`, and has to: adding
//! `solana-client` to the validator fails to resolve, because Solana 1.18 pins
//! `ed25519-dalek 1.0.1 -> curve25519-dalek 3.2.1 -> zeroize <1.4` while alloy
//! requires `zeroize ^1.5`. The two dependency trees are mutually exclusive.
//! Splitting the process is the correct boundary anyway — it shares no chain
//! client with the EVM side, only the sig-store, which it reaches over HTTP.
//!
//! It performs the validator's job for Solana: scan the gate for `Sent`,
//! independently recompute the submissionId, sign it with the SAME secp256k1 key
//! the EVM validator uses, and store the signature.
//!
//! This is a library so the `gate-admin` binary shares one copy of the gate's
//! account layout and digest domains with the runner ([`gate`]) rather than
//! keeping its own — the duplication that let `bridge_domain` break both.

pub mod config;
pub mod evm;
pub mod gate;
pub mod refund;
pub mod source;
pub mod state;
pub mod store;
pub mod target;
