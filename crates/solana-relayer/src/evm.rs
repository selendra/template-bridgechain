//! A read-only view of an EVM `Gate`, over raw JSON-RPC (audit round 4, M-4 / M-13).
//!
//! This crate cannot link alloy (its `zeroize ^1.5` cannot coexist with
//! `solana-client`'s `<1.4` pin — see `Cargo.toml`), so the three getters the
//! refund attester needs are encoded by hand: `executed(bytes32)`,
//! `cancelled(bytes32)` and `sentBy(bytes32)`, each a 4-byte selector plus one
//! word. Nothing here signs or sends; it only reads, at a confirmed block.
//!
//! It mirrors `crates/validator/src/refund.rs::GateReader` exactly — including
//! the aged-block search — because the attestation it feeds must follow the same
//! rules as the EVM validators' or the two halves of the mesh would disagree
//! about when a transfer may be burned.

use std::time::Duration;

use serde_json::{json, Value};

use crate::config::EvmReader;

/// What the EVM destination says about a submission at a confirmed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvmDestinationState {
    pub executed: bool,
    pub cancelled: bool,
}

/// What an EVM source gate says about a submission at a confirmed block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct EvmSourceState {
    /// `sentBy(id) != 0` — this gate really locked the funds.
    pub sent: bool,
    pub refunded: bool,
}

/// `keccak(signature)[..4]`.
pub fn selector(signature: &str) -> [u8; 4] {
    let h = bridge_solana::hash::keccak(signature.as_bytes());
    [h[0], h[1], h[2], h[3]]
}

/// Calldata for a `fn(bytes32)` getter.
pub fn encode_bytes32_call(signature: &str, id: &[u8; 32]) -> Vec<u8> {
    let mut d = Vec::with_capacity(36);
    d.extend_from_slice(&selector(signature));
    d.extend_from_slice(id);
    d
}

/// Decode an ABI `bool` return word. Anything but a single word that is 0 or 1
/// is an error — a getter that returns nothing (wrong address, not a gate) must
/// never read as `false`, because `false` is the answer that authorises a burn.
pub fn decode_bool(ret: &[u8]) -> anyhow::Result<bool> {
    if ret.len() != 32 {
        anyhow::bail!("expected a 32-byte bool word, got {} bytes", ret.len());
    }
    if ret[..31].iter().any(|b| *b != 0) || ret[31] > 1 {
        anyhow::bail!("return word is not a bool");
    }
    Ok(ret[31] == 1)
}

/// Decode an ABI `address` return word to "is it non-zero?".
pub fn decode_address_is_set(ret: &[u8]) -> anyhow::Result<bool> {
    if ret.len() != 32 {
        anyhow::bail!("expected a 32-byte address word, got {} bytes", ret.len());
    }
    if ret[..12].iter().any(|b| *b != 0) {
        anyhow::bail!("return word is not an address");
    }
    Ok(ret[12..].iter().any(|b| *b != 0))
}

/// Parse a `0x`-hex JSON-RPC quantity.
fn quantity(v: &Value) -> anyhow::Result<u64> {
    let s = v.as_str().ok_or_else(|| anyhow::anyhow!("quantity is not a string: {v}"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    Ok(u64::from_str_radix(if s.is_empty() { "0" } else { s }, 16)?)
}

pub struct GateReader {
    pub chain_id: u64,
    gate: String,
    rpc: String,
    block_confirmation: u64,
    client: reqwest::Client,
}

impl GateReader {
    pub fn new(cfg: &EvmReader) -> anyhow::Result<Self> {
        let gate = cfg.gate.trim().to_ascii_lowercase();
        let hex = gate.strip_prefix("0x").unwrap_or(&gate);
        anyhow::ensure!(
            hex.len() == 40 && hex.chars().all(|c| c.is_ascii_hexdigit()),
            "evm reader {}: gate {:?} is not a 20-byte address",
            cfg.chain_id,
            cfg.gate
        );
        Ok(GateReader {
            chain_id: cfg.chain_id,
            gate: format!("0x{hex}"),
            rpc: cfg.rpc_url()?,
            block_confirmation: cfg.block_confirmation,
            // Bounded: this loop must never hang on a dead endpoint (M-9's
            // lesson for the store client applies to the chain client too).
            client: reqwest::Client::builder()
                .timeout(Duration::from_secs(20))
                .build()
                .unwrap_or_default(),
        })
    }

    async fn rpc(&self, method: &str, params: Value) -> anyhow::Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let res = self.client.post(&self.rpc).json(&body).send().await?;
        if !res.status().is_success() {
            anyhow::bail!("evm rpc {method} on chain {}: HTTP {}", self.chain_id, res.status());
        }
        // Cap the body: an answer to these calls is a few hundred bytes.
        let bytes = res.bytes().await?;
        if bytes.len() > 1 << 20 {
            anyhow::bail!("evm rpc {method}: oversized response");
        }
        let v: Value = serde_json::from_slice(&bytes)?;
        if let Some(err) = v.get("error") {
            anyhow::bail!("evm rpc {method} on chain {}: {err}", self.chain_id);
        }
        v.get("result").cloned().ok_or_else(|| anyhow::anyhow!("evm rpc {method}: no result"))
    }

    /// The newest block we are willing to trust (tip minus the confirmation
    /// buffer). Reading `executed` at the tip would let a reorg make a claimed
    /// transfer look unclaimed — and this loop would then attest a cancel for a
    /// transfer that was actually paid.
    pub async fn confirmed_block(&self) -> anyhow::Result<u64> {
        let latest = quantity(&self.rpc("eth_blockNumber", json!([])).await?)?;
        Ok(latest.saturating_sub(self.block_confirmation))
    }

    async fn block_timestamp(&self, number: u64) -> anyhow::Result<i64> {
        let block = self
            .rpc("eth_getBlockByNumber", json!([format!("0x{number:x}"), false]))
            .await?;
        if block.is_null() {
            anyhow::bail!("block {number} vanished");
        }
        Ok(quantity(&block["timestamp"])? as i64)
    }

    async fn call(&self, data: &[u8], block: u64) -> anyhow::Result<Vec<u8>> {
        let ret = self
            .rpc(
                "eth_call",
                json!([{ "to": self.gate, "data": format!("0x{}", hex::encode(data)) },
                       format!("0x{block:x}")]),
            )
            .await?;
        let s = ret.as_str().ok_or_else(|| anyhow::anyhow!("eth_call result is not hex"))?;
        Ok(hex::decode(s.strip_prefix("0x").unwrap_or(s))?)
    }

    /// Destination-side view at a confirmed block.
    pub async fn destination_state(&self, id: &[u8; 32]) -> anyhow::Result<EvmDestinationState> {
        let block = self.confirmed_block().await?;
        let executed = decode_bool(&self.call(&encode_bytes32_call("executed(bytes32)", id), block).await?)?;
        let cancelled =
            decode_bool(&self.call(&encode_bytes32_call("cancelled(bytes32)", id), block).await?)?;
        Ok(EvmDestinationState { executed, cancelled })
    }

    /// Source-side view at a confirmed block: did this gate lock `id`
    /// (`sentBy != 0`), and has it already paid it back (`refunded`)?
    pub async fn source_state(&self, id: &[u8; 32]) -> anyhow::Result<EvmSourceState> {
        let block = self.confirmed_block().await?;
        let sent =
            decode_address_is_set(&self.call(&encode_bytes32_call("sentBy(bytes32)", id), block).await?)?;
        let refunded =
            decode_bool(&self.call(&encode_bytes32_call("refunded(bytes32)", id), block).await?)?;
        Ok(EvmSourceState { sent, refunded })
    }

    /// A block provably at least `timeout_secs` old by the chain's OWN clock —
    /// `None` when the chain has no block that old yet. Conservative: steps back
    /// exponentially, so overshooting only lengthens the effective timeout.
    pub async fn aged_block(&self, timeout_secs: i64) -> anyhow::Result<Option<u64>> {
        let head_num = self.confirmed_block().await?;
        let target = self.block_timestamp(head_num).await?.saturating_sub(timeout_secs);
        let mut step: u64 = ((timeout_secs.max(1) as u64) / 12).max(1);
        for _ in 0..24 {
            let Some(candidate) = head_num.checked_sub(step) else { return Ok(None) };
            if self.block_timestamp(candidate).await? <= target {
                return Ok(Some(candidate));
            }
            step = step.saturating_mul(2);
        }
        Ok(None)
    }

    /// Was `id` already locked on this gate as of `block`? `sentBy` is written in
    /// the same transaction that locks the funds, so a non-zero value at a
    /// historical height is the chain's own statement that the deposit existed by
    /// then — an authenticated age check that owes nothing to the store.
    pub async fn was_sent_by_block(&self, id: &[u8; 32], block: u64) -> anyhow::Result<bool> {
        decode_address_is_set(&self.call(&encode_bytes32_call("sentBy(bytes32)", id), block).await?)
    }

    /// This attester's own answer to "has the unclaimed timeout elapsed on the
    /// source chain?" — `false` whenever it cannot be shown on-chain.
    pub async fn aged_out(&self, id: &[u8; 32], timeout_secs: i64) -> anyhow::Result<bool> {
        match self.aged_block(timeout_secs).await? {
            Some(block) => self.was_sent_by_block(id, block).await,
            None => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three getters' selectors, pinned to `cast sig` values so a typo in a
    /// signature string cannot silently call a different function (an unknown
    /// selector returns empty data, which `decode_bool` refuses — but pin it
    /// anyway).
    #[test]
    fn selectors_match_the_gate_abi() {
        // `cast sig` ground truth.
        assert_eq!(hex::encode(selector("executed(bytes32)")), "a9fcfb33");
        assert_eq!(hex::encode(selector("cancelled(bytes32)")), "2ac12622");
        assert_eq!(hex::encode(selector("sentBy(bytes32)")), "7b372346");
        assert_eq!(hex::encode(selector("refunded(bytes32)")), "f05e0f7e");
        // Structural pins: 4 bytes + one word, id verbatim.
        let id = [0xABu8; 32];
        let call = encode_bytes32_call("sentBy(bytes32)", &id);
        assert_eq!(call.len(), 36);
        assert_eq!(&call[4..], &id);
        // Distinct functions, distinct selectors.
        assert_ne!(selector("executed(bytes32)"), selector("cancelled(bytes32)"));
        assert_ne!(selector("executed(bytes32)"), selector("sentBy(bytes32)"));
    }

    /// `false` is the answer that authorises a burn, so it may only come from a
    /// genuine bool word — never from empty data or a revert.
    #[test]
    fn a_bool_is_only_decoded_from_a_real_bool_word() {
        let mut t = [0u8; 32];
        t[31] = 1;
        assert_eq!(decode_bool(&t).unwrap(), true);
        assert_eq!(decode_bool(&[0u8; 32]).unwrap(), false);
        assert!(decode_bool(&[]).is_err(), "empty return (wrong address) must not read as false");
        assert!(decode_bool(&[0u8; 31]).is_err());
        let mut junk = [0u8; 32];
        junk[0] = 1;
        assert!(decode_bool(&junk).is_err());
    }

    #[test]
    fn a_sent_by_word_is_set_only_for_a_non_zero_address() {
        assert_eq!(decode_address_is_set(&[0u8; 32]).unwrap(), false);
        let mut w = [0u8; 32];
        w[31] = 0x11;
        assert_eq!(decode_address_is_set(&w).unwrap(), true);
        assert!(decode_address_is_set(&[]).is_err());
        let mut junk = [0u8; 32];
        junk[0] = 1; // not an address-shaped word
        assert!(decode_address_is_set(&junk).is_err());
    }

    #[test]
    fn quantities_parse_as_hex() {
        assert_eq!(quantity(&json!("0x10")).unwrap(), 16);
        assert_eq!(quantity(&json!("0x0")).unwrap(), 0);
        assert!(quantity(&json!(16)).is_err(), "JSON numbers are not RPC quantities");
    }

    #[test]
    fn the_gate_address_is_validated() {
        let ok = EvmReader {
            chain_id: 1,
            gate: "0x0000000000000000000000000000000000000001".into(),
            rpc: Some("http://x".into()),
            rpc_env: None,
            block_confirmation: 1,
        };
        assert!(GateReader::new(&ok).is_ok());
        let bad = EvmReader { gate: "0x1234".into(), ..ok.clone() };
        assert!(GateReader::new(&bad).is_err());
    }
}
