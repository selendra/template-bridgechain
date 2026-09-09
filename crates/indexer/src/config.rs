use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Postgres connection string. Falls back to the `DATABASE_URL` env var.
    #[serde(default)]
    pub database_url: Option<String>,
    /// One block per chain to mirror events from.
    pub chains: Vec<ChainCfg>,
    /// How long an unclaimed transfer sits before being flagged refund-eligible,
    /// which nominates it for a validator cancel attestation (the validators
    /// re-check the destination on-chain before acting). See
    /// `bridge_db::Db::sweep_refund_eligible`.
    #[serde(default = "default_refund_timeout_secs")]
    pub refund_timeout_secs: i64,
    /// How often the eligibility sweep runs. The default suits production; tests
    /// lower it so a stranded transfer is nominated promptly.
    #[serde(default = "default_sweep_interval_secs")]
    pub sweep_interval_secs: u64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainCfg {
    pub chain_id: u64,
    pub rpc: String,
    /// Gate address on this chain — indexes `Sent`/`Claimed`. Omit to skip.
    #[serde(default)]
    pub gate: Option<String>,
    /// SwapRouter address on this chain — indexes `SwapBridged`/`Finalized`/
    /// `FinalizeFallback`. Omit to skip.
    #[serde(default)]
    pub router: Option<String>,
    /// SwapPool address on this chain — indexes `Swapped`. Omit to skip.
    #[serde(default)]
    pub pool: Option<String>,
    #[serde(default)]
    pub start_block: u64,
    /// Finality buffer: only process up to `latest - block_confirmation`.
    ///
    /// The indexer signs nothing, so a reorg here cannot directly move funds —
    /// validators independently re-read both gates at their own confirmed block
    /// before attesting. It still matters: this process is the ONLY writer of
    /// `refund_status`, and `mark_claimed` clears an `eligible` flag. Reading at
    /// the tip means a reorged-away `Claimed` can un-flag a genuinely stranded
    /// transfer, and a reorged-away `Cancelled` can leave the candidate list
    /// asserting a burn that no longer exists. `Config::load` refuses a 0 buffer
    /// unless `allow_zero_confirmation` is set.
    #[serde(default)]
    pub block_confirmation: u64,
    /// Opt out of the non-zero `block_confirmation` requirement. ONLY for
    /// instant-finality local chains (anvil). Mirrors the validator's field of the
    /// same name so the two configs read identically.
    #[serde(default)]
    pub allow_zero_confirmation: bool,
    #[serde(default = "default_interval")]
    pub poll_interval_ms: u64,
    /// Delay between windows while catching up. Defaults to
    /// `poll_interval_ms`; see the validator's field of the same name for why
    /// reading back-to-back is opt-in per endpoint.
    #[serde(default)]
    pub catchup_poll_interval_ms: Option<u64>,
    #[serde(default = "default_range")]
    pub max_block_range: u64,
}

fn default_interval() -> u64 {
    2000
}
fn default_range() -> u64 {
    2000
}
fn default_refund_timeout_secs() -> i64 {
    24 * 60 * 60
}
fn default_sweep_interval_secs() -> u64 {
    60
}

impl Config {
    pub fn load(path: &str) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("reading config {path}: {e}"))?;
        Self::from_toml(&raw)
    }

    /// Parse + validate from a TOML string. Split out from [`load`] so the
    /// fail-closed checks below are unit-testable without the filesystem.
    pub fn from_toml(raw: &str) -> anyhow::Result<Self> {
        let cfg: Config = toml::from_str(raw)?;
        anyhow::ensure!(!cfg.chains.is_empty(), "config needs at least one [[chains]] block");
        for i in 0..cfg.chains.len() {
            for j in (i + 1)..cfg.chains.len() {
                if cfg.chains[i].chain_id == cfg.chains[j].chain_id {
                    anyhow::bail!("duplicate chain_id {} in config", cfg.chains[i].chain_id);
                }
            }
        }
        // M-7: the indexer owns `refund_status`, so a tip read can un-flag a
        // stranded transfer (reorged-away `Claimed`) or assert a burn that no
        // longer exists (reorged-away `Cancelled`). Fail closed, exactly as the
        // validator does, unless the operator opts in for an instant-final chain.
        // Degenerate values that TOML accepts and the loops do not. Each of
        // these used to be taken at face value: a zero range makes the scan
        // window empty (or underflows) so the cursor never advances; a zero
        // sweep interval is a busy loop hammering Postgres; a non-positive
        // refund timeout flags EVERY unclaimed transfer refund-eligible the
        // instant it is indexed, nominating live transfers for cancellation.
        anyhow::ensure!(
            cfg.refund_timeout_secs > 0,
            "refund_timeout_secs must be > 0 (got {}) — a non-positive timeout would flag every \
             unclaimed transfer refund-eligible immediately",
            cfg.refund_timeout_secs
        );
        anyhow::ensure!(
            cfg.sweep_interval_secs > 0,
            "sweep_interval_secs must be > 0 — zero is a busy loop against the database"
        );
        for c in &cfg.chains {
            anyhow::ensure!(
                c.max_block_range > 0,
                "chain_id {} has max_block_range = 0 — the scan window would be empty and the \
                 cursor would never advance",
                c.chain_id
            );
            if c.block_confirmation == 0 && !c.allow_zero_confirmation {
                anyhow::bail!(
                    "chain_id {} has block_confirmation = 0 — the indexer would record \
                     Claimed/Cancelled/Refunded from the chain tip, so a reorg could clear a \
                     refund-eligible flag or assert a burn that was rolled back. Set \
                     block_confirmation to exceed the chain's finality depth, or set \
                     allow_zero_confirmation = true ONLY for an instant-finality dev chain \
                     (e.g. anvil).",
                    c.chain_id
                );
            }
        }
        Ok(cfg)
    }

    pub fn resolved_database_url(&self) -> anyhow::Result<String> {
        self.database_url
            .clone()
            .or_else(|| std::env::var("DATABASE_URL").ok())
            .ok_or_else(|| anyhow::anyhow!("no database_url configured and DATABASE_URL env unset"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(chain_body: &str) -> String {
        format!(
            "database_url = \"postgres://x@localhost/x\"\n\
             [[chains]]\n\
             chain_id = 1337\n\
             rpc = \"http://127.0.0.1:8545\"\n\
             gate = \"0x0000000000000000000000000000000000000001\"\n\
             {chain_body}\n"
        )
    }

    // M-7: omitted (defaults to 0) must fail closed.
    #[test]
    fn zero_confirmation_is_rejected_by_default() {
        let err = Config::from_toml(&cfg("")).unwrap_err().to_string();
        assert!(err.contains("block_confirmation = 0"), "got: {err}");

        let err = Config::from_toml(&cfg("block_confirmation = 0")).unwrap_err().to_string();
        assert!(err.contains("block_confirmation = 0"), "got: {err}");
    }

    #[test]
    fn zero_confirmation_opt_in_is_honored() {
        let c = Config::from_toml(&cfg("block_confirmation = 0\nallow_zero_confirmation = true"))
            .expect("opt-in should load");
        assert!(c.chains[0].allow_zero_confirmation);
        assert_eq!(c.chains[0].block_confirmation, 0);
    }

    #[test]
    fn nonzero_confirmation_is_accepted() {
        let c = Config::from_toml(&cfg("block_confirmation = 12")).expect("should load");
        assert_eq!(c.chains[0].block_confirmation, 12);
    }

    #[test]
    fn zero_max_block_range_is_rejected() {
        let err = Config::from_toml(&cfg("block_confirmation = 12\nmax_block_range = 0"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("max_block_range = 0"), "got: {err}");
    }

    #[test]
    fn zero_sweep_interval_is_rejected() {
        let raw = format!("sweep_interval_secs = 0\n{}", cfg("block_confirmation = 12"));
        let err = Config::from_toml(&raw).unwrap_err().to_string();
        assert!(err.contains("sweep_interval_secs"), "got: {err}");
    }

    #[test]
    fn non_positive_refund_timeout_is_rejected() {
        for v in ["0", "-1", "-86400"] {
            let raw = format!("refund_timeout_secs = {v}\n{}", cfg("block_confirmation = 12"));
            let err = Config::from_toml(&raw).unwrap_err().to_string();
            assert!(err.contains("refund_timeout_secs must be > 0"), "{v}: got: {err}");
        }
        let raw = format!("refund_timeout_secs = 1\n{}", cfg("block_confirmation = 12"));
        assert!(Config::from_toml(&raw).is_ok());
    }

    /// The defaults themselves must satisfy the new checks.
    #[test]
    fn defaults_are_valid() {
        let c = Config::from_toml(&cfg("block_confirmation = 12")).expect("defaults load");
        assert!(c.refund_timeout_secs > 0 && c.sweep_interval_secs > 0 && c.chains[0].max_block_range > 0);
    }

    // M-4: a typo must be an error, not a silent default.
    #[test]
    fn misspelled_field_is_rejected_not_ignored() {
        let err = Config::from_toml(&cfg("block_confirmation = 0\nallow_zero_confirmations = true"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("allow_zero_confirmations") || err.contains("unknown field"),
            "got: {err}"
        );
    }
}
