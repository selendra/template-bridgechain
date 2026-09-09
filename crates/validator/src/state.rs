//! Resumable cursor + sequential-nonce enforcement + pause state.
//!
//! Mirrors three pieces of the production node:
//!   * the per-chain DB cursor (`supported_chains.latestBlock`) → here a JSON file,
//!   * `NonceControllingService` (MISSED_NONCE / DUPLICATED_NONCE → pause),
//!   * the scanner pause/resume flag driven by the operator API.
//!
//! The whole struct is shared behind a `tokio::sync::Mutex`; the scan loop and
//! the operator API both mutate it.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The part that survives a restart.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Persist {
    /// Last block whose logs were fully processed (resume from `last_block + 1`).
    pub last_block: u64,
    /// Last accepted nonce, keyed by **(source chain, target chain)**.
    ///
    /// The on-chain nonce is `nonceTo[chainIdTo]` on each SOURCE gate, so every
    /// source produces its own 0,1,2,… sequence toward a given destination. In a
    /// mesh where two sources bridge to the same destination, both legitimately
    /// emit nonce 0 for that `chainIdTo` — keying by `chain_to` alone would flag
    /// the second as a duplicate and wrongly pause. The sequence is unique per
    /// `(chain_from, chain_to)` (both are bound into the submissionId), so that
    /// is the key. Serialized as `{ "<from>": { "<to>": <nonce> } }`.
    pub nonces: BTreeMap<u64, BTreeMap<u64, u64>>,
    /// A safety stop (nonce anomaly / submissionId mismatch / operator pause) is
    /// **persisted**: it MUST survive a restart, or a crash-loop would silently
    /// clear a pause the operator has not investigated and resume signing into the
    /// very anomaly that tripped it. Cleared only by an explicit operator resume
    /// or rescan. `#[serde(default)]` keeps old state files (without these keys)
    /// loadable as not-paused.
    #[serde(default)]
    pub paused: bool,
    #[serde(default)]
    pub pause_reason: Option<PauseReason>,
}

/// What the nonce checker decides for a freshly seen event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceDecision {
    /// Expected next nonce — process it.
    Accept,
    /// `nonce <= last seen` — already processed (possible RPC replay).
    Duplicated,
    /// `nonce > last + 1` — a gap; we missed an event.
    Missed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PauseReason {
    Operator,
    MissedNonce { chain_from: u64, chain_to: u64, expected: u64, got: u64 },
    DuplicatedNonce { chain_from: u64, chain_to: u64, last: u64, got: u64 },
    IdMismatch { submission_id: String },
}

impl PauseReason {
    pub fn as_str(&self) -> String {
        match self {
            PauseReason::Operator => "operator".into(),
            PauseReason::MissedNonce { chain_from, chain_to, expected, got } => {
                format!("MISSED_NONCE chain_from={chain_from} chain_to={chain_to} expected={expected} got={got}")
            }
            PauseReason::DuplicatedNonce { chain_from, chain_to, last, got } => {
                format!("DUPLICATED_NONCE chain_from={chain_from} chain_to={chain_to} last={last} got={got}")
            }
            PauseReason::IdMismatch { submission_id } => {
                format!("ID_MISMATCH submission_id={submission_id}")
            }
        }
    }
}

#[derive(Debug)]
pub struct Runtime {
    pub persist: Persist,
    path: PathBuf,
}

impl Runtime {
    /// Load persisted state if present, else start fresh from `start_block`
    /// (the first block we'd scan is `last_block + 1`, so seed `last_block`
    /// with `start_block.saturating_sub(1)`).
    ///
    /// A file that EXISTS but does not parse is a hard error, not a fresh start
    /// (audit 2026-09-09, "corrupt/zero-length state file clears a persisted
    /// pause"). The file is where a safety stop lives across restarts; treating
    /// a truncated or garbled one as "no state" would silently clear that stop
    /// — the exact failure `Persist::paused` exists to prevent — and would also
    /// rewind the cursor to `start_block`, re-signing history. An operator has
    /// to look at it: move it aside (accepting a rescan from `start_block`) or
    /// restore it. Only a MISSING file means fresh.
    pub fn load_or_init(path: &Path, start_block: u64) -> anyhow::Result<Self> {
        let fresh = || Persist {
            last_block: start_block.saturating_sub(1),
            ..Default::default()
        };
        let persist = if path.exists() {
            let raw = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("reading state file {}: {e}", path.display()))?;
            serde_json::from_str(&raw).map_err(|e| {
                anyhow::anyhow!(
                    "state file {} exists but is not valid scanner state ({e}; {} bytes). \
                     REFUSING TO START: it may hold a persisted safety stop, and starting \
                     fresh would clear it and rewind the cursor to start_block. Restore the \
                     file from backup, or move it aside to deliberately rescan from block {}.",
                    path.display(),
                    raw.len(),
                    start_block
                )
            })?
        } else {
            fresh()
        };
        // A persisted safety stop must be honoured across the restart — surface it
        // loudly so the operator knows the scanner came up paused and why.
        if persist.paused {
            let reason = persist.pause_reason.as_ref().map(|r| r.as_str()).unwrap_or_default();
            tracing::warn!(path = %path.display(), reason = %reason, "resuming PAUSED from persisted state; operator resume required");
        }
        Ok(Self { persist, path: path.to_path_buf() })
    }

    /// Whether the scanner is under a safety stop.
    pub fn paused(&self) -> bool {
        self.persist.paused
    }

    /// The current pause reason, if paused.
    pub fn pause_reason(&self) -> Option<&PauseReason> {
        self.persist.pause_reason.as_ref()
    }

    pub fn next_block(&self) -> u64 {
        self.persist.last_block + 1
    }

    /// Atomically persist (write temp + fsync + rename) so a crash mid-write
    /// can't corrupt the cursor.
    ///
    /// The fsync matters: `rename` is atomic with respect to the directory
    /// entry, but without `sync_all` the new inode's DATA may still be in the
    /// page cache when the entry is swapped, and a power loss then leaves a
    /// correctly-named ZERO-LENGTH file — which `load_or_init` now refuses,
    /// rather than reading as "fresh" and clearing a persisted pause.
    pub fn save(&self) -> anyhow::Result<()> {
        use std::io::Write;
        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let tmp = self.path.with_extension("json.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(serde_json::to_string_pretty(&self.persist)?.as_bytes())?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        // Best effort: also flush the directory so the rename itself is durable.
        // Not every filesystem allows opening a directory for sync; a failure
        // here is not worth failing the save over, the data is already on disk.
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if let Ok(dir) = std::fs::File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    }

    /// Last accepted nonce for a `(chain_from, chain_to)` pair, if any.
    pub fn last_nonce(&self, chain_from: u64, chain_to: u64) -> Option<u64> {
        self.persist.nonces.get(&chain_from).and_then(|m| m.get(&chain_to)).copied()
    }

    /// Decide whether `nonce` for the `(chain_from, chain_to)` corridor is the
    /// expected next one. Pure — does not mutate; call [`Runtime::accept_nonce`]
    /// on Accept.
    pub fn check_nonce(&self, chain_from: u64, chain_to: u64, nonce: u64) -> NonceDecision {
        match self.last_nonce(chain_from, chain_to) {
            // First event ever seen for this corridor: accept (we may be resuming
            // mid-stream; the gap-from-genesis is not meaningful here).
            None => NonceDecision::Accept,
            Some(last) if nonce == last + 1 => NonceDecision::Accept,
            Some(last) if nonce <= last => NonceDecision::Duplicated,
            Some(_) => NonceDecision::Missed,
        }
    }

    pub fn accept_nonce(&mut self, chain_from: u64, chain_to: u64, nonce: u64) {
        self.persist.nonces.entry(chain_from).or_default().insert(chain_to, nonce);
    }

    /// Copy of the whole nonce cursor, to be handed back to [`Runtime::restore_nonces`].
    ///
    /// The scan loop advances this cursor per EVENT but its block cursor per
    /// BATCH, so the two only agree at a batch boundary. Taking a snapshot at
    /// that boundary is what lets a half-finished batch be undone.
    pub fn nonce_snapshot(&self) -> BTreeMap<u64, BTreeMap<u64, u64>> {
        self.persist.nonces.clone()
    }

    /// Roll the nonce cursor back to a [`Runtime::nonce_snapshot`].
    ///
    /// Called whenever a batch stops early and the block cursor therefore stays
    /// put: the same events are about to be replayed, and a cursor left ahead of
    /// them would read the replay as DUPLICATED_NONCE and pause the scanner on an
    /// anomaly that never happened.
    pub fn restore_nonces(&mut self, snapshot: BTreeMap<u64, BTreeMap<u64, u64>>) {
        self.persist.nonces = snapshot;
    }

    pub fn pause(&mut self, reason: PauseReason) {
        self.persist.paused = true;
        self.persist.pause_reason = Some(reason);
    }

    /// Clear the pause flag (operator resume).
    pub fn resume(&mut self) {
        self.persist.paused = false;
        self.persist.pause_reason = None;
    }

    /// Reset the cursor to re-scan from `from_block` and clear nonce tracking so
    /// re-processing is clean (operator rescan). Also clears any pause.
    pub fn rescan_from(&mut self, from_block: u64) {
        self.persist.last_block = from_block.saturating_sub(1);
        self.persist.nonces.clear();
        self.resume();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt() -> Runtime {
        Runtime {
            persist: Persist::default(),
            path: PathBuf::from("/dev/null"),
        }
    }

    // corridor 1337 -> 1338 in these tests unless noted
    const FROM: u64 = 1337;
    const TO: u64 = 1338;

    #[test]
    fn first_event_for_chain_is_accepted() {
        let r = rt();
        assert_eq!(r.check_nonce(FROM, TO, 0), NonceDecision::Accept);
        assert_eq!(r.check_nonce(FROM, TO, 7), NonceDecision::Accept);
    }

    #[test]
    fn sequential_nonces_accept_then_advance() {
        let mut r = rt();
        assert_eq!(r.check_nonce(FROM, TO, 0), NonceDecision::Accept);
        r.accept_nonce(FROM, TO, 0);
        assert_eq!(r.check_nonce(FROM, TO, 1), NonceDecision::Accept);
        r.accept_nonce(FROM, TO, 1);
        assert_eq!(r.check_nonce(FROM, TO, 2), NonceDecision::Accept);
    }

    #[test]
    fn gap_is_missed() {
        let mut r = rt();
        r.accept_nonce(FROM, TO, 0);
        assert_eq!(r.check_nonce(FROM, TO, 2), NonceDecision::Missed);
    }

    #[test]
    fn replay_is_duplicated() {
        let mut r = rt();
        r.accept_nonce(FROM, TO, 5);
        assert_eq!(r.check_nonce(FROM, TO, 5), NonceDecision::Duplicated);
        assert_eq!(r.check_nonce(FROM, TO, 3), NonceDecision::Duplicated);
    }

    #[test]
    fn nonces_are_independent_per_target_chain() {
        let mut r = rt();
        r.accept_nonce(FROM, TO, 4);
        // a different target chain starts fresh
        assert_eq!(r.check_nonce(FROM, 9999, 0), NonceDecision::Accept);
        // and 1338 still enforces sequence
        assert_eq!(r.check_nonce(FROM, TO, 6), NonceDecision::Missed);
    }

    #[test]
    fn nonces_are_independent_per_source_chain() {
        // THE mesh case: two sources bridging to the SAME destination each run
        // their own 0,1,2,… sequence and must not collide.
        let mut r = rt();
        r.accept_nonce(1337, TO, 0);
        // a second source to the same destination legitimately starts at 0
        assert_eq!(r.check_nonce(1339, TO, 0), NonceDecision::Accept);
        r.accept_nonce(1339, TO, 0);
        // each corridor keeps its own sequence
        assert_eq!(r.check_nonce(1337, TO, 1), NonceDecision::Accept);
        assert_eq!(r.check_nonce(1339, TO, 1), NonceDecision::Accept);
        // and a genuine replay within a corridor is still caught
        assert_eq!(r.check_nonce(1337, TO, 0), NonceDecision::Duplicated);
    }

    /// THE regression. The scan loop advances the nonce cursor per event but the
    /// block cursor per batch, so a batch that stops early (a sig-store blip, a
    /// nonce anomaly) leaves the two out of step and the SAME events get
    /// rescanned. Without the rollback the replay of an already-accepted nonce
    /// reads as DUPLICATED and pauses the validator — a persisted stop, on a
    /// fault that never happened.
    #[test]
    fn a_rolled_back_batch_replays_without_a_false_duplicate() {
        let mut r = rt();
        r.accept_nonce(FROM, TO, 4);

        // Batch boundary: snapshot, then consume nonce 5 before the batch fails.
        let before = r.nonce_snapshot();
        assert_eq!(r.check_nonce(FROM, TO, 5), NonceDecision::Accept);
        r.accept_nonce(FROM, TO, 5);

        // Pre-fix: the replay of 5 lands on last == 5 and reads as a duplicate.
        assert_eq!(r.check_nonce(FROM, TO, 5), NonceDecision::Duplicated);

        r.restore_nonces(before);
        assert_eq!(
            r.check_nonce(FROM, TO, 5),
            NonceDecision::Accept,
            "a rescanned event must be re-processable, not read as a replay"
        );
        // ...and a genuine replay is still caught once the batch does complete.
        r.accept_nonce(FROM, TO, 5);
        assert_eq!(r.check_nonce(FROM, TO, 5), NonceDecision::Duplicated);
    }

    /// The rollback must not mask a real anomaly either: a gap is still a gap
    /// after the replay, so the operator sees MISSED_NONCE rather than the
    /// DUPLICATED_NONCE the un-rolled-back cursor invented.
    #[test]
    fn rollback_preserves_a_genuine_gap() {
        let mut r = rt();
        r.accept_nonce(FROM, TO, 4);
        let before = r.nonce_snapshot();

        r.accept_nonce(FROM, TO, 5); // first event of the batch, fine
        assert_eq!(r.check_nonce(FROM, TO, 8), NonceDecision::Missed); // second: a gap

        r.restore_nonces(before);
        assert_eq!(r.check_nonce(FROM, TO, 5), NonceDecision::Accept);
        assert_eq!(r.check_nonce(FROM, TO, 8), NonceDecision::Missed);
    }

    #[test]
    fn rescan_resets_cursor_and_nonces() {
        let mut r = rt();
        r.persist.last_block = 100;
        r.accept_nonce(FROM, TO, 9);
        r.pause(PauseReason::Operator);
        r.rescan_from(50);
        assert_eq!(r.next_block(), 50);
        assert!(r.persist.nonces.is_empty());
        assert!(!r.paused());
    }

    fn temp_state(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("val-state-test-{tag}-{}.json", std::process::id()))
    }

    /// THE regression (audit 2026-09-09). A truncated or garbled state file used
    /// to load as `fresh()`: not paused, cursor at start_block. A crash-loop with
    /// a half-written file therefore cleared a safety stop nobody had cleared.
    #[test]
    fn a_corrupt_state_file_refuses_to_load() {
        let path = temp_state("corrupt");
        for garbage in ["", "{", "not json", "\0\0\0\0", "{\"last_block\": \"nope\"}"] {
            std::fs::write(&path, garbage).unwrap();
            let err = Runtime::load_or_init(&path, 100).unwrap_err().to_string();
            assert!(err.contains("REFUSING TO START"), "garbage {garbage:?}: {err}");
            assert!(err.contains(&path.display().to_string()), "names the file: {err}");
        }
        let _ = std::fs::remove_file(&path);
    }

    /// The other half of the contract: a MISSING file is still a fresh start.
    #[test]
    fn a_missing_state_file_is_fresh() {
        let path = temp_state("missing");
        let _ = std::fs::remove_file(&path);
        let r = Runtime::load_or_init(&path, 100).unwrap();
        assert_eq!(r.next_block(), 100);
        assert!(!r.paused());
    }

    /// Old state files without the pause keys must still load (serde defaults),
    /// so upgrading does not trip the corrupt-file refusal.
    #[test]
    fn a_pre_pause_state_file_still_loads() {
        let path = temp_state("old-format");
        std::fs::write(&path, r#"{"last_block": 41, "nonces": {"1337": {"1338": 3}}}"#).unwrap();
        let r = Runtime::load_or_init(&path, 0).unwrap();
        assert_eq!(r.next_block(), 42);
        assert!(!r.paused());
        assert_eq!(r.last_nonce(1337, 1338), Some(3));
        let _ = std::fs::remove_file(&path);
    }

    /// `save` leaves no temp file behind and the result reloads.
    #[test]
    fn save_is_atomic_and_reloadable() {
        let path = temp_state("save");
        let _ = std::fs::remove_file(&path);
        let mut r = Runtime::load_or_init(&path, 0).unwrap();
        r.persist.last_block = 7;
        r.save().unwrap();
        assert!(!path.with_extension("json.tmp").exists(), "temp file must be renamed away");
        assert_eq!(Runtime::load_or_init(&path, 0).unwrap().next_block(), 8);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn pause_state_survives_save_and_reload() {
        // The safety stop MUST persist: a restart after a nonce anomaly must come
        // back paused, not silently resume signing into the anomaly.
        let dir = std::env::temp_dir();
        let path = dir.join(format!("val-state-test-{}.json", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let mut r = Runtime::load_or_init(&path, 0).unwrap();
        r.persist.last_block = 42;
        r.pause(PauseReason::MissedNonce { chain_from: 1, chain_to: 2, expected: 5, got: 8 });
        r.save().unwrap();

        let r2 = Runtime::load_or_init(&path, 0).unwrap();
        assert!(r2.paused(), "must reload paused");
        assert_eq!(r2.persist.last_block, 42);
        assert_eq!(
            r2.pause_reason(),
            Some(&PauseReason::MissedNonce { chain_from: 1, chain_to: 2, expected: 5, got: 8 })
        );

        // An operator resume clears it and persists the clear.
        let mut r3 = Runtime::load_or_init(&path, 0).unwrap();
        r3.resume();
        r3.save().unwrap();
        assert!(!Runtime::load_or_init(&path, 0).unwrap().paused());

        let _ = std::fs::remove_file(&path);
    }
}
