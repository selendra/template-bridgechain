//! Live-Postgres tests for the audit-2026-09-09 store fixes.
//!
//! Gated on `BRIDGE_TEST_DATABASE_URL` (e.g. `postgres://bridge:bridge@127.0.0.1:5432/bridge`)
//! and skipped — passing, with a note on stderr — when it is unset, so the unit
//! suite stays runnable without infrastructure. Every test uses ids unique to
//! the run, so they are safe to re-run against one database.

use alloy::signers::local::PrivateKeySigner;
use alloy::signers::SignerSync;
use alloy_primitives::{Address, B256, U256};
use bridge_core::store::{SigKind, SignerSig, StoreError, SubmissionRecord, MAX_SIGNATURES_PER_SUBMISSION};
use bridge_db::{Db, DbError};

/// Two tests connecting at once both run `migrate()`, and concurrent
/// `CREATE TABLE IF NOT EXISTS` races on a fresh database. Serialise.
static LIVE_DB: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn live_db() -> Option<(Db, tokio::sync::MutexGuard<'static, ()>)> {
    let url = match std::env::var("BRIDGE_TEST_DATABASE_URL") {
        Ok(u) if !u.is_empty() => u,
        _ => {
            eprintln!("BRIDGE_TEST_DATABASE_URL unset — skipping live-Postgres test");
            return None;
        }
    };
    let guard = LIVE_DB.lock().await;
    Some((Db::connect(&url).await.expect("connect"), guard))
}

fn token() -> Address {
    Address::repeat_byte(0x11)
}

/// A well-formed record with a run-unique nonce and no signatures.
fn record(chain_to: u64) -> SubmissionRecord {
    let debridge_id = bridge_core::debridge_id(U256::from(1337u64), token());
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos() as u64;
    let receiver = Address::repeat_byte(0xAB).to_vec();
    let domain = B256::repeat_byte(0xD0);
    let id = bridge_core::submission_id(
        domain,
        debridge_id,
        U256::from(100u64),
        U256::from(1337u64),
        U256::from(chain_to),
        U256::from(nonce),
        &receiver,
    );
    SubmissionRecord {
        submission_id: format!("{id:#x}"),
        bridge_domain: format!("{domain:#x}"),
        debridge_id: format!("{debridge_id:#x}"),
        amount: "100".into(),
        chain_id_from: 1337,
        chain_id_to: chain_to,
        nonce,
        receiver: format!("0x{}", hex::encode(&receiver)),
        auto_params: "0x".into(),
        native_sender: "0x".into(),
        token: format!("{:#x}", token()),
        signatures: vec![],
        cancel_signatures: vec![],
        refund_signatures: vec![],
    }
}

fn sign(signer: &PrivateKeySigner, id_hex: &str, kind: SigKind) -> SignerSig {
    let id: B256 = id_hex.parse().unwrap();
    let sig = signer.sign_message_sync(kind.digest(id).as_slice()).unwrap();
    SignerSig { signer: format!("{:#x}", signer.address()), signature: bridge_core::signer::encode_signature(&sig) }
}

fn is_cap(e: &DbError, kind: &str) -> bool {
    matches!(e, DbError::Store(StoreError::TooManySignatures(k)) if *k == kind)
}

// --- M-2: caps ----------------------------------------------------------------

#[tokio::test]
async fn transfer_signers_per_submission_are_capped() {
    let Some((db, _g)) = live_db().await else { return };
    let rec = record(1338);
    let id = rec.submission_id.clone();
    let mut signers = Vec::new();
    for _ in 0..MAX_SIGNATURES_PER_SUBMISSION {
        let s = PrivateKeySigner::random();
        db.upsert_signature(rec.clone(), sign(&s, &id, SigKind::Transfer)).await.unwrap();
        signers.push(s);
    }
    let extra = PrivateKeySigner::random();
    let err = db.upsert_signature(rec.clone(), sign(&extra, &id, SigKind::Transfer)).await.unwrap_err();
    assert!(is_cap(&err, "transfer"), "{err}");
    assert!(err.is_client_error(), "a cap hit is the caller's problem (4xx), not a 500");
    // An existing signer re-posting is idempotent and still allowed.
    let merged = db.upsert_signature(rec.clone(), sign(&signers[7], &id, SigKind::Transfer)).await.unwrap();
    assert_eq!(merged.signatures.len(), MAX_SIGNATURES_PER_SUBMISSION);
}

#[tokio::test]
async fn attestation_signers_are_capped_per_domain() {
    let Some((db, _g)) = live_db().await else { return };
    let rec = record(1338);
    let id = rec.submission_id.clone();
    db.observe_submission(rec.clone()).await.unwrap();
    for _ in 0..MAX_SIGNATURES_PER_SUBMISSION {
        let s = PrivateKeySigner::random();
        db.upsert_attestation(&id, SigKind::Cancel, sign(&s, &id, SigKind::Cancel)).await.unwrap();
    }
    let extra = PrivateKeySigner::random();
    let err = db.upsert_attestation(&id, SigKind::Cancel, sign(&extra, &id, SigKind::Cancel)).await.unwrap_err();
    assert!(is_cap(&err, "cancel"), "{err}");
    // Domains are independent: the same signer's refund attestation is fine.
    let r = db.upsert_attestation(&id, SigKind::Refund, sign(&extra, &id, SigKind::Refund)).await.unwrap();
    assert_eq!(r.refund_signatures.len(), 1);
    assert_eq!(r.cancel_signatures.len(), MAX_SIGNATURES_PER_SUBMISSION);
}

// --- M-1 + park semantics -----------------------------------------------------

#[tokio::test]
async fn keeper_claim_note_is_advisory_and_parks_nothing() {
    let Some((db, _g)) = live_db().await else { return };
    let chain_to = 700_000 + (std::process::id() as u64 % 90_000);
    let rec = record(chain_to);
    let id = rec.submission_id.clone();

    // Unknown id: no error, and nothing parked.
    db.note_keeper_claim(&id, "0xkeeper").await.unwrap();
    db.observe_submission(rec.clone()).await.unwrap();
    let h = db.history_page(100, 0).await.unwrap();
    let row = h.iter().find(|r| r.submission_id == id).unwrap();
    assert_eq!(row.status, "signed");
    assert_eq!(row.keeper_claim_tx, None, "nothing may be parked from an advisory write");

    // Known id: only keeper_claim_tx moves; first write wins.
    db.note_keeper_claim(&id, "0xkeeper1").await.unwrap();
    db.note_keeper_claim(&id, "0xkeeper2").await.unwrap();
    let h = db.history_page(100, 0).await.unwrap();
    let row = h.iter().find(|r| r.submission_id == id).unwrap();
    assert_eq!(row.status, "signed");
    assert_eq!(row.claim_tx, None);
    assert_eq!(row.keeper_claim_tx.as_deref(), Some("0xkeeper1"));
    assert!(db.pending_claims(chain_to).await.unwrap().iter().any(|r| r.submission_id == id));
}

#[tokio::test]
async fn an_observed_claim_before_the_row_is_parked_then_applied() {
    let Some((db, _g)) = live_db().await else { return };
    let chain_to = 800_000 + (std::process::id() as u64 % 90_000);
    let rec = record(chain_to);
    let id = rec.submission_id.clone();

    db.mark_claimed(&id, "0xclaim").await.unwrap(); // destination seen first
    db.observe_submission(rec.clone()).await.unwrap(); // source arrives later
    let h = db.history_page(100, 0).await.unwrap();
    let row = h.iter().find(|r| r.submission_id == id).unwrap();
    assert_eq!(row.status, "claimed");
    assert_eq!(row.claim_tx.as_deref(), Some("0xclaim"));
    assert!(!db.pending_claims(chain_to).await.unwrap().iter().any(|r| r.submission_id == id));
}

/// The guard-declined case must still not park: a `cancelled` after `refunded`
/// matches no row (by design) and the row EXISTS, so the re-run UPDATE also
/// declines and nothing is parked that could later regress the row.
#[tokio::test]
async fn a_declined_lifecycle_update_on_an_existing_row_parks_nothing() {
    let Some((db, _g)) = live_db().await else { return };
    let rec = record(1338);
    let id = rec.submission_id.clone();
    db.observe_submission(rec.clone()).await.unwrap();
    db.mark_refunded(&id, "0xrefund").await.unwrap();
    db.mark_cancelled(&id, "0xcancel").await.unwrap();
    let h = db.history_page(100, 0).await.unwrap();
    let row = h.iter().find(|r| r.submission_id == id).unwrap();
    assert_eq!(row.refund_status, "refunded");
    assert_eq!(row.cancel_tx, None);
    // Re-observing (idempotent insert) must not resurrect a parked cancel either.
    db.observe_submission(rec.clone()).await.unwrap();
    let h = db.history_page(100, 0).await.unwrap();
    let row = h.iter().find(|r| r.submission_id == id).unwrap();
    assert_eq!(row.refund_status, "refunded");
}

// --- record_finalized park path ------------------------------------------------

#[tokio::test]
async fn a_finalize_seen_before_the_intent_is_parked_then_applied() {
    let Some((db, _g)) = live_db().await else { return };
    let rec = record(1338);
    let id = rec.submission_id.clone();
    db.observe_submission(rec.clone()).await.unwrap();

    // Destination leg first: no swap_bridges row yet.
    db.record_finalized(&id, "0xfin", "999", true).await.unwrap();
    let h = db.history_page(100, 0).await.unwrap();
    assert!(h.iter().find(|r| r.submission_id == id).unwrap().swap_intent.is_none());

    // Source leg arrives: the parked outcome is folded in.
    db.record_swap_bridge_intent(&id, "0xtin", "1000", "990", "0xtout", "0xrecv").await.unwrap();
    let h = db.history_page(100, 0).await.unwrap();
    let intent = h.iter().find(|r| r.submission_id == id).unwrap().swap_intent.clone().unwrap();
    assert_eq!(intent.finalize_tx.as_deref(), Some("0xfin"));
    assert_eq!(intent.finalize_amount_out.as_deref(), Some("999"));
    assert_eq!(intent.finalize_fallback, Some(true));
    assert!(intent.finalized_at.is_some());
}

#[tokio::test]
async fn a_finalize_after_the_intent_is_applied_directly() {
    let Some((db, _g)) = live_db().await else { return };
    let rec = record(1338);
    let id = rec.submission_id.clone();
    db.observe_submission(rec.clone()).await.unwrap();
    db.record_swap_bridge_intent(&id, "0xtin", "1000", "990", "0xtout", "0xrecv").await.unwrap();
    db.record_finalized(&id, "0xfin2", "998", false).await.unwrap();
    let h = db.history_page(100, 0).await.unwrap();
    let intent = h.iter().find(|r| r.submission_id == id).unwrap().swap_intent.clone().unwrap();
    assert_eq!(intent.finalize_tx.as_deref(), Some("0xfin2"));
    assert_eq!(intent.finalize_fallback, Some(false));
}

#[tokio::test]
async fn record_finalized_rejects_a_malformed_id() {
    let Some((db, _g)) = live_db().await else { return };
    let err = db.record_finalized("not-an-id", "0x", "1", false).await.unwrap_err();
    assert!(err.is_client_error(), "{err}");
}

// --- paging -------------------------------------------------------------------

#[tokio::test]
async fn load_page_walks_the_same_order_as_load_all() {
    let Some((db, _g)) = live_db().await else { return };
    for _ in 0..3 {
        db.observe_submission(record(1338)).await.unwrap();
    }
    let all = db.load_all().await.unwrap();
    let mut walked = Vec::new();
    let mut offset = 0;
    loop {
        let page = db.load_page(2, offset).await.unwrap();
        if page.is_empty() {
            break;
        }
        offset += page.len() as i64;
        walked.extend(page);
    }
    assert_eq!(
        walked.iter().map(|r| &r.submission_id).collect::<Vec<_>>(),
        all.iter().map(|r| &r.submission_id).collect::<Vec<_>>()
    );
    assert_eq!(db.history_page(1, 0).await.unwrap().len(), 1);
}
