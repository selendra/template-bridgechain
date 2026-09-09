//! bridge-db — the Postgres source of truth for the bridge.
//!
//! Replaces the file-per-id JSON store (`bridge-core::store`) with a real
//! database that holds **transaction history** (`submissions` + `signatures`,
//! with a lifecycle `status`) and the two **allowlists** (`allowed_tokens`,
//! `allowed_chains`). The HTTP `sig-store` service is the only process that
//! talks to it; validators/keepers/graphql reach it through that service.
//!
//! The same trust-boundary checks the file store enforced are reused verbatim
//! from `bridge-core::store` (the `abi` feature): a record's `submission_id`
//! must equal the keccak of its own params, params are immutable once stored,
//! and every signature must recover to its claimed signer.

use std::str::FromStr;

use alloy_primitives::{Address, U256};
use bridge_core::allow::{AllowedChain, AllowedToken, SubmissionHistory, SwapBridgeInfo, SwapRecord};
use bridge_core::store::{self, SigKind, SignerSig, StoreError, SubmissionRecord};
use sqlx::postgres::PgPoolOptions;
use sqlx::{FromRow, PgPool};

#[derive(Debug, thiserror::Error)]
pub enum DbError {
    /// A trust-boundary violation (bad id, param conflict, forged signature).
    /// These map to HTTP 4xx — the caller sent something invalid.
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("db: {0}")]
    Sqlx(#[from] sqlx::Error),
    #[error("bad field: {0}")]
    BadField(&'static str),
    /// Deleting this row would leave `{0}` empty, and an empty allowlist means
    /// "allow everything" — so the delete is refused rather than silently
    /// disabling enforcement. See [`Db::remove_allowed_token`].
    #[error(
        "refusing to delete the last {0} entry: an empty allowlist allows EVERYTHING, \
         so emptying it would silently disable enforcement at both the validator and \
         the keeper. Add a replacement entry first, or drop the table to opt out \
         deliberately."
    )]
    LastAllowlistEntry(&'static str),
}

/// Canonical form of a submissionId used as the DB key everywhere: lowercase,
/// always `0x`-prefixed. Callers reach us with either form (the validator stores
/// `0x…`; the keeper/graphql strip the `0x` before putting it in a URL), so we
/// must normalize on every lookup or an `UPDATE`/`SELECT` silently misses.
fn norm_id(s: &str) -> String {
    let s = s.strip_prefix("0x").unwrap_or(s);
    format!("0x{}", s.to_ascii_lowercase())
}

/// [`norm_id`], but rejecting anything that is not a 32-byte hex hash first.
///
/// The lifecycle writers all take a submissionId straight off the wire, so the
/// shape check has to happen before it becomes a query key — a malformed id can
/// only ever match nothing, and letting it through would silently no-op the
/// UPDATE and then park a bogus `pending_lifecycle` row under it.
fn checked_id(submission_id: &str) -> Result<String, DbError> {
    if !store::is_valid_submission_id(submission_id) {
        return Err(DbError::BadField("submission_id"));
    }
    Ok(norm_id(submission_id))
}

impl DbError {
    /// True for caller-input errors (HTTP 4xx); false for server/IO faults (5xx).
    pub fn is_client_error(&self) -> bool {
        match self {
            DbError::Store(e) => !matches!(e, StoreError::Io(_) | StoreError::Json(_)),
            DbError::BadField(_) => true,
            DbError::LastAllowlistEntry(_) => true,
            DbError::Sqlx(_) => false,
        }
    }
}

/// Columns of the `submissions` table.
#[derive(FromRow)]
struct SubmissionRow {
    submission_id: String,
    /// NULL for rows predating the deployment domain — see the schema comment.
    bridge_domain: Option<String>,
    debridge_id: String,
    amount: String,
    chain_id_from: i64,
    chain_id_to: i64,
    nonce: i64,
    receiver: String,
    auto_params: String,
    native_sender: String,
    status: String,
    claim_tx: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
    refund_status: String,
    refund_tx: Option<String>,
    cancel_tx: Option<String>,
    token: Option<String>,
    /// The keeper's own report of its claim tx (M-1). Advisory: informs nothing.
    keeper_claim_tx: Option<String>,
}

#[derive(FromRow)]
struct SwapBridgeRow {
    submission_id: String,
    token_in: String,
    amount_in: String,
    stable_out: String,
    final_token: String,
    final_receiver: String,
    finalize_tx: Option<String>,
    finalize_amount_out: Option<String>,
    finalize_fallback: Option<bool>,
    finalized_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl SwapBridgeRow {
    fn into_info(self) -> SwapBridgeInfo {
        SwapBridgeInfo {
            token_in: self.token_in,
            amount_in: self.amount_in,
            stable_out: self.stable_out,
            final_token: self.final_token,
            final_receiver: self.final_receiver,
            finalize_tx: self.finalize_tx,
            finalize_amount_out: self.finalize_amount_out,
            finalize_fallback: self.finalize_fallback,
            finalized_at: self.finalized_at.map(|t| t.to_rfc3339()),
        }
    }
}

#[derive(FromRow)]
struct SwapRow {
    chain_id: i64,
    tx_hash: String,
    log_index: i32,
    sender: String,
    receiver: String,
    token_in: String,
    token_out: String,
    amount_in: String,
    amount_out: String,
    block_number: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl SwapRow {
    fn into_record(self) -> SwapRecord {
        SwapRecord {
            chain_id: self.chain_id as u64,
            tx_hash: self.tx_hash,
            log_index: self.log_index as i64,
            sender: self.sender,
            receiver: self.receiver,
            token_in: self.token_in,
            token_out: self.token_out,
            amount_in: self.amount_in,
            amount_out: self.amount_out,
            block_number: self.block_number as u64,
            created_at: self.created_at.to_rfc3339(),
        }
    }
}

#[derive(FromRow)]
struct SigRow {
    submission_id: String,
    /// `transfer` (from the `signatures` table) | `cancel` | `refund`.
    kind: String,
    signer: String,
    signature: String,
}

impl SubmissionRow {
    fn into_record(self, sigs: Attestations) -> SubmissionRecord {
        SubmissionRecord {
            submission_id: self.submission_id,
            bridge_domain: self.bridge_domain.unwrap_or_default(),
            debridge_id: self.debridge_id,
            amount: self.amount,
            chain_id_from: self.chain_id_from as u64,
            chain_id_to: self.chain_id_to as u64,
            nonce: self.nonce as u64,
            receiver: self.receiver,
            auto_params: self.auto_params,
            native_sender: self.native_sender,
            token: self.token.unwrap_or_default(),
            signatures: sigs.transfer,
            cancel_signatures: sigs.cancel,
            refund_signatures: sigs.refund,
        }
    }

    fn into_history(
        self,
        signature_count: i64,
        cancel_signature_count: i64,
        refund_signature_count: i64,
        swap_intent: Option<SwapBridgeInfo>,
    ) -> SubmissionHistory {
        SubmissionHistory {
            submission_id: self.submission_id,
            debridge_id: self.debridge_id,
            amount: self.amount,
            chain_id_from: self.chain_id_from as u64,
            chain_id_to: self.chain_id_to as u64,
            nonce: self.nonce as u64,
            receiver: self.receiver,
            status: self.status,
            claim_tx: self.claim_tx,
            signature_count,
            created_at: self.created_at.to_rfc3339(),
            updated_at: self.updated_at.to_rfc3339(),
            stuck: self.refund_status != "none",
            refund_status: self.refund_status,
            refund_tx: self.refund_tx,
            cancel_tx: self.cancel_tx,
            token: self.token,
            cancel_signature_count,
            refund_signature_count,
            swap_intent,
            keeper_claim_tx: self.keeper_claim_tx,
        }
    }
}

/// A submission's signatures split by the domain they authorise.
#[derive(Default)]
struct Attestations {
    transfer: Vec<SignerSig>,
    cancel: Vec<SignerSig>,
    refund: Vec<SignerSig>,
}

impl Attestations {
    fn push(&mut self, kind: &str, sig: SignerSig) {
        match SigKind::parse(kind) {
            Some(SigKind::Transfer) => self.transfer.push(sig),
            Some(SigKind::Cancel) => self.cancel.push(sig),
            Some(SigKind::Refund) => self.refund.push(sig),
            // An unrecognized kind must NOT fall into a quorum bucket — least of
            // all `transfer`, which authorises a claim. Today unreachable (the
            // write path constrains `kind` to cancel/refund and the signatures
            // table contributes the literal 'transfer'), so this is defensive
            // against a future writer or a hand-edited row.
            None => {
                tracing::warn!(kind, "ignoring signature with unrecognized attestation kind");
            }
        }
    }
}

/// The id⇄params binding: a record's `submission_id` MUST equal the canonical
/// keccak of its own parameters, and its `token` must hash to its `debridge_id`.
///
/// This is the check that makes a row self-certifying, and it guards BOTH write
/// paths into `submissions` (a validator's `upsert_signature` and the indexer's
/// `observe_submission`). One copy, because a path that skipped it would be a way
/// to insert a row whose id names one transfer and whose params describe another.
/// Returns the verified canonical id, so a caller that needs it (to authenticate
/// an attached signature) does not recompute it.
fn verify_binding(record: &SubmissionRecord) -> Result<alloy_primitives::B256, DbError> {
    // Guard the id before it is used as a key (and as a sig-store URL segment).
    if !store::is_valid_submission_id(&record.submission_id) {
        return Err(StoreError::BadField("submission_id").into());
    }
    let computed = store::canonical_submission_id(record)?;
    let claimed = alloy_primitives::B256::from_str(&record.submission_id)
        .map_err(|_| StoreError::BadField("submission_id"))?;
    if computed != claimed {
        return Err(StoreError::IdMismatch {
            claimed: format!("{claimed:#x}"),
            computed: format!("{computed:#x}"),
        }
        .into());
    }
    // `token` is not covered by the submissionId, so it gets its own exact
    // binding (debridge_id == keccak(chain_id_from, token)) before storage.
    store::verify_token_binding(record)?;
    Ok(computed)
}

/// The `INSERT` that creates a `submissions` row, shared by both write paths.
///
/// `ON CONFLICT` makes the first insert concurrency-safe: when several
/// validators POST the same brand-new submissionId at once they all find no
/// existing row and race here, and without this the losers hit a duplicate-key
/// error (a 500 that drops their signature). The id⇄params binding guarantees any
/// existing row has identical params, so the conflict path only ever backfills
/// `token` — never any other field.
async fn insert_submission_row<'e, E>(executor: E, id: &str, record: &SubmissionRecord) -> Result<(), DbError>
where
    E: sqlx::Executor<'e, Database = sqlx::Postgres>,
{
    sqlx::query(
        "INSERT INTO submissions \
         (submission_id, bridge_domain, debridge_id, amount, chain_id_from, chain_id_to, nonce, \
          receiver, auto_params, native_sender, token) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) \
         ON CONFLICT (submission_id) DO UPDATE \
           SET token = COALESCE(submissions.token, EXCLUDED.token)",
    )
    .bind(id)
    .bind(record.bridge_domain.to_ascii_lowercase())
    .bind(record.debridge_id.to_ascii_lowercase())
    .bind(&record.amount)
    .bind(record.chain_id_from as i64)
    .bind(record.chain_id_to as i64)
    .bind(record.nonce as i64)
    .bind(record.receiver.to_ascii_lowercase())
    .bind(record.auto_params.to_ascii_lowercase())
    .bind(record.native_sender.to_ascii_lowercase())
    .bind(Some(record.token.to_ascii_lowercase()).filter(|t| !t.is_empty()))
    .execute(executor)
    .await?;
    Ok(())
}

/// The union of a submission's transfer signatures and its cancel/refund
/// attestations, as `(submission_id, kind, signer, signature)` rows.
///
/// `where_clause` is appended verbatim and is a literal in both call sites — it
/// never carries caller input.
fn sig_query(where_clause: &str) -> String {
    format!(
        "SELECT submission_id, 'transfer' AS kind, signer, signature FROM signatures {where_clause} \
         UNION ALL \
         SELECT submission_id, kind, signer, signature FROM attestations {where_clause} \
         ORDER BY submission_id, kind, signer"
    )
}

/// Serialize writers to an allowlist table for the rest of the transaction.
///
/// Without it, [`refuse_if_emptied`] is racy in the obvious way: two concurrent
/// deletes each count the rows against their own snapshot, each sees one left,
/// each commits, and the list is empty anyway. `SHARE ROW EXCLUSIVE` blocks
/// other writers while still letting the validator's and keeper's reads through,
/// and this is an admin-frequency path where that costs nothing.
///
/// `table` is a LITERAL at every call site, never caller input — it is
/// interpolated because a table name cannot be a bind parameter.
async fn lock_allowlist_table(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &'static str,
) -> Result<(), DbError> {
    sqlx::query(&format!("LOCK TABLE {table} IN SHARE ROW EXCLUSIVE MODE"))
        .execute(&mut **tx)
        .await?;
    Ok(())
}

/// Fail the transaction if the delete that just ran emptied the table.
///
/// Checked AFTER the delete rather than before, so a delete that matched nothing
/// still reports "not found" rather than being refused as if it were the last
/// row. Returning `Err` drops the transaction uncommitted, which rolls the
/// delete back.
async fn refuse_if_emptied(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    table: &'static str,
) -> Result<(), DbError> {
    let (remaining,): (i64,) = sqlx::query_as(&format!("SELECT COUNT(*)::BIGINT FROM {table}"))
        .fetch_one(&mut **tx)
        .await?;
    if remaining == 0 {
        return Err(DbError::LastAllowlistEntry(table));
    }
    Ok(())
}

/// M-2: refuse a NEW signer once a submission already holds
/// [`store::MAX_SIGNATURES_PER_SUBMISSION`] rows in `kind`'s domain — the same
/// bound the file store enforces, so the two backends agree.
///
/// A re-POST from a signer already on the record is always allowed through (it
/// is a no-op `ON CONFLICT DO NOTHING`), so an honest validator can never be
/// locked out of a submission that junk has filled: the cap bounds distinct
/// signers, not requests. `count_sql`/`present_sql` are literals at every call
/// site, parameterised on `$1 = id` (and `$2 = signer` for the latter).
async fn enforce_signature_cap(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    count_sql: &str,
    present_sql: &str,
    id: &str,
    signer_lc: &str,
    kind: &'static str,
) -> Result<(), DbError> {
    let (count,): (i64,) = sqlx::query_as(count_sql).bind(id).fetch_one(&mut **tx).await?;
    if count < store::MAX_SIGNATURES_PER_SUBMISSION as i64 {
        return Ok(());
    }
    let present: Option<(i32,)> =
        sqlx::query_as(present_sql).bind(id).bind(signer_lc).fetch_optional(&mut **tx).await?;
    if present.is_some() {
        return Ok(());
    }
    Err(StoreError::TooManySignatures(kind).into())
}

/// The lifecycle UPDATE to re-run if [`Db::park_if_missing`] finds the row
/// appeared under it. `sql` is a literal at every call site.
struct Retry<'a> {
    sql: &'static str,
    arg: &'a str,
}

/// The columns a parked `pending_lifecycle` marker carries.
struct Marker<'a> {
    /// Empty means "leave `status` alone".
    status: &'a str,
    claim_tx: Option<&'a str>,
    cancel_tx: Option<&'a str>,
    refund_tx: Option<&'a str>,
    refund_status: Option<&'a str>,
}

impl Marker<'static> {
    const NONE: Marker<'static> =
        Marker { status: "", claim_tx: None, cancel_tx: None, refund_tx: None, refund_status: None };
}

/// A handle to the bridge database (cheap to clone — wraps a connection pool).
#[derive(Clone)]
pub struct Db {
    pool: PgPool,
}

impl Db {
    /// Connect (with a small pool) and ensure the schema exists. Retries for a
    /// short window so the service tolerates Postgres still starting up (docker
    /// healthcheck races, `initdb`'s bootstrap restart, compose ordering).
    pub async fn connect(url: &str) -> Result<Db, DbError> {
        let mut last: Option<sqlx::Error> = None;
        for attempt in 1..=30 {
            match PgPoolOptions::new().max_connections(10).connect(url).await {
                Ok(pool) => {
                    let db = Db { pool };
                    db.migrate().await?;
                    return Ok(db);
                }
                Err(e) => {
                    tracing::warn!(attempt, error = %e, "Postgres not ready; retrying in 500ms");
                    last = Some(e);
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
            }
        }
        Err(DbError::Sqlx(last.expect("loop ran at least once")))
    }

    /// A handle whose pool connects on first use and applies NO schema.
    ///
    /// For tests of the HTTP layer that must reject a request BEFORE touching the
    /// database (body caps, scope checks): they need an `AppState` but must never
    /// need Postgres. Not for services — use [`Db::connect`], which migrates.
    pub fn connect_lazy(url: &str) -> Result<Db, DbError> {
        Ok(Db { pool: PgPoolOptions::new().max_connections(1).connect_lazy(url)? })
    }

    /// Apply the idempotent schema. Safe to call on every startup.
    pub async fn migrate(&self) -> Result<(), DbError> {
        sqlx::raw_sql(include_str!("../schema.sql")).execute(&self.pool).await?;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Signature store (source of truth) — same contract as bridge-core::store.
    // ---------------------------------------------------------------------

    /// Insert/merge a record + one signature, enforcing the trust boundary.
    /// Returns the resulting record with all known signatures.
    pub async fn upsert_signature(
        &self,
        record: SubmissionRecord,
        sig: SignerSig,
    ) -> Result<SubmissionRecord, DbError> {
        // (1) id <-> params binding, plus the `token` binding, and then
        // (3) signature authenticity against the id we just verified.
        let computed = verify_binding(&record)?;
        store::verify_signature(computed, &sig)?;
        // Store the encoding the Gate accepts, never the caller's. A high-`s`
        // signature authenticates fine here (alloy normalises before recovering)
        // and then reverts `ECDSA.recover` on-chain, taking the whole quorum array
        // with it — see `store::canonical_signature`.
        let sig = store::canonical_signature(&sig)?;

        let id = norm_id(&record.submission_id);
        let mut tx = self.pool.begin().await?;

        // (2) params are immutable: insert once; on a re-POST verify the stored
        // params still match, else reject (poisoning defense).
        let existing: Option<SubmissionRow> =
            sqlx::query_as("SELECT * FROM submissions WHERE submission_id = $1")
                .bind(&id)
                .fetch_optional(&mut *tx)
                .await?;

        if let Some(row) = existing {
            // Reuse bridge-core's param-equality check rather than re-deriving the
            // field list here. Compare against a copy of `record` whose id is
            // normalized the same way `row.submission_id` is (both `0x`-prefixed,
            // lowercase) — `record.submission_id` itself may lack the prefix.
            let mut incoming = record.clone();
            incoming.submission_id = id.clone();
            if !store::same_params(&row.into_record(Attestations::default()), &incoming) {
                return Err(StoreError::ParamsConflict(record.submission_id.clone()).into());
            }
            // Backfill `token` if this row predates it (e.g. inserted by an older
            // indexer). Verified above, and only ever written once — never
            // overwritten, so it stays as immutable as the rest of the params.
            if !record.token.is_empty() {
                sqlx::query(
                    "UPDATE submissions SET token = $2 WHERE submission_id = $1 AND token IS NULL",
                )
                .bind(&id)
                .bind(record.token.to_ascii_lowercase())
                .execute(&mut *tx)
                .await?;
            }
        } else {
            insert_submission_row(&mut *tx, &id, &record).await?;
        }

        // M-2: bound the row count BEFORE inserting. Counted inside the same
        // transaction as the insert so two concurrent writers cannot both read
        // `cap - 1` and both land; the `SELECT ... FOR UPDATE` on the submission
        // row serialises them (the row exists by now on either branch above).
        let signer_lc = sig.signer.to_ascii_lowercase();
        sqlx::query("SELECT 1 FROM submissions WHERE submission_id = $1 FOR UPDATE")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        enforce_signature_cap(
            &mut tx,
            "SELECT COUNT(*)::BIGINT FROM signatures WHERE submission_id = $1",
            "SELECT 1 FROM signatures WHERE submission_id = $1 AND signer = $2",
            &id,
            &signer_lc,
            "transfer",
        )
        .await?;

        // Merge the signature, deduped by signer.
        let inserted = sqlx::query(
            "INSERT INTO signatures (submission_id, signer, signature) VALUES ($1,$2,$3) \
             ON CONFLICT (submission_id, signer) DO NOTHING",
        )
        .bind(&id)
        .bind(&signer_lc)
        .bind(&sig.signature)
        .execute(&mut *tx)
        .await?;
        if inserted.rows_affected() > 0 {
            sqlx::query("UPDATE submissions SET updated_at = now() WHERE submission_id = $1")
                .bind(&id)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await?;
        // Same ordering hazard as `observe_submission`: a validator's POST can
        // create the row after the indexer already saw the destination event.
        self.apply_pending_lifecycle(&id).await?;
        self.load(&id)
            .await?
            .ok_or(DbError::BadField("submission_id"))
    }

    /// Load one record (params + signatures) by submissionId.
    pub async fn load(&self, submission_id: &str) -> Result<Option<SubmissionRecord>, DbError> {
        if !store::is_valid_submission_id(submission_id) {
            return Ok(None);
        }
        let id = norm_id(submission_id);
        let row: Option<SubmissionRow> =
            sqlx::query_as("SELECT * FROM submissions WHERE submission_id = $1")
                .bind(&id)
                .fetch_optional(&self.pool)
                .await?;
        let Some(row) = row else { return Ok(None) };

        let sigs: Vec<SigRow> = sqlx::query_as(&sig_query("WHERE submission_id = $1"))
            .bind(&id)
            .fetch_all(&self.pool)
            .await?;

        let mut collected = Attestations::default();
        for s in sigs {
            collected.push(&s.kind, SignerSig { signer: s.signer, signature: s.signature });
        }
        Ok(Some(row.into_record(collected)))
    }

    /// Load every record (params + signatures). Two queries + an in-memory join,
    /// so the keeper's poll is one round trip per table rather than N+1.
    pub async fn load_all(&self) -> Result<Vec<SubmissionRecord>, DbError> {
        let rows: Vec<SubmissionRow> =
            sqlx::query_as("SELECT * FROM submissions ORDER BY created_at").fetch_all(&self.pool).await?;
        self.attach_signatures(rows, false).await
    }

    /// One page of records (params + signatures), oldest first — the same order
    /// [`Db::load_all`] uses, so a consumer walking `offset` in steps of `limit`
    /// sees exactly what one unbounded call would have. Bounds what a single
    /// `Read`-scoped HTTP request can pull (audit 2026-09-09, item 10).
    pub async fn load_page(&self, limit: i64, offset: i64) -> Result<Vec<SubmissionRecord>, DbError> {
        let rows: Vec<SubmissionRow> =
            sqlx::query_as("SELECT * FROM submissions ORDER BY created_at, submission_id LIMIT $1 OFFSET $2")
                .bind(limit.max(0))
                .bind(offset.max(0))
                .fetch_all(&self.pool)
                .await?;
        self.attach_signatures(rows, true).await
    }

    /// Attach every row's three signature sets in ONE extra query, rather than
    /// one query per row.
    ///
    /// `scoped` restricts that query to the rows in hand. Pass `true` whenever
    /// the rows are a SUBSET of the table — `refund_candidates` is usually a
    /// handful out of many thousands, and an unscoped fetch there would trade
    /// N+1 round trips for dragging the whole signature table across the wire.
    /// `load_all` passes `false`: its rows are the whole table anyway, so
    /// scoping would only add a large id array to the query for nothing.
    async fn attach_signatures(
        &self,
        rows: Vec<SubmissionRow>,
        scoped: bool,
    ) -> Result<Vec<SubmissionRecord>, DbError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let sigs: Vec<SigRow> = if scoped {
            let ids: Vec<String> = rows.iter().map(|r| r.submission_id.clone()).collect();
            sqlx::query_as(&sig_query("WHERE submission_id = ANY($1)"))
                .bind(&ids)
                .fetch_all(&self.pool)
                .await?
        } else {
            sqlx::query_as(&sig_query("")).fetch_all(&self.pool).await?
        };

        let mut by_id: std::collections::HashMap<String, Attestations> =
            std::collections::HashMap::new();
        for s in sigs {
            by_id
                .entry(s.submission_id)
                .or_default()
                .push(&s.kind, SignerSig { signer: s.signer, signature: s.signature });
        }
        Ok(rows
            .into_iter()
            .map(|r| {
                let sigs = by_id.remove(&r.submission_id).unwrap_or_default();
                r.into_record(sigs)
            })
            .collect())
    }

    /// Merge a cancel/refund attestation into an existing submission.
    ///
    /// Trust boundary, exactly like [`Db::upsert_signature`] but for the other
    /// two domains: the signature must recover to its claimed signer over
    /// `kind`'s own digest. That is what stops a validator's transfer signature
    /// from being replayed to burn (`cancel`) or claw back (`refund`) a healthy
    /// transfer — those are different messages entirely.
    ///
    /// Never creates a submission: an attestation about a transfer we have never
    /// observed is meaningless, and the id⇄params binding stays the only way a
    /// row comes into existence.
    pub async fn upsert_attestation(
        &self,
        submission_id: &str,
        kind: SigKind,
        sig: SignerSig,
    ) -> Result<SubmissionRecord, DbError> {
        if !store::is_valid_submission_id(submission_id) {
            return Err(StoreError::BadField("submission_id").into());
        }
        if kind == SigKind::Transfer {
            // Transfer signatures carry the full params and go through the
            // id<->params binding; they must not sneak in via this route.
            return Err(DbError::BadField("kind"));
        }
        let id = norm_id(submission_id);

        let existing = self.load(&id).await?.ok_or(DbError::BadField("submission_id"))?;
        let parsed = alloy_primitives::B256::from_str(&existing.submission_id)
            .map_err(|_| StoreError::BadField("submission_id"))?;
        store::verify_attestation(parsed, kind, &sig)?;
        // Cancel and refund hit the same on-chain verifier a claim does, so a
        // non-canonical attestation would brick the recovery path too.
        let sig = store::canonical_signature(&sig)?;

        // M-2: same per-domain cap as `upsert_signature`, under the same row lock.
        let signer_lc = sig.signer.to_ascii_lowercase();
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT 1 FROM submissions WHERE submission_id = $1 FOR UPDATE")
            .bind(&id)
            .execute(&mut *tx)
            .await?;
        let count_sql = match kind {
            SigKind::Cancel => {
                "SELECT COUNT(*)::BIGINT FROM attestations WHERE submission_id = $1 AND kind = 'cancel'"
            }
            SigKind::Refund => {
                "SELECT COUNT(*)::BIGINT FROM attestations WHERE submission_id = $1 AND kind = 'refund'"
            }
            SigKind::Transfer => unreachable!("rejected above"),
        };
        let present_sql = match kind {
            SigKind::Cancel => {
                "SELECT 1 FROM attestations WHERE submission_id = $1 AND signer = $2 AND kind = 'cancel'"
            }
            SigKind::Refund => {
                "SELECT 1 FROM attestations WHERE submission_id = $1 AND signer = $2 AND kind = 'refund'"
            }
            SigKind::Transfer => unreachable!("rejected above"),
        };
        enforce_signature_cap(&mut tx, count_sql, present_sql, &id, &signer_lc, kind.as_str()).await?;

        sqlx::query(
            "INSERT INTO attestations (submission_id, kind, signer, signature) \
             VALUES ($1,$2,$3,$4) ON CONFLICT (submission_id, kind, signer) DO NOTHING",
        )
        .bind(&id)
        .bind(kind.as_str())
        .bind(&signer_lc)
        .bind(&sig.signature)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.load(&id).await?.ok_or(DbError::BadField("submission_id"))
    }

    // ---------------------------------------------------------------------
    // Transaction history (status).
    // ---------------------------------------------------------------------

    /// Mark a submission `claimed`, recording the target-chain claim tx hash.
    ///
    /// **Authoritative — on-chain observation only.** The sole caller is the
    /// indexer, on a `Gate.Claimed` event it read from the destination chain. The
    /// keeper's own report goes through [`Db::note_keeper_claim`] instead and
    /// touches none of the columns below (audit 2026-09-09, M-1: the Relay-scoped
    /// HTTP route used to land here, so a leaked keeper token could hide any
    /// transfer from both the claim and refund queues, and pre-poison future ids
    /// via the park table).
    ///
    /// Also clears an `eligible` refund flag: a transfer that sat past the
    /// timeout and then got claimed after all is not stuck, and leaving it
    /// flagged would show a permanent false "refund eligible" in the UI and keep
    /// validators considering it for a cancel attestation. `cancelled`/`refunded`
    /// are terminal and never reset — a claim cannot follow them (the on-chain
    /// `executed` flag makes that impossible), so seeing one would mean the two
    /// chains disagree, and quietly overwriting it would hide that.
    pub async fn mark_claimed(&self, submission_id: &str, claim_tx: &str) -> Result<(), DbError> {
        let id = checked_id(submission_id)?;
        const SQL: &str = "UPDATE submissions SET status = 'claimed', claim_tx = $2, updated_at = now(), \
                    refund_status = CASE WHEN refund_status = 'eligible' THEN 'none' \
                                         ELSE refund_status END \
             WHERE submission_id = $1";
        let affected = self.lifecycle_update(SQL, &id, claim_tx).await?;
        // The indexer scans each chain in its own loop, so a destination
        // `Claimed` can arrive before the source `Sent` has created the row —
        // routinely during backfill. An UPDATE ... WHERE matches nothing and
        // reports success, which silently loses the claim: the transfer stays
        // `signed` and the refund sweep later flags a DELIVERED transfer as
        // eligible. Park it instead; `observe_submission` applies it on arrival.
        self.park_if_missing(
            &id,
            affected,
            Retry { sql: SQL, arg: claim_tx },
            Marker { status: "claimed", claim_tx: Some(claim_tx), ..Marker::NONE },
        )
        .await
    }

    /// The keeper's report that it submitted `claim()` for this transfer.
    ///
    /// **Advisory (M-1).** Writes `keeper_claim_tx` and nothing else: not
    /// `status`, not `refund_status`, and no parked marker for an id we have no
    /// row for. Every work queue (`pending_claims`, `sweep_refund_eligible`,
    /// `refund_candidates`) keys on `status`, which only an observed on-chain
    /// `Claimed` may set — so a Relay-scoped credential can annotate history but
    /// cannot make a transfer disappear from it. First write wins, so a leaked
    /// token cannot even overwrite an honest keeper's annotation.
    ///
    /// Unknown ids are a silent no-op rather than an error: the keeper may
    /// legitimately claim before the indexer's `Sent` row exists, and a 4xx there
    /// would only make it retry a write that carries no authority anyway.
    pub async fn note_keeper_claim(&self, submission_id: &str, claim_tx: &str) -> Result<(), DbError> {
        let id = checked_id(submission_id)?;
        sqlx::query(
            "UPDATE submissions SET keeper_claim_tx = COALESCE(keeper_claim_tx, $2) \
             WHERE submission_id = $1",
        )
        .bind(&id)
        .bind(claim_tx)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Run one lifecycle `UPDATE ... WHERE submission_id = $1` with `$2 = arg`
    /// and return how many rows it touched.
    async fn lifecycle_update(&self, sql: &str, id: &str, arg: &str) -> Result<u64, DbError> {
        let res = sqlx::query(sql).bind(id).bind(arg).execute(&self.pool).await?;
        Ok(res.rows_affected())
    }

    /// Stash a lifecycle marker whose submission row does not exist yet.
    ///
    /// Keyed on the row being ABSENT, not on `rows_affected == 0`. Those are not
    /// the same thing: `mark_cancelled` carries `AND refund_status <> 'refunded'`,
    /// so a row that is already refunded matches nothing — and parking a
    /// `cancelled` marker there would later REGRESS a refunded transfer back to
    /// cancelled, putting a settled transfer back on the refund-candidate list.
    /// A guard that legitimately rejected the update must not be mistaken for a
    /// missing row.
    ///
    /// ## The race (audit 2026-09-09, LOW: `park_if_missing` TOCTOU)
    ///
    /// Between the UPDATE matching nothing and the existence check finding the
    /// row, `observe_submission` can insert it and run `apply_pending_lifecycle`
    /// against an empty park table. Returning "the guard declined it" there lost
    /// the `Claimed`. So:
    ///
    /// 1. if the row exists now, RE-RUN the original UPDATE (`retry`) — its own
    ///    guard decides again, correctly, against the row that now exists;
    /// 2. if it does not, park the marker, then check ONCE MORE: a row inserted
    ///    between the check and the park has already run its apply against a
    ///    table that lacked our marker, so apply it ourselves. Any insert after
    ///    our park commits sees the marker on its own apply. One of the two sides
    ///    always observes the other, without an advisory lock on the hot path.
    async fn park_if_missing(
        &self,
        id: &str,
        rows_affected: u64,
        retry: Retry<'_>,
        marker: Marker<'_>,
    ) -> Result<(), DbError> {
        if rows_affected > 0 {
            return Ok(());
        }
        if self.submission_exists(id).await? {
            self.lifecycle_update(retry.sql, id, retry.arg).await?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO pending_lifecycle \
               (submission_id, status, claim_tx, cancel_tx, refund_tx, refund_status) \
             VALUES ($1,$2,$3,$4,$5,$6) \
             ON CONFLICT (submission_id) DO UPDATE SET \
               status        = COALESCE(EXCLUDED.status,        pending_lifecycle.status), \
               claim_tx      = COALESCE(EXCLUDED.claim_tx,      pending_lifecycle.claim_tx), \
               cancel_tx     = COALESCE(EXCLUDED.cancel_tx,     pending_lifecycle.cancel_tx), \
               refund_tx     = COALESCE(EXCLUDED.refund_tx,     pending_lifecycle.refund_tx), \
               refund_status = COALESCE(EXCLUDED.refund_status, pending_lifecycle.refund_status)",
        )
        .bind(id)
        .bind(if marker.status.is_empty() { None } else { Some(marker.status) })
        .bind(marker.claim_tx)
        .bind(marker.cancel_tx)
        .bind(marker.refund_tx)
        .bind(marker.refund_status)
        .execute(&self.pool)
        .await?;
        if self.submission_exists(id).await? {
            self.apply_pending_lifecycle(id).await?;
        }
        Ok(())
    }

    async fn submission_exists(&self, id: &str) -> Result<bool, DbError> {
        let exists: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM submissions WHERE submission_id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(exists.is_some())
    }

    /// Apply (and clear) any lifecycle marker parked before this row existed.
    async fn apply_pending_lifecycle(&self, id: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE submissions s SET \
               status        = COALESCE(p.status,        s.status), \
               claim_tx      = COALESCE(p.claim_tx,      s.claim_tx), \
               cancel_tx     = COALESCE(p.cancel_tx,     s.cancel_tx), \
               refund_tx     = COALESCE(p.refund_tx,     s.refund_tx), \
               refund_status = COALESCE(p.refund_status, s.refund_status), \
               updated_at    = now() \
             FROM pending_lifecycle p \
             WHERE s.submission_id = $1 AND p.submission_id = s.submission_id",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM pending_lifecycle WHERE submission_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Record that the destination gate burned this transfer (`Gate.Cancelled`).
    /// This is the state that unlocks refund attestations, so it is only ever
    /// written from an observed on-chain event, never from a relayer's say-so.
    pub async fn mark_cancelled(&self, submission_id: &str, cancel_tx: &str) -> Result<(), DbError> {
        let id = checked_id(submission_id)?;
        const SQL: &str = "UPDATE submissions SET refund_status = 'cancelled', cancel_tx = $2, updated_at = now() \
             WHERE submission_id = $1 AND refund_status <> 'refunded'";
        let affected = self.lifecycle_update(SQL, &id, cancel_tx).await?;
        self.park_if_missing(
            &id,
            affected,
            Retry { sql: SQL, arg: cancel_tx },
            Marker { cancel_tx: Some(cancel_tx), refund_status: Some("cancelled"), ..Marker::NONE },
        )
        .await
    }

    /// Record that the source gate returned the funds (`Gate.Refunded`).
    pub async fn mark_refunded(&self, submission_id: &str, refund_tx: &str) -> Result<(), DbError> {
        let id = checked_id(submission_id)?;
        const SQL: &str = "UPDATE submissions SET refund_status = 'refunded', refund_tx = $2, updated_at = now() \
             WHERE submission_id = $1";
        let affected = self.lifecycle_update(SQL, &id, refund_tx).await?;
        self.park_if_missing(
            &id,
            affected,
            Retry { sql: SQL, arg: refund_tx },
            Marker { refund_tx: Some(refund_tx), refund_status: Some("refunded"), ..Marker::NONE },
        )
        .await
    }

    /// The transaction-history view: every submission with its status, claim tx,
    /// signature count, refund eligibility, swap intent (if any), and timestamps.
    /// Newest first. Unbounded — see [`Db::history_page`] for the HTTP surface.
    pub async fn history(&self) -> Result<Vec<SubmissionHistory>, DbError> {
        let rows: Vec<SubmissionRow> =
            sqlx::query_as("SELECT * FROM submissions ORDER BY created_at DESC").fetch_all(&self.pool).await?;
        self.history_for(rows).await
    }

    /// One page of the history view, newest first (ties broken by id so pages
    /// are stable). The aggregate queries are scoped to the page's ids rather
    /// than the whole table.
    pub async fn history_page(&self, limit: i64, offset: i64) -> Result<Vec<SubmissionHistory>, DbError> {
        let rows: Vec<SubmissionRow> = sqlx::query_as(
            "SELECT * FROM submissions ORDER BY created_at DESC, submission_id LIMIT $1 OFFSET $2",
        )
        .bind(limit.max(0))
        .bind(offset.max(0))
        .fetch_all(&self.pool)
        .await?;
        self.history_for(rows).await
    }

    /// Attach signature counts, attestation counts and swap intent to `rows`,
    /// with every aggregate scoped to exactly those rows.
    async fn history_for(&self, rows: Vec<SubmissionRow>) -> Result<Vec<SubmissionHistory>, DbError> {
        if rows.is_empty() {
            return Ok(Vec::new());
        }
        let ids: Vec<String> = rows.iter().map(|r| r.submission_id.clone()).collect();
        let counts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT submission_id, COUNT(*)::BIGINT FROM signatures \
             WHERE submission_id = ANY($1) GROUP BY submission_id",
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await?;
        let counts: std::collections::HashMap<String, i64> = counts.into_iter().collect();

        // Cancel/refund quorum progress, counted per domain so the UI can show
        // how far a stuck transfer has got through the refund path.
        let att_counts: Vec<(String, String, i64)> = sqlx::query_as(
            "SELECT submission_id, kind, COUNT(*)::BIGINT FROM attestations \
             WHERE submission_id = ANY($1) GROUP BY submission_id, kind",
        )
        .bind(&ids)
        .fetch_all(&self.pool)
        .await?;
        let mut cancel_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        let mut refund_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
        for (id, kind, n) in att_counts {
            match SigKind::parse(&kind) {
                Some(SigKind::Cancel) => {
                    cancel_counts.insert(id, n);
                }
                Some(SigKind::Refund) => {
                    refund_counts.insert(id, n);
                }
                _ => {}
            }
        }

        let swap_bridges: Vec<SwapBridgeRow> =
            sqlx::query_as("SELECT * FROM swap_bridges WHERE submission_id = ANY($1)")
                .bind(&ids)
                .fetch_all(&self.pool)
                .await?;
        let mut swap_bridges: std::collections::HashMap<String, SwapBridgeInfo> = swap_bridges
            .into_iter()
            .map(|r| (r.submission_id.clone(), r.into_info()))
            .collect();

        Ok(rows
            .into_iter()
            .map(|r| {
                let n = counts.get(&r.submission_id).copied().unwrap_or(0);
                let c = cancel_counts.get(&r.submission_id).copied().unwrap_or(0);
                let f = refund_counts.get(&r.submission_id).copied().unwrap_or(0);
                let intent = swap_bridges.remove(&r.submission_id);
                r.into_history(n, c, f, intent)
            })
            .collect())
    }

    // ---------------------------------------------------------------------
    // Indexer support: observe on-chain events independently of validator
    // signing, so a transfer is visible even before (or without) any signature.
    // ---------------------------------------------------------------------

    /// Insert a submission row on first observation of its `Sent` event, before
    /// any signature exists. Idempotent — a later `upsert_signature` call for the
    /// same id just adds signatures to this row. Enforces the same id<->params
    /// binding as `upsert_signature`, but never touches an existing row (params
    /// are immutable; if a row already exists there is nothing to update here).
    pub async fn observe_submission(&self, record: SubmissionRecord) -> Result<(), DbError> {
        verify_binding(&record)?;

        let id = norm_id(&record.submission_id);
        insert_submission_row(&self.pool, &id, &record).await?;
        // A `Claimed`/`Cancelled`/`Refunded` may have been observed on the other
        // chain before this row existed; fold it in now.
        self.apply_pending_lifecycle(&id).await?;
        Ok(())
    }

    /// Record a completed same-chain swap (`SwapPool.Swapped`). Idempotent on
    /// `(chain_id, tx_hash, log_index)` so a re-scanned block range is harmless.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_swap(
        &self,
        chain_id: u64,
        tx_hash: &str,
        log_index: i64,
        sender: &str,
        receiver: &str,
        token_in: &str,
        token_out: &str,
        amount_in: &str,
        amount_out: &str,
        block_number: u64,
    ) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO swaps \
             (chain_id, tx_hash, log_index, sender, receiver, token_in, token_out, \
              amount_in, amount_out, block_number) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) \
             ON CONFLICT (chain_id, tx_hash, log_index) DO NOTHING",
        )
        .bind(chain_id as i64)
        .bind(tx_hash.to_ascii_lowercase())
        .bind(log_index as i32)
        .bind(sender.to_ascii_lowercase())
        .bind(receiver.to_ascii_lowercase())
        .bind(token_in.to_ascii_lowercase())
        .bind(token_out.to_ascii_lowercase())
        .bind(amount_in)
        .bind(amount_out)
        .bind(block_number as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn list_swaps(&self, chain_id: Option<u64>, limit: i64) -> Result<Vec<SwapRecord>, DbError> {
        let rows: Vec<SwapRow> = match chain_id {
            Some(c) => {
                sqlx::query_as(
                    "SELECT * FROM swaps WHERE chain_id = $1 ORDER BY created_at DESC LIMIT $2",
                )
                .bind(c as i64)
                .bind(limit)
                .fetch_all(&self.pool)
                .await?
            }
            None => {
                sqlx::query_as("SELECT * FROM swaps ORDER BY created_at DESC LIMIT $1")
                    .bind(limit)
                    .fetch_all(&self.pool)
                    .await?
            }
        };
        Ok(rows.into_iter().map(SwapRow::into_record).collect())
    }

    /// Record the source-leg swap intent of a `SwapRouter.swapAndBridge` call
    /// (the `SwapBridged` event), keyed by the bridge submission it produced.
    /// The submission row itself must already exist (inserted by
    /// `observe_submission` from the paired `Sent` event in the same tx).
    pub async fn record_swap_bridge_intent(
        &self,
        submission_id: &str,
        token_in: &str,
        amount_in: &str,
        stable_out: &str,
        final_token: &str,
        final_receiver: &str,
    ) -> Result<(), DbError> {
        let id = norm_id(submission_id);
        sqlx::query(
            "INSERT INTO swap_bridges \
             (submission_id, token_in, amount_in, stable_out, final_token, final_receiver) \
             VALUES ($1,$2,$3,$4,$5,$6) \
             ON CONFLICT (submission_id) DO NOTHING",
        )
        .bind(&id)
        .bind(token_in.to_ascii_lowercase())
        .bind(amount_in)
        .bind(stable_out)
        .bind(final_token.to_ascii_lowercase())
        .bind(final_receiver.to_ascii_lowercase())
        .execute(&self.pool)
        .await?;
        // The destination leg may already have been observed — fold it in.
        self.apply_pending_finalize(&id).await?;
        Ok(())
    }

    /// Apply (and clear) a destination outcome parked before the intent row
    /// existed. Mirror of [`Db::apply_pending_lifecycle`] for `swap_bridges`.
    async fn apply_pending_finalize(&self, id: &str) -> Result<(), DbError> {
        sqlx::query(
            "UPDATE swap_bridges b SET \
               finalize_tx         = p.finalize_tx, \
               finalize_amount_out = p.finalize_amount_out, \
               finalize_fallback   = p.finalize_fallback, \
               finalized_at        = now() \
             FROM pending_finalize p \
             WHERE b.submission_id = $1 AND p.submission_id = b.submission_id \
               AND b.finalize_tx IS NULL",
        )
        .bind(id)
        .execute(&self.pool)
        .await?;
        sqlx::query("DELETE FROM pending_finalize WHERE submission_id = $1")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    async fn swap_bridge_exists(&self, id: &str) -> Result<bool, DbError> {
        let exists: Option<(i32,)> =
            sqlx::query_as("SELECT 1 FROM swap_bridges WHERE submission_id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(exists.is_some())
    }

    /// Record the destination-leg outcome (`Finalized` / `FinalizeFallback`) of a
    /// swap-bridge. `fallback = true` means the destination swap failed and the
    /// stable was delivered directly instead.
    ///
    /// The destination leg is scanned independently of the source leg, so this
    /// can run before `record_swap_bridge_intent` has created the row (the same
    /// race `pending_lifecycle` exists for). It used to be a silent no-op then —
    /// the UI showed a finished swap-bridge as forever pending. Now it parks the
    /// outcome in `pending_finalize`, applied when the intent arrives, with the
    /// same double-check as [`Db::park_if_missing`] so an intent row inserted
    /// concurrently cannot slip between the check and the park.
    pub async fn record_finalized(
        &self,
        submission_id: &str,
        finalize_tx: &str,
        amount_out: &str,
        fallback: bool,
    ) -> Result<(), DbError> {
        let id = checked_id(submission_id)?;
        let update = || async {
            let res = sqlx::query(
                "UPDATE swap_bridges SET finalize_tx = $2, finalize_amount_out = $3, \
                 finalize_fallback = $4, finalized_at = now() WHERE submission_id = $1",
            )
            .bind(&id)
            .bind(finalize_tx)
            .bind(amount_out)
            .bind(fallback)
            .execute(&self.pool)
            .await?;
            Ok::<u64, DbError>(res.rows_affected())
        };
        if update().await? > 0 {
            return Ok(());
        }
        if self.swap_bridge_exists(&id).await? {
            // Lost the race against `record_swap_bridge_intent`; the row is there now.
            update().await?;
            return Ok(());
        }
        sqlx::query(
            "INSERT INTO pending_finalize \
               (submission_id, finalize_tx, finalize_amount_out, finalize_fallback) \
             VALUES ($1,$2,$3,$4) \
             ON CONFLICT (submission_id) DO NOTHING",
        )
        .bind(&id)
        .bind(finalize_tx)
        .bind(amount_out)
        .bind(fallback)
        .execute(&self.pool)
        .await?;
        if self.swap_bridge_exists(&id).await? {
            self.apply_pending_finalize(&id).await?;
        }
        Ok(())
    }

    /// Flip `refund_status` from `'none'` to `'eligible'` for submissions that
    /// are still unclaimed and older than `timeout`.
    ///
    /// This only nominates candidates — it moves no funds and authorises nothing.
    /// A validator independently re-checks the destination gate (`executed` must
    /// still be false) before it will attest a cancel, so a wrong or manipulated
    /// timestamp here can at most cause a needless look, never a payout.
    pub async fn sweep_refund_eligible(&self, timeout: chrono::Duration) -> Result<u64, DbError> {
        let cutoff = chrono::Utc::now() - timeout;
        let res = sqlx::query(
            "UPDATE submissions SET refund_status = 'eligible', updated_at = now() \
             WHERE status <> 'claimed' AND refund_status = 'none' AND created_at < $1",
        )
        .bind(cutoff)
        .execute(&self.pool)
        .await?;
        Ok(res.rows_affected())
    }

    /// Submissions a refund relayer should look at: flagged stuck, not yet
    /// refunded, and destined for / originating from the given chain.
    ///
    /// Deliberately returns candidates rather than decisions — the caller must
    /// still verify both chains on-chain before signing anything.
    pub async fn refund_candidates(&self) -> Result<Vec<SubmissionRecord>, DbError> {
        let rows: Vec<SubmissionRow> = sqlx::query_as(
            "SELECT * FROM submissions \
             WHERE status <> 'claimed' AND refund_status IN ('eligible','cancelled') \
             ORDER BY created_at",
        )
        .fetch_all(&self.pool)
        .await?;

        // One extra query for every candidate's signature sets, not one per
        // candidate: this list is polled by every validator's refund loop on
        // every tick, so the old per-row `load` was N+1 round trips per poll.
        // Scoped, because candidates are a small subset of the table.
        self.attach_signatures(rows, true).await
    }

    /// The target-side WORK QUEUE for one destination chain: transfers that may
    /// still need a `claim` or a `cancel` there.
    ///
    /// ## Why this exists
    ///
    /// The keeper used to call [`load_all`] every tick — an unbounded
    /// `SELECT * FROM submissions` plus a join over every signature row ever
    /// written — and then, because [`SubmissionRecord`] carries no lifecycle at
    /// all, a DELIVERED transfer looked exactly like a pending one and fell
    /// through to `gate.executed()`. One `eth_call` per historically-delivered
    /// transfer, per poll interval, per target chain, forever. At a two-second
    /// poll and 100k lifetime transfers that is ~50k `eth_call`/second against the
    /// destination RPC: the keeper stops working long before the bridge does
    /// anything wrong, and the keeper is also what relays cancels and refunds.
    ///
    /// The lifecycle columns the indexer already maintains answer it in SQL, on
    /// indexed columns.
    ///
    /// ## What it is not
    ///
    /// A hint, not an authority. Every `try_*` still re-checks the chain before it
    /// submits, so a row wrongly included costs one wasted read and a row wrongly
    /// excluded is one the chain says is already settled. `status` only reaches
    /// `'claimed'` from a `Claimed` event the indexer observed (M-1: the keeper's
    /// own report is advisory and does not move it), so a deployment running no
    /// indexer keeps re-probing rows a keeper delivered — exactly the pre-indexer
    /// behaviour, never worse.
    pub async fn pending_claims(&self, chain_id_to: u64) -> Result<Vec<SubmissionRecord>, DbError> {
        let rows: Vec<SubmissionRow> = sqlx::query_as(
            "SELECT * FROM submissions \
             WHERE chain_id_to = $1 AND status <> 'claimed' \
               AND refund_status NOT IN ('cancelled','refunded') \
             ORDER BY created_at",
        )
        .bind(chain_id_to as i64)
        .fetch_all(&self.pool)
        .await?;
        self.attach_signatures(rows, true).await
    }

    /// The source-side work queue for one origin chain: transfers that may still
    /// need a `refund` paid out there.
    ///
    /// Keyed on "a validator has attested a refund for this", not on the
    /// `refund_status` column, deliberately. A refund quorum only forms after the
    /// validators independently observe the destination burn, so the attestation
    /// is the precondition itself — and unlike `refund_status` it does not depend
    /// on an indexer being deployed. See [`pending_claims`] for why the queue is a
    /// hint rather than an authority.
    pub async fn pending_refunds(
        &self,
        chain_id_from: u64,
    ) -> Result<Vec<SubmissionRecord>, DbError> {
        let rows: Vec<SubmissionRow> = sqlx::query_as(
            "SELECT s.* FROM submissions s \
             WHERE s.chain_id_from = $1 AND s.refund_status <> 'refunded' \
               AND EXISTS ( \
                 SELECT 1 FROM attestations a \
                 WHERE a.submission_id = s.submission_id AND a.kind = 'refund' \
               ) \
             ORDER BY s.created_at",
        )
        .bind(chain_id_from as i64)
        .fetch_all(&self.pool)
        .await?;
        self.attach_signatures(rows, true).await
    }

    /// Resume cursor for one chain (indexer). `None` if never persisted.
    pub async fn get_cursor(&self, chain_id: u64) -> Result<Option<u64>, DbError> {
        let row: Option<(i64,)> =
            sqlx::query_as("SELECT last_block FROM indexer_cursors WHERE chain_id = $1")
                .bind(chain_id as i64)
                .fetch_optional(&self.pool)
                .await?;
        Ok(row.map(|(b,)| b as u64))
    }

    pub async fn set_cursor(&self, chain_id: u64, last_block: u64) -> Result<(), DbError> {
        sqlx::query(
            "INSERT INTO indexer_cursors (chain_id, last_block, updated_at) VALUES ($1,$2,now()) \
             ON CONFLICT (chain_id) DO UPDATE SET last_block = EXCLUDED.last_block, updated_at = now()",
        )
        .bind(chain_id as i64)
        .bind(last_block as i64)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ---------------------------------------------------------------------
    // Allowlists.
    // ---------------------------------------------------------------------

    /// Whitelist a token. `debridge_id = keccak256(chain_id, token)` is derived
    /// here so a caller can't pin a token onto the wrong hash. Upsert by key.
    pub async fn add_allowed_token(
        &self,
        chain_id: u64,
        token: &str,
        symbol: Option<&str>,
    ) -> Result<AllowedToken, DbError> {
        let addr = Address::from_str(token.trim()).map_err(|_| DbError::BadField("token"))?;
        let token_lc = format!("{addr:#x}");
        let debridge_id = format!("{:#x}", bridge_core::debridge_id(U256::from(chain_id), addr));
        sqlx::query(
            "INSERT INTO allowed_tokens (chain_id, token_address, debridge_id, symbol) \
             VALUES ($1,$2,$3,$4) \
             ON CONFLICT (chain_id, token_address) \
             DO UPDATE SET debridge_id = EXCLUDED.debridge_id, symbol = EXCLUDED.symbol",
        )
        .bind(chain_id as i64)
        .bind(&token_lc)
        .bind(&debridge_id)
        .bind(symbol)
        .execute(&self.pool)
        .await?;
        Ok(AllowedToken {
            chain_id,
            token: token_lc,
            debridge_id,
            symbol: symbol.map(str::to_string),
        })
    }

    /// Remove a token from the allowlist. Returns true if a row was deleted.
    ///
    /// Refuses to delete the LAST entry. The list's semantics are opt-in —
    /// `Allowlist::token_allowed` treats an empty list as "no restriction
    /// configured" — so pruning row by row crosses from deny-by-default to
    /// allow-everything the moment the final row goes, with no error and no log,
    /// at both enforcement points at once (the validator and the keeper build
    /// their view from the same fetch). Turning enforcement off should be a
    /// decision, not the side effect of one more DELETE.
    pub async fn remove_allowed_token(&self, chain_id: u64, token: &str) -> Result<bool, DbError> {
        let addr = Address::from_str(token.trim()).map_err(|_| DbError::BadField("token"))?;
        let mut tx = self.pool.begin().await?;
        lock_allowlist_table(&mut tx, "allowed_tokens").await?;
        let res = sqlx::query("DELETE FROM allowed_tokens WHERE chain_id = $1 AND token_address = $2")
            .bind(chain_id as i64)
            .bind(format!("{addr:#x}"))
            .execute(&mut *tx)
            .await?;
        if res.rows_affected() > 0 {
            refuse_if_emptied(&mut tx, "allowed_tokens").await?;
        }
        tx.commit().await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn list_allowed_tokens(&self) -> Result<Vec<AllowedToken>, DbError> {
        let rows: Vec<(i64, String, String, Option<String>)> = sqlx::query_as(
            "SELECT chain_id, token_address, debridge_id, symbol FROM allowed_tokens \
             ORDER BY chain_id, token_address",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(chain_id, token, debridge_id, symbol)| AllowedToken {
                chain_id: chain_id as u64,
                token,
                debridge_id,
                symbol,
            })
            .collect())
    }

    pub async fn add_allowed_chain(&self, from: u64, to: u64) -> Result<AllowedChain, DbError> {
        sqlx::query(
            "INSERT INTO allowed_chains (chain_id_from, chain_id_to) VALUES ($1,$2) \
             ON CONFLICT (chain_id_from, chain_id_to) DO NOTHING",
        )
        .bind(from as i64)
        .bind(to as i64)
        .execute(&self.pool)
        .await?;
        Ok(AllowedChain { chain_id_from: from, chain_id_to: to })
    }

    /// Remove a chain pair from the allowlist. Returns true if a row was deleted.
    /// Refuses the last entry, for the reason [`Db::remove_allowed_token`] gives.
    pub async fn remove_allowed_chain(&self, from: u64, to: u64) -> Result<bool, DbError> {
        let mut tx = self.pool.begin().await?;
        lock_allowlist_table(&mut tx, "allowed_chains").await?;
        let res =
            sqlx::query("DELETE FROM allowed_chains WHERE chain_id_from = $1 AND chain_id_to = $2")
                .bind(from as i64)
                .bind(to as i64)
                .execute(&mut *tx)
                .await?;
        if res.rows_affected() > 0 {
            refuse_if_emptied(&mut tx, "allowed_chains").await?;
        }
        tx.commit().await?;
        Ok(res.rows_affected() > 0)
    }

    pub async fn list_allowed_chains(&self) -> Result<Vec<AllowedChain>, DbError> {
        let rows: Vec<(i64, i64)> = sqlx::query_as(
            "SELECT chain_id_from, chain_id_to FROM allowed_chains ORDER BY chain_id_from, chain_id_to",
        )
        .fetch_all(&self.pool)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(chain_id_from, chain_id_to)| AllowedChain {
                chain_id_from: chain_id_from as u64,
                chain_id_to: chain_id_to as u64,
            })
            .collect())
    }
}
