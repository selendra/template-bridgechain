-- bridge-db schema. Idempotent: re-run on every startup (CREATE ... IF NOT EXISTS).
-- The DB is the single source of truth for transaction history + allowlists.

-- One row per cross-chain transfer (the off-chain mirror of a `Sent` event),
-- plus its lifecycle status. Parameters are IMMUTABLE once written; only the
-- status / claim_tx / updated_at columns ever change after insert.
CREATE TABLE IF NOT EXISTS submissions (
    submission_id   TEXT PRIMARY KEY,
    debridge_id     TEXT        NOT NULL,
    amount          TEXT        NOT NULL,          -- uint256 as decimal string
    chain_id_from   BIGINT      NOT NULL,
    chain_id_to     BIGINT      NOT NULL,
    nonce           BIGINT      NOT NULL,
    receiver        TEXT        NOT NULL,
    auto_params     TEXT        NOT NULL DEFAULT '0x',
    native_sender   TEXT        NOT NULL DEFAULT '0x',
    status          TEXT        NOT NULL DEFAULT 'signed',  -- 'signed' | 'claimed'
    claim_tx        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- Refund lifecycle:
    --   none      -- healthy, or already delivered
    --   eligible  -- past the timeout and still unclaimed; validators may attest
    --                a cancel (set by the indexer's periodic sweep, cleared again
    --                if the transfer is claimed after all)
    --   cancelled -- burned on the DESTINATION chain, so `claim` can never land.
    --                This is what unlocks refund attestations.
    --   refunded  -- funds returned to the sender on the SOURCE chain
    refund_status   TEXT        NOT NULL DEFAULT 'none',
    refund_tx       TEXT,
    -- Destination-chain `Gate.cancel` tx hash, once burned.
    cancel_tx       TEXT,
    -- The source-chain ERC-20 that was locked. Not derivable from debridge_id
    -- (a one-way hash), and the refund relayer needs the concrete address to
    -- build `Gate.refund`. Written from the `Sent` event; verified against
    -- debridge_id before it is ever stored (see bridge_core::store).
    token           TEXT
);
CREATE INDEX IF NOT EXISTS idx_submissions_to     ON submissions (chain_id_to);
-- The keeper's source-side work queue filters on chain_id_from every tick.
CREATE INDEX IF NOT EXISTS idx_submissions_from   ON submissions (chain_id_from);
CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions (status);
CREATE INDEX IF NOT EXISTS idx_submissions_refund ON submissions (refund_status);
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS refund_status TEXT NOT NULL DEFAULT 'none';
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS refund_tx TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS cancel_tx TEXT;
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS token TEXT;

-- Validator attestations for the refund path, kept apart from `signatures`
-- because each domain authorises a DIFFERENT on-chain effect and therefore
-- needs its own independent quorum:
--   'cancel'  -- burn the transfer on the destination gate (releases nothing)
--   'refund'  -- return the locked funds on the source gate
-- Mixing them would let a transfer quorum burn or claw back a healthy transfer.
-- Each row's signature is verified against its own digest before insert.
CREATE TABLE IF NOT EXISTS attestations (
    submission_id   TEXT        NOT NULL REFERENCES submissions (submission_id) ON DELETE CASCADE,
    kind            TEXT        NOT NULL,
    signer          TEXT        NOT NULL,
    signature       TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (submission_id, kind, signer)
);
CREATE INDEX IF NOT EXISTS idx_attestations_kind ON attestations (kind);

-- Collected validator signatures, deduped by signer per submission.
CREATE TABLE IF NOT EXISTS signatures (
    submission_id   TEXT        NOT NULL REFERENCES submissions (submission_id) ON DELETE CASCADE,
    signer          TEXT        NOT NULL,
    signature       TEXT        NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (submission_id, signer)
);

-- Allowlist: which ERC-20s may bridge. `debridge_id` is keccak256(chain_id, token),
-- precomputed so the validator/keeper match a `Sent` event by one hash lookup.
CREATE TABLE IF NOT EXISTS allowed_tokens (
    chain_id        BIGINT      NOT NULL,
    token_address   TEXT        NOT NULL,
    debridge_id     TEXT        NOT NULL,
    symbol          TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id, token_address)
);
CREATE INDEX IF NOT EXISTS idx_allowed_tokens_debridge ON allowed_tokens (debridge_id);

-- Allowlist: which directed source->target chain pairs may bridge.
CREATE TABLE IF NOT EXISTS allowed_chains (
    chain_id_from   BIGINT      NOT NULL,
    chain_id_to     BIGINT      NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (chain_id_from, chain_id_to)
);

-- Same-chain swaps (SwapPool.Swapped), mirrored by the indexer. Swaps are
-- atomic (revert on failure), so this only ever holds completed swaps.
CREATE TABLE IF NOT EXISTS swaps (
    id              BIGSERIAL   PRIMARY KEY,
    chain_id        BIGINT      NOT NULL,
    tx_hash         TEXT        NOT NULL,
    log_index       INT         NOT NULL,
    sender          TEXT        NOT NULL,
    receiver        TEXT        NOT NULL,
    token_in        TEXT        NOT NULL,
    token_out       TEXT        NOT NULL,
    amount_in       TEXT        NOT NULL,
    amount_out      TEXT        NOT NULL,
    block_number    BIGINT      NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (chain_id, tx_hash, log_index)
);
CREATE INDEX IF NOT EXISTS idx_swaps_chain  ON swaps (chain_id);
CREATE INDEX IF NOT EXISTS idx_swaps_sender ON swaps (sender);

-- Swap intent + destination outcome for a SwapRouter.swapAndBridge transfer,
-- one row per bridge submission. Populated by the indexer from SwapBridged
-- (source leg) and Finalized/FinalizeFallback (destination leg).
CREATE TABLE IF NOT EXISTS swap_bridges (
    submission_id       TEXT        PRIMARY KEY REFERENCES submissions (submission_id) ON DELETE CASCADE,
    token_in            TEXT        NOT NULL,
    amount_in           TEXT        NOT NULL,
    stable_out          TEXT        NOT NULL,
    final_token         TEXT        NOT NULL,
    final_receiver      TEXT        NOT NULL,
    finalize_tx         TEXT,
    finalize_amount_out TEXT,
    finalize_fallback   BOOLEAN,
    finalized_at        TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-chain resume cursor for the indexer (keeps it stateless/restartable,
-- unlike the validator's local-file cursor).
CREATE TABLE IF NOT EXISTS indexer_cursors (
    chain_id        BIGINT      PRIMARY KEY,
    last_block      BIGINT      NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lifecycle events observed BEFORE the transfer's own row exists.
--
-- The indexer runs one loop per chain, concurrently, so the destination's
-- `Claimed` can be read before the source's `Sent` has created the submissions
-- row — routinely so during a backfill, where the two chains are scanned at
-- unrelated speeds. `mark_claimed` is an UPDATE ... WHERE, which matches zero
-- rows and returns success, so the claim was silently dropped: the transfer
-- stayed `signed` forever and the refund sweep then flagged a DELIVERED
-- transfer as refund-eligible.
--
-- Rows here are parked markers, applied by `apply_pending_lifecycle` as soon as
-- the submission appears, then deleted. Not a queue — at most one row per
-- submission, last write wins per column.
CREATE TABLE IF NOT EXISTS pending_lifecycle (
    submission_id   TEXT        PRIMARY KEY,
    status          TEXT,
    claim_tx        TEXT,
    cancel_tx       TEXT,
    refund_tx       TEXT,
    refund_status   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Deployment generation of the emitting gate. Part of the submissionId preimage,
-- so `canonical_submission_id` cannot re-derive an id without it. Nullable
-- because rows written before the domain existed have none: those belong to a
-- superseded generation and MUST fail the id check rather than be recomputed
-- under a zero domain, which is exactly the cross-deployment replay this closes.
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS bridge_domain TEXT;

-- Audit 2026-09-09, M-1: the keeper's claim report is ADVISORY.
--
-- `POST /submissions/:id/claimed` (Relay scope) used to write `status='claimed'`
-- directly, which every work queue filters on — so a leaked keeper token could
-- hide any transfer from both the claim path and the refund path, and (since
-- ids are deterministic) pre-poison future ones via the park table. The keeper
-- now lands here instead; `status` is written ONLY from an observed on-chain
-- `Claimed` (the indexer). Nothing reads this column for control flow.
ALTER TABLE submissions ADD COLUMN IF NOT EXISTS keeper_claim_tx TEXT;

-- Destination-leg swap outcomes (`Finalized` / `FinalizeFallback`) observed
-- BEFORE the `swap_bridges` intent row exists — the same cross-chain scan race
-- `pending_lifecycle` covers for the submission itself. Applied and deleted by
-- `record_swap_bridge_intent` when the intent row arrives.
CREATE TABLE IF NOT EXISTS pending_finalize (
    submission_id       TEXT        PRIMARY KEY,
    finalize_tx         TEXT        NOT NULL,
    finalize_amount_out TEXT        NOT NULL,
    finalize_fallback   BOOLEAN     NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
