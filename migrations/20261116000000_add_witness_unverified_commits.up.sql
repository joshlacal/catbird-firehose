-- Fail-closed witness verdicts.
--
-- A transparency commit the witness could not verify, could not store, or never
-- received is recorded here instead of being silently skipped. Nothing in these
-- tables counts as witnessed state.

-- One row per (commit, op path, reason) the witness withheld. Commit-level
-- verdicts (signature, CAR, MST, DID resolution, storage) use op_path '#commit'
-- and list the claimed transparency paths in `claimed_paths`.
CREATE TABLE witness_unverified_commits (
    id BIGSERIAL PRIMARY KEY,
    actor_did TEXT NOT NULL,
    seq BIGINT NOT NULL,
    commit_rev TEXT NOT NULL,
    commit_cid TEXT,
    op_path TEXT NOT NULL,
    claimed_paths TEXT[] NOT NULL DEFAULT '{}',
    reason TEXT NOT NULL,
    detail TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (actor_did, seq, op_path, reason)
);

CREATE INDEX idx_witness_unverified_commits_actor
    ON witness_unverified_commits (actor_did, detected_at DESC);

CREATE INDEX idx_witness_unverified_commits_reason
    ON witness_unverified_commits (reason, detected_at DESC);

-- Firehose events dropped before reaching the witness (broadcast lag). Every
-- actor's transparency state is unverified across [last_seq_before_gap,
-- first_seq_after_gap].
CREATE TABLE witness_stream_gaps (
    id BIGSERIAL PRIMARY KEY,
    dropped_events BIGINT NOT NULL,
    last_seq_before_gap BIGINT,
    first_seq_after_gap BIGINT,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_witness_stream_gaps_detected
    ON witness_stream_gaps (detected_at DESC);

-- TRUE only when previousEpochHead and prevSig were checked against a witnessed
-- predecessor epoch (or the epoch is 0). Existing rows are backfilled from the
-- witnessed predecessor they link to; anything else stays unverified.
ALTER TABLE witness_mailbox_epochs
    ADD COLUMN chain_verified BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE witness_mailbox_epochs AS cur
SET chain_verified = TRUE
WHERE cur.epoch_number = 0
   OR EXISTS (
        SELECT 1
        FROM witness_mailbox_epochs AS prev
        WHERE prev.actor_did = cur.actor_did
          AND prev.epoch_number = cur.epoch_number - 1
          AND prev.epoch_head = cur.previous_epoch_head
   );
