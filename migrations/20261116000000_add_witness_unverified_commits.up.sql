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

-- TRUE only when every link from epoch 0 up to this epoch was witnessed and
-- checked (previousEpochHead and prevSig against a chain-verified predecessor).
-- Epoch 0 is the anchor. Existing rows are backfilled by walking forward from
-- epoch 0 while each next epoch's previousEpochHead matches its predecessor's
-- head; the witness stores an epoch next to a pinned neighbour only after the
-- prevSig on that link verified. Anything past a missing epoch stays unverified
-- until the witness sees the missing link.
ALTER TABLE witness_mailbox_epochs
    ADD COLUMN chain_verified BOOLEAN NOT NULL DEFAULT FALSE;

WITH RECURSIVE verified_chain AS (
    SELECT actor_did, epoch_number, epoch_head
    FROM witness_mailbox_epochs
    WHERE epoch_number = 0
      AND previous_epoch_head IS NULL
    UNION ALL
    SELECT cur.actor_did, cur.epoch_number, cur.epoch_head
    FROM witness_mailbox_epochs AS cur
    JOIN verified_chain AS prev
      ON prev.actor_did = cur.actor_did
     AND cur.epoch_number = prev.epoch_number + 1
     AND cur.previous_epoch_head = prev.epoch_head
)
UPDATE witness_mailbox_epochs AS e
SET chain_verified = TRUE
FROM verified_chain AS v
WHERE e.actor_did = v.actor_did
  AND e.epoch_number = v.epoch_number;

-- Chain verdict of the epoch the `self` head points at. A head on an
-- unverified epoch is the latest observed pointer, not a witnessed one.
ALTER TABLE witness_mailbox_heads
    ADD COLUMN current_epoch_chain_verified BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE witness_mailbox_heads AS h
SET current_epoch_chain_verified = TRUE
FROM witness_mailbox_epochs AS e
WHERE e.actor_did = h.actor_did
  AND e.epoch_number = h.current_epoch_number
  AND e.epoch_head = h.current_epoch_head
  AND e.chain_verified;
