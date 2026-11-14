-- NBD-style firehose-witnessed monotonic device & mailbox key transparency tables (Y-6 / D-1).
-- Indexes public ATProto repo commits for `blue.catbird.chat.device` and
-- `blue.catbird.labyrinth.mailboxKeys` (`self` + 12-digit `<epochNumber>`) and records
-- append-only anomalies on rollback, split-view equivocation, broken hash chains, or
-- create-only violations.

CREATE TABLE witness_actor_heads (
    actor_did TEXT PRIMARY KEY,
    max_rev TEXT NOT NULL,
    last_commit_cid TEXT NOT NULL,
    last_seq BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE witness_chat_devices (
    actor_did TEXT NOT NULL,
    rkey TEXT NOT NULL,
    record_cid TEXT NOT NULL,
    algorithm TEXT NOT NULL,
    mls_signature_public_key BYTEA NOT NULL,
    record_created_at TEXT NOT NULL,
    first_seen_seq BIGINT NOT NULL,
    first_seen_rev TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor_did, rkey)
);

CREATE INDEX idx_witness_chat_devices_actor_seq
    ON witness_chat_devices (actor_did, first_seen_seq ASC);

CREATE TABLE witness_mailbox_epochs (
    actor_did TEXT NOT NULL,
    epoch_number BIGINT NOT NULL,
    rkey TEXT NOT NULL,
    record_cid TEXT NOT NULL,
    epoch_head BYTEA NOT NULL,
    previous_epoch_head BYTEA,
    signing_pubkey BYTEA NOT NULL,
    auth_pubkey BYTEA NOT NULL,
    encryption_pubkey BYTEA NOT NULL,
    members_hash BYTEA NOT NULL,
    self_sig BYTEA NOT NULL,
    prev_sig BYTEA,
    backend TEXT,
    immutable_pinned BOOLEAN NOT NULL DEFAULT FALSE,
    first_seen_seq BIGINT NOT NULL,
    first_seen_rev TEXT NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (actor_did, epoch_number)
);

CREATE INDEX idx_witness_mailbox_epochs_actor_head
    ON witness_mailbox_epochs (actor_did, epoch_head);

CREATE TABLE witness_mailbox_heads (
    actor_did TEXT PRIMARY KEY,
    current_epoch_number BIGINT NOT NULL,
    current_epoch_head BYTEA NOT NULL,
    current_record_cid TEXT NOT NULL,
    last_seen_seq BIGINT NOT NULL,
    last_seen_rev TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE witness_anomalies (
    id BIGSERIAL PRIMARY KEY,
    actor_did TEXT NOT NULL,
    seq BIGINT NOT NULL,
    commit_rev TEXT NOT NULL,
    commit_cid TEXT NOT NULL,
    op_action TEXT NOT NULL,
    op_path TEXT NOT NULL,
    record_cid TEXT,
    anomaly_kind TEXT NOT NULL,
    detail TEXT NOT NULL,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (actor_did, seq, op_path, anomaly_kind)
);

CREATE INDEX idx_witness_anomalies_actor
    ON witness_anomalies (actor_did, detected_at DESC);

CREATE INDEX idx_witness_anomalies_kind
    ON witness_anomalies (anomaly_kind, detected_at DESC);
