ALTER TABLE witness_mailbox_heads DROP COLUMN IF EXISTS current_epoch_chain_verified;
ALTER TABLE witness_mailbox_epochs DROP COLUMN IF EXISTS chain_verified;
DROP TABLE IF EXISTS witness_stream_gaps;
DROP TABLE IF EXISTS witness_unverified_commits;
