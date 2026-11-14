use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres, Row, Transaction};

use crate::{
    ActorHeadRecord, AnomalyRecord, MailboxEpochRecord, MailboxHeadRecord, WitnessedDeviceRecord,
};

/// Domain-separated 64-bit advisory lock key for an actor DID's transparency log.
pub fn advisory_lock_key_for_witness_actor(did: &str) -> i64 {
    let mut hasher = Sha256::new();
    hasher.update(b"firehose_witness_actor_lock:");
    hasher.update(did.as_bytes());
    let digest = hasher.finalize();
    i64::from_be_bytes(digest[..8].try_into().expect("8-byte prefix"))
}

pub async fn acquire_witness_actor_lock(
    tx: &mut Transaction<'_, Postgres>,
    did: &str,
) -> Result<()> {
    let key = advisory_lock_key_for_witness_actor(did);
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(key)
        .execute(&mut **tx)
        .await?;
    Ok(())
}

pub async fn fetch_actor_head(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
) -> Result<Option<ActorHeadRecord>> {
    let row = sqlx::query(
        r#"
        SELECT max_rev, last_commit_cid, last_seq
        FROM witness_actor_heads
        WHERE actor_did = $1
        "#,
    )
    .bind(actor_did)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row.map(|r| ActorHeadRecord {
        max_rev: r.get("max_rev"),
        last_commit_cid: r.get("last_commit_cid"),
        last_seq: r.get("last_seq"),
    }))
}

pub async fn upsert_actor_head(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    max_rev: &str,
    last_commit_cid: &str,
    last_seq: i64,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO witness_actor_heads (actor_did, max_rev, last_commit_cid, last_seq, updated_at)
        VALUES ($1, $2, $3, $4, NOW())
        ON CONFLICT (actor_did) DO UPDATE
        SET max_rev = EXCLUDED.max_rev,
            last_commit_cid = EXCLUDED.last_commit_cid,
            last_seq = EXCLUDED.last_seq,
            updated_at = NOW()
        "#,
    )
    .bind(actor_did)
    .bind(max_rev)
    .bind(last_commit_cid)
    .bind(last_seq)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn fetch_chat_device(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    rkey: &str,
) -> Result<Option<WitnessedDeviceRecord>> {
    let row = sqlx::query(
        r#"
        SELECT rkey, record_cid, algorithm, mls_signature_public_key, record_created_at, first_seen_seq, first_seen_rev
        FROM witness_chat_devices
        WHERE actor_did = $1 AND rkey = $2
        "#,
    )
    .bind(actor_did)
    .bind(rkey)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row.map(|r| WitnessedDeviceRecord {
        rkey: r.get("rkey"),
        record_cid: r.get("record_cid"),
        algorithm: r.get("algorithm"),
        mls_signature_public_key: r.get("mls_signature_public_key"),
        record_created_at: r.get("record_created_at"),
        first_seen_seq: r.get("first_seen_seq"),
        first_seen_rev: r.get("first_seen_rev"),
    }))
}

pub async fn insert_chat_device(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    rec: &WitnessedDeviceRecord,
) -> Result<bool> {
    let res = sqlx::query(
        r#"
        INSERT INTO witness_chat_devices (
            actor_did, rkey, record_cid, algorithm, mls_signature_public_key,
            record_created_at, first_seen_seq, first_seen_rev
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (actor_did, rkey) DO NOTHING
        "#,
    )
    .bind(actor_did)
    .bind(&rec.rkey)
    .bind(&rec.record_cid)
    .bind(&rec.algorithm)
    .bind(&rec.mls_signature_public_key)
    .bind(&rec.record_created_at)
    .bind(rec.first_seen_seq)
    .bind(&rec.first_seen_rev)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn fetch_mailbox_epoch(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    epoch_number: i64,
) -> Result<Option<MailboxEpochRecord>> {
    let row = sqlx::query(
        r#"
        SELECT epoch_number, rkey, record_cid, epoch_head, previous_epoch_head,
               signing_pubkey, auth_pubkey, encryption_pubkey, members_hash,
               self_sig, prev_sig, backend, immutable_pinned, first_seen_seq, first_seen_rev
        FROM witness_mailbox_epochs
        WHERE actor_did = $1 AND epoch_number = $2
        "#,
    )
    .bind(actor_did)
    .bind(epoch_number)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row.map(|r| MailboxEpochRecord {
        epoch_number: r.get("epoch_number"),
        rkey: r.get("rkey"),
        record_cid: r.get("record_cid"),
        epoch_head: r.get("epoch_head"),
        previous_epoch_head: r.get("previous_epoch_head"),
        signing_pubkey: r.get("signing_pubkey"),
        auth_pubkey: r.get("auth_pubkey"),
        encryption_pubkey: r.get("encryption_pubkey"),
        members_hash: r.get("members_hash"),
        self_sig: r.get("self_sig"),
        prev_sig: r.get("prev_sig"),
        backend: r.get("backend"),
        immutable_pinned: r.get("immutable_pinned"),
        first_seen_seq: r.get("first_seen_seq"),
        first_seen_rev: r.get("first_seen_rev"),
    }))
}

pub async fn upsert_mailbox_epoch(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    rec: &MailboxEpochRecord,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO witness_mailbox_epochs (
            actor_did, epoch_number, rkey, record_cid, epoch_head, previous_epoch_head,
            signing_pubkey, auth_pubkey, encryption_pubkey, members_hash,
            self_sig, prev_sig, backend, immutable_pinned, first_seen_seq, first_seen_rev
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
        ON CONFLICT (actor_did, epoch_number) DO UPDATE
        SET rkey = CASE WHEN witness_mailbox_epochs.immutable_pinned THEN witness_mailbox_epochs.rkey ELSE EXCLUDED.rkey END,
            immutable_pinned = witness_mailbox_epochs.immutable_pinned OR EXCLUDED.immutable_pinned
        "#,
    )
    .bind(actor_did)
    .bind(rec.epoch_number)
    .bind(&rec.rkey)
    .bind(&rec.record_cid)
    .bind(&rec.epoch_head)
    .bind(&rec.previous_epoch_head)
    .bind(&rec.signing_pubkey)
    .bind(&rec.auth_pubkey)
    .bind(&rec.encryption_pubkey)
    .bind(&rec.members_hash)
    .bind(&rec.self_sig)
    .bind(&rec.prev_sig)
    .bind(&rec.backend)
    .bind(rec.immutable_pinned)
    .bind(rec.first_seen_seq)
    .bind(&rec.first_seen_rev)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn fetch_mailbox_head(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
) -> Result<Option<MailboxHeadRecord>> {
    let row = sqlx::query(
        r#"
        SELECT current_epoch_number, current_epoch_head, current_record_cid, last_seen_seq, last_seen_rev
        FROM witness_mailbox_heads
        WHERE actor_did = $1
        "#,
    )
    .bind(actor_did)
    .fetch_optional(&mut **tx)
    .await?;

    Ok(row.map(|r| MailboxHeadRecord {
        current_epoch_number: r.get("current_epoch_number"),
        current_epoch_head: r.get("current_epoch_head"),
        current_record_cid: r.get("current_record_cid"),
        last_seen_seq: r.get("last_seen_seq"),
        last_seen_rev: r.get("last_seen_rev"),
    }))
}

pub async fn upsert_mailbox_head(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    head: &MailboxHeadRecord,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO witness_mailbox_heads (
            actor_did, current_epoch_number, current_epoch_head, current_record_cid,
            last_seen_seq, last_seen_rev, updated_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, NOW())
        ON CONFLICT (actor_did) DO UPDATE
        SET current_epoch_number = EXCLUDED.current_epoch_number,
            current_epoch_head = EXCLUDED.current_epoch_head,
            current_record_cid = EXCLUDED.current_record_cid,
            last_seen_seq = EXCLUDED.last_seen_seq,
            last_seen_rev = EXCLUDED.last_seen_rev,
            updated_at = NOW()
        "#,
    )
    .bind(actor_did)
    .bind(head.current_epoch_number)
    .bind(&head.current_epoch_head)
    .bind(&head.current_record_cid)
    .bind(head.last_seen_seq)
    .bind(&head.last_seen_rev)
    .execute(&mut **tx)
    .await?;
    Ok(())
}

pub async fn insert_anomaly(
    tx: &mut Transaction<'_, Postgres>,
    actor_did: &str,
    anomaly: &AnomalyRecord,
) -> Result<bool> {
    let res = sqlx::query(
        r#"
        INSERT INTO witness_anomalies (
            actor_did, seq, commit_rev, commit_cid, op_action, op_path,
            record_cid, anomaly_kind, detail
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (actor_did, seq, op_path, anomaly_kind) DO NOTHING
        "#,
    )
    .bind(actor_did)
    .bind(anomaly.seq)
    .bind(&anomaly.commit_rev)
    .bind(&anomaly.commit_cid)
    .bind(&anomaly.op_action)
    .bind(&anomaly.op_path)
    .bind(&anomaly.record_cid)
    .bind(anomaly.kind.as_str())
    .bind(&anomaly.detail)
    .execute(&mut **tx)
    .await?;
    Ok(res.rows_affected() > 0)
}

pub async fn list_anomalies_for_actor(
    pool: &Pool<Postgres>,
    actor_did: &str,
) -> Result<Vec<(String, String, String)>> {
    let rows = sqlx::query(
        r#"
        SELECT anomaly_kind, op_path, detail
        FROM witness_anomalies
        WHERE actor_did = $1
        ORDER BY id ASC
        "#,
    )
    .bind(actor_did)
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| (r.get("anomaly_kind"), r.get("op_path"), r.get("detail")))
        .collect())
}
