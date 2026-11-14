//! NBD-style firehose-witnessed monotonic device & mailbox key transparency consumer (`Y-6` / `D-1`).
//!
//! Observes public ATProto `#commit` events on `com.atproto.sync.subscribeRepos` for:
//! - `blue.catbird.chat.device/<rkey>` (strictly create-only per-device MLS signature keys)
//! - `blue.catbird.labyrinth.mailboxKeys/<12-digit-epoch>` (strictly create-only epoch snapshots)
//! - `blue.catbird.labyrinth.mailboxKeys/self` (monotonic pointer to the account's latest epoch)
//!
//! Any PDS rollback (`rev` regression), commit equivocation, create-only mutation/deletion,
//! non-12-digit epoch rkey mismatch, hash-chain break (`previousEpochHead != prior.epochHead`),
//! or split-view equivocation at the same epoch/device is recorded in `witness_anomalies` and
//! surfaced via Prometheus metrics.

pub mod db;
pub mod metrics;

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::Arc;

use anyhow::Result;
use catbird_atproto::generated::blue_catbird::{
    chat::device::Device, labyrinth::mailbox_keys::MailboxKeys,
};
use catbird_firehose_fanout::Consumer;
use ipld_core::{
    cid::{Cid, Version},
    ipld::Ipld,
};
use jacquard_api::com_atproto::sync::subscribe_repos::SubscribeReposMessage;
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres};
use tracing::warn;

pub const CHAT_DEVICE_COLLECTION: &str = "blue.catbird.chat.device";
pub const MAILBOX_KEYS_COLLECTION: &str = "blue.catbird.labyrinth.mailboxKeys";
/// Upper bound on `epochNumber` matching 12-digit zero-padded snapshot rkeys (`000000000000..=999999999999`),
/// strictly within the `blue.catbird.labyrinth.defs#epochPublic` lexicon ceiling (`1_099_511_627_776`).
pub const MAX_MAILBOX_EPOCH_NUMBER: i64 = 999_999_999_999;

const MAX_CAR_ARCHIVE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CAR_HEADER_BYTES: usize = 64 * 1024;
const MAX_CAR_SECTIONS: usize = 4_096;
const MAX_WITNESS_RECORD_BLOCK_BYTES: usize = 256 * 1024;
const DAG_CBOR_CODEC: u64 = 0x71;
const SHA2_256_CODE: u64 = 0x12;
const SHA2_256_DIGEST_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WitnessAnomalyKind {
    RepoRevRollback,
    RepoCommitEquivocation,
    ChatDeviceMutatedOrDeleted,
    ChatDeviceSplitViewEquivocation,
    MailboxKeysDeleted,
    ImmutableMailboxEpochMutated,
    InvalidMailboxEpochRkey,
    MailboxEpochRegression,
    MailboxSplitViewEquivocation,
    MailboxBrokenHashChain,
    MalformedTransparencyRecord,
}

impl WitnessAnomalyKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RepoRevRollback => "repo_rev_rollback",
            Self::RepoCommitEquivocation => "repo_commit_equivocation",
            Self::ChatDeviceMutatedOrDeleted => "chat_device_mutated_or_deleted",
            Self::ChatDeviceSplitViewEquivocation => "chat_device_split_view_equivocation",
            Self::MailboxKeysDeleted => "mailbox_keys_deleted",
            Self::ImmutableMailboxEpochMutated => "immutable_mailbox_epoch_mutated",
            Self::InvalidMailboxEpochRkey => "invalid_mailbox_epoch_rkey",
            Self::MailboxEpochRegression => "mailbox_epoch_regression",
            Self::MailboxSplitViewEquivocation => "mailbox_split_view_equivocation",
            Self::MailboxBrokenHashChain => "mailbox_broken_hash_chain",
            Self::MalformedTransparencyRecord => "malformed_transparency_record",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActorHeadRecord {
    pub max_rev: String,
    pub last_commit_cid: String,
    pub last_seq: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessedDeviceRecord {
    pub rkey: String,
    pub record_cid: String,
    pub algorithm: String,
    pub mls_signature_public_key: Vec<u8>,
    pub record_created_at: String,
    pub first_seen_seq: i64,
    pub first_seen_rev: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEpochRecord {
    pub epoch_number: i64,
    pub rkey: String,
    pub record_cid: String,
    pub epoch_head: Vec<u8>,
    pub previous_epoch_head: Option<Vec<u8>>,
    pub signing_pubkey: Vec<u8>,
    pub auth_pubkey: Vec<u8>,
    pub encryption_pubkey: Vec<u8>,
    pub members_hash: Vec<u8>,
    pub self_sig: Vec<u8>,
    pub prev_sig: Option<Vec<u8>>,
    pub backend: Option<String>,
    pub immutable_pinned: bool,
    pub first_seen_seq: i64,
    pub first_seen_rev: String,
}

impl MailboxEpochRecord {
    pub fn cryptographic_material_matches(&self, other: &Self) -> bool {
        self.epoch_number == other.epoch_number
            && self.epoch_head == other.epoch_head
            && self.previous_epoch_head == other.previous_epoch_head
            && self.signing_pubkey == other.signing_pubkey
            && self.auth_pubkey == other.auth_pubkey
            && self.encryption_pubkey == other.encryption_pubkey
            && self.members_hash == other.members_hash
            && self.self_sig == other.self_sig
            && self.prev_sig == other.prev_sig
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxHeadRecord {
    pub current_epoch_number: i64,
    pub current_epoch_head: Vec<u8>,
    pub current_record_cid: String,
    pub last_seen_seq: i64,
    pub last_seen_rev: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnomalyRecord {
    pub seq: i64,
    pub commit_rev: String,
    pub commit_cid: String,
    pub op_action: String,
    pub op_path: String,
    pub record_cid: Option<String>,
    pub kind: WitnessAnomalyKind,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct ObservedRepoOp {
    pub action: String,
    pub path: String,
    pub cid: Option<String>,
    pub block: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct ObservedCommit {
    pub actor_did: String,
    pub seq: i64,
    pub rev: String,
    pub commit_cid: String,
    pub ops: Vec<ObservedRepoOp>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct WitnessOutcome {
    pub indexed_devices: usize,
    pub indexed_mailbox_records: usize,
    pub anomalies: Vec<AnomalyRecord>,
}

pub fn is_transparency_path(path: &str) -> bool {
    matches!(
        path.split_once('/'),
        Some((collection, rkey))
            if !rkey.is_empty()
                && !rkey.contains('/')
                && (collection == CHAT_DEVICE_COLLECTION || collection == MAILBOX_KEYS_COLLECTION)
    )
}

pub fn parse_12_digit_epoch_rkey(rkey: &str) -> Option<i64> {
    if rkey.len() != 12 || !rkey.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    rkey.parse::<i64>().ok()
}

fn parse_device_block(
    rkey: &str,
    cid: &str,
    seq: i64,
    rev: &str,
    block: &[u8],
) -> Result<WitnessedDeviceRecord, String> {
    let parsed: Device = serde_ipld_dagcbor::from_slice(block)
        .map_err(|e| format!("failed to decode blue.catbird.chat.device CBOR: {e}"))?;
    if parsed.extra_data.as_ref().is_some_and(|m| !m.is_empty()) {
        return Err("unexpected extra fields in blue.catbird.chat.device".to_string());
    }
    let alg = parsed.algorithm.as_ref();
    let expected_key_len = match alg {
        "ed25519" => 32usize,
        "p256" => 33usize,
        other => {
            return Err(format!(
                "unsupported blue.catbird.chat.device algorithm '{other}'"
            ));
        }
    };
    let pubkey = parsed.mls_signature_public_key.as_ref();
    if pubkey.len() != expected_key_len
        && !(alg == "p256" && pubkey.len() == 65 && pubkey[0] == 0x04)
    {
        return Err(format!(
            "invalid {alg} signature public key length {}",
            pubkey.len()
        ));
    }
    Ok(WitnessedDeviceRecord {
        rkey: rkey.to_string(),
        record_cid: cid.to_string(),
        algorithm: alg.to_string(),
        mls_signature_public_key: pubkey.to_vec(),
        record_created_at: parsed.created_at.as_ref().to_string(),
        first_seen_seq: seq,
        first_seen_rev: rev.to_string(),
    })
}

fn parse_mailbox_keys_block(
    rkey: &str,
    cid: &str,
    seq: i64,
    rev: &str,
    immutable_pinned: bool,
    block: &[u8],
) -> Result<MailboxEpochRecord, String> {
    let parsed: MailboxKeys = serde_ipld_dagcbor::from_slice(block)
        .map_err(|e| format!("failed to decode blue.catbird.labyrinth.mailboxKeys CBOR: {e}"))?;
    if parsed.extra_data.as_ref().is_some_and(|m| !m.is_empty())
        || parsed
            .current
            .extra_data
            .as_ref()
            .is_some_and(|m| !m.is_empty())
    {
        return Err("unexpected extra fields in blue.catbird.labyrinth.mailboxKeys".to_string());
    }
    let cur = &parsed.current;
    if !(0..=MAX_MAILBOX_EPOCH_NUMBER).contains(&cur.epoch_number) {
        return Err(format!(
            "epochNumber {} outside allowed 0..={} range",
            cur.epoch_number, MAX_MAILBOX_EPOCH_NUMBER
        ));
    }
    if cur.epoch_head.len() != 32 {
        return Err(format!(
            "epochHead must be 32 bytes, got {}",
            cur.epoch_head.len()
        ));
    }
    if let Some(prev_head) = cur.previous_epoch_head.as_ref() {
        if prev_head.len() != 32 {
            return Err(format!(
                "previousEpochHead must be 32 bytes, got {}",
                prev_head.len()
            ));
        }
    }
    if cur.signing_pubkey.len() != 32 || cur.auth_pubkey.len() != 32 || cur.members_hash.len() != 32
    {
        return Err("signingPubkey, authPubkey, and membersHash must each be 32 bytes".to_string());
    }
    if cur.encryption_pubkey.len() != 1216 {
        return Err(format!(
            "encryptionPubkey must be 1216 bytes (X25519 || ML-KEM-768), got {}",
            cur.encryption_pubkey.len()
        ));
    }
    if cur.self_sig.len() != 64 {
        return Err(format!(
            "selfSig must be 64 bytes, got {}",
            cur.self_sig.len()
        ));
    }
    if let Some(prev_sig) = cur.prev_sig.as_ref() {
        if prev_sig.len() != 64 {
            return Err(format!("prevSig must be 64 bytes, got {}", prev_sig.len()));
        }
    }

    Ok(MailboxEpochRecord {
        epoch_number: cur.epoch_number,
        rkey: rkey.to_string(),
        record_cid: cid.to_string(),
        epoch_head: cur.epoch_head.to_vec(),
        previous_epoch_head: cur.previous_epoch_head.as_ref().map(|b| b.to_vec()),
        signing_pubkey: cur.signing_pubkey.to_vec(),
        auth_pubkey: cur.auth_pubkey.to_vec(),
        encryption_pubkey: cur.encryption_pubkey.to_vec(),
        members_hash: cur.members_hash.to_vec(),
        self_sig: cur.self_sig.to_vec(),
        prev_sig: cur.prev_sig.as_ref().map(|b| b.to_vec()),
        backend: parsed.backend.as_ref().map(|b| b.as_str().to_string()),
        immutable_pinned,
        first_seen_seq: seq,
        first_seen_rev: rev.to_string(),
    })
}

#[allow(async_fn_in_trait)]
pub trait WitnessStore {
    async fn get_actor_head(&mut self, actor_did: &str) -> Result<Option<ActorHeadRecord>>;
    async fn set_actor_head(
        &mut self,
        actor_did: &str,
        max_rev: &str,
        last_commit_cid: &str,
        last_seq: i64,
    ) -> Result<()>;

    async fn get_chat_device(
        &mut self,
        actor_did: &str,
        rkey: &str,
    ) -> Result<Option<WitnessedDeviceRecord>>;
    async fn put_chat_device(
        &mut self,
        actor_did: &str,
        rec: &WitnessedDeviceRecord,
    ) -> Result<bool>;

    async fn get_mailbox_epoch(
        &mut self,
        actor_did: &str,
        epoch_number: i64,
    ) -> Result<Option<MailboxEpochRecord>>;
    async fn put_mailbox_epoch(&mut self, actor_did: &str, rec: &MailboxEpochRecord) -> Result<()>;

    async fn get_mailbox_head(&mut self, actor_did: &str) -> Result<Option<MailboxHeadRecord>>;
    async fn set_mailbox_head(&mut self, actor_did: &str, head: &MailboxHeadRecord) -> Result<()>;

    async fn record_anomaly(&mut self, actor_did: &str, anomaly: &AnomalyRecord) -> Result<bool>;
}

pub struct PgWitnessStore<'a, 'c> {
    tx: &'a mut sqlx::Transaction<'c, Postgres>,
}

impl<'a, 'c> PgWitnessStore<'a, 'c> {
    pub fn new(tx: &'a mut sqlx::Transaction<'c, Postgres>) -> Self {
        Self { tx }
    }
}

impl WitnessStore for PgWitnessStore<'_, '_> {
    async fn get_actor_head(&mut self, actor_did: &str) -> Result<Option<ActorHeadRecord>> {
        db::fetch_actor_head(self.tx, actor_did).await
    }

    async fn set_actor_head(
        &mut self,
        actor_did: &str,
        max_rev: &str,
        last_commit_cid: &str,
        last_seq: i64,
    ) -> Result<()> {
        db::upsert_actor_head(self.tx, actor_did, max_rev, last_commit_cid, last_seq).await
    }

    async fn get_chat_device(
        &mut self,
        actor_did: &str,
        rkey: &str,
    ) -> Result<Option<WitnessedDeviceRecord>> {
        db::fetch_chat_device(self.tx, actor_did, rkey).await
    }

    async fn put_chat_device(
        &mut self,
        actor_did: &str,
        rec: &WitnessedDeviceRecord,
    ) -> Result<bool> {
        db::insert_chat_device(self.tx, actor_did, rec).await
    }

    async fn get_mailbox_epoch(
        &mut self,
        actor_did: &str,
        epoch_number: i64,
    ) -> Result<Option<MailboxEpochRecord>> {
        db::fetch_mailbox_epoch(self.tx, actor_did, epoch_number).await
    }

    async fn put_mailbox_epoch(&mut self, actor_did: &str, rec: &MailboxEpochRecord) -> Result<()> {
        db::upsert_mailbox_epoch(self.tx, actor_did, rec).await
    }

    async fn get_mailbox_head(&mut self, actor_did: &str) -> Result<Option<MailboxHeadRecord>> {
        db::fetch_mailbox_head(self.tx, actor_did).await
    }

    async fn set_mailbox_head(&mut self, actor_did: &str, head: &MailboxHeadRecord) -> Result<()> {
        db::upsert_mailbox_head(self.tx, actor_did, head).await
    }

    async fn record_anomaly(&mut self, actor_did: &str, anomaly: &AnomalyRecord) -> Result<bool> {
        db::insert_anomaly(self.tx, actor_did, anomaly).await
    }
}

#[derive(Debug, Default)]
pub struct InMemoryWitnessStore {
    pub actor_heads: HashMap<String, ActorHeadRecord>,
    pub chat_devices: HashMap<(String, String), WitnessedDeviceRecord>,
    pub mailbox_epochs: HashMap<(String, i64), MailboxEpochRecord>,
    pub mailbox_heads: HashMap<String, MailboxHeadRecord>,
    pub anomalies: Vec<(String, AnomalyRecord)>,
}

impl WitnessStore for InMemoryWitnessStore {
    async fn get_actor_head(&mut self, actor_did: &str) -> Result<Option<ActorHeadRecord>> {
        Ok(self.actor_heads.get(actor_did).cloned())
    }

    async fn set_actor_head(
        &mut self,
        actor_did: &str,
        max_rev: &str,
        last_commit_cid: &str,
        last_seq: i64,
    ) -> Result<()> {
        self.actor_heads.insert(
            actor_did.to_string(),
            ActorHeadRecord {
                max_rev: max_rev.to_string(),
                last_commit_cid: last_commit_cid.to_string(),
                last_seq,
            },
        );
        Ok(())
    }

    async fn get_chat_device(
        &mut self,
        actor_did: &str,
        rkey: &str,
    ) -> Result<Option<WitnessedDeviceRecord>> {
        Ok(self
            .chat_devices
            .get(&(actor_did.to_string(), rkey.to_string()))
            .cloned())
    }

    async fn put_chat_device(
        &mut self,
        actor_did: &str,
        rec: &WitnessedDeviceRecord,
    ) -> Result<bool> {
        let key = (actor_did.to_string(), rec.rkey.clone());
        if self.chat_devices.contains_key(&key) {
            return Ok(false);
        }
        self.chat_devices.insert(key, rec.clone());
        Ok(true)
    }

    async fn get_mailbox_epoch(
        &mut self,
        actor_did: &str,
        epoch_number: i64,
    ) -> Result<Option<MailboxEpochRecord>> {
        Ok(self
            .mailbox_epochs
            .get(&(actor_did.to_string(), epoch_number))
            .cloned())
    }

    async fn put_mailbox_epoch(&mut self, actor_did: &str, rec: &MailboxEpochRecord) -> Result<()> {
        let key = (actor_did.to_string(), rec.epoch_number);
        if let Some(existing) = self.mailbox_epochs.get_mut(&key) {
            if !existing.immutable_pinned && rec.immutable_pinned {
                existing.rkey = rec.rkey.clone();
                existing.immutable_pinned = true;
            }
        } else {
            self.mailbox_epochs.insert(key, rec.clone());
        }
        Ok(())
    }

    async fn get_mailbox_head(&mut self, actor_did: &str) -> Result<Option<MailboxHeadRecord>> {
        Ok(self.mailbox_heads.get(actor_did).cloned())
    }

    async fn set_mailbox_head(&mut self, actor_did: &str, head: &MailboxHeadRecord) -> Result<()> {
        self.mailbox_heads
            .insert(actor_did.to_string(), head.clone());
        Ok(())
    }

    async fn record_anomaly(&mut self, actor_did: &str, anomaly: &AnomalyRecord) -> Result<bool> {
        let dup = self.anomalies.iter().any(|(d, a)| {
            d == actor_did
                && a.seq == anomaly.seq
                && a.op_path == anomaly.op_path
                && a.kind == anomaly.kind
        });
        if dup {
            return Ok(false);
        }
        self.anomalies
            .push((actor_did.to_string(), anomaly.clone()));
        Ok(true)
    }
}

#[allow(clippy::too_many_arguments)]
async fn emit_anomaly<S: WitnessStore>(
    store: &mut S,
    commit: &ObservedCommit,
    action: &str,
    path: &str,
    record_cid: Option<String>,
    kind: WitnessAnomalyKind,
    detail: String,
    outcome: &mut WitnessOutcome,
) -> Result<()> {
    let anomaly = AnomalyRecord {
        seq: commit.seq,
        commit_rev: commit.rev.clone(),
        commit_cid: commit.commit_cid.clone(),
        op_action: action.to_string(),
        op_path: path.to_string(),
        record_cid,
        kind,
        detail,
    };
    if store.record_anomaly(&commit.actor_did, &anomaly).await? {
        metrics::WITNESS_ANOMALIES_DETECTED
            .with_label_values(&[kind.as_str()])
            .inc();
        warn!(
            actor_did = %commit.actor_did,
            seq = commit.seq,
            rev = %commit.rev,
            path = %path,
            anomaly = kind.as_str(),
            detail = %anomaly.detail,
            "Detected NBD device/mailbox transparency anomaly"
        );
    }
    outcome.anomalies.push(anomaly);
    Ok(())
}

/// Evaluate all transparency invariants for one `#commit` event against `store`.
pub async fn evaluate_commit<S: WitnessStore>(
    store: &mut S,
    commit: &ObservedCommit,
) -> Result<WitnessOutcome> {
    let mut outcome = WitnessOutcome::default();
    let prior_actor_head = store.get_actor_head(&commit.actor_did).await?;

    if let Some(ref head) = prior_actor_head {
        // Exact replay of the latest checkpointed commit -> no-op.
        if commit.seq <= head.last_seq
            && commit.rev == head.max_rev
            && commit.commit_cid == head.last_commit_cid
        {
            return Ok(outcome);
        }

        if commit.seq > head.last_seq {
            if commit.rev.as_str() < head.max_rev.as_str() {
                emit_anomaly(
                    store,
                    commit,
                    "commit",
                    "#commit",
                    None,
                    WitnessAnomalyKind::RepoRevRollback,
                    format!(
                        "repo rev regressed from '{}' (seq {}) to '{}' (seq {})",
                        head.max_rev, head.last_seq, commit.rev, commit.seq
                    ),
                    &mut outcome,
                )
                .await?;
            } else if commit.rev == head.max_rev && commit.commit_cid != head.last_commit_cid {
                emit_anomaly(
                    store,
                    commit,
                    "commit",
                    "#commit",
                    None,
                    WitnessAnomalyKind::RepoCommitEquivocation,
                    format!(
                        "repo emitted two distinct commit CIDs ('{}' vs '{}') at rev '{}'",
                        head.last_commit_cid, commit.commit_cid, commit.rev
                    ),
                    &mut outcome,
                )
                .await?;
            }
        }
    }

    for op in &commit.ops {
        if !is_transparency_path(&op.path) {
            continue;
        }
        let Some((collection, rkey)) = op.path.split_once('/') else {
            continue;
        };

        match collection {
            CHAT_DEVICE_COLLECTION => {
                evaluate_chat_device_op(store, commit, op, rkey, &mut outcome).await?;
            }
            MAILBOX_KEYS_COLLECTION => {
                evaluate_mailbox_keys_op(store, commit, op, rkey, &mut outcome).await?;
            }
            _ => {}
        }
    }

    let next_max_rev = match prior_actor_head.as_ref() {
        Some(head) if head.max_rev.as_str() > commit.rev.as_str() => head.max_rev.as_str(),
        _ => commit.rev.as_str(),
    };
    let next_seq = prior_actor_head
        .as_ref()
        .map_or(commit.seq, |h| h.last_seq.max(commit.seq));
    let next_cid = match prior_actor_head.as_ref() {
        Some(head) if commit.seq < head.last_seq => head.last_commit_cid.as_str(),
        _ => commit.commit_cid.as_str(),
    };
    store
        .set_actor_head(&commit.actor_did, next_max_rev, next_cid, next_seq)
        .await?;

    Ok(outcome)
}

async fn evaluate_chat_device_op<S: WitnessStore>(
    store: &mut S,
    commit: &ObservedCommit,
    op: &ObservedRepoOp,
    rkey: &str,
    outcome: &mut WitnessOutcome,
) -> Result<()> {
    if op.action != "create" {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            op.cid.clone(),
            WitnessAnomalyKind::ChatDeviceMutatedOrDeleted,
            format!(
                "forbidden '{}' on create-only blue.catbird.chat.device/{}",
                op.action, rkey
            ),
            outcome,
        )
        .await?;
        return Ok(());
    }

    let (Some(cid), Some(block)) = (op.cid.as_deref(), op.block.as_deref()) else {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            op.cid.clone(),
            WitnessAnomalyKind::MalformedTransparencyRecord,
            format!("missing CID or CAR block for {}", op.path),
            outcome,
        )
        .await?;
        return Ok(());
    };

    let parsed = match parse_device_block(rkey, cid, commit.seq, &commit.rev, block) {
        Ok(rec) => rec,
        Err(reason) => {
            emit_anomaly(
                store,
                commit,
                &op.action,
                &op.path,
                Some(cid.to_string()),
                WitnessAnomalyKind::MalformedTransparencyRecord,
                reason,
                outcome,
            )
            .await?;
            return Ok(());
        }
    };

    if let Some(existing) = store.get_chat_device(&commit.actor_did, rkey).await? {
        if existing.record_cid != parsed.record_cid
            || existing.mls_signature_public_key != parsed.mls_signature_public_key
            || existing.algorithm != parsed.algorithm
        {
            emit_anomaly(
                store,
                commit,
                &op.action,
                &op.path,
                Some(cid.to_string()),
                WitnessAnomalyKind::ChatDeviceSplitViewEquivocation,
                format!(
                    "conflicting blue.catbird.chat.device/{} create (cid '{}' vs pinned '{}')",
                    rkey, parsed.record_cid, existing.record_cid
                ),
                outcome,
            )
            .await?;
        } else if commit.seq > existing.first_seen_seq {
            emit_anomaly(
                store,
                commit,
                &op.action,
                &op.path,
                Some(cid.to_string()),
                WitnessAnomalyKind::ChatDeviceMutatedOrDeleted,
                format!(
                    "duplicate create on existing blue.catbird.chat.device/{} after seq {}",
                    rkey, existing.first_seen_seq
                ),
                outcome,
            )
            .await?;
        }
        return Ok(());
    }

    if store.put_chat_device(&commit.actor_did, &parsed).await? {
        outcome.indexed_devices += 1;
        metrics::WITNESS_RECORDS_INDEXED
            .with_label_values(&[CHAT_DEVICE_COLLECTION])
            .inc();
    }
    Ok(())
}

async fn evaluate_mailbox_keys_op<S: WitnessStore>(
    store: &mut S,
    commit: &ObservedCommit,
    op: &ObservedRepoOp,
    rkey: &str,
    outcome: &mut WitnessOutcome,
) -> Result<()> {
    if op.action == "delete" {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            op.cid.clone(),
            WitnessAnomalyKind::MailboxKeysDeleted,
            format!(
                "forbidden delete on blue.catbird.labyrinth.mailboxKeys/{}",
                rkey
            ),
            outcome,
        )
        .await?;
        return Ok(());
    }

    let is_self_rkey = rkey == "self";
    let expected_immutable_epoch = if is_self_rkey {
        None
    } else {
        match parse_12_digit_epoch_rkey(rkey) {
            Some(epoch) => Some(epoch),
            None => {
                emit_anomaly(
                    store,
                    commit,
                    &op.action,
                    &op.path,
                    op.cid.clone(),
                    WitnessAnomalyKind::InvalidMailboxEpochRkey,
                    format!(
                        "mailboxKeys rkey '{}' must be 'self' or 12-digit zero-padded epochNumber",
                        rkey
                    ),
                    outcome,
                )
                .await?;
                return Ok(());
            }
        }
    };

    if !is_self_rkey && op.action != "create" {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            op.cid.clone(),
            WitnessAnomalyKind::ImmutableMailboxEpochMutated,
            format!(
                "forbidden '{}' on immutable mailboxKeys snapshot rkey '{}'",
                op.action, rkey
            ),
            outcome,
        )
        .await?;
        return Ok(());
    }

    if op.action != "create" && op.action != "update" {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            op.cid.clone(),
            WitnessAnomalyKind::MalformedTransparencyRecord,
            format!("unexpected commit op action '{}' on {}", op.action, op.path),
            outcome,
        )
        .await?;
        return Ok(());
    }

    let (Some(cid), Some(block)) = (op.cid.as_deref(), op.block.as_deref()) else {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            op.cid.clone(),
            WitnessAnomalyKind::MalformedTransparencyRecord,
            format!("missing CID or CAR block for {}", op.path),
            outcome,
        )
        .await?;
        return Ok(());
    };

    let parsed =
        match parse_mailbox_keys_block(rkey, cid, commit.seq, &commit.rev, !is_self_rkey, block) {
            Ok(rec) => rec,
            Err(reason) => {
                emit_anomaly(
                    store,
                    commit,
                    &op.action,
                    &op.path,
                    Some(cid.to_string()),
                    WitnessAnomalyKind::MalformedTransparencyRecord,
                    reason,
                    outcome,
                )
                .await?;
                return Ok(());
            }
        };

    if let Some(expected_epoch) = expected_immutable_epoch {
        if parsed.epoch_number != expected_epoch {
            emit_anomaly(
                store,
                commit,
                &op.action,
                &op.path,
                Some(cid.to_string()),
                WitnessAnomalyKind::InvalidMailboxEpochRkey,
                format!(
                    "mailboxKeys rkey '{}' does not match payload epochNumber {}",
                    rkey, parsed.epoch_number
                ),
                outcome,
            )
            .await?;
            return Ok(());
        }
    }

    // Structural hash-chain invariants on epoch 0 vs epoch > 0.
    if parsed.epoch_number == 0
        && (parsed.previous_epoch_head.is_some() || parsed.prev_sig.is_some())
    {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            Some(cid.to_string()),
            WitnessAnomalyKind::MailboxBrokenHashChain,
            "epoch 0 must not carry previousEpochHead or prevSig".to_string(),
            outcome,
        )
        .await?;
        return Ok(());
    }
    if parsed.epoch_number > 0
        && (parsed.previous_epoch_head.is_none() || parsed.prev_sig.is_none())
    {
        emit_anomaly(
            store,
            commit,
            &op.action,
            &op.path,
            Some(cid.to_string()),
            WitnessAnomalyKind::MailboxBrokenHashChain,
            format!(
                "epoch {} missing required previousEpochHead or prevSig",
                parsed.epoch_number
            ),
            outcome,
        )
        .await?;
        return Ok(());
    }

    // Cross-check against any already-pinned snapshot at the same epoch_number.
    if let Some(existing_same) = store
        .get_mailbox_epoch(&commit.actor_did, parsed.epoch_number)
        .await?
    {
        if !existing_same.cryptographic_material_matches(&parsed) {
            emit_anomaly(
                store,
                commit,
                &op.action,
                &op.path,
                Some(cid.to_string()),
                WitnessAnomalyKind::MailboxSplitViewEquivocation,
                format!(
                    "split-view equivocation at mailbox epoch {} (rkey '{}')",
                    parsed.epoch_number, rkey
                ),
                outcome,
            )
            .await?;
            return Ok(());
        }
        if !is_self_rkey
            && existing_same.immutable_pinned
            && commit.seq > existing_same.first_seen_seq
        {
            emit_anomaly(
                store,
                commit,
                &op.action,
                &op.path,
                Some(cid.to_string()),
                WitnessAnomalyKind::ImmutableMailboxEpochMutated,
                format!(
                    "duplicate create on already-pinned mailbox epoch {} after seq {}",
                    parsed.epoch_number, existing_same.first_seen_seq
                ),
                outcome,
            )
            .await?;
            return Ok(());
        }
    }

    // Cross-check backward link `epoch - 1` if known.
    if parsed.epoch_number > 0 {
        if let Some(prev_epoch_num) = parsed.epoch_number.checked_sub(1) {
            if let Some(prior_epoch) = store
                .get_mailbox_epoch(&commit.actor_did, prev_epoch_num)
                .await?
            {
                if parsed.previous_epoch_head.as_deref() != Some(prior_epoch.epoch_head.as_slice())
                {
                    emit_anomaly(
                        store,
                        commit,
                        &op.action,
                        &op.path,
                        Some(cid.to_string()),
                        WitnessAnomalyKind::MailboxBrokenHashChain,
                        format!(
                            "epoch {} previousEpochHead does not match witnessed epoch {} head",
                            parsed.epoch_number, prev_epoch_num
                        ),
                        outcome,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }
    }

    // Cross-check forward link `epoch + 1` if already witnessed out-of-order.
    if let Some(next_epoch_num) = parsed.epoch_number.checked_add(1) {
        if let Some(next_epoch) = store
            .get_mailbox_epoch(&commit.actor_did, next_epoch_num)
            .await?
        {
            if next_epoch.previous_epoch_head.as_deref() != Some(parsed.epoch_head.as_slice()) {
                emit_anomaly(
                    store,
                    commit,
                    &op.action,
                    &op.path,
                    Some(cid.to_string()),
                    WitnessAnomalyKind::MailboxBrokenHashChain,
                    format!(
                        "epoch {} epochHead does not match witnessed epoch {} previousEpochHead",
                        parsed.epoch_number, next_epoch_num
                    ),
                    outcome,
                )
                .await?;
                return Ok(());
            }
        }
    }

    // Enforce monotonic `self` pointer progression.
    if is_self_rkey {
        if let Some(head) = store.get_mailbox_head(&commit.actor_did).await? {
            if commit.seq > head.last_seen_seq {
                if parsed.epoch_number < head.current_epoch_number {
                    emit_anomaly(
                        store,
                        commit,
                        &op.action,
                        &op.path,
                        Some(cid.to_string()),
                        WitnessAnomalyKind::MailboxEpochRegression,
                        format!(
                            "mailboxKeys/self regressed from epoch {} to {}",
                            head.current_epoch_number, parsed.epoch_number
                        ),
                        outcome,
                    )
                    .await?;
                    return Ok(());
                }
                if parsed.epoch_number == head.current_epoch_number
                    && parsed.epoch_head != head.current_epoch_head
                {
                    emit_anomaly(
                        store,
                        commit,
                        &op.action,
                        &op.path,
                        Some(cid.to_string()),
                        WitnessAnomalyKind::MailboxSplitViewEquivocation,
                        format!(
                            "mailboxKeys/self changed epochHead without advancing epoch {}",
                            parsed.epoch_number
                        ),
                        outcome,
                    )
                    .await?;
                    return Ok(());
                }
                if head.current_epoch_number.checked_add(1) == Some(parsed.epoch_number)
                    && parsed.previous_epoch_head.as_deref()
                        != Some(head.current_epoch_head.as_slice())
                {
                    emit_anomaly(
                        store,
                        commit,
                        &op.action,
                        &op.path,
                        Some(cid.to_string()),
                        WitnessAnomalyKind::MailboxBrokenHashChain,
                        format!(
                            "mailboxKeys/self advanced {} -> {} with mismatched previousEpochHead",
                            head.current_epoch_number, parsed.epoch_number
                        ),
                        outcome,
                    )
                    .await?;
                    return Ok(());
                }
            }
        }
    }

    store.put_mailbox_epoch(&commit.actor_did, &parsed).await?;
    if is_self_rkey {
        let should_advance_head = match store.get_mailbox_head(&commit.actor_did).await? {
            None => true,
            Some(head) => {
                parsed.epoch_number > head.current_epoch_number
                    || (parsed.epoch_number == head.current_epoch_number
                        && commit.seq >= head.last_seen_seq)
            }
        };
        if should_advance_head {
            store
                .set_mailbox_head(
                    &commit.actor_did,
                    &MailboxHeadRecord {
                        current_epoch_number: parsed.epoch_number,
                        current_epoch_head: parsed.epoch_head.clone(),
                        current_record_cid: parsed.record_cid.clone(),
                        last_seen_seq: commit.seq,
                        last_seen_rev: commit.rev.clone(),
                    },
                )
                .await?;
        }
    }

    outcome.indexed_mailbox_records += 1;
    metrics::WITNESS_RECORDS_INDEXED
        .with_label_values(&[MAILBOX_KEYS_COLLECTION])
        .inc();
    Ok(())
}

/// Firehose `Consumer` that indexes and witnesses `blue.catbird.chat.device` and
/// `blue.catbird.labyrinth.mailboxKeys` commit operations in PostgreSQL.
pub struct WitnessConsumer {
    db_pool: Pool<Postgres>,
}

impl WitnessConsumer {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self { db_pool }
    }

    pub async fn ingest_observed_commit(&self, commit: &ObservedCommit) -> Result<WitnessOutcome> {
        let mut tx = self.db_pool.begin().await?;
        db::acquire_witness_actor_lock(&mut tx, &commit.actor_did).await?;
        let outcome = {
            let mut pg_store = PgWitnessStore::new(&mut tx);
            evaluate_commit(&mut pg_store, commit).await?
        };
        tx.commit().await?;
        metrics::WITNESS_COMMITS_PROCESSED.inc();
        Ok(outcome)
    }
}

fn read_uvarint_usize(buf: &[u8]) -> Result<(usize, usize), &'static str> {
    let mut acc: u64 = 0;
    for idx in 0..9usize {
        let byte = *buf.get(idx).ok_or("truncated CAR varint")?;
        let low = u64::from(byte & 0x7F);
        let shifted = low
            .checked_shl((idx as u32) * 7)
            .ok_or("CAR varint shift overflow")?;
        acc |= shifted;
        if (byte & 0x80) == 0 {
            if idx > 0 && byte == 0 {
                return Err("non-minimal CAR varint");
            }
            let val = usize::try_from(acc).map_err(|_| "CAR varint exceeds usize")?;
            return Ok((val, idx + 1));
        }
    }
    Err("CAR varint exceeds 9 bytes")
}

fn is_valid_dag_cbor_sha256_cid_v1(cid: &Cid) -> bool {
    cid.version() == Version::V1
        && cid.codec() == DAG_CBOR_CODEC
        && cid.hash().code() == SHA2_256_CODE
        && cid.hash().digest().len() == SHA2_256_DIGEST_LEN
}

/// Bounded, panic-free in-slice CARv1 block reader for untrusted firehose `#commit.blocks`.
///
/// Validates header and section lengths against remaining slice bounds before slicing or
/// decoding, uses `checked_sub` for `section_len` vs `cid_len`, caps section count, and
/// requires `CIDv1` + `dag-cbor` (`0x71`) + `sha2-256` (`0x12`) with verified `SHA256(block)`
/// on every block.
fn parse_bounded_car_v1_blocks(car_bytes: &[u8]) -> Result<HashMap<Cid, &[u8]>, String> {
    if car_bytes.is_empty() {
        return Err("empty CAR archive".to_string());
    }
    if car_bytes.len() > MAX_CAR_ARCHIVE_BYTES {
        return Err(format!(
            "CAR archive length {} exceeds {} limit",
            car_bytes.len(),
            MAX_CAR_ARCHIVE_BYTES
        ));
    }

    let (header_len, hdr_varint_len) = read_uvarint_usize(car_bytes).map_err(str::to_string)?;
    if !(1..=MAX_CAR_HEADER_BYTES).contains(&header_len) {
        return Err(format!(
            "CAR header length {header_len} outside 1..={MAX_CAR_HEADER_BYTES}"
        ));
    }
    let hdr_end = hdr_varint_len
        .checked_add(header_len)
        .ok_or_else(|| "CAR header offset overflow".to_string())?;
    let hdr_slice = car_bytes
        .get(hdr_varint_len..hdr_end)
        .ok_or_else(|| "CAR header exceeds archive bounds".to_string())?;

    let hdr_ipld: Ipld = serde_ipld_dagcbor::from_slice(hdr_slice)
        .map_err(|e| format!("invalid CARv1 DAG-CBOR header: {e}"))?;
    let Ipld::Map(hdr_map) = hdr_ipld else {
        return Err("CAR header must be a DAG-CBOR map".to_string());
    };
    if hdr_map.get("version") != Some(&Ipld::Integer(1)) {
        return Err("CAR header version must equal 1".to_string());
    }
    match hdr_map.get("roots") {
        Some(Ipld::List(roots))
            if roots.len() <= 64 && roots.iter().all(|r| matches!(r, Ipld::Link(_))) => {}
        _ => return Err("CAR header must contain 0..=64 CID roots".to_string()),
    }

    let mut blocks = HashMap::new();
    let mut pos = hdr_end;
    let mut section_count = 0usize;

    while pos < car_bytes.len() {
        section_count = section_count
            .checked_add(1)
            .ok_or_else(|| "CAR section count overflow".to_string())?;
        if section_count > MAX_CAR_SECTIONS {
            return Err(format!(
                "CAR section count exceeds {MAX_CAR_SECTIONS} limit"
            ));
        }

        let rem = car_bytes
            .get(pos..)
            .ok_or_else(|| "CAR section cursor out of bounds".to_string())?;
        let (section_len, varint_len) = read_uvarint_usize(rem).map_err(str::to_string)?;
        if section_len == 0 {
            return Err("empty CAR section".to_string());
        }
        let section_start = pos
            .checked_add(varint_len)
            .ok_or_else(|| "CAR section start overflow".to_string())?;
        let section_end = section_start
            .checked_add(section_len)
            .ok_or_else(|| "CAR section end overflow".to_string())?;
        let section = car_bytes
            .get(section_start..section_end)
            .ok_or_else(|| "CAR section exceeds archive bounds".to_string())?;
        pos = section_end;

        let mut cursor = Cursor::new(section);
        let cid =
            Cid::read_bytes(&mut cursor).map_err(|e| format!("invalid CAR section CID: {e}"))?;
        let cid_len = usize::try_from(cursor.position())
            .map_err(|_| "CAR CID offset overflow".to_string())?;
        let data_len = section
            .len()
            .checked_sub(cid_len)
            .ok_or_else(|| "CAR section shorter than CID".to_string())?;
        let block_end = cid_len
            .checked_add(data_len)
            .ok_or_else(|| "CAR block end overflow".to_string())?;
        let block = section
            .get(cid_len..block_end)
            .ok_or_else(|| "CAR block slice out of bounds".to_string())?;

        if !is_valid_dag_cbor_sha256_cid_v1(&cid) {
            return Err(format!(
                "unsupported CAR block CID (version={:?}, codec=0x{:x}, hash=0x{:x})",
                cid.version(),
                cid.codec(),
                cid.hash().code()
            ));
        }
        let actual_digest: [u8; SHA2_256_DIGEST_LEN] = Sha256::digest(block).into();
        if actual_digest.as_slice() != cid.hash().digest() {
            return Err(format!("CAR block SHA-256 digest mismatch for CID {cid}"));
        }

        blocks.insert(cid, block);
    }

    Ok(blocks)
}

impl Consumer for WitnessConsumer {
    fn name(&self) -> &str {
        "device-key-transparency-witness"
    }

    fn handle_lag(&self, dropped_events: u64) {
        metrics::WITNESS_CONSUMER_LAG_EVENTS.inc();
        metrics::WITNESS_CONSUMER_DROPPED_EVENTS.inc_by(dropped_events as f64);
    }

    async fn handle_event(&self, event: Arc<SubscribeReposMessage>) -> Result<()> {
        let SubscribeReposMessage::Commit(commit) = event.as_ref() else {
            return Ok(());
        };

        let has_transparency_ops = commit
            .ops
            .iter()
            .any(|op| is_transparency_path(op.path.as_ref()));
        if !has_transparency_ops {
            return Ok(());
        }

        let car_blocks = if commit.blocks.is_empty() {
            None
        } else {
            match parse_bounded_car_v1_blocks(&commit.blocks) {
                Ok(blocks) => Some(blocks),
                Err(err) => {
                    warn!(
                        actor_did = %commit.repo,
                        seq = commit.seq,
                        rev = %commit.rev,
                        error = %err,
                        "Invalid or corrupt CAR blocks on transparency commit; evaluating ops as missing-block anomalies"
                    );
                    None
                }
            }
        };

        let mut ops = Vec::with_capacity(commit.ops.len());
        for op in &commit.ops {
            let path: &str = op.path.as_ref();
            if !is_transparency_path(path) {
                continue;
            }
            let action: &str = op.action.as_ref();
            let mut cid_str = None;
            let mut block_bytes = None;

            if let Some(cid_link) = &op.cid {
                match cid_link.to_ipld() {
                    Ok(cid) => {
                        cid_str = Some(cid.to_string());
                        if is_valid_dag_cbor_sha256_cid_v1(&cid) {
                            if let Some(raw_block) =
                                car_blocks.as_ref().and_then(|m| m.get(&cid).copied())
                            {
                                if raw_block.len() <= MAX_WITNESS_RECORD_BLOCK_BYTES {
                                    block_bytes = Some(raw_block.to_vec());
                                }
                            }
                        }
                    }
                    Err(_) => {
                        cid_str = Some(format!("{cid_link:?}"));
                    }
                }
            }

            ops.push(ObservedRepoOp {
                action: action.to_string(),
                path: path.to_string(),
                cid: cid_str,
                block: block_bytes,
            });
        }

        let observed = ObservedCommit {
            actor_did: commit.repo.to_string(),
            seq: commit.seq,
            rev: commit.rev.as_ref().to_string(),
            commit_cid: format!("{}", commit.commit),
            ops,
        };

        self.ingest_observed_commit(&observed).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use catbird_atproto::generated::blue_catbird::labyrinth::{
        mailbox_keys::MailboxKeysBackend, EpochPublic, TransportAttestation,
    };
    use catbird_atproto::jacquard_common::{
        deps::bytes::Bytes as JqBytes, types::string::Datetime,
    };

    fn encode_device_cbor(alg: &str, key_byte: u8, key_len: usize) -> Vec<u8> {
        let dt: Datetime = "2026-11-13T12:00:00Z".parse().expect("valid RFC3339");
        let dev: Device = Device {
            algorithm: alg.into(),
            created_at: dt,
            mls_signature_public_key: JqBytes::from(vec![key_byte; key_len]),
            extra_data: None,
        };
        serde_ipld_dagcbor::to_vec(&dev).expect("encode Device DAG-CBOR")
    }

    fn encode_mailbox_cbor(
        epoch_number: i64,
        head_byte: u8,
        prev_head_byte: Option<u8>,
    ) -> Vec<u8> {
        let dt: Datetime = "2026-11-13T12:00:00Z".parse().expect("valid RFC3339");
        let mk: MailboxKeys = MailboxKeys {
            backend: Some(MailboxKeysBackend::Space),
            current: EpochPublic {
                attestation: TransportAttestation {
                    sig: JqBytes::from(vec![0xAA; 64]),
                    transport_pubkey: JqBytes::from(vec![0xBB; 32]),
                    extra_data: None,
                },
                auth_pubkey: JqBytes::from(vec![0x11; 32]),
                encryption_pubkey: JqBytes::from(vec![0x22; 1216]),
                epoch_head: JqBytes::from(vec![head_byte; 32]),
                epoch_number,
                members_hash: JqBytes::from(vec![0x33; 32]),
                prev_sig: prev_head_byte.map(|_| JqBytes::from(vec![0x44; 64])),
                previous_epoch_head: prev_head_byte.map(|b| JqBytes::from(vec![b; 32])),
                self_sig: JqBytes::from(vec![0x55; 64]),
                signing_pubkey: JqBytes::from(vec![0x66; 32]),
                extra_data: None,
            },
            updated_at: dt,
            extra_data: None,
        };
        serde_ipld_dagcbor::to_vec(&mk).expect("encode MailboxKeys DAG-CBOR")
    }

    #[tokio::test]
    async fn witnesses_valid_multi_device_and_monotonic_mailbox_hash_chain() {
        let mut store = InMemoryWitnessStore::default();
        let alice = "did:plc:alicewitness000000000001";

        let out1 = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 100,
                rev: "3l7aaaa000001".to_string(),
                commit_cid: "bafycommit1".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.chat.device/3l7devphone".to_string(),
                        cid: Some("bafydev1".to_string()),
                        block: Some(encode_device_cbor("ed25519", 0x01, 32)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000000".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xA0, None)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xA0, None)),
                    },
                ],
            },
        )
        .await
        .unwrap();
        assert_eq!(out1.indexed_devices, 1);
        assert_eq!(out1.indexed_mailbox_records, 2);
        assert!(out1.anomalies.is_empty());

        // Second device + epoch 1 chained cleanly to epoch 0 (0xA0 -> 0xA1).
        let out2 = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 101,
                rev: "3l7aaaa000002".to_string(),
                commit_cid: "bafycommit2".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.chat.device/3l7devipad".to_string(),
                        cid: Some("bafydev2".to_string()),
                        block: Some(encode_device_cbor("p256", 0x02, 33)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000001".to_string(),
                        cid: Some("bafymk1".to_string()),
                        block: Some(encode_mailbox_cbor(1, 0xA1, Some(0xA0))),
                    },
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk1".to_string()),
                        block: Some(encode_mailbox_cbor(1, 0xA1, Some(0xA0))),
                    },
                ],
            },
        )
        .await
        .unwrap();
        assert_eq!(out2.indexed_devices, 1);
        assert_eq!(out2.indexed_mailbox_records, 2);
        assert!(out2.anomalies.is_empty());

        // Exact cursor replay of seq 101 produces zero anomalies.
        let replay = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 101,
                rev: "3l7aaaa000002".to_string(),
                commit_cid: "bafycommit2".to_string(),
                ops: vec![],
            },
        )
        .await
        .unwrap();
        assert!(replay.anomalies.is_empty());
    }

    #[tokio::test]
    async fn detects_create_only_violations_on_chat_device_and_mailbox_keys() {
        let mut store = InMemoryWitnessStore::default();
        let bob = "did:plc:bobwitness00000000000002";

        evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: bob.to_string(),
                seq: 10,
                rev: "3l7bbbb000001".to_string(),
                commit_cid: "bafybob1".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.chat.device/3l7dev1".to_string(),
                        cid: Some("bafydev1".to_string()),
                        block: Some(encode_device_cbor("ed25519", 0x09, 32)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000000".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xB0, None)),
                    },
                ],
            },
        )
        .await
        .unwrap();

        let bad = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: bob.to_string(),
                seq: 11,
                rev: "3l7bbbb000002".to_string(),
                commit_cid: "bafybob2".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.chat.device/3l7dev1".to_string(),
                        cid: Some("bafydev1b".to_string()),
                        block: Some(encode_device_cbor("ed25519", 0x0A, 32)),
                    },
                    ObservedRepoOp {
                        action: "delete".to_string(),
                        path: "blue.catbird.chat.device/3l7dev1".to_string(),
                        cid: None,
                        block: None,
                    },
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000000".to_string(),
                        cid: Some("bafymk0b".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xB9, None)),
                    },
                    ObservedRepoOp {
                        action: "delete".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: None,
                        block: None,
                    },
                ],
            },
        )
        .await
        .unwrap();

        let kinds: Vec<WitnessAnomalyKind> = bad.anomalies.iter().map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            vec![
                WitnessAnomalyKind::ChatDeviceMutatedOrDeleted,
                WitnessAnomalyKind::ChatDeviceMutatedOrDeleted,
                WitnessAnomalyKind::ImmutableMailboxEpochMutated,
                WitnessAnomalyKind::MailboxKeysDeleted,
            ]
        );
    }

    #[tokio::test]
    async fn detects_rollback_broken_hash_chain_and_split_view_equivocation() {
        let mut store = InMemoryWitnessStore::default();
        let carol = "did:plc:carolwitness000000000003";

        // Seed epoch 0 -> epoch 1.
        evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: carol.to_string(),
                seq: 50,
                rev: "3l7cccc000010".to_string(),
                commit_cid: "bafycarol1".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000000".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xC0, None)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000001".to_string(),
                        cid: Some("bafymk1".to_string()),
                        block: Some(encode_mailbox_cbor(1, 0xC1, Some(0xC0))),
                    },
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk1".to_string()),
                        block: Some(encode_mailbox_cbor(1, 0xC1, Some(0xC0))),
                    },
                ],
            },
        )
        .await
        .unwrap();

        // 1) Repo rev rollback + self epoch regression (1 -> 0) + split-view on epoch 1 + broken chain on epoch 2.
        let anomalies_out = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: carol.to_string(),
                seq: 51,
                rev: "3l7cccc000005".to_string(),
                commit_cid: "bafycarol_rollback".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xC0, None)),
                    },
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk1_evil".to_string()),
                        block: Some(encode_mailbox_cbor(1, 0xEE, Some(0xC0))),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000002".to_string(),
                        cid: Some("bafymk2_broken".to_string()),
                        block: Some(encode_mailbox_cbor(2, 0xC2, Some(0xFF))),
                    },
                ],
            },
        )
        .await
        .unwrap();

        let kinds: Vec<WitnessAnomalyKind> =
            anomalies_out.anomalies.iter().map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            vec![
                WitnessAnomalyKind::RepoRevRollback,
                WitnessAnomalyKind::MailboxEpochRegression,
                WitnessAnomalyKind::MailboxSplitViewEquivocation,
                WitnessAnomalyKind::MailboxBrokenHashChain,
            ]
        );
    }

    #[tokio::test]
    async fn postgres_migration_persists_witnessed_state_and_anomalies() {
        let user = std::env::var("USER").unwrap_or_else(|_| "postgres".to_string());
        let db_url = std::env::var("WITNESS_TEST_DATABASE_URL")
            .unwrap_or_else(|_| format!("postgres://{user}@127.0.0.1:5432/postgres"));
        let schema = format!("witness_test_{}", uuid::Uuid::new_v4().simple());

        let admin_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&db_url)
            .await
            .expect("connect local postgres for isolated witness schema test");
        sqlx::query(&format!("CREATE SCHEMA \"{schema}\""))
            .execute(&admin_pool)
            .await
            .expect("create isolated witness schema");

        let schema_for_conn = schema.clone();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(3)
            .after_connect(move |conn, _meta| {
                let s = schema_for_conn.clone();
                Box::pin(async move {
                    sqlx::query(&format!("SET search_path TO \"{s}\""))
                        .execute(conn)
                        .await?;
                    Ok(())
                })
            })
            .connect(&db_url)
            .await
            .expect("connect scoped witness pool");

        let migration_up =
            include_str!("../../../migrations/20261113000000_add_device_key_witness.up.sql");
        sqlx::raw_sql(migration_up)
            .execute(&pool)
            .await
            .expect("apply witness up migration");

        let consumer = WitnessConsumer::new(pool.clone());
        let did = "did:plc:davepgwitness00000000004";
        let ok = consumer
            .ingest_observed_commit(&ObservedCommit {
                actor_did: did.to_string(),
                seq: 1,
                rev: "3l7dddd222222".to_string(),
                commit_cid: "bafydave1".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.chat.device/3l7dev1".to_string(),
                        cid: Some("bafydev1".to_string()),
                        block: Some(encode_device_cbor("ed25519", 0x77, 32)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000000".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xD0, None)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(0, 0xD0, None)),
                    },
                ],
            })
            .await
            .unwrap();
        assert_eq!(ok.anomalies.len(), 0);

        let violation = consumer
            .ingest_observed_commit(&ObservedCommit {
                actor_did: did.to_string(),
                seq: 2,
                rev: "3l7dddd222223".to_string(),
                commit_cid: "bafydave2".to_string(),
                ops: vec![ObservedRepoOp {
                    action: "delete".to_string(),
                    path: "blue.catbird.chat.device/3l7dev1".to_string(),
                    cid: None,
                    block: None,
                }],
            })
            .await
            .unwrap();
        assert_eq!(violation.anomalies.len(), 1);

        let stored = db::list_anomalies_for_actor(&pool, did).await.unwrap();
        assert_eq!(stored.len(), 1);
        assert_eq!(stored[0].0, "chat_device_mutated_or_deleted");

        // Also exercise Consumer::handle_event end-to-end with a real CAR-encoded #commit payload.
        {
            use atrium_repo::blockstore::{AsyncBlockStoreWrite, CarStore, DAG_CBOR, SHA2_256};
            use ipld_core::ipld::Ipld;
            use std::collections::BTreeMap;

            let dev2_bytes = encode_device_cbor("p256", 0x03, 33);
            let mut car_buf = Cursor::new(Vec::new());
            let mut car = CarStore::create(&mut car_buf).await.unwrap();
            let dev2_cid = car
                .write_block(DAG_CBOR, SHA2_256, &dev2_bytes)
                .await
                .unwrap();
            let root_cid = car
                .write_block(DAG_CBOR, SHA2_256, b"\xa1dtest\xf5")
                .await
                .unwrap();
            drop(car);
            let car_bytes = car_buf.into_inner();

            let mut op_map = BTreeMap::new();
            op_map.insert("action".to_string(), Ipld::String("create".to_string()));
            op_map.insert(
                "path".to_string(),
                Ipld::String("blue.catbird.chat.device/3l7devcar2".to_string()),
            );
            op_map.insert("cid".to_string(), Ipld::Link(dev2_cid));

            let mut commit_map = BTreeMap::new();
            commit_map.insert("blobs".to_string(), Ipld::List(vec![]));
            commit_map.insert("blocks".to_string(), Ipld::Bytes(car_bytes));
            commit_map.insert("commit".to_string(), Ipld::Link(root_cid));
            commit_map.insert("ops".to_string(), Ipld::List(vec![Ipld::Map(op_map)]));
            commit_map.insert("rebase".to_string(), Ipld::Bool(false));
            commit_map.insert("repo".to_string(), Ipld::String(did.to_string()));
            commit_map.insert("rev".to_string(), Ipld::String("3l7dddd222224".to_string()));
            commit_map.insert("seq".to_string(), Ipld::Integer(3));
            commit_map.insert(
                "time".to_string(),
                Ipld::String("2026-11-13T12:05:00Z".to_string()),
            );
            commit_map.insert("tooBig".to_string(), Ipld::Bool(false));

            let raw_commit = serde_ipld_dagcbor::to_vec(&Ipld::Map(commit_map)).unwrap();
            let decoded_commit: jacquard_api::com_atproto::sync::subscribe_repos::Commit =
                serde_ipld_dagcbor::from_slice(&raw_commit).unwrap();
            use jacquard_common::IntoStatic as _;
            let msg = SubscribeReposMessage::Commit(Box::new(decoded_commit.into_static()));
            consumer.handle_event(Arc::new(msg)).await.unwrap();

            let mut tx = pool.begin().await.unwrap();
            let stored_dev2 = db::fetch_chat_device(&mut tx, did, "3l7devcar2")
                .await
                .unwrap()
                .expect("CAR-ingested chat.device must be persisted");
            assert_eq!(stored_dev2.algorithm, "p256");
            assert_eq!(stored_dev2.first_seen_seq, 3);
            tx.commit().await.unwrap();

            // Corrupt CAR bytes on a transparency commit must still record MalformedTransparencyRecord
            // instead of dropping the commit on CarStore::open error.
            let mut corrupt_op = BTreeMap::new();
            corrupt_op.insert("action".to_string(), Ipld::String("create".to_string()));
            corrupt_op.insert(
                "path".to_string(),
                Ipld::String("blue.catbird.chat.device/3l7devcorrupt".to_string()),
            );
            corrupt_op.insert("cid".to_string(), Ipld::Link(dev2_cid));

            let mut corrupt_commit = BTreeMap::new();
            corrupt_commit.insert("blobs".to_string(), Ipld::List(vec![]));
            corrupt_commit.insert(
                "blocks".to_string(),
                Ipld::Bytes(b"not-a-valid-car-archive".to_vec()),
            );
            corrupt_commit.insert("commit".to_string(), Ipld::Link(root_cid));
            corrupt_commit.insert("ops".to_string(), Ipld::List(vec![Ipld::Map(corrupt_op)]));
            corrupt_commit.insert("rebase".to_string(), Ipld::Bool(false));
            corrupt_commit.insert("repo".to_string(), Ipld::String(did.to_string()));
            corrupt_commit.insert("rev".to_string(), Ipld::String("3l7dddd222225".to_string()));
            corrupt_commit.insert("seq".to_string(), Ipld::Integer(4));
            corrupt_commit.insert(
                "time".to_string(),
                Ipld::String("2026-11-13T12:06:00Z".to_string()),
            );
            corrupt_commit.insert("tooBig".to_string(), Ipld::Bool(false));

            let raw_corrupt = serde_ipld_dagcbor::to_vec(&Ipld::Map(corrupt_commit)).unwrap();
            let decoded_corrupt: jacquard_api::com_atproto::sync::subscribe_repos::Commit =
                serde_ipld_dagcbor::from_slice(&raw_corrupt).unwrap();
            let corrupt_msg =
                SubscribeReposMessage::Commit(Box::new(decoded_corrupt.into_static()));
            consumer.handle_event(Arc::new(corrupt_msg)).await.unwrap();

            let anomalies = db::list_anomalies_for_actor(&pool, did).await.unwrap();
            assert!(
                anomalies.iter().any(|(kind, path, _detail)| {
                    kind == WitnessAnomalyKind::MalformedTransparencyRecord.as_str()
                        && path == "blue.catbird.chat.device/3l7devcorrupt"
                }),
                "corrupt CAR commit must record MalformedTransparencyRecord anomaly"
            );

            // Feed adversarial CARv1 payloads directly into `WitnessConsumer::handle_event`:
            // (a) `data_len < cid_len` (`section_len = 1` followed by 36B CIDv1 -> subtraction underflow trap)
            // (b) oversized `header_len` varint (~4 GiB header claim in a 16-byte buffer -> OOM trap)
            // (c) non-SHA256 identity multihash (`0x00`) CID section
            let valid_hdr_bytes = {
                let mut h = BTreeMap::new();
                h.insert("version".to_string(), Ipld::Integer(1));
                h.insert("roots".to_string(), Ipld::List(vec![Ipld::Link(root_cid)]));
                serde_ipld_dagcbor::to_vec(&Ipld::Map(h)).unwrap()
            };

            let mut underflow_car = Vec::new();
            underflow_car.push(valid_hdr_bytes.len() as u8);
            underflow_car.extend_from_slice(&valid_hdr_bytes);
            // Section claims `section_len = 1`, followed by 36-byte CIDv1 bytes (`data_len < cid_len`).
            underflow_car.push(1u8);
            underflow_car.extend_from_slice(&dev2_cid.to_bytes());

            // Oversized header varint: `0xFF, 0xFF, 0xFF, 0xFF, 0x0F` (~4 GiB) with only 8 trailing bytes.
            let oversized_hdr_car = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0xA1, 0x61, 0x76, 0x01];

            // Identity multihash (`0x00`) CIDv1 section (`0x01` CIDv1, `0x71` dag-cbor, `0x00` identity, len 4, "abcd").
            let mut identity_mh_car = Vec::new();
            identity_mh_car.push(valid_hdr_bytes.len() as u8);
            identity_mh_car.extend_from_slice(&valid_hdr_bytes);
            let fake_cid_and_block: &[u8] = &[
                0x01, 0x71, 0x00, 0x04, b'a', b'b', b'c', b'd', b'a', b'b', b'c', b'd',
            ];
            identity_mh_car.push(fake_cid_and_block.len() as u8);
            identity_mh_car.extend_from_slice(fake_cid_and_block);

            for (idx, (rkey_suffix, rev_str, seq_num, bad_blocks)) in [
                ("3l7underflow", "3l7dddd222226", 5i64, underflow_car),
                ("3l7hugehdr", "3l7dddd222227", 6i64, oversized_hdr_car),
                ("3l7identmh", "3l7dddd222232", 7i64, identity_mh_car),
            ]
            .into_iter()
            .enumerate()
            {
                let op_path = format!("blue.catbird.chat.device/{rkey_suffix}");
                let mut adv_op = BTreeMap::new();
                adv_op.insert("action".to_string(), Ipld::String("create".to_string()));
                adv_op.insert("path".to_string(), Ipld::String(op_path.clone()));
                adv_op.insert("cid".to_string(), Ipld::Link(dev2_cid));

                let mut adv_commit = BTreeMap::new();
                adv_commit.insert("blobs".to_string(), Ipld::List(vec![]));
                adv_commit.insert("blocks".to_string(), Ipld::Bytes(bad_blocks));
                adv_commit.insert("commit".to_string(), Ipld::Link(root_cid));
                adv_commit.insert("ops".to_string(), Ipld::List(vec![Ipld::Map(adv_op)]));
                adv_commit.insert("rebase".to_string(), Ipld::Bool(false));
                adv_commit.insert("repo".to_string(), Ipld::String(did.to_string()));
                adv_commit.insert("rev".to_string(), Ipld::String(rev_str.to_string()));
                adv_commit.insert("seq".to_string(), Ipld::Integer(seq_num as i128));
                adv_commit.insert(
                    "time".to_string(),
                    Ipld::String(format!("2026-11-13T12:0{}:00Z", 7 + idx)),
                );
                adv_commit.insert("tooBig".to_string(), Ipld::Bool(false));

                let raw_adv = serde_ipld_dagcbor::to_vec(&Ipld::Map(adv_commit)).unwrap();
                let decoded_adv: jacquard_api::com_atproto::sync::subscribe_repos::Commit =
                    serde_ipld_dagcbor::from_slice(&raw_adv).unwrap();
                let adv_msg = SubscribeReposMessage::Commit(Box::new(decoded_adv.into_static()));
                consumer.handle_event(Arc::new(adv_msg)).await.unwrap();

                let anomalies = db::list_anomalies_for_actor(&pool, did).await.unwrap();
                assert!(
                    anomalies.iter().any(|(kind, path, _)| {
                        kind == WitnessAnomalyKind::MalformedTransparencyRecord.as_str()
                            && path == &op_path
                    }),
                    "adversarial CAR case {rkey_suffix} must record MalformedTransparencyRecord without panic/OOM"
                );
            }
        }

        let _ = sqlx::query(&format!("DROP SCHEMA IF EXISTS \"{schema}\" CASCADE"))
            .execute(&admin_pool)
            .await;
    }

    #[tokio::test]
    async fn rejects_overflow_and_out_of_bounds_epoch_number_on_mailbox_keys_self() {
        let mut store = InMemoryWitnessStore::default();
        let alice = "did:plc:aliceepochbounds00000001";

        // 1. `epochNumber = i64::MAX` on `mailboxKeys/self` must be rejected cleanly as
        //    `MalformedTransparencyRecord` without `epoch_number + 1` overflow panic/wraparound.
        let out_max = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 1,
                rev: "3l7eeee222222".to_string(),
                commit_cid: "bafymax1".to_string(),
                ops: vec![ObservedRepoOp {
                    action: "create".to_string(),
                    path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                    cid: Some("bafymkmax".to_string()),
                    block: Some(encode_mailbox_cbor(i64::MAX, 0xAA, None)),
                }],
            },
        )
        .await
        .unwrap();
        assert_eq!(out_max.indexed_mailbox_records, 0);
        assert_eq!(out_max.anomalies.len(), 1);
        assert_eq!(
            out_max.anomalies[0].kind,
            WitnessAnomalyKind::MalformedTransparencyRecord
        );
        assert!(store.get_mailbox_head(alice).await.unwrap().is_none());

        // 2. `epochNumber = 1_000_000_000_000` (13 digits, above 12-digit snapshot ceiling) also rejected.
        let out_13d = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 2,
                rev: "3l7eeee222223".to_string(),
                commit_cid: "bafymax2".to_string(),
                ops: vec![ObservedRepoOp {
                    action: "create".to_string(),
                    path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                    cid: Some("bafymk13d".to_string()),
                    block: Some(encode_mailbox_cbor(1_000_000_000_000, 0xBB, None)),
                }],
            },
        )
        .await
        .unwrap();
        assert_eq!(out_13d.indexed_mailbox_records, 0);
        assert_eq!(out_13d.anomalies.len(), 1);
        assert_eq!(
            out_13d.anomalies[0].kind,
            WitnessAnomalyKind::MalformedTransparencyRecord
        );

        // 3. Exact 12-digit ceiling `MAX_MAILBOX_EPOCH_NUMBER` (`999_999_999_999`) succeeds without overflow.
        let out_ceiling = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 3,
                rev: "3l7eeee222224".to_string(),
                commit_cid: "bafymax3".to_string(),
                ops: vec![ObservedRepoOp {
                    action: "create".to_string(),
                    path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                    cid: Some("bafymkceil".to_string()),
                    block: Some(encode_mailbox_cbor(
                        MAX_MAILBOX_EPOCH_NUMBER,
                        0xCC,
                        Some(0x11),
                    )),
                }],
            },
        )
        .await
        .unwrap();
        assert_eq!(out_ceiling.anomalies.len(), 0);
        assert_eq!(out_ceiling.indexed_mailbox_records, 1);
    }

    #[test]
    fn bounded_car_reader_rejects_underflow_oversized_header_and_digest_mismatch() {
        let block = b"\xa1dtest\xf5";
        let digest = Sha256::digest(block);
        let mh = ipld_core::cid::multihash::Multihash::wrap(SHA2_256_CODE, &digest).unwrap();
        let valid_cid = Cid::new_v1(DAG_CBOR_CODEC, mh);
        let cid_bytes = valid_cid.to_bytes();

        let hdr_bytes = {
            let mut h = std::collections::BTreeMap::new();
            h.insert("version".to_string(), Ipld::Integer(1));
            h.insert("roots".to_string(), Ipld::List(vec![Ipld::Link(valid_cid)]));
            serde_ipld_dagcbor::to_vec(&Ipld::Map(h)).unwrap()
        };

        // Positive control
        let mut good_car = Vec::new();
        good_car.push(hdr_bytes.len() as u8);
        good_car.extend_from_slice(&hdr_bytes);
        good_car.push((cid_bytes.len() + block.len()) as u8);
        good_car.extend_from_slice(&cid_bytes);
        good_car.extend_from_slice(block);
        let parsed = parse_bounded_car_v1_blocks(&good_car).expect("valid CARv1");
        assert_eq!(parsed.get(&valid_cid).copied(), Some(block.as_slice()));

        // `data_len < cid_len` (`section_len = 1` + 36B CID)
        let mut underflow_car = Vec::new();
        underflow_car.push(hdr_bytes.len() as u8);
        underflow_car.extend_from_slice(&hdr_bytes);
        underflow_car.push(1u8);
        underflow_car.extend_from_slice(&cid_bytes);
        assert!(parse_bounded_car_v1_blocks(&underflow_car).is_err());

        // Truncated mid-CID (`section_len = 12`, only 12 bytes of 36B CID)
        let mut mid_cid_car = Vec::new();
        mid_cid_car.push(hdr_bytes.len() as u8);
        mid_cid_car.extend_from_slice(&hdr_bytes);
        mid_cid_car.push(12u8);
        mid_cid_car.extend_from_slice(&cid_bytes[..12]);
        assert!(parse_bounded_car_v1_blocks(&mid_cid_car).is_err());

        // Oversized header varint (~4 GiB)
        let huge_hdr = [0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0x00];
        assert!(parse_bounded_car_v1_blocks(&huge_hdr).is_err());

        // Wrong SHA-256 digest
        let mut tampered_car = good_car.clone();
        let last = tampered_car.len() - 1;
        tampered_car[last] ^= 0xFF;
        assert!(parse_bounded_car_v1_blocks(&tampered_car).is_err());
    }
}
