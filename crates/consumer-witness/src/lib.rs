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
pub mod verify;

pub use verify::{
    verify_atproto_v3_commit_signature, verify_mst_key_lookup, AtprotoKeyResolver,
    AtprotoVerifyingKey, CommitVerifyError, HttpAtprotoKeyResolver, StaticAtprotoKeyResolver,
    P256_MULTICODEC_PREFIX, SECP256K1_MULTICODEC_PREFIX,
};

use std::collections::HashMap;
use std::io::Cursor;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

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
    let pubkey = parsed.mls_signature_public_key.as_ref();
    if let Err(err) = verify::verify_chat_device_pubkey(alg, pubkey) {
        metrics::WITNESS_VERIFICATION_FAILURES
            .with_label_values(&["invalid_chat_device_pubkey"])
            .inc();
        return Err(err);
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
    actor_did: &str,
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
    let self_msg = [verify::LABYRINTH_SELF_SIG_PREFIX, cur.epoch_head.as_ref()].concat();
    if let Err(err) = verify::verify_labyrinth_xeddsa(
        cur.signing_pubkey.as_ref(),
        &self_msg,
        cur.self_sig.as_ref(),
        "selfSig",
    ) {
        metrics::WITNESS_VERIFICATION_FAILURES
            .with_label_values(&["invalid_mailbox_self_sig"])
            .inc();
        return Err(err);
    }
    if let Err(err) = verify::verify_labyrinth_ed25519_attestation(
        actor_did,
        cur.epoch_head.as_ref(),
        cur.attestation.transport_pubkey.as_ref(),
        cur.attestation.sig.as_ref(),
    ) {
        metrics::WITNESS_VERIFICATION_FAILURES
            .with_label_values(&["invalid_mailbox_attestation_sig"])
            .inc();
        return Err(err);
    }
    if let Some(prev_sig) = cur.prev_sig.as_ref() {
        if let Err(err) = verify::check_xeddsa_sig_canonical(prev_sig.as_ref(), "prevSig") {
            metrics::WITNESS_VERIFICATION_FAILURES
                .with_label_values(&["invalid_mailbox_prev_sig"])
                .inc();
            return Err(err);
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

    let parsed = match parse_mailbox_keys_block(
        &commit.actor_did,
        rkey,
        cid,
        commit.seq,
        &commit.rev,
        !is_self_rkey,
        block,
    ) {
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

    // Cross-check backward link `epoch - 1` if known (both hash link and XEdDSA prevSig).
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
                let prev_sig_bytes = parsed.prev_sig.as_deref().unwrap_or_default();
                let prev_msg = [
                    verify::LABYRINTH_PREV_SIG_PREFIX,
                    parsed.epoch_head.as_slice(),
                ]
                .concat();
                if let Err(err) = verify::verify_labyrinth_xeddsa(
                    &prior_epoch.signing_pubkey,
                    &prev_msg,
                    prev_sig_bytes,
                    "prevSig",
                ) {
                    metrics::WITNESS_VERIFICATION_FAILURES
                        .with_label_values(&["invalid_mailbox_prev_sig"])
                        .inc();
                    emit_anomaly(
                        store,
                        commit,
                        &op.action,
                        &op.path,
                        Some(cid.to_string()),
                        WitnessAnomalyKind::MailboxBrokenHashChain,
                        format!(
                            "epoch {} prevSig failed XEdDSA verification under epoch {} signingPubkey: {err}",
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
            let next_prev_sig = next_epoch.prev_sig.as_deref().unwrap_or_default();
            let next_prev_msg = [
                verify::LABYRINTH_PREV_SIG_PREFIX,
                next_epoch.epoch_head.as_slice(),
            ]
            .concat();
            if let Err(err) = verify::verify_labyrinth_xeddsa(
                &parsed.signing_pubkey,
                &next_prev_msg,
                next_prev_sig,
                "nextEpoch.prevSig",
            ) {
                metrics::WITNESS_VERIFICATION_FAILURES
                    .with_label_values(&["invalid_mailbox_prev_sig"])
                    .inc();
                emit_anomaly(
                    store,
                    commit,
                    &op.action,
                    &op.path,
                    Some(cid.to_string()),
                    WitnessAnomalyKind::MailboxBrokenHashChain,
                    format!(
                        "epoch {} signingPubkey failed XEdDSA verification of witnessed epoch {} prevSig: {err}",
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

/// Firehose `Consumer` that cryptographically verifies ATProto v3 commits + MST proofs and
/// witnesses `blue.catbird.chat.device` and `blue.catbird.labyrinth.mailboxKeys` operations.
pub struct WitnessConsumer {
    db_pool: Pool<Postgres>,
    key_resolver: Arc<dyn AtprotoKeyResolver>,
    verification_failures: AtomicU64,
}

impl WitnessConsumer {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        Self::with_key_resolver(db_pool, Arc::new(HttpAtprotoKeyResolver::new()))
    }

    pub fn with_key_resolver(
        db_pool: Pool<Postgres>,
        key_resolver: Arc<dyn AtprotoKeyResolver>,
    ) -> Self {
        Self {
            db_pool,
            key_resolver,
            verification_failures: AtomicU64::new(0),
        }
    }

    pub fn verification_failures_count(&self) -> u64 {
        self.verification_failures.load(Ordering::Relaxed)
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

    /// Authenticate the CARv1 archive, `#atproto` v3 ECDSA commit signature (`P-256` or
    /// `secp256k1`, compact 64-byte low-S), and MST inclusion/exclusion proofs for every
    /// transparency op in `commit` before any witness state is mutated.
    pub async fn verify_and_extract_observed_commit(
        &self,
        commit: &jacquard_api::com_atproto::sync::subscribe_repos::Commit,
    ) -> std::result::Result<ObservedCommit, CommitVerifyError> {
        if commit.blocks.is_empty() {
            return Err(CommitVerifyError::EmptyCar);
        }

        let commit_cid = commit
            .commit
            .to_ipld()
            .map_err(|e| CommitVerifyError::InvalidCommitCid(e.to_string()))?;
        if !is_valid_dag_cbor_sha256_cid_v1(&commit_cid) {
            return Err(CommitVerifyError::InvalidCommitCid(format!(
                "commit CID {commit_cid} is not CIDv1(dag-cbor, sha2-256)"
            )));
        }

        let (roots, car_blocks) =
            parse_bounded_car_v1(&commit.blocks).map_err(CommitVerifyError::InvalidCar)?;
        if roots.as_slice() != [commit_cid] {
            return Err(CommitVerifyError::CommitRootMismatch(format!(
                "CAR header roots {roots:?} do not match frame commit CID {commit_cid}"
            )));
        }

        let commit_block = car_blocks
            .get(&commit_cid)
            .copied()
            .ok_or_else(|| CommitVerifyError::MissingCommitBlock(commit_cid.to_string()))?;

        let actor_did: &str = commit.repo.as_ref();
        let rev_str: &str = commit.rev.as_ref();

        let mut key = self
            .key_resolver
            .resolve_atproto_key(actor_did, false)
            .await
            .map_err(CommitVerifyError::DidResolution)?;

        let mst_root_cid = match verify::verify_atproto_v3_commit_signature(
            commit_block,
            actor_did,
            rev_str,
            &key,
        ) {
            Ok(root) => root,
            Err(CommitVerifyError::InvalidSignature) => {
                // Key rotation resilience: force-refresh DID document once on signature failure.
                key = self
                    .key_resolver
                    .resolve_atproto_key(actor_did, true)
                    .await
                    .map_err(CommitVerifyError::DidResolution)?;
                verify::verify_atproto_v3_commit_signature(commit_block, actor_did, rev_str, &key)?
            }
            Err(other) => return Err(other),
        };

        let mut ops = Vec::with_capacity(commit.ops.len());
        for op in &commit.ops {
            let path: &str = op.path.as_ref();
            if !is_transparency_path(path) {
                continue;
            }
            let action: &str = op.action.as_ref();
            match action {
                "create" | "update" => {
                    let cid_link = op.cid.as_ref().ok_or_else(|| {
                        CommitVerifyError::InvalidOpCid(format!(
                            "{action} op on {path} missing required CID"
                        ))
                    })?;
                    let op_cid = cid_link
                        .to_ipld()
                        .map_err(|e| CommitVerifyError::InvalidOpCid(e.to_string()))?;
                    if !is_valid_dag_cbor_sha256_cid_v1(&op_cid) {
                        return Err(CommitVerifyError::InvalidOpCid(format!(
                            "op CID {op_cid} on {path} is not CIDv1(dag-cbor, sha2-256)"
                        )));
                    }
                    let mst_val =
                        verify::verify_mst_key_lookup(&car_blocks, mst_root_cid, path.as_bytes())
                            .map_err(CommitVerifyError::MstProofFailed)?;
                    if mst_val != Some(op_cid) {
                        return Err(CommitVerifyError::MstProofFailed(format!(
                            "MST lookup for {path} resolved to {mst_val:?}, expected Some({op_cid})"
                        )));
                    }
                    let raw_block = car_blocks.get(&op_cid).copied().ok_or_else(|| {
                        CommitVerifyError::MissingOrOversizedRecordBlock(format!(
                            "missing CAR block {op_cid} for {path}"
                        ))
                    })?;
                    if raw_block.len() > MAX_WITNESS_RECORD_BLOCK_BYTES {
                        return Err(CommitVerifyError::MissingOrOversizedRecordBlock(format!(
                            "record block {op_cid} for {path} exceeds {MAX_WITNESS_RECORD_BLOCK_BYTES} bytes"
                        )));
                    }
                    ops.push(ObservedRepoOp {
                        action: action.to_string(),
                        path: path.to_string(),
                        cid: Some(op_cid.to_string()),
                        block: Some(raw_block.to_vec()),
                    });
                }
                "delete" => {
                    if op.cid.is_some() {
                        return Err(CommitVerifyError::InvalidOpCid(format!(
                            "delete op on {path} must not carry a CID"
                        )));
                    }
                    let mst_val =
                        verify::verify_mst_key_lookup(&car_blocks, mst_root_cid, path.as_bytes())
                            .map_err(CommitVerifyError::MstProofFailed)?;
                    if mst_val.is_some() {
                        return Err(CommitVerifyError::MstProofFailed(format!(
                            "delete op on {path} contradicted by MST inclusion {mst_val:?}"
                        )));
                    }
                    ops.push(ObservedRepoOp {
                        action: action.to_string(),
                        path: path.to_string(),
                        cid: None,
                        block: None,
                    });
                }
                other => {
                    return Err(CommitVerifyError::MstProofFailed(format!(
                        "unsupported repo op action '{other}' on {path}"
                    )));
                }
            }
        }

        metrics::WITNESS_COMMIT_SIG_VERIFIED
            .with_label_values(&[key.curve_label()])
            .inc();

        Ok(ObservedCommit {
            actor_did: actor_did.to_string(),
            seq: commit.seq,
            rev: rev_str.to_string(),
            commit_cid: commit_cid.to_string(),
            ops,
        })
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

type ParsedCarV1<'a> = (Vec<Cid>, HashMap<Cid, &'a [u8]>);

/// Bounded, panic-free in-slice CARv1 reader for untrusted firehose `#commit.blocks`.
///
/// Validates header and section lengths against remaining slice bounds before slicing or
/// decoding, enforces canonical DAG-CBOR on header, uses `checked_sub` for `section_len`
/// vs `cid_len`, caps section count, rejects duplicate CIDs, and requires `CIDv1` +
/// `dag-cbor` (`0x71`) + `sha2-256` (`0x12`) with verified `SHA256(block)` on every block.
fn parse_bounded_car_v1(car_bytes: &[u8]) -> Result<ParsedCarV1<'_>, String> {
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
    verify::verify_canonical_dagcbor(hdr_slice)
        .map_err(|e| format!("non-canonical CARv1 header DAG-CBOR: {e}"))?;

    let hdr_ipld: Ipld = serde_ipld_dagcbor::from_slice(hdr_slice)
        .map_err(|e| format!("invalid CARv1 DAG-CBOR header: {e}"))?;
    let Ipld::Map(hdr_map) = hdr_ipld else {
        return Err("CAR header must be a DAG-CBOR map".to_string());
    };
    if hdr_map.len() != 2 || hdr_map.get("version") != Some(&Ipld::Integer(1)) {
        return Err("CAR header must contain version=1 and roots".to_string());
    }
    let roots = match hdr_map.get("roots") {
        Some(Ipld::List(list)) if list.len() <= 64 => {
            let mut cids = Vec::with_capacity(list.len());
            for item in list {
                let Ipld::Link(cid) = item else {
                    return Err("CAR header roots entries must be CID links".to_string());
                };
                cids.push(*cid);
            }
            cids
        }
        _ => return Err("CAR header must contain 0..=64 CID roots".to_string()),
    };

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
        if cid.to_bytes().as_slice() != &section[..cid_len] {
            return Err("non-canonical CID encoding in CAR section".to_string());
        }
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

        if blocks.insert(cid, block).is_some() {
            return Err(format!("duplicate CID {cid} in CAR archive"));
        }
    }

    Ok((roots, blocks))
}

#[cfg(test)]
fn parse_bounded_car_v1_blocks(car_bytes: &[u8]) -> Result<HashMap<Cid, &[u8]>, String> {
    parse_bounded_car_v1(car_bytes).map(|(_roots, blocks)| blocks)
}

impl Consumer for WitnessConsumer {
    fn name(&self) -> &str {
        "device-key-transparency-witness"
    }

    fn handle_lag(&self, dropped_events: u64) {
        metrics::WITNESS_CONSUMER_LAG_EVENTS.inc();
        metrics::WITNESS_CONSUMER_DROPPED_EVENTS.inc_by(dropped_events as f64);
    }

    fn handle_error(&self, _error: &anyhow::Error) {
        metrics::WITNESS_CONSUMER_EVENT_ERRORS.inc();
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

        let observed = match self.verify_and_extract_observed_commit(commit).await {
            Ok(obs) => obs,
            Err(err) => {
                self.verification_failures.fetch_add(1, Ordering::Relaxed);
                metrics::WITNESS_VERIFICATION_FAILURES
                    .with_label_values(&[err.metric_reason()])
                    .inc();
                warn!(
                    actor_did = %commit.repo,
                    seq = commit.seq,
                    rev = %commit.rev,
                    reason = err.metric_reason(),
                    error = %err,
                    "Rejected firehose transparency commit failing cryptographic/Merkle verification"
                );
                return Err(anyhow::Error::new(err));
            }
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
    use std::collections::BTreeMap;

    fn encode_device_cbor(alg: &str, seed_byte: u8, _key_len: usize) -> Vec<u8> {
        let dt: Datetime = "2026-11-13T12:00:00Z".parse().expect("valid RFC3339");
        let pubkey_bytes = match alg {
            "ed25519" => {
                let sk = ed25519_dalek::SigningKey::from_bytes(&[seed_byte; 32]);
                sk.verifying_key().to_bytes().to_vec()
            }
            "p256" => {
                let mut scalar_seed = [seed_byte.max(1); 32];
                scalar_seed[0] = seed_byte.wrapping_add(1).max(1);
                let sk = p256::ecdsa::SigningKey::from_bytes((&scalar_seed).into())
                    .expect("valid P-256 test scalar");
                sk.verifying_key()
                    .to_encoded_point(true)
                    .as_bytes()
                    .to_vec()
            }
            _ => vec![seed_byte; 32],
        };
        let dev: Device = Device {
            algorithm: alg.into(),
            created_at: dt,
            mls_signature_public_key: JqBytes::from(pubkey_bytes),
            extra_data: None,
        };
        serde_ipld_dagcbor::to_vec(&dev).expect("encode Device DAG-CBOR")
    }

    fn test_epoch_signing_secret(actor_did: &str, epoch_number: i64) -> [u8; 32] {
        Sha256::digest(format!(
            "test-labyrinth-epoch-sig:{actor_did}:{epoch_number}"
        ))
        .into()
    }

    fn encode_mailbox_cbor(
        actor_did: &str,
        epoch_number: i64,
        head_byte: u8,
        prev_head_byte: Option<u8>,
    ) -> Vec<u8> {
        use ed25519_dalek::Signer as _;

        let dt: Datetime = "2026-11-13T12:00:00Z".parse().expect("valid RFC3339");
        let epoch_head = [head_byte; 32];
        let sig_secret = test_epoch_signing_secret(actor_did, epoch_number);
        let signing_pubkey = verify::xeddsa_public_from_secret(&sig_secret);
        let self_msg = [verify::LABYRINTH_SELF_SIG_PREFIX, epoch_head.as_slice()].concat();
        let self_sig = verify::xeddsa_sign_deterministic(&sig_secret, &self_msg, &[0x42; 64]);

        let prev_sig = prev_head_byte.map(|_| {
            let prev_secret = test_epoch_signing_secret(actor_did, epoch_number.saturating_sub(1));
            let prev_msg = [verify::LABYRINTH_PREV_SIG_PREFIX, epoch_head.as_slice()].concat();
            JqBytes::from(
                verify::xeddsa_sign_deterministic(&prev_secret, &prev_msg, &[0x43; 64]).to_vec(),
            )
        });

        let transport_seed: [u8; 32] =
            Sha256::digest(format!("test-labyrinth-transport:{actor_did}")).into();
        let transport_sk = ed25519_dalek::SigningKey::from_bytes(&transport_seed);
        let mut attest_msg =
            format!("{}{actor_did}:", verify::LABYRINTH_ATTEST_PREFIX).into_bytes();
        attest_msg.extend_from_slice(&epoch_head);
        let attest_sig = transport_sk.sign(&attest_msg);

        let mk: MailboxKeys = MailboxKeys {
            backend: Some(MailboxKeysBackend::Space),
            current: EpochPublic {
                attestation: TransportAttestation {
                    sig: JqBytes::from(attest_sig.to_bytes().to_vec()),
                    transport_pubkey: JqBytes::from(
                        transport_sk.verifying_key().to_bytes().to_vec(),
                    ),
                    extra_data: None,
                },
                auth_pubkey: JqBytes::from(vec![0x11; 32]),
                encryption_pubkey: JqBytes::from(vec![0x22; 1216]),
                epoch_head: JqBytes::from(epoch_head.to_vec()),
                epoch_number,
                members_hash: JqBytes::from(vec![0x33; 32]),
                prev_sig,
                previous_epoch_head: prev_head_byte.map(|b| JqBytes::from(vec![b; 32])),
                self_sig: JqBytes::from(self_sig.to_vec()),
                signing_pubkey: JqBytes::from(signing_pubkey.to_vec()),
                extra_data: None,
            },
            updated_at: dt,
            extra_data: None,
        };
        serde_ipld_dagcbor::to_vec(&mk).expect("encode MailboxKeys DAG-CBOR")
    }

    fn build_subscribe_repos_commit_msg(
        did: &str,
        rev: &str,
        seq: i64,
        commit_cid: Cid,
        car_bytes: Vec<u8>,
        ops: Vec<(&str, &str, Option<Cid>)>,
    ) -> Arc<SubscribeReposMessage> {
        use jacquard_common::IntoStatic as _;

        let mut op_list = Vec::with_capacity(ops.len());
        for (action, path, cid_opt) in ops {
            let mut op_map = BTreeMap::new();
            op_map.insert("action".to_string(), Ipld::String(action.to_string()));
            op_map.insert("path".to_string(), Ipld::String(path.to_string()));
            if let Some(cid) = cid_opt {
                op_map.insert("cid".to_string(), Ipld::Link(cid));
            }
            op_list.push(Ipld::Map(op_map));
        }

        let mut commit_map = BTreeMap::new();
        commit_map.insert("blobs".to_string(), Ipld::List(vec![]));
        commit_map.insert("blocks".to_string(), Ipld::Bytes(car_bytes));
        commit_map.insert("commit".to_string(), Ipld::Link(commit_cid));
        commit_map.insert("ops".to_string(), Ipld::List(op_list));
        commit_map.insert("rebase".to_string(), Ipld::Bool(false));
        commit_map.insert("repo".to_string(), Ipld::String(did.to_string()));
        commit_map.insert("rev".to_string(), Ipld::String(rev.to_string()));
        commit_map.insert("seq".to_string(), Ipld::Integer(seq as i128));
        commit_map.insert(
            "time".to_string(),
            Ipld::String("2026-11-13T12:05:00Z".to_string()),
        );
        commit_map.insert("tooBig".to_string(), Ipld::Bool(false));

        let raw_commit = serde_ipld_dagcbor::to_vec(&Ipld::Map(commit_map)).unwrap();
        let decoded_commit: jacquard_api::com_atproto::sync::subscribe_repos::Commit =
            serde_ipld_dagcbor::from_slice(&raw_commit).unwrap();
        Arc::new(SubscribeReposMessage::Commit(Box::new(
            decoded_commit.into_static(),
        )))
    }

    fn sub_be_32(minuend: &[u8; 32], subtrahend: &[u8; 32]) -> [u8; 32] {
        let mut out = [0u8; 32];
        let mut borrow = 0i16;
        for i in (0..32).rev() {
            let diff = i16::from(minuend[i]) - i16::from(subtrahend[i]) - borrow;
            if diff < 0 {
                out[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                out[i] = diff as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0, "minuend must be >= subtrahend");
        out
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
                        block: Some(encode_mailbox_cbor(alice, 0, 0xA0, None)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(alice, 0, 0xA0, None)),
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
                        block: Some(encode_mailbox_cbor(alice, 1, 0xA1, Some(0xA0))),
                    },
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk1".to_string()),
                        block: Some(encode_mailbox_cbor(alice, 1, 0xA1, Some(0xA0))),
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
                        block: Some(encode_mailbox_cbor(bob, 0, 0xB0, None)),
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
                        block: Some(encode_mailbox_cbor(bob, 0, 0xB9, None)),
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
                        block: Some(encode_mailbox_cbor(carol, 0, 0xC0, None)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000001".to_string(),
                        cid: Some("bafymk1".to_string()),
                        block: Some(encode_mailbox_cbor(carol, 1, 0xC1, Some(0xC0))),
                    },
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk1".to_string()),
                        block: Some(encode_mailbox_cbor(carol, 1, 0xC1, Some(0xC0))),
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
                        block: Some(encode_mailbox_cbor(carol, 0, 0xC0, None)),
                    },
                    ObservedRepoOp {
                        action: "update".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk1_evil".to_string()),
                        block: Some(encode_mailbox_cbor(carol, 1, 0xEE, Some(0xC0))),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000002".to_string(),
                        cid: Some("bafymk2_broken".to_string()),
                        block: Some(encode_mailbox_cbor(carol, 2, 0xC2, Some(0xFF))),
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

        let did = "did:plc:davepgwitness00000000004";
        let dave_p256_sk = p256::ecdsa::SigningKey::from_bytes((&[0x44u8; 32]).into())
            .expect("valid P-256 signing key");
        let resolver = Arc::new(StaticAtprotoKeyResolver::new());
        resolver.insert(
            did,
            AtprotoVerifyingKey::P256(*dave_p256_sk.verifying_key()),
        );

        let k256_did = "did:plc:evak256witness0000000005";
        let eva_k256_sk = k256::ecdsa::SigningKey::from_bytes((&[0x55u8; 32]).into())
            .expect("valid secp256k1 signing key");
        resolver.insert(
            k256_did,
            AtprotoVerifyingKey::Secp256k1(*eva_k256_sk.verifying_key()),
        );

        let consumer = WitnessConsumer::with_key_resolver(pool.clone(), resolver.clone());
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
                        block: Some(encode_mailbox_cbor(did, 0, 0xD0, None)),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/self".to_string(),
                        cid: Some("bafymk0".to_string()),
                        block: Some(encode_mailbox_cbor(did, 0, 0xD0, None)),
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

        // Exercise Consumer::handle_event end-to-end with real P-256 AND secp256k1 signed CARv1 + MST commits,
        // then verify corrupt/forged frames propagate Err and increment failure metrics without poisoning heads.
        {
            // 1) Valid P-256 signed v3 commit + MST proof for `did`.
            let dev2_path = "blue.catbird.chat.device/3l7devcar2";
            let dev2_bytes = encode_device_cbor("p256", 0x03, 33);
            let dev2_cid = verify::compute_dagcbor_cid(&dev2_bytes);
            let mut mst_records = BTreeMap::new();
            mst_records.insert(dev2_path.to_string(), dev2_cid);
            let mst_bytes = verify::encode_mst_leaf_cbor(&mst_records);
            let mst_cid = verify::compute_dagcbor_cid(&mst_bytes);
            let unsigned_commit =
                verify::encode_unsigned_v3_commit_cbor(did, "3l7dddd222224", mst_cid, None);
            let sig_p256 = verify::sign_p256_low_s(&dave_p256_sk, &unsigned_commit);
            let signed_commit =
                verify::encode_signed_v3_commit_cbor(did, "3l7dddd222224", mst_cid, None, sig_p256);
            let root_cid = verify::compute_dagcbor_cid(&signed_commit);
            let car_bytes = verify::encode_car_v1(
                &[root_cid],
                &[
                    (root_cid, signed_commit),
                    (mst_cid, mst_bytes),
                    (dev2_cid, dev2_bytes),
                ],
            );

            let msg = build_subscribe_repos_commit_msg(
                did,
                "3l7dddd222224",
                3,
                root_cid,
                car_bytes,
                vec![("create", dev2_path, Some(dev2_cid))],
            );
            consumer.handle_event(msg).await.unwrap();

            let mut tx = pool.begin().await.unwrap();
            let stored_dev2 = db::fetch_chat_device(&mut tx, did, "3l7devcar2")
                .await
                .unwrap()
                .expect("P-256 signed CAR-ingested chat.device must be persisted");
            assert_eq!(stored_dev2.algorithm, "p256");
            assert_eq!(stored_dev2.first_seen_seq, 3);
            tx.commit().await.unwrap();

            // 2) Valid secp256k1 signed v3 commit + MST proof for `k256_did`.
            let eva_dev_path = "blue.catbird.chat.device/3l7evadev1";
            let eva_dev_bytes = encode_device_cbor("ed25519", 0x29, 32);
            let eva_dev_cid = verify::compute_dagcbor_cid(&eva_dev_bytes);
            let mut eva_mst_map = BTreeMap::new();
            eva_mst_map.insert(eva_dev_path.to_string(), eva_dev_cid);
            let eva_mst_bytes = verify::encode_mst_leaf_cbor(&eva_mst_map);
            let eva_mst_cid = verify::compute_dagcbor_cid(&eva_mst_bytes);
            let eva_unsigned = verify::encode_unsigned_v3_commit_cbor(
                k256_did,
                "3l7eeee222222",
                eva_mst_cid,
                Some(root_cid),
            );
            let sig_k256 = verify::sign_k256_low_s(&eva_k256_sk, &eva_unsigned);
            let eva_signed = verify::encode_signed_v3_commit_cbor(
                k256_did,
                "3l7eeee222222",
                eva_mst_cid,
                Some(root_cid),
                sig_k256,
            );
            let eva_root_cid = verify::compute_dagcbor_cid(&eva_signed);
            let eva_car = verify::encode_car_v1(
                &[eva_root_cid],
                &[
                    (eva_root_cid, eva_signed),
                    (eva_mst_cid, eva_mst_bytes),
                    (eva_dev_cid, eva_dev_bytes),
                ],
            );
            let eva_msg = build_subscribe_repos_commit_msg(
                k256_did,
                "3l7eeee222222",
                4,
                eva_root_cid,
                eva_car,
                vec![("create", eva_dev_path, Some(eva_dev_cid))],
            );
            consumer.handle_event(eva_msg).await.unwrap();
            let mut tx = pool.begin().await.unwrap();
            let stored_eva = db::fetch_chat_device(&mut tx, k256_did, "3l7evadev1")
                .await
                .unwrap()
                .expect("secp256k1 signed CAR-ingested chat.device must be persisted");
            assert_eq!(stored_eva.algorithm, "ed25519");
            tx.commit().await.unwrap();

            // 3) Corrupt CAR bytes & adversarial CARv1 payloads MUST return Err, increment
            //    verification_failures + WITNESS_VERIFICATION_FAILURES, and NOT advance actor_head!
            let valid_hdr_bytes = {
                let mut h = BTreeMap::new();
                h.insert("version".to_string(), Ipld::Integer(1));
                h.insert("roots".to_string(), Ipld::List(vec![Ipld::Link(root_cid)]));
                serde_ipld_dagcbor::to_vec(&Ipld::Map(h)).unwrap()
            };

            let mut underflow_car = Vec::new();
            underflow_car.push(valid_hdr_bytes.len() as u8);
            underflow_car.extend_from_slice(&valid_hdr_bytes);
            underflow_car.push(1u8);
            underflow_car.extend_from_slice(&dev2_cid.to_bytes());

            let oversized_hdr_car = vec![0xFF, 0xFF, 0xFF, 0xFF, 0x0F, 0xA1, 0x61, 0x76, 0x01];

            let mut identity_mh_car = Vec::new();
            identity_mh_car.push(valid_hdr_bytes.len() as u8);
            identity_mh_car.extend_from_slice(&valid_hdr_bytes);
            let fake_cid_and_block: &[u8] = &[
                0x01, 0x71, 0x00, 0x04, b'a', b'b', b'c', b'd', b'a', b'b', b'c', b'd',
            ];
            identity_mh_car.push(fake_cid_and_block.len() as u8);
            identity_mh_car.extend_from_slice(fake_cid_and_block);

            let failures_before = consumer.verification_failures_count();
            let metric_invalid_car_before = metrics::WITNESS_VERIFICATION_FAILURES
                .with_label_values(&["invalid_car"])
                .get();

            for (rkey_suffix, rev_str, seq_num, bad_blocks) in [
                (
                    "3l7devcorrupt",
                    "3l7dddd222225",
                    5i64,
                    b"not-a-valid-car-archive".to_vec(),
                ),
                ("3l7underflow", "3l7dddd222226", 6i64, underflow_car),
                ("3l7hugehdr", "3l7dddd222227", 7i64, oversized_hdr_car),
                ("3l7identmh", "3l7dddd222232", 8i64, identity_mh_car),
            ] {
                let op_path = format!("blue.catbird.chat.device/{rkey_suffix}");
                let adv_msg = build_subscribe_repos_commit_msg(
                    did,
                    rev_str,
                    seq_num,
                    root_cid,
                    bad_blocks,
                    vec![("create", &op_path, Some(dev2_cid))],
                );
                let err = consumer
                    .handle_event(adv_msg)
                    .await
                    .expect_err("corrupt/adversarial CAR must propagate verification error");
                consumer.handle_error(&err);
                assert!(err.downcast_ref::<CommitVerifyError>().is_some());
            }

            assert_eq!(consumer.verification_failures_count(), failures_before + 4);
            let metric_invalid_car_after = metrics::WITNESS_VERIFICATION_FAILURES
                .with_label_values(&["invalid_car"])
                .get();
            assert!(
                (metric_invalid_car_after - metric_invalid_car_before) >= 4.0,
                "WITNESS_VERIFICATION_FAILURES[invalid_car] must increment on every rejected CAR"
            );

            // Confirm unauthenticated commits did NOT poison `did`'s actor_head in Postgres.
            let mut tx = pool.begin().await.unwrap();
            let head = db::fetch_actor_head(&mut tx, did)
                .await
                .unwrap()
                .expect("actor head exists");
            assert_eq!(head.max_rev, "3l7dddd222224");
            assert_eq!(head.last_seq, 3);
            tx.commit().await.unwrap();
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
                    block: Some(encode_mailbox_cbor(alice, i64::MAX, 0xAA, None)),
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
                    block: Some(encode_mailbox_cbor(alice, 1_000_000_000_000, 0xBB, None)),
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
                        alice,
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

        // Duplicate CID block rejected
        let mut dup_car = good_car.clone();
        dup_car.push((cid_bytes.len() + block.len()) as u8);
        dup_car.extend_from_slice(&cid_bytes);
        dup_car.extend_from_slice(block);
        assert!(parse_bounded_car_v1_blocks(&dup_car).is_err());

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

    #[test]
    fn verifies_valid_p256_and_secp256k1_signed_commits_and_multikey_did_docs() {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};

        let did_p256 = "did:plc:p256commitverify00000001";
        let did_k256 = "did:plc:k256commitverify00000002";
        let mst_cid = verify::compute_dagcbor_cid(&verify::encode_mst_leaf_cbor(&BTreeMap::new()));
        let prev_cid = verify::compute_dagcbor_cid(b"\xa1dprev\xf5");

        // 1) P-256 (`0x1200` / `[0x80, 0x24]` / `zDna...`) Multikey + JWK + signed commit
        let p256_sk = p256::ecdsa::SigningKey::from_bytes((&[0x21u8; 32]).into()).unwrap();
        let p256_vk = AtprotoVerifyingKey::P256(*p256_sk.verifying_key());
        let p256_multikey = p256_vk.to_multikey();
        assert!(
            p256_multikey.starts_with("zDna"),
            "P-256 Multikey must use 0x1200 base58btc prefix zDna..., got {p256_multikey}"
        );
        assert_eq!(
            AtprotoVerifyingKey::from_multikey(&p256_multikey).unwrap(),
            p256_vk
        );

        let p256_did_doc = serde_json::json!({
            "id": did_p256,
            "verificationMethod": [{
                "id": format!("{did_p256}#atproto"),
                "type": "Multikey",
                "controller": did_p256,
                "publicKeyMultibase": p256_multikey,
            }]
        });
        let resolved_p256 = AtprotoVerifyingKey::parse_did_document_atproto_key(
            did_p256,
            &serde_json::to_vec(&p256_did_doc).unwrap(),
        )
        .unwrap();
        assert_eq!(resolved_p256, p256_vk);

        let unsigned_p256 =
            verify::encode_unsigned_v3_commit_cbor(did_p256, "3l7p256000001", mst_cid, None);
        let sig_p256 = verify::sign_p256_low_s(&p256_sk, &unsigned_p256);
        let signed_p256 = verify::encode_signed_v3_commit_cbor(
            did_p256,
            "3l7p256000001",
            mst_cid,
            None,
            sig_p256,
        );
        let out_p256 = verify_atproto_v3_commit_signature(
            &signed_p256,
            did_p256,
            "3l7p256000001",
            &resolved_p256,
        )
        .expect("valid P-256 commit signature must verify");
        assert_eq!(out_p256, mst_cid);

        // 2) secp256k1 (`0xe7` / `[0xe7, 0x01]` / `zQ3s...`) Multikey + JWK + signed commit (with prev link)
        let k256_sk = k256::ecdsa::SigningKey::from_bytes((&[0x31u8; 32]).into()).unwrap();
        let k256_vk = AtprotoVerifyingKey::Secp256k1(*k256_sk.verifying_key());
        let k256_multikey = k256_vk.to_multikey();
        assert!(
            k256_multikey.starts_with("zQ3s"),
            "secp256k1 Multikey must use 0xe7 base58btc prefix zQ3s..., got {k256_multikey}"
        );
        assert_eq!(
            AtprotoVerifyingKey::from_multikey(&k256_multikey).unwrap(),
            k256_vk
        );

        let k256_uncompressed = k256_sk.verifying_key().to_encoded_point(false);
        let k256_jwk_doc = serde_json::json!({
            "id": did_k256,
            "verificationMethod": [{
                "id": "#atproto",
                "type": "JsonWebKey2020",
                "controller": did_k256,
                "publicKeyJwk": {
                    "kty": "EC",
                    "crv": "secp256k1",
                    "x": URL_SAFE_NO_PAD.encode(k256_uncompressed.x().unwrap()),
                    "y": URL_SAFE_NO_PAD.encode(k256_uncompressed.y().unwrap()),
                }
            }]
        });
        let resolved_k256 = AtprotoVerifyingKey::parse_did_document_atproto_key(
            did_k256,
            &serde_json::to_vec(&k256_jwk_doc).unwrap(),
        )
        .unwrap();
        assert_eq!(resolved_k256, k256_vk);

        let unsigned_k256 = verify::encode_unsigned_v3_commit_cbor(
            did_k256,
            "3l7k256000002",
            mst_cid,
            Some(prev_cid),
        );
        let sig_k256 = verify::sign_k256_low_s(&k256_sk, &unsigned_k256);
        let signed_k256 = verify::encode_signed_v3_commit_cbor(
            did_k256,
            "3l7k256000002",
            mst_cid,
            Some(prev_cid),
            sig_k256,
        );
        let out_k256 = verify_atproto_v3_commit_signature(
            &signed_k256,
            did_k256,
            "3l7k256000002",
            &resolved_k256,
        )
        .expect("valid secp256k1 commit signature must verify");
        assert_eq!(out_k256, mst_cid);
    }

    #[test]
    fn rejects_tampered_commit_bytes_wrong_atproto_key_and_spoofed_mst_ops() {
        let did = "did:plc:tampertest00000000000001";
        let rev = "3l7tamper0001";
        let p256_sk = p256::ecdsa::SigningKey::from_bytes((&[0x41u8; 32]).into()).unwrap();
        let wrong_p256_sk = p256::ecdsa::SigningKey::from_bytes((&[0x42u8; 32]).into()).unwrap();
        let wrong_k256_sk = k256::ecdsa::SigningKey::from_bytes((&[0x43u8; 32]).into()).unwrap();

        let dev_path = "blue.catbird.chat.device/3l7realdev";
        let dev_bytes = encode_device_cbor("ed25519", 0x12, 32);
        let dev_cid = verify::compute_dagcbor_cid(&dev_bytes);

        let mut mst_map = BTreeMap::new();
        mst_map.insert(dev_path.to_string(), dev_cid);
        let mst_bytes = verify::encode_mst_leaf_cbor(&mst_map);
        let mst_cid = verify::compute_dagcbor_cid(&mst_bytes);

        let unsigned = verify::encode_unsigned_v3_commit_cbor(did, rev, mst_cid, None);
        let sig = verify::sign_p256_low_s(&p256_sk, &unsigned);
        let valid_commit =
            verify::encode_signed_v3_commit_cbor(did, rev, mst_cid, None, sig.clone());
        let right_vk = AtprotoVerifyingKey::P256(*p256_sk.verifying_key());

        // 1) Tampered MST data root inside commit CBOR while reusing original signature
        let evil_mst_cid =
            verify::compute_dagcbor_cid(&verify::encode_mst_leaf_cbor(&BTreeMap::new()));
        let tampered_data_commit =
            verify::encode_signed_v3_commit_cbor(did, rev, evil_mst_cid, None, sig.clone());
        assert_eq!(
            verify_atproto_v3_commit_signature(&tampered_data_commit, did, rev, &right_vk),
            Err(CommitVerifyError::InvalidSignature)
        );

        // 2) Tampered rev in commit CBOR (matching frame rev, breaking signature over unsigned commit)
        let tampered_rev_commit =
            verify::encode_signed_v3_commit_cbor(did, "3l7tamper9999", mst_cid, None, sig);
        assert_eq!(
            verify_atproto_v3_commit_signature(
                &tampered_rev_commit,
                did,
                "3l7tamper9999",
                &right_vk
            ),
            Err(CommitVerifyError::InvalidSignature)
        );

        // 3) Commit rev / DID mismatch against outer firehose frame metadata
        assert!(matches!(
            verify_atproto_v3_commit_signature(&valid_commit, did, "3l7otherrev00", &right_vk),
            Err(CommitVerifyError::CommitMetadataMismatch(_))
        ));
        assert!(matches!(
            verify_atproto_v3_commit_signature(
                &valid_commit,
                "did:plc:otheractor00000000000009",
                rev,
                &right_vk
            ),
            Err(CommitVerifyError::CommitMetadataMismatch(_))
        ));

        // 4) Wrong #atproto key (same curve P-256, and cross-curve secp256k1)
        let wrong_p256_vk = AtprotoVerifyingKey::P256(*wrong_p256_sk.verifying_key());
        let wrong_k256_vk = AtprotoVerifyingKey::Secp256k1(*wrong_k256_sk.verifying_key());
        assert_eq!(
            verify_atproto_v3_commit_signature(&valid_commit, did, rev, &wrong_p256_vk),
            Err(CommitVerifyError::InvalidSignature)
        );
        assert_eq!(
            verify_atproto_v3_commit_signature(&valid_commit, did, rev, &wrong_k256_vk),
            Err(CommitVerifyError::InvalidSignature)
        );

        // 5) MST inclusion/exclusion checks reject spoofed paths and wrong CIDs
        let mut blocks = HashMap::new();
        blocks.insert(mst_cid, mst_bytes.as_slice());
        assert_eq!(
            verify_mst_key_lookup(&blocks, mst_cid, dev_path.as_bytes()).unwrap(),
            Some(dev_cid)
        );
        assert_eq!(
            verify_mst_key_lookup(
                &blocks,
                mst_cid,
                b"blue.catbird.chat.device/3l7spoofedabsent"
            )
            .unwrap(),
            None
        );
    }

    #[test]
    fn rejects_malformed_der_and_high_s_ecdsa_commit_signatures_for_both_curves() {
        const P256_ORDER_BE: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2,
            0xfc, 0x63, 0x25, 0x51,
        ];
        const K256_ORDER_BE: [u8; 32] = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x41,
        ];

        let did = "did:plc:malleabilitytest00000001";
        let rev = "3l7malleable1";
        let mst_cid = verify::compute_dagcbor_cid(&verify::encode_mst_leaf_cbor(&BTreeMap::new()));
        let unsigned = verify::encode_unsigned_v3_commit_cbor(did, rev, mst_cid, None);

        let p256_sk = p256::ecdsa::SigningKey::from_bytes((&[0x61u8; 32]).into()).unwrap();
        let p256_vk = AtprotoVerifyingKey::P256(*p256_sk.verifying_key());
        let p256_low = verify::sign_p256_low_s(&p256_sk, &unsigned);

        // Empty, 63-byte, 65-byte, and ASN.1 DER signatures must all fail as MalformedSignature.
        let p256_der = p256::ecdsa::Signature::from_slice(&p256_low)
            .unwrap()
            .to_der()
            .as_bytes()
            .to_vec();
        for bad_sig in [
            vec![],
            p256_low[..63].to_vec(),
            [p256_low.as_slice(), &[0x00]].concat(),
            p256_der,
            vec![0x00; 64],
        ] {
            let commit_bytes =
                verify::encode_signed_v3_commit_cbor(did, rev, mst_cid, None, bad_sig);
            assert!(
                matches!(
                    verify_atproto_v3_commit_signature(&commit_bytes, did, rev, &p256_vk),
                    Err(CommitVerifyError::MalformedSignature(_))
                ),
                "expected MalformedSignature"
            );
        }

        // Construct genuine malleable high-S P-256 signature (`r || (n - s)`) and prove HighSSignature rejection.
        let mut p256_high = [0u8; 64];
        p256_high[..32].copy_from_slice(&p256_low[..32]);
        let p256_s: [u8; 32] = p256_low[32..].try_into().unwrap();
        p256_high[32..].copy_from_slice(&sub_be_32(&P256_ORDER_BE, &p256_s));
        assert_eq!(
            &p256::ecdsa::Signature::from_slice(&p256_high)
                .unwrap()
                .normalize_s()
                .unwrap()
                .to_bytes()[..],
            p256_low.as_slice()
        );
        let p256_high_commit =
            verify::encode_signed_v3_commit_cbor(did, rev, mst_cid, None, p256_high.to_vec());
        assert_eq!(
            verify_atproto_v3_commit_signature(&p256_high_commit, did, rev, &p256_vk),
            Err(CommitVerifyError::HighSSignature)
        );

        // Construct genuine malleable high-S secp256k1 signature (`r || (n - s)`) and prove HighSSignature rejection.
        let k256_sk = k256::ecdsa::SigningKey::from_bytes((&[0x71u8; 32]).into()).unwrap();
        let k256_vk = AtprotoVerifyingKey::Secp256k1(*k256_sk.verifying_key());
        let k256_low = verify::sign_k256_low_s(&k256_sk, &unsigned);
        let mut k256_high = [0u8; 32 * 2];
        k256_high[..32].copy_from_slice(&k256_low[..32]);
        let k256_s: [u8; 32] = k256_low[32..].try_into().unwrap();
        k256_high[32..].copy_from_slice(&sub_be_32(&K256_ORDER_BE, &k256_s));
        assert_eq!(
            &k256::ecdsa::Signature::from_slice(&k256_high)
                .unwrap()
                .normalize_s()
                .unwrap()
                .to_bytes()[..],
            k256_low.as_slice()
        );
        let k256_high_commit =
            verify::encode_signed_v3_commit_cbor(did, rev, mst_cid, None, k256_high.to_vec());
        assert_eq!(
            verify_atproto_v3_commit_signature(&k256_high_commit, did, rev, &k256_vk),
            Err(CommitVerifyError::HighSSignature)
        );
    }

    #[tokio::test]
    async fn rejects_forged_mailbox_keys_signatures_and_off_curve_device_keys() {
        let mut store = InMemoryWitnessStore::default();
        let alice = "did:plc:alicesigcheck00000000001";

        // Seed valid epoch 0.
        let seed_out = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 1,
                rev: "3l7sig0000001".to_string(),
                commit_cid: "bafysig1".to_string(),
                ops: vec![ObservedRepoOp {
                    action: "create".to_string(),
                    path: "blue.catbird.labyrinth.mailboxKeys/000000000000".to_string(),
                    cid: Some("bafymk0".to_string()),
                    block: Some(encode_mailbox_cbor(alice, 0, 0x10, None)),
                }],
            },
        )
        .await
        .unwrap();
        assert!(seed_out.anomalies.is_empty());

        // 1) Forged 64-byte `selfSig` (canonical scalar = 1, wrong signature) must be rejected.
        let mut forged_self: MailboxKeys =
            serde_ipld_dagcbor::from_slice(&encode_mailbox_cbor(alice, 1, 0x11, Some(0x10)))
                .unwrap();
        let mut fake_sig = [0u8; 64];
        fake_sig[32] = 1;
        forged_self.current.self_sig = JqBytes::from(fake_sig.to_vec());
        let forged_self_bytes = serde_ipld_dagcbor::to_vec(&forged_self).unwrap();

        // 2) Forged `prevSig` signed by a rogue X25519 key while `previousEpochHead` matches epoch 0!
        let mut forged_prev: MailboxKeys =
            serde_ipld_dagcbor::from_slice(&encode_mailbox_cbor(alice, 1, 0x11, Some(0x10)))
                .unwrap();
        let rogue_prev_msg = [verify::LABYRINTH_PREV_SIG_PREFIX, &[0x11u8; 32]].concat();
        let rogue_prev_sig =
            verify::xeddsa_sign_deterministic(&[0x99u8; 32], &rogue_prev_msg, &[0x55; 64]);
        forged_prev.current.prev_sig = Some(JqBytes::from(rogue_prev_sig.to_vec()));
        let forged_prev_bytes = serde_ipld_dagcbor::to_vec(&forged_prev).unwrap();

        // 3) Forged `attestation.sig` signed for a different DID.
        let wrong_did_attest_bytes =
            encode_mailbox_cbor("did:plc:impersonated000000000009", 2, 0x12, Some(0x11));

        // 4) Off-curve 33-byte P-256 `chat.device` key (`0x00` invalid SEC1 tag).
        let dt: Datetime = "2026-11-13T12:00:00Z".parse().unwrap();
        let bad_dev: Device = Device {
            algorithm: "p256".into(),
            created_at: dt,
            mls_signature_public_key: JqBytes::from(vec![0x00; 33]),
            extra_data: None,
        };
        let bad_dev_bytes = serde_ipld_dagcbor::to_vec(&bad_dev).unwrap();

        let self_fail_before = metrics::WITNESS_VERIFICATION_FAILURES
            .with_label_values(&["invalid_mailbox_self_sig"])
            .get();
        let prev_fail_before = metrics::WITNESS_VERIFICATION_FAILURES
            .with_label_values(&["invalid_mailbox_prev_sig"])
            .get();
        let attest_fail_before = metrics::WITNESS_VERIFICATION_FAILURES
            .with_label_values(&["invalid_mailbox_attestation_sig"])
            .get();
        let dev_fail_before = metrics::WITNESS_VERIFICATION_FAILURES
            .with_label_values(&["invalid_chat_device_pubkey"])
            .get();

        let bad_out = evaluate_commit(
            &mut store,
            &ObservedCommit {
                actor_did: alice.to_string(),
                seq: 2,
                rev: "3l7sig0000002".to_string(),
                commit_cid: "bafysig2".to_string(),
                ops: vec![
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000001".to_string(),
                        cid: Some("bafymk1_badself".to_string()),
                        block: Some(forged_self_bytes),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000001".to_string(),
                        cid: Some("bafymk1_badprev".to_string()),
                        block: Some(forged_prev_bytes),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.labyrinth.mailboxKeys/000000000002".to_string(),
                        cid: Some("bafymk2_badattest".to_string()),
                        block: Some(wrong_did_attest_bytes),
                    },
                    ObservedRepoOp {
                        action: "create".to_string(),
                        path: "blue.catbird.chat.device/3l7badcurve".to_string(),
                        cid: Some("bafybaddev".to_string()),
                        block: Some(bad_dev_bytes),
                    },
                ],
            },
        )
        .await
        .unwrap();

        assert_eq!(bad_out.indexed_devices, 0);
        assert_eq!(bad_out.indexed_mailbox_records, 0);
        let kinds: Vec<WitnessAnomalyKind> = bad_out.anomalies.iter().map(|a| a.kind).collect();
        assert_eq!(
            kinds,
            vec![
                WitnessAnomalyKind::MalformedTransparencyRecord,
                WitnessAnomalyKind::MailboxBrokenHashChain,
                WitnessAnomalyKind::MalformedTransparencyRecord,
                WitnessAnomalyKind::MalformedTransparencyRecord,
            ]
        );
        assert!(
            metrics::WITNESS_VERIFICATION_FAILURES
                .with_label_values(&["invalid_mailbox_self_sig"])
                .get()
                > self_fail_before
        );
        assert!(
            metrics::WITNESS_VERIFICATION_FAILURES
                .with_label_values(&["invalid_mailbox_prev_sig"])
                .get()
                > prev_fail_before
        );
        assert!(
            metrics::WITNESS_VERIFICATION_FAILURES
                .with_label_values(&["invalid_mailbox_attestation_sig"])
                .get()
                > attest_fail_before
        );
        assert!(
            metrics::WITNESS_VERIFICATION_FAILURES
                .with_label_values(&["invalid_chat_device_pubkey"])
                .get()
                > dev_fail_before
        );
    }

    #[tokio::test]
    async fn propagates_verification_errors_and_retries_did_key_refresh_once() {
        let did = "did:plc:errorprop000000000000001";
        let rev = "3l7errprop222";
        let real_sk = k256::ecdsa::SigningKey::from_bytes((&[0x81u8; 32]).into()).unwrap();
        let stale_sk = k256::ecdsa::SigningKey::from_bytes((&[0x82u8; 32]).into()).unwrap();

        let resolver = Arc::new(StaticAtprotoKeyResolver::new());
        resolver.insert(
            did,
            AtprotoVerifyingKey::Secp256k1(*stale_sk.verifying_key()),
        );

        let lazy_pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://unused@127.0.0.1:1/unused")
            .expect("lazy pool");
        let consumer = WitnessConsumer::with_key_resolver(lazy_pool, resolver.clone());

        let dev_path = "blue.catbird.chat.device/3l7errdev1";
        let dev_bytes = encode_device_cbor("ed25519", 0x33, 32);
        let dev_cid = verify::compute_dagcbor_cid(&dev_bytes);
        let mut mst_map = BTreeMap::new();
        mst_map.insert(dev_path.to_string(), dev_cid);
        let mst_bytes = verify::encode_mst_leaf_cbor(&mst_map);
        let mst_cid = verify::compute_dagcbor_cid(&mst_bytes);
        let unsigned = verify::encode_unsigned_v3_commit_cbor(did, rev, mst_cid, None);
        let sig = verify::sign_k256_low_s(&real_sk, &unsigned);
        let signed = verify::encode_signed_v3_commit_cbor(did, rev, mst_cid, None, sig);
        let root_cid = verify::compute_dagcbor_cid(&signed);

        // 1) Wrong `#atproto` key triggers 1 initial lookup + 1 force-refresh retry, then propagates Err!
        let valid_car = verify::encode_car_v1(
            &[root_cid],
            &[
                (root_cid, signed.clone()),
                (mst_cid, mst_bytes.clone()),
                (dev_cid, dev_bytes.clone()),
            ],
        );
        let msg_wrong_key = build_subscribe_repos_commit_msg(
            did,
            rev,
            10,
            root_cid,
            valid_car.clone(),
            vec![("create", dev_path, Some(dev_cid))],
        );
        let err = consumer
            .handle_event(msg_wrong_key)
            .await
            .expect_err("wrong #atproto key must return Err");
        assert_eq!(
            err.downcast_ref::<CommitVerifyError>(),
            Some(&CommitVerifyError::InvalidSignature)
        );
        assert_eq!(resolver.lookup_count(), 2);
        assert_eq!(resolver.force_refresh_count(), 1);
        assert_eq!(consumer.verification_failures_count(), 1);

        // 2) Spoofed `commit.ops` claiming an extra un-committed device key fails MST proof and propagates Err!
        resolver.insert(
            did,
            AtprotoVerifyingKey::Secp256k1(*real_sk.verifying_key()),
        );
        let msg_spoofed_op = build_subscribe_repos_commit_msg(
            did,
            rev,
            11,
            root_cid,
            valid_car,
            vec![(
                "create",
                "blue.catbird.chat.device/3l7spoofed",
                Some(dev_cid),
            )],
        );
        let err_mst = consumer
            .handle_event(msg_spoofed_op)
            .await
            .expect_err("spoofed repo op must fail MST verification");
        assert!(matches!(
            err_mst.downcast_ref::<CommitVerifyError>(),
            Some(CommitVerifyError::MstProofFailed(_))
        ));
        assert_eq!(consumer.verification_failures_count(), 2);

        // 3) Empty CAR on transparency commit propagates EmptyCar Err!
        let msg_empty = build_subscribe_repos_commit_msg(
            did,
            rev,
            12,
            root_cid,
            vec![],
            vec![("delete", dev_path, None)],
        );
        let err_empty = consumer
            .handle_event(msg_empty)
            .await
            .expect_err("empty CAR must fail verification");
        assert_eq!(
            err_empty.downcast_ref::<CommitVerifyError>(),
            Some(&CommitVerifyError::EmptyCar)
        );
        assert_eq!(consumer.verification_failures_count(), 3);
    }
}
