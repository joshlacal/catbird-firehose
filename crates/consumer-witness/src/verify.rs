//! Cryptographic verification for firehose-witnessed ATProto v3 commits (`P-256` & `secp256k1`
//! `#atproto` DID keys, compact 64-byte low-S ECDSA, canonical DAG-CBOR, MST inclusion/exclusion)
//! and Labyrinth transparency record signatures (`MailboxKeys` XEdDSA + Ed25519 attestation).

use std::collections::{BTreeMap, HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    RwLock,
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use constant_time_eq::constant_time_eq;
#[cfg(test)]
use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::{edwards::EdwardsPoint, montgomery::MontgomeryPoint, scalar::Scalar};
use multibase::Base;
use petrel_core::{Cid, Value};
use reqwest::Client as HttpClient;
use serde::Deserialize;
use sha2::{Digest, Sha512};
use thiserror::Error;
use url::Url;

pub const DEFAULT_PLC_DIRECTORY_URL: &str = "https://plc.directory";
pub const DEFAULT_DID_KEY_CACHE_TTL_SECS: u64 = 3600;
const MAX_DID_DOCUMENT_BYTES: usize = 256 * 1024;
const MAX_COMMIT_BLOCK_BYTES: usize = 256 * 1024;
const DAGCBOR_MAX_DEPTH: usize = 32;
const MST_MAX_DEPTH: usize = 64;
const DAG_CBOR_CODEC: u64 = 0x71;
const SHA2_256_CODE: u64 = 0x12;
const SHA2_256_DIGEST_LEN: usize = 32;

/// Unsigned varint encoding of multicodec `0x1200` (`p256-pub`, `zDna...`).
pub const P256_MULTICODEC_PREFIX: [u8; 2] = [0x80, 0x24];
/// Unsigned varint encoding of multicodec `0xe7` (`secp256k1-pub`, `zQ3s...`).
pub const SECP256K1_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];

pub const LABYRINTH_SELF_SIG_PREFIX: &[u8] = b"minos.unstructured_signature.epoch_self:";
pub const LABYRINTH_PREV_SIG_PREFIX: &[u8] = b"minos.unstructured_signature.epoch_prev:";
pub const LABYRINTH_ATTEST_PREFIX: &str = "catbird.labyrinth.epoch_head_attest:";

/// `2^255 - 19`, little-endian, for X25519 reduced-field verification.
const P25519_LE: [u8; 32] = {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    p
};

/// `hash_1` prefix (`0xFE || 0xFF^31`) for XEdDSA deterministic signing in tests.
#[cfg(test)]
const XEDDSA_HASH1_PREFIX: [u8; 32] = {
    let mut b = [0xffu8; 32];
    b[0] = 0xfe;
    b
};

/// Structured verification errors with bounded Prometheus failure-reason labels.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CommitVerifyError {
    #[error("empty CAR archive on transparency commit")]
    EmptyCar,
    #[error("invalid CARv1 archive: {0}")]
    InvalidCar(String),
    #[error("invalid commit CID in firehose frame: {0}")]
    InvalidCommitCid(String),
    #[error("CARv1 header roots do not match frame commit CID: {0}")]
    CommitRootMismatch(String),
    #[error("missing root commit block in CARv1 archive: {0}")]
    MissingCommitBlock(String),
    #[error("malformed ATProto v3 commit DAG-CBOR: {0}")]
    MalformedCommitCbor(String),
    #[error("ATProto v3 commit metadata mismatch: {0}")]
    CommitMetadataMismatch(String),
    #[error("malformed ATProto commit signature: {0}")]
    MalformedSignature(String),
    #[error("non-canonical high-S ECDSA signature rejected per ATProto cryptography spec")]
    HighSSignature,
    #[error("ATProto commit ECDSA signature failed verification against DID #atproto key")]
    InvalidSignature,
    #[error("DID #atproto verification key resolution failed: {0}")]
    DidResolution(String),
    #[error("invalid repo op CID in firehose frame: {0}")]
    InvalidOpCid(String),
    #[error("MST inclusion/exclusion proof failed against signed commit root: {0}")]
    MstProofFailed(String),
    #[error("missing or oversized record block in CARv1 archive: {0}")]
    MissingOrOversizedRecordBlock(String),
}

impl CommitVerifyError {
    pub fn metric_reason(&self) -> &'static str {
        match self {
            Self::EmptyCar => "empty_car",
            Self::InvalidCar(_) => "invalid_car",
            Self::InvalidCommitCid(_) => "invalid_commit_cid",
            Self::CommitRootMismatch(_) => "commit_root_mismatch",
            Self::MissingCommitBlock(_) => "missing_commit_block",
            Self::MalformedCommitCbor(_) => "malformed_commit_cbor",
            Self::CommitMetadataMismatch(_) => "commit_metadata_mismatch",
            Self::MalformedSignature(_) => "malformed_signature",
            Self::HighSSignature => "high_s_signature",
            Self::InvalidSignature => "invalid_signature",
            Self::DidResolution(_) => "did_resolution_failed",
            Self::InvalidOpCid(_) => "invalid_op_cid",
            Self::MstProofFailed(_) => "mst_proof_failed",
            Self::MissingOrOversizedRecordBlock(_) => "missing_or_oversized_record_block",
        }
    }
}

/// Verified `#atproto` public key (`P-256` or `secp256k1`) for ATProto repository commit signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AtprotoVerifyingKey {
    P256(p256::ecdsa::VerifyingKey),
    Secp256k1(k256::ecdsa::VerifyingKey),
}

impl AtprotoVerifyingKey {
    pub fn curve_label(&self) -> &'static str {
        match self {
            Self::P256(_) => "p256",
            Self::Secp256k1(_) => "secp256k1",
        }
    }

    /// Parse an ATProto `Multikey` (`zDna...` for multicodec `0x1200` P-256 or `zQ3s...` for
    /// multicodec `0xe7` secp256k1) or `did:key:z...` string into a verified curve point.
    pub fn from_multikey(multibase_or_did_key: &str) -> Result<Self, String> {
        let mb = multibase_or_did_key
            .strip_prefix("did:key:")
            .unwrap_or(multibase_or_did_key);
        let (base, raw) = multibase::decode(mb)
            .map_err(|e| format!("invalid multibase encoding on #atproto key: {e}"))?;
        if base != Base::Base58Btc {
            return Err("ATProto Multikey must use base58btc ('z') multibase".to_string());
        }
        if raw.len() != 35 {
            return Err(format!(
                "ATProto compressed Multikey must be 35 bytes (2B multicodec + 33B SEC1), got {}",
                raw.len()
            ));
        }
        if raw[2] != 0x02 && raw[2] != 0x03 {
            return Err("ATProto Multikey must use compressed SEC1 point encoding".to_string());
        }
        if raw[..2] == P256_MULTICODEC_PREFIX {
            let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..])
                .map_err(|e| format!("invalid P-256 #atproto SEC1 point: {e}"))?;
            return Ok(Self::P256(vk));
        }
        if raw[..2] == SECP256K1_MULTICODEC_PREFIX {
            let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&raw[2..])
                .map_err(|e| format!("invalid secp256k1 #atproto SEC1 point: {e}"))?;
            return Ok(Self::Secp256k1(vk));
        }
        Err(format!(
            "unsupported #atproto multicodec prefix [0x{:02x}, 0x{:02x}]",
            raw[0], raw[1]
        ))
    }

    /// Encode as canonical base58btc ATProto `Multikey` (`zDna...` or `zQ3s...`).
    pub fn to_multikey(&self) -> String {
        let mut buf = Vec::with_capacity(35);
        match self {
            Self::P256(vk) => {
                buf.extend_from_slice(&P256_MULTICODEC_PREFIX);
                buf.extend_from_slice(vk.to_encoded_point(true).as_bytes());
            }
            Self::Secp256k1(vk) => {
                buf.extend_from_slice(&SECP256K1_MULTICODEC_PREFIX);
                buf.extend_from_slice(vk.to_encoded_point(true).as_bytes());
            }
        }
        multibase::encode(Base::Base58Btc, buf)
    }

    /// Extract and validate the `#atproto` verification key from a DID document JSON payload.
    pub fn parse_did_document_atproto_key(
        expected_did: &str,
        did_doc_bytes: &[u8],
    ) -> Result<Self, String> {
        if did_doc_bytes.len() > MAX_DID_DOCUMENT_BYTES {
            return Err("DID document exceeds 256 KiB limit".to_string());
        }
        let doc: WireDidDocument = serde_json::from_slice(did_doc_bytes)
            .map_err(|e| format!("invalid DID document JSON: {e}"))?;
        if doc.id != expected_did {
            return Err(format!(
                "DID document id '{}' does not match expected '{}'",
                doc.id, expected_did
            ));
        }

        for vm in &doc.verification_method {
            let is_atproto_frag = vm.id == "#atproto"
                || vm
                    .id
                    .strip_prefix(expected_did)
                    .is_some_and(|suffix| suffix == "#atproto");
            if !is_atproto_frag {
                continue;
            }
            if let Some(ctrl) = vm.controller.as_deref() {
                if ctrl != expected_did {
                    return Err(format!(
                        "#atproto verificationMethod controller '{}' does not match DID '{}'",
                        ctrl, expected_did
                    ));
                }
            }
            return parse_wire_verification_method(vm);
        }

        Err(format!(
            "DID document for '{expected_did}' has no #atproto verificationMethod"
        ))
    }

    /// Verify a compact 64-byte low-S ATProto ECDSA signature over canonical unsigned commit CBOR.
    pub fn verify_commit_sig(
        &self,
        unsigned_commit_cbor: &[u8],
        sig_bytes: &[u8],
    ) -> Result<(), CommitVerifyError> {
        if sig_bytes.len() != 64 {
            return Err(CommitVerifyError::MalformedSignature(format!(
                "ATProto ECDSA signature must be compact 64 bytes (r || s), got {}",
                sig_bytes.len()
            )));
        }

        match self {
            Self::P256(vk) => {
                use p256::ecdsa::signature::Verifier as _;
                let sig = p256::ecdsa::Signature::from_slice(sig_bytes).map_err(|e| {
                    CommitVerifyError::MalformedSignature(format!(
                        "invalid P-256 signature scalars: {e}"
                    ))
                })?;
                if sig.normalize_s().is_some() {
                    return Err(CommitVerifyError::HighSSignature);
                }
                vk.verify(unsigned_commit_cbor, &sig)
                    .map_err(|_| CommitVerifyError::InvalidSignature)
            }
            Self::Secp256k1(vk) => {
                use k256::ecdsa::signature::Verifier as _;
                let sig = k256::ecdsa::Signature::from_slice(sig_bytes).map_err(|e| {
                    CommitVerifyError::MalformedSignature(format!(
                        "invalid secp256k1 signature scalars: {e}"
                    ))
                })?;
                if sig.normalize_s().is_some() {
                    return Err(CommitVerifyError::HighSSignature);
                }
                vk.verify(unsigned_commit_cbor, &sig)
                    .map_err(|_| CommitVerifyError::InvalidSignature)
            }
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireDidDocument {
    id: String,
    #[serde(default)]
    verification_method: Vec<WireVerificationMethod>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WireVerificationMethod {
    id: String,
    #[serde(rename = "type")]
    method_type: String,
    #[serde(default)]
    controller: Option<String>,
    #[serde(default)]
    public_key_multibase: Option<String>,
    #[serde(default)]
    public_key_jwk: Option<WireEcJwk>,
}

#[derive(Debug, Deserialize)]
struct WireEcJwk {
    kty: String,
    crv: String,
    x: String,
    y: String,
}

fn parse_wire_verification_method(
    vm: &WireVerificationMethod,
) -> Result<AtprotoVerifyingKey, String> {
    if let Some(mb) = vm.public_key_multibase.as_deref() {
        match vm.method_type.as_str() {
            "Multikey" => return AtprotoVerifyingKey::from_multikey(mb),
            "EcdsaSecp256r1VerificationKey2019" => {
                if let Ok(k @ AtprotoVerifyingKey::P256(_)) = AtprotoVerifyingKey::from_multikey(mb)
                {
                    return Ok(k);
                }
                let (base, raw) = multibase::decode(mb)
                    .map_err(|e| format!("invalid legacy P-256 multibase key: {e}"))?;
                if base != Base::Base58Btc || (raw.len() != 33 && raw.len() != 65) {
                    return Err("invalid EcdsaSecp256r1VerificationKey2019 encoding".to_string());
                }
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|e| format!("invalid legacy P-256 SEC1 point: {e}"))?;
                return Ok(AtprotoVerifyingKey::P256(vk));
            }
            "EcdsaSecp256k1VerificationKey2019" => {
                if let Ok(k @ AtprotoVerifyingKey::Secp256k1(_)) =
                    AtprotoVerifyingKey::from_multikey(mb)
                {
                    return Ok(k);
                }
                let (base, raw) = multibase::decode(mb)
                    .map_err(|e| format!("invalid legacy secp256k1 multibase key: {e}"))?;
                if base != Base::Base58Btc || (raw.len() != 33 && raw.len() != 65) {
                    return Err("invalid EcdsaSecp256k1VerificationKey2019 encoding".to_string());
                }
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&raw)
                    .map_err(|e| format!("invalid legacy secp256k1 SEC1 point: {e}"))?;
                return Ok(AtprotoVerifyingKey::Secp256k1(vk));
            }
            other => {
                return Err(format!(
                    "unsupported #atproto verificationMethod type '{other}'"
                ));
            }
        }
    }

    if let Some(jwk) = &vm.public_key_jwk {
        if jwk.kty != "EC" {
            return Err(format!(
                "unsupported #atproto JWK kty '{}', expected 'EC'",
                jwk.kty
            ));
        }
        let x = URL_SAFE_NO_PAD
            .decode(&jwk.x)
            .map_err(|e| format!("invalid JWK x coordinate base64url: {e}"))?;
        let y = URL_SAFE_NO_PAD
            .decode(&jwk.y)
            .map_err(|e| format!("invalid JWK y coordinate base64url: {e}"))?;
        if x.len() != 32 || y.len() != 32 {
            return Err("EC JWK x and y coordinates must each be 32 bytes".to_string());
        }
        let mut sec1 = [0u8; 65];
        sec1[0] = 0x04;
        sec1[1..33].copy_from_slice(&x);
        sec1[33..65].copy_from_slice(&y);
        return match jwk.crv.as_str() {
            "P-256" => {
                let vk = p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map_err(|e| format!("invalid P-256 JWK point: {e}"))?;
                Ok(AtprotoVerifyingKey::P256(vk))
            }
            "secp256k1" => {
                let vk = k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                    .map_err(|e| format!("invalid secp256k1 JWK point: {e}"))?;
                Ok(AtprotoVerifyingKey::Secp256k1(vk))
            }
            other => Err(format!("unsupported #atproto JWK curve '{other}'")),
        };
    }

    Err("#atproto verificationMethod missing publicKeyMultibase and publicKeyJwk".to_string())
}

/// Resolver for actor DID `#atproto` commit verification keys.
#[async_trait]
pub trait AtprotoKeyResolver: Send + Sync {
    async fn resolve_atproto_key(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<AtprotoVerifyingKey, String>;
}

/// Deterministic in-memory `#atproto` key resolver for tests and offline verification.
#[derive(Default)]
pub struct StaticAtprotoKeyResolver {
    keys: RwLock<HashMap<String, AtprotoVerifyingKey>>,
    lookups: AtomicU64,
    force_refreshes: AtomicU64,
}

impl StaticAtprotoKeyResolver {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&self, did: impl Into<String>, key: AtprotoVerifyingKey) {
        self.keys
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(did.into(), key);
    }

    pub fn lookup_count(&self) -> u64 {
        self.lookups.load(Ordering::Relaxed)
    }

    pub fn force_refresh_count(&self) -> u64 {
        self.force_refreshes.load(Ordering::Relaxed)
    }
}

#[async_trait]
impl AtprotoKeyResolver for StaticAtprotoKeyResolver {
    async fn resolve_atproto_key(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<AtprotoVerifyingKey, String> {
        self.lookups.fetch_add(1, Ordering::Relaxed);
        if force_refresh {
            self.force_refreshes.fetch_add(1, Ordering::Relaxed);
        }
        let guard = self.keys.read().unwrap_or_else(|e| e.into_inner());
        guard
            .get(did)
            .cloned()
            .ok_or_else(|| format!("DID '{did}' not registered in StaticAtprotoKeyResolver"))
    }
}

/// Production HTTP resolver for `did:plc` and SSRF-guarded `did:web` `#atproto` keys.
pub struct HttpAtprotoKeyResolver {
    http_client: HttpClient,
    plc_directory_url: String,
    ttl: Duration,
    cache: RwLock<HashMap<String, (Instant, AtprotoVerifyingKey)>>,
}

impl HttpAtprotoKeyResolver {
    pub fn new() -> Self {
        let plc_directory_url = std::env::var("PLC_DIRECTORY_URL")
            .unwrap_or_else(|_| DEFAULT_PLC_DIRECTORY_URL.to_string())
            .trim_end_matches('/')
            .to_string();
        Self::with_plc_directory_url(
            plc_directory_url,
            Duration::from_secs(DEFAULT_DID_KEY_CACHE_TTL_SECS),
        )
    }

    pub fn with_plc_directory_url(plc_directory_url: impl Into<String>, ttl: Duration) -> Self {
        let http_client = HttpClient::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("build HttpAtprotoKeyResolver reqwest client");
        Self {
            http_client,
            plc_directory_url: plc_directory_url.into().trim_end_matches('/').to_string(),
            ttl,
            cache: RwLock::new(HashMap::new()),
        }
    }

    fn build_resolution_url(&self, did: &str) -> Result<Url, String> {
        if let Some(plc_id) = did.strip_prefix("did:plc:") {
            if plc_id.len() < 16
                || plc_id.len() > 64
                || !plc_id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
            {
                return Err(format!("invalid did:plc identifier '{did}'"));
            }
            return Url::parse(&format!("{}/{did}", self.plc_directory_url))
                .map_err(|e| format!("invalid PLC directory URL: {e}"));
        }
        if did.starts_with("did:web:") {
            return build_safe_did_web_url(did);
        }
        Err(format!("unsupported DID method for '{did}'"))
    }
}

impl Default for HttpAtprotoKeyResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl AtprotoKeyResolver for HttpAtprotoKeyResolver {
    async fn resolve_atproto_key(
        &self,
        did: &str,
        force_refresh: bool,
    ) -> Result<AtprotoVerifyingKey, String> {
        if !force_refresh {
            let guard = self.cache.read().unwrap_or_else(|e| e.into_inner());
            if let Some((expires_at, key)) = guard.get(did) {
                if Instant::now() < *expires_at {
                    return Ok(key.clone());
                }
            }
        }

        let url = self.build_resolution_url(did)?;
        let resp = self
            .http_client
            .get(url)
            .header(
                reqwest::header::ACCEPT,
                "application/did+ld+json, application/json",
            )
            .send()
            .await
            .map_err(|e| format!("HTTP request failed resolving {did}: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "DID resolution returned HTTP {} for {did}",
                resp.status()
            ));
        }
        if resp
            .content_length()
            .is_some_and(|len| len > MAX_DID_DOCUMENT_BYTES as u64)
        {
            return Err(format!("DID document exceeds 256 KiB for {did}"));
        }
        let body = resp
            .bytes()
            .await
            .map_err(|e| format!("failed reading DID document body for {did}: {e}"))?;
        let key = AtprotoVerifyingKey::parse_did_document_atproto_key(did, &body)?;
        self.cache
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(did.to_string(), (Instant::now() + self.ttl, key.clone()));
        Ok(key)
    }
}

fn build_safe_did_web_url(did: &str) -> Result<Url, String> {
    let authority = did
        .strip_prefix("did:web:")
        .ok_or_else(|| "invalid did:web prefix".to_string())?;
    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.contains('%')
        || authority.contains(':')
    {
        return Err("unsupported or unsafe did:web authority".to_string());
    }
    let url = Url::parse(&format!("https://{authority}/.well-known/did.json"))
        .map_err(|e| format!("invalid did:web authority: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "did:web missing host".to_string())?;
    let lower = host.to_ascii_lowercase();
    if lower == "localhost"
        || lower.ends_with(".local")
        || lower.ends_with(".localhost")
        || host.parse::<IpAddr>().is_ok()
        || url.port().is_some()
    {
        return Err("refusing local, IP, or explicit-port did:web host".to_string());
    }
    Ok(url)
}

pub(crate) fn is_valid_dag_cbor_sha256_cid_v1(cid: &Cid) -> bool {
    cid.codec() == DAG_CBOR_CODEC
        && cid.hash_code() == SHA2_256_CODE
        && cid.digest().len() == SHA2_256_DIGEST_LEN
}

fn read_cbor_uint(bytes: &[u8], pos: &mut usize, info: u8) -> Result<u64, String> {
    match info {
        0..=23 => Ok(u64::from(info)),
        24 => {
            let b = *bytes
                .get(*pos)
                .ok_or_else(|| "truncated CBOR uint8".to_string())?;
            *pos += 1;
            if b < 24 {
                return Err("non-canonical CBOR uint8".to_string());
            }
            Ok(u64::from(b))
        }
        25 => {
            let end = pos
                .checked_add(2)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| "truncated CBOR uint16".to_string())?;
            let v = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
            *pos = end;
            if v <= u16::from(u8::MAX) {
                return Err("non-canonical CBOR uint16".to_string());
            }
            Ok(u64::from(v))
        }
        26 => {
            let end = pos
                .checked_add(4)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| "truncated CBOR uint32".to_string())?;
            let v = u32::from_be_bytes([
                bytes[*pos],
                bytes[*pos + 1],
                bytes[*pos + 2],
                bytes[*pos + 3],
            ]);
            *pos = end;
            if v <= u32::from(u16::MAX) {
                return Err("non-canonical CBOR uint32".to_string());
            }
            Ok(u64::from(v))
        }
        27 => {
            let end = pos
                .checked_add(8)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| "truncated CBOR uint64".to_string())?;
            let v = u64::from_be_bytes([
                bytes[*pos],
                bytes[*pos + 1],
                bytes[*pos + 2],
                bytes[*pos + 3],
                bytes[*pos + 4],
                bytes[*pos + 5],
                bytes[*pos + 6],
                bytes[*pos + 7],
            ]);
            *pos = end;
            if v <= u64::from(u32::MAX) {
                return Err("non-canonical CBOR uint64".to_string());
            }
            Ok(v)
        }
        _ => Err("indefinite or reserved CBOR integer encoding".to_string()),
    }
}

fn verify_canonical_dagcbor_item(
    bytes: &[u8],
    pos: &mut usize,
    depth: usize,
) -> Result<(), String> {
    if depth > DAGCBOR_MAX_DEPTH {
        return Err("DAG-CBOR nesting depth exceeded".to_string());
    }
    let head = *bytes
        .get(*pos)
        .ok_or_else(|| "truncated DAG-CBOR item".to_string())?;
    *pos += 1;
    let major = head >> 5;
    let info = head & 0x1f;
    match major {
        0 | 1 => {
            read_cbor_uint(bytes, pos, info)?;
            Ok(())
        }
        2 => {
            let len = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR bytes length overflow".to_string())?;
            let end = pos
                .checked_add(len)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| "truncated CBOR bytes".to_string())?;
            *pos = end;
            Ok(())
        }
        3 => {
            let len = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR text length overflow".to_string())?;
            let end = pos
                .checked_add(len)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| "truncated CBOR text".to_string())?;
            std::str::from_utf8(&bytes[*pos..end])
                .map_err(|_| "invalid UTF-8 in CBOR text".to_string())?;
            *pos = end;
            Ok(())
        }
        4 => {
            let count = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR array length overflow".to_string())?;
            for _ in 0..count {
                verify_canonical_dagcbor_item(bytes, pos, depth + 1)?;
            }
            Ok(())
        }
        5 => {
            let count = usize::try_from(read_cbor_uint(bytes, pos, info)?)
                .map_err(|_| "CBOR map length overflow".to_string())?;
            let mut prev_key: Option<&[u8]> = None;
            for _ in 0..count {
                let key_head = *bytes
                    .get(*pos)
                    .ok_or_else(|| "truncated CBOR map key".to_string())?;
                if (key_head >> 5) != 3 {
                    return Err("DAG-CBOR map key must be a UTF-8 string".to_string());
                }
                *pos += 1;
                let key_len = usize::try_from(read_cbor_uint(bytes, pos, key_head & 0x1f)?)
                    .map_err(|_| "CBOR map key length overflow".to_string())?;
                let key_end = pos
                    .checked_add(key_len)
                    .filter(|&e| e <= bytes.len())
                    .ok_or_else(|| "truncated CBOR map key".to_string())?;
                let key_slice = &bytes[*pos..key_end];
                std::str::from_utf8(key_slice)
                    .map_err(|_| "invalid UTF-8 in CBOR map key".to_string())?;
                if let Some(prev) = prev_key {
                    if (prev.len(), prev) >= (key_slice.len(), key_slice) {
                        return Err("non-canonical or duplicate DAG-CBOR map key order".to_string());
                    }
                }
                prev_key = Some(key_slice);
                *pos = key_end;
                verify_canonical_dagcbor_item(bytes, pos, depth + 1)?;
            }
            Ok(())
        }
        6 => {
            let tag = read_cbor_uint(bytes, pos, info)?;
            if tag != 42 {
                return Err("unsupported CBOR tag in DAG-CBOR".to_string());
            }
            let payload_head = *bytes
                .get(*pos)
                .ok_or_else(|| "truncated CBOR CID tag".to_string())?;
            if (payload_head >> 5) != 2 {
                return Err("DAG-CBOR tag 42 payload must be byte string".to_string());
            }
            *pos += 1;
            let len = usize::try_from(read_cbor_uint(bytes, pos, payload_head & 0x1f)?)
                .map_err(|_| "CBOR CID tag length overflow".to_string())?;
            let end = pos
                .checked_add(len)
                .filter(|&e| e <= bytes.len())
                .ok_or_else(|| "truncated CBOR CID bytes".to_string())?;
            let cid_bytes = &bytes[*pos..end];
            if cid_bytes.first() != Some(&0x00) {
                return Err("DAG-CBOR tag 42 CID missing identity multibase prefix".to_string());
            }
            let parsed = Cid::from_bytes(&cid_bytes[1..])
                .map_err(|_| "invalid CID inside tag 42".to_string())?;
            if parsed.as_bytes() != &cid_bytes[1..] {
                return Err("non-canonical CID bytes inside tag 42".to_string());
            }
            *pos = end;
            Ok(())
        }
        7 => match info {
            20..=22 => Ok(()),
            _ => Err("floats and undefined are forbidden in ATProto DAG-CBOR".to_string()),
        },
        _ => Err("invalid CBOR major type".to_string()),
    }
}

/// Validate strict canonical ATProto DAG-CBOR encoding without floats, duplicate keys, or trailing bytes.
pub fn verify_canonical_dagcbor(bytes: &[u8]) -> Result<(), String> {
    if bytes.is_empty() {
        return Err("empty DAG-CBOR block".to_string());
    }
    let mut pos = 0usize;
    verify_canonical_dagcbor_item(bytes, &mut pos, 0)?;
    if pos != bytes.len() {
        return Err("trailing bytes after DAG-CBOR item".to_string());
    }
    Ok(())
}

/// Verify a signed ATProto v3 repository commit DAG-CBOR block against `verifying_key`,
/// returning the authenticated MST root CID (`data`).
pub fn verify_atproto_v3_commit_signature(
    commit_block: &[u8],
    expected_did: &str,
    expected_rev: &str,
    verifying_key: &AtprotoVerifyingKey,
) -> Result<Cid, CommitVerifyError> {
    if commit_block.len() > MAX_COMMIT_BLOCK_BYTES {
        return Err(CommitVerifyError::MalformedCommitCbor(
            "commit block exceeds 256 KiB".to_string(),
        ));
    }
    verify_canonical_dagcbor(commit_block).map_err(CommitVerifyError::MalformedCommitCbor)?;

    let decoded: Value = petrel_core::from_dag_cbor(commit_block)
        .map_err(|e| CommitVerifyError::MalformedCommitCbor(e.to_string()))?;
    let Value::Object(mut map) = decoded else {
        return Err(CommitVerifyError::MalformedCommitCbor(
            "commit root must be a DAG-CBOR map".to_string(),
        ));
    };

    if map.len() != 6 {
        return Err(CommitVerifyError::MalformedCommitCbor(format!(
            "ATProto v3 commit must contain exactly 6 fields (did, version, data, rev, prev, sig), got {}",
            map.len()
        )));
    }

    match map.get("version") {
        Some(Value::Integer(3)) => {}
        Some(other) => {
            return Err(CommitVerifyError::CommitMetadataMismatch(format!(
                "expected ATProto commit version 3, got {other:?}"
            )));
        }
        None => {
            return Err(CommitVerifyError::MalformedCommitCbor(
                "missing 'version' field in commit".to_string(),
            ));
        }
    }

    match map.get("did") {
        Some(Value::String(did)) if did == expected_did => {}
        Some(Value::String(did)) => {
            return Err(CommitVerifyError::CommitMetadataMismatch(format!(
                "commit DID '{did}' does not match firehose repo '{expected_did}'"
            )));
        }
        _ => {
            return Err(CommitVerifyError::MalformedCommitCbor(
                "missing or non-string 'did' field in commit".to_string(),
            ));
        }
    }

    match map.get("rev") {
        Some(Value::String(rev)) if !rev.is_empty() && rev.len() <= 64 && rev == expected_rev => {}
        Some(Value::String(rev)) => {
            return Err(CommitVerifyError::CommitMetadataMismatch(format!(
                "commit rev '{rev}' does not match firehose rev '{expected_rev}'"
            )));
        }
        _ => {
            return Err(CommitVerifyError::MalformedCommitCbor(
                "missing or non-string 'rev' field in commit".to_string(),
            ));
        }
    }

    let data_cid = match map.get("data") {
        Some(Value::Link(cid)) if is_valid_dag_cbor_sha256_cid_v1(cid) => cid.clone(),
        _ => {
            return Err(CommitVerifyError::MalformedCommitCbor(
                "missing or non-CIDv1(dag-cbor, sha2-256) 'data' link in commit".to_string(),
            ));
        }
    };

    match map.get("prev") {
        Some(Value::Null) => {}
        Some(Value::Link(prev_cid)) if is_valid_dag_cbor_sha256_cid_v1(prev_cid) => {}
        _ => {
            return Err(CommitVerifyError::MalformedCommitCbor(
                "ATProto v3 commit requires 'prev' as null or valid CIDv1 link".to_string(),
            ));
        }
    }

    let sig_bytes = match map.remove("sig") {
        Some(Value::Bytes(bytes)) => bytes,
        _ => {
            return Err(CommitVerifyError::MalformedCommitCbor(
                "missing or non-bytes 'sig' field in commit".to_string(),
            ));
        }
    };

    let unsigned_cbor = petrel_core::to_dag_cbor(&Value::Object(map)).map_err(|e| {
        CommitVerifyError::MalformedCommitCbor(format!("encode unsigned commit: {e}"))
    })?;
    debug_assert!(verify_canonical_dagcbor(&unsigned_cbor).is_ok());

    verifying_key.verify_commit_sig(&unsigned_cbor, &sig_bytes)?;
    Ok(data_cid)
}

#[derive(Debug)]
struct MstEntry {
    p: usize,
    k: Vec<u8>,
    v: Cid,
    t: Option<Cid>,
}

#[derive(Debug)]
struct MstNodeData {
    l: Option<Cid>,
    e: Vec<MstEntry>,
}

fn mst_field<'a>(map: &'a BTreeMap<String, Value>, name: &str) -> Result<&'a Value, String> {
    map.get(name)
        .ok_or_else(|| format!("missing field `{name}`"))
}

fn mst_optional_link(value: Option<&Value>, name: &str) -> Result<Option<Cid>, String> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Link(cid)) => Ok(Some(cid.clone())),
        Some(other) => Err(format!(
            "`{name}` must be a CID link or null, got {}",
            other.kind()
        )),
    }
}

/// Reads an MST node the way the previous serde decoding did: `l`/`e` and `p`/`k`/`v`/`t`
/// are required (`l` and `t` may be null or absent) and other keys are ignored.
fn parse_mst_node(bytes: &[u8]) -> Result<MstNodeData, String> {
    let value: Value = petrel_core::from_dag_cbor(bytes).map_err(|e| e.to_string())?;
    let Value::Object(node) = value else {
        return Err("MST node must be a map".to_string());
    };
    let l = mst_optional_link(node.get("l"), "l")?;
    let Value::Array(raw_entries) = mst_field(&node, "e")? else {
        return Err("`e` must be an array".to_string());
    };
    let mut e = Vec::with_capacity(raw_entries.len());
    for raw in raw_entries {
        let Value::Object(entry) = raw else {
            return Err("MST entry must be a map".to_string());
        };
        let p = match mst_field(entry, "p")? {
            Value::Integer(p) => {
                usize::try_from(*p).map_err(|_| "`p` must be a non-negative integer".to_string())?
            }
            _ => return Err("`p` must be an integer".to_string()),
        };
        let Value::Bytes(k) = mst_field(entry, "k")? else {
            return Err("`k` must be a byte string".to_string());
        };
        let Value::Link(v) = mst_field(entry, "v")? else {
            return Err("`v` must be a CID link".to_string());
        };
        let t = mst_optional_link(entry.get("t"), "t")?;
        e.push(MstEntry {
            p,
            k: k.clone(),
            v: v.clone(),
            t,
        });
    }
    Ok(MstNodeData { l, e })
}

/// ATProto MST layer of `key`: the number of leading zero 2-bit chunks of `SHA-256(key)`
/// (fanout 4). Every entry in a node shares one layer and a node's subtrees sit exactly one
/// layer below it.
pub fn mst_key_layer(key: &[u8]) -> u32 {
    let digest = sha2::Sha256::digest(key);
    let mut layer = 0;
    for byte in digest {
        if byte == 0 {
            layer += 4;
            continue;
        }
        layer += byte.leading_zeros() / 2;
        break;
    }
    layer
}

/// Walk a canonical ATProto MST rooted at `mst_root_cid` for `target_key`, returning
/// `Ok(Some(record_cid))` on verified inclusion or `Ok(None)` on verified exclusion.
///
/// Every node on the path must be canonical: entries sorted with minimal prefix compression,
/// all entries on one key layer ([`mst_key_layer`]), each subtree exactly one layer below its
/// parent, and a root that carries entries unless the tree is empty.
pub fn verify_mst_key_lookup(
    blocks: &HashMap<Cid, &[u8]>,
    mst_root_cid: Cid,
    target_key: &[u8],
) -> Result<Option<Cid>, String> {
    let mut visited = HashSet::new();
    walk_mst_node(
        blocks,
        mst_root_cid,
        target_key,
        MstWalkBounds {
            lower: None,
            upper: None,
            expected_layer: None,
        },
        &mut visited,
        0,
    )
}

/// Constraints a parent places on the subtree being walked.
#[derive(Clone, Copy)]
struct MstWalkBounds<'a> {
    lower: Option<&'a [u8]>,
    upper: Option<&'a [u8]>,
    /// `None` only at the root, whose layer is taken from its own entries.
    expected_layer: Option<u32>,
}

fn walk_mst_node(
    blocks: &HashMap<Cid, &[u8]>,
    node_cid: Cid,
    target_key: &[u8],
    bounds: MstWalkBounds<'_>,
    visited: &mut HashSet<Cid>,
    depth: usize,
) -> Result<Option<Cid>, String> {
    let MstWalkBounds {
        lower: lower_bound,
        upper: upper_bound,
        expected_layer,
    } = bounds;
    if depth > MST_MAX_DEPTH {
        return Err("MST proof exceeded maximum depth".to_string());
    }
    if !visited.insert(node_cid.clone()) {
        return Err("cycle detected in MST proof".to_string());
    }
    let node_bytes = blocks
        .get(&node_cid)
        .copied()
        .ok_or_else(|| format!("missing MST node block {node_cid} in CAR archive"))?;
    verify_canonical_dagcbor(node_bytes)?;
    let node = parse_mst_node(node_bytes).map_err(|e| format!("malformed MST node block: {e}"))?;

    let mut keys: Vec<Vec<u8>> = Vec::with_capacity(node.e.len());
    for (idx, entry) in node.e.iter().enumerate() {
        if entry.k.is_empty() {
            return Err("MST entry key suffix cannot be empty".to_string());
        }
        if !is_valid_dag_cbor_sha256_cid_v1(&entry.v) {
            return Err("MST entry value CID must be CIDv1(dag-cbor, sha2-256)".to_string());
        }
        if let Some(sub) = &entry.t {
            if !is_valid_dag_cbor_sha256_cid_v1(sub) {
                return Err("MST subtree CID must be CIDv1(dag-cbor, sha2-256)".to_string());
            }
        }
        let full_key = if idx == 0 {
            if entry.p != 0 {
                return Err("first MST entry must have zero prefix length".to_string());
            }
            entry.k.clone()
        } else {
            let prev = &keys[idx - 1];
            if entry.p > prev.len() {
                return Err("MST entry prefix length exceeds previous key".to_string());
            }
            if entry.p < prev.len() && prev[entry.p] == entry.k[0] {
                return Err("non-canonical MST entry prefix length".to_string());
            }
            let total = entry
                .p
                .checked_add(entry.k.len())
                .ok_or_else(|| "MST key length overflow".to_string())?;
            let mut full = Vec::with_capacity(total);
            full.extend_from_slice(&prev[..entry.p]);
            full.extend_from_slice(&entry.k);
            if prev.as_slice() >= full.as_slice() {
                return Err("MST entries are not in strict lexicographic order".to_string());
            }
            full
        };
        if std::str::from_utf8(&full_key).is_err() {
            return Err("MST entry key is not valid UTF-8".to_string());
        }
        if let Some(lo) = lower_bound {
            if full_key.as_slice() <= lo {
                return Err("MST entry key violates parent lower bound".to_string());
            }
        }
        if let Some(hi) = upper_bound {
            if full_key.as_slice() >= hi {
                return Err("MST entry key violates parent upper bound".to_string());
            }
        }
        keys.push(full_key);
    }

    if let Some(left) = &node.l {
        if !is_valid_dag_cbor_sha256_cid_v1(left) {
            return Err("MST left subtree CID must be CIDv1(dag-cbor, sha2-256)".to_string());
        }
    }

    // Key-layer canonicality: one layer per node, subtrees exactly one layer down.
    let node_layer = match keys.first() {
        Some(first) => {
            let layer = mst_key_layer(first);
            if keys.iter().any(|key| mst_key_layer(key) != layer) {
                return Err("MST node mixes keys from different layers".to_string());
            }
            if let Some(expected) = expected_layer {
                if layer != expected {
                    return Err(format!(
                        "MST node layer {layer} does not match expected subtree layer {expected}"
                    ));
                }
            }
            layer
        }
        None => match (expected_layer, &node.l) {
            // Empty repository.
            (None, None) => return Ok(None),
            (None, Some(_)) => {
                return Err("MST root without entries must be trimmed to its subtree".to_string())
            }
            (Some(_), None) => return Err("non-root MST node cannot be empty".to_string()),
            // Entry-less intermediate node on a skipped layer.
            (Some(layer), Some(_)) => layer,
        },
    };
    let has_subtree = node.l.is_some() || node.e.iter().any(|entry| entry.t.is_some());
    let child_layer = node_layer.checked_sub(1);
    if has_subtree && child_layer.is_none() {
        return Err("layer-0 MST node cannot have subtrees".to_string());
    }

    if keys.is_empty() {
        let left_cid = node
            .l
            .expect("entry-less intermediate node has a left subtree");
        return walk_mst_node(
            blocks,
            left_cid,
            target_key,
            MstWalkBounds {
                lower: lower_bound,
                upper: upper_bound,
                expected_layer: child_layer,
            },
            visited,
            depth + 1,
        );
    }

    match keys.binary_search_by(|candidate| candidate.as_slice().cmp(target_key)) {
        Ok(idx) => Ok(Some(node.e[idx].v.clone())),
        Err(0) => match node.l {
            Some(left_cid) => walk_mst_node(
                blocks,
                left_cid,
                target_key,
                MstWalkBounds {
                    lower: lower_bound,
                    upper: Some(keys[0].as_slice()),
                    expected_layer: child_layer,
                },
                visited,
                depth + 1,
            ),
            None => Ok(None),
        },
        Err(insert_pos) => {
            let idx = insert_pos - 1;
            let next_upper = keys.get(insert_pos).map(Vec::as_slice).or(upper_bound);
            match node.e[idx].t.clone() {
                Some(sub_cid) => walk_mst_node(
                    blocks,
                    sub_cid,
                    target_key,
                    MstWalkBounds {
                        lower: Some(keys[idx].as_slice()),
                        upper: next_upper,
                        expected_layer: child_layer,
                    },
                    visited,
                    depth + 1,
                ),
                None => Ok(None),
            }
        }
    }
}

/// Validate a `blue.catbird.chat.device` public key on curve (`ed25519` or `p256`).
pub fn verify_chat_device_pubkey(alg: &str, pubkey: &[u8]) -> Result<(), String> {
    match alg {
        "ed25519" => {
            let bytes: &[u8; 32] = pubkey.try_into().map_err(|_| {
                format!(
                    "invalid ed25519 signature public key length {}",
                    pubkey.len()
                )
            })?;
            let vk = ed25519_dalek::VerifyingKey::from_bytes(bytes)
                .map_err(|e| format!("invalid ed25519 device public key: {e}"))?;
            if vk.is_weak() {
                return Err("weak small-order ed25519 device public key".to_string());
            }
            Ok(())
        }
        "p256" => {
            if pubkey.len() != 33 && !(pubkey.len() == 65 && pubkey[0] == 0x04) {
                return Err(format!(
                    "invalid p256 signature public key length {}",
                    pubkey.len()
                ));
            }
            p256::ecdsa::VerifyingKey::from_sec1_bytes(pubkey)
                .map_err(|e| format!("invalid p256 device public key point: {e}"))?;
            Ok(())
        }
        other => Err(format!(
            "unsupported blue.catbird.chat.device algorithm '{other}'"
        )),
    }
}

fn is_reduced_p25519(u: &[u8; 32]) -> bool {
    for i in (0..32).rev() {
        if u[i] != P25519_LE[i] {
            return u[i] < P25519_LE[i];
        }
    }
    false
}

fn xeddsa_challenge(r: &[u8; 32], a: &[u8; 32], msg: &[u8]) -> Scalar {
    let mut h = Sha512::new();
    h.update(r);
    h.update(a);
    h.update(msg);
    let wide: [u8; 64] = h.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Verify canonical XEdDSA scalar encoding (`len == 64` and `s < q`).
pub fn check_xeddsa_sig_canonical(sig_bytes: &[u8], field_name: &str) -> Result<[u8; 64], String> {
    let sig: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| format!("{field_name} must be 64 bytes, got {}", sig_bytes.len()))?;
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32-byte s half");
    if s_bytes[31] & 0xe0 != 0
        || Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes)).is_none()
    {
        return Err(format!("{field_name} has non-canonical XEdDSA scalar s"));
    }
    Ok(sig)
}

/// Verify a Labyrinth XEdDSA signature (`selfSig` / `prevSig`) under a 32-byte X25519 Montgomery key.
pub fn verify_labyrinth_xeddsa(
    pubkey_bytes: &[u8],
    msg: &[u8],
    sig_bytes: &[u8],
    field_name: &str,
) -> Result<(), String> {
    let u: &[u8; 32] = pubkey_bytes
        .try_into()
        .map_err(|_| format!("{field_name} verifying key must be 32 bytes"))?;
    if !is_reduced_p25519(u) {
        return Err(format!("{field_name} verifying key u >= p"));
    }
    let sig = check_xeddsa_sig_canonical(sig_bytes, field_name)?;
    let r_bytes: &[u8; 32] = sig[..32].try_into().expect("32-byte R half");
    let s_bytes: [u8; 32] = sig[32..].try_into().expect("32-byte s half");
    let s = Option::<Scalar>::from(Scalar::from_canonical_bytes(s_bytes))
        .ok_or_else(|| format!("{field_name} non-canonical scalar"))?;

    let a_point = MontgomeryPoint(*u)
        .to_edwards(0)
        .ok_or_else(|| format!("{field_name} verifying key not on curve"))?;
    if a_point.is_small_order() {
        return Err(format!("{field_name} small-order verifying key"));
    }
    let a_bytes = a_point.compress().to_bytes();
    let h = xeddsa_challenge(r_bytes, &a_bytes, msg);
    let r_check = EdwardsPoint::vartime_double_scalar_mul_basepoint(&(-h), &a_point, &s);
    if constant_time_eq(r_check.compress().as_bytes(), r_bytes) {
        Ok(())
    } else {
        Err(format!(
            "{field_name} cryptographic XEdDSA verification failed"
        ))
    }
}

/// Verify a Labyrinth `[CB-18]` Ed25519 `TransportAttestation` signature strictly (RFC 8032).
pub fn verify_labyrinth_ed25519_attestation(
    actor_did: &str,
    epoch_head: &[u8],
    transport_pubkey: &[u8],
    sig_bytes: &[u8],
) -> Result<(), String> {
    let pk_arr: &[u8; 32] = transport_pubkey.try_into().map_err(|_| {
        format!(
            "attestation.transportPubkey must be 32 bytes, got {}",
            transport_pubkey.len()
        )
    })?;
    let sig_arr: &[u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| format!("attestation.sig must be 64 bytes, got {}", sig_bytes.len()))?;
    let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_arr)
        .map_err(|e| format!("invalid attestation Ed25519 public key: {e}"))?;
    if vk.is_weak() {
        return Err("weak small-order attestation Ed25519 public key".to_string());
    }
    let sig = ed25519_dalek::Signature::from_bytes(sig_arr);
    let mut msg = format!("{LABYRINTH_ATTEST_PREFIX}{actor_did}:").into_bytes();
    msg.extend_from_slice(epoch_head);
    vk.verify_strict(&msg, &sig)
        .map_err(|e| format!("attestation Ed25519 signature verification failed: {e}"))
}

#[cfg(test)]
pub(crate) fn xeddsa_public_from_secret(secret: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*secret).to_bytes()
}

#[cfg(test)]
pub(crate) fn xeddsa_sign_deterministic(
    secret: &[u8; 32],
    msg: &[u8],
    nonce_z: &[u8; 64],
) -> [u8; 64] {
    let clamped = clamp_integer(*secret);
    let mut a = Scalar::from_bytes_mod_order(clamped);
    let e = EdwardsPoint::mul_base(&a);
    let sign = e.compress().as_bytes()[31] >> 7;
    let a_point = if sign == 1 {
        a = -a;
        -e
    } else {
        e
    };
    let a_bytes = a_point.compress().to_bytes();

    let mut h1 = Sha512::new();
    h1.update(XEDDSA_HASH1_PREFIX);
    h1.update(a.as_bytes());
    h1.update(msg);
    h1.update(nonce_z);
    let wide: [u8; 64] = h1.finalize().into();
    let r = Scalar::from_bytes_mod_order_wide(&wide);

    let r_bytes = EdwardsPoint::mul_base(&r).compress().to_bytes();
    let h = xeddsa_challenge(&r_bytes, &a_bytes, msg);
    let s = r + h * a;

    let mut sig = [0u8; 64];
    sig[..32].copy_from_slice(&r_bytes);
    sig[32..].copy_from_slice(s.as_bytes());
    sig
}

/// Test/fixture builder for canonical signed ATProto v3 commits + single-leaf MST CARv1 archives.
#[cfg(test)]
pub(crate) fn encode_unsigned_v3_commit_cbor(
    did: &str,
    rev: &str,
    data_cid: Cid,
    prev_cid: Option<Cid>,
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert("did".to_string(), Value::String(did.to_string()));
    map.insert("version".to_string(), Value::Integer(3));
    map.insert("data".to_string(), Value::Link(data_cid));
    map.insert("rev".to_string(), Value::String(rev.to_string()));
    map.insert(
        "prev".to_string(),
        prev_cid.map_or(Value::Null, Value::Link),
    );
    petrel_core::to_dag_cbor(&Value::Object(map)).expect("encode unsigned v3 commit")
}

#[cfg(test)]
pub(crate) fn encode_signed_v3_commit_cbor(
    did: &str,
    rev: &str,
    data_cid: Cid,
    prev_cid: Option<Cid>,
    sig_bytes: Vec<u8>,
) -> Vec<u8> {
    let mut map = BTreeMap::new();
    map.insert("did".to_string(), Value::String(did.to_string()));
    map.insert("version".to_string(), Value::Integer(3));
    map.insert("data".to_string(), Value::Link(data_cid));
    map.insert("rev".to_string(), Value::String(rev.to_string()));
    map.insert(
        "prev".to_string(),
        prev_cid.map_or(Value::Null, Value::Link),
    );
    map.insert("sig".to_string(), Value::Bytes(sig_bytes));
    petrel_core::to_dag_cbor(&Value::Object(map)).expect("encode signed v3 commit")
}

#[cfg(test)]
pub(crate) fn compute_dagcbor_cid(block: &[u8]) -> Cid {
    Cid::for_dag_cbor(block)
}

#[cfg(test)]
pub(crate) fn sign_p256_low_s(sk: &p256::ecdsa::SigningKey, msg: &[u8]) -> Vec<u8> {
    use p256::ecdsa::signature::Signer as _;
    let sig: p256::ecdsa::Signature = sk.sign(msg);
    sig.normalize_s().unwrap_or(sig).to_bytes().to_vec()
}

#[cfg(test)]
pub(crate) fn sign_k256_low_s(sk: &k256::ecdsa::SigningKey, msg: &[u8]) -> Vec<u8> {
    use k256::ecdsa::signature::Signer as _;
    let sig: k256::ecdsa::Signature = sk.sign(msg);
    sig.normalize_s().unwrap_or(sig).to_bytes().to_vec()
}

/// One flat MST node holding every record (canonical only for zero or one record, or for
/// records that all share one layer).
#[cfg(test)]
pub(crate) fn encode_mst_leaf_cbor(sorted_records: &BTreeMap<String, Cid>) -> Vec<u8> {
    let entries: Vec<(&[u8], Cid, Option<Cid>)> = sorted_records
        .iter()
        .map(|(path, cid)| (path.as_bytes(), cid.clone(), None))
        .collect();
    encode_mst_node_cbor(None, &entries)
}

/// Canonical ATProto MST over `records`: returns the root CID and every node block. Builds
/// the same shape as the reference implementation, including entry-less intermediate nodes
/// when a layer is skipped.
#[cfg(test)]
pub(crate) fn encode_canonical_mst(records: &BTreeMap<String, Cid>) -> (Cid, Vec<(Cid, Vec<u8>)>) {
    let items: Vec<(&[u8], Cid)> = records
        .iter()
        .map(|(path, cid)| (path.as_bytes(), cid.clone()))
        .collect();
    let root_layer = items
        .iter()
        .map(|(key, _)| mst_key_layer(key))
        .max()
        .unwrap_or(0);
    let mut blocks = Vec::new();
    let root = build_canonical_mst_node(&items, root_layer, &mut blocks);
    (root, blocks)
}

#[cfg(test)]
fn build_canonical_mst_node(
    items: &[(&[u8], Cid)],
    layer: u32,
    blocks: &mut Vec<(Cid, Vec<u8>)>,
) -> Cid {
    let mut left = None;
    let mut entries: Vec<(&[u8], Cid, Option<Cid>)> = Vec::new();
    let mut group: Vec<(&[u8], Cid)> = Vec::new();
    for (key, cid) in items.iter().cloned() {
        if mst_key_layer(key) == layer {
            attach_canonical_subtree(&mut group, layer, &mut left, &mut entries, blocks);
            entries.push((key, cid, None));
        } else {
            group.push((key, cid));
        }
    }
    attach_canonical_subtree(&mut group, layer, &mut left, &mut entries, blocks);
    let bytes = encode_mst_node_cbor(left, &entries);
    let cid = compute_dagcbor_cid(&bytes);
    blocks.push((cid.clone(), bytes));
    cid
}

/// Build `group` (keys strictly between two entries of a layer-`layer` node) as the subtree
/// left of the next entry, or as the node's `l` pointer when no entry precedes it.
#[cfg(test)]
fn attach_canonical_subtree<'k>(
    group: &mut Vec<(&'k [u8], Cid)>,
    layer: u32,
    left: &mut Option<Cid>,
    entries: &mut [(&'k [u8], Cid, Option<Cid>)],
    blocks: &mut Vec<(Cid, Vec<u8>)>,
) {
    if group.is_empty() {
        return;
    }
    let child_layer = layer.checked_sub(1).expect("MST keys below layer 0");
    let child = build_canonical_mst_node(group, child_layer, blocks);
    match entries.last_mut() {
        Some(last) => last.2 = Some(child),
        None => *left = Some(child),
    }
    group.clear();
}

/// Encode one MST node (`l` + prefix-compressed `e`) as DAG-CBOR.
#[cfg(test)]
pub(crate) fn encode_mst_node_cbor(
    left: Option<Cid>,
    sorted: &[(&[u8], Cid, Option<Cid>)],
) -> Vec<u8> {
    let mut entries = Vec::with_capacity(sorted.len());
    let mut prev_key: Option<&[u8]> = None;
    for (key_bytes, cid, subtree) in sorted.iter().cloned() {
        let prefix_len = match prev_key {
            None => 0usize,
            Some(prev) => prev
                .iter()
                .zip(key_bytes.iter())
                .take_while(|(a, b)| a == b)
                .count(),
        };
        let suffix = key_bytes[prefix_len..].to_vec();
        let mut entry_map = BTreeMap::new();
        entry_map.insert("p".to_string(), Value::Integer(prefix_len as i64));
        entry_map.insert("k".to_string(), Value::Bytes(suffix));
        entry_map.insert("v".to_string(), Value::Link(cid));
        entry_map.insert("t".to_string(), subtree.map_or(Value::Null, Value::Link));
        entries.push(Value::Object(entry_map));
        prev_key = Some(key_bytes);
    }
    let mut node_map = BTreeMap::new();
    node_map.insert("l".to_string(), left.map_or(Value::Null, Value::Link));
    node_map.insert("e".to_string(), Value::Array(entries));
    petrel_core::to_dag_cbor(&Value::Object(node_map)).expect("encode MST leaf")
}

#[cfg(test)]
fn push_uvarint_usize(out: &mut Vec<u8>, mut val: usize) {
    while val >= 0x80 {
        out.push(((val as u8) & 0x7f) | 0x80);
        val >>= 7;
    }
    out.push(val as u8);
}

#[cfg(test)]
pub(crate) fn encode_car_v1(roots: &[Cid], sections: &[(Cid, Vec<u8>)]) -> Vec<u8> {
    let mut hdr_map = BTreeMap::new();
    hdr_map.insert("version".to_string(), Value::Integer(1));
    hdr_map.insert(
        "roots".to_string(),
        Value::Array(roots.iter().cloned().map(Value::Link).collect()),
    );
    let hdr_bytes = petrel_core::to_dag_cbor(&Value::Object(hdr_map)).expect("encode CARv1 header");
    let mut out = Vec::new();
    push_uvarint_usize(&mut out, hdr_bytes.len());
    out.extend_from_slice(&hdr_bytes);
    for (cid, block) in sections {
        let cid_bytes = cid.as_bytes();
        push_uvarint_usize(&mut out, cid_bytes.len() + block.len());
        out.extend_from_slice(cid_bytes);
        out.extend_from_slice(block);
    }
    out
}
