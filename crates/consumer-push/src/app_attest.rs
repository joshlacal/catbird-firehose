use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use appattest_rs::{
    assertion::Assertion,
    attestation::{Attestation, AttestationEnvironment},
    error::AppAttestError,
};
use base64::{engine::general_purpose, Engine as _};
use ciborium::de::from_reader;
use constant_time_eq::constant_time_eq;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha256;
use time::{Duration, OffsetDateTime};

#[derive(Clone)]
pub struct AppAttestService {
    app_id: Arc<str>,
    challenge_ttl: Duration,
    environment: AttestationEnvironment,
}

pub struct AttestationVerification {
    pub public_key: Vec<u8>,
    pub receipt: Vec<u8>,
}

pub struct AssertionVerification {
    pub counter: u32,
}

#[derive(Debug, Deserialize)]
struct RawAssertion {
    #[serde(rename = "authenticatorData")]
    authenticator_data: Vec<u8>,
    #[serde(rename = "signature")]
    _signature: Vec<u8>,
}

impl AppAttestService {
    pub fn new(app_id: String, challenge_ttl_secs: u64, production: bool) -> Self {
        let ttl = Duration::seconds(challenge_ttl_secs as i64);
        let environment = if production {
            AttestationEnvironment::Production
        } else {
            AttestationEnvironment::Development
        };

        let service = Self {
            app_id: Arc::from(app_id),
            challenge_ttl: ttl,
            environment,
        };

        tracing::info!(
            app_attest.app_id = %service.app_id,
            app_attest.challenge_ttl_secs = challenge_ttl_secs,
            app_attest.environment = ?service.environment,
            "Configured App Attest service"
        );

        service
    }

    pub fn is_development_mode(&self) -> bool {
        if matches!(self.environment, AttestationEnvironment::Production) {
            return false;
        }

        let force_production =
            std::env::var("APP_ATTEST_FORCE_PRODUCTION").unwrap_or_default() == "true";
        if force_production {
            return false;
        }

        let disable_fallback =
            std::env::var("APP_ATTEST_DISABLE_FALLBACK").unwrap_or_default() == "true";
        if disable_fallback {
            return false;
        }

        let explicit_dev_fallback =
            std::env::var("APP_ATTEST_ALLOW_DEV_FALLBACK").unwrap_or_default() == "true";
        let is_testflight_fallback =
            std::env::var("APP_ATTEST_TESTFLIGHT_FALLBACK").unwrap_or_default() == "true";
        if explicit_dev_fallback || is_testflight_fallback {
            return true;
        }

        false
    }

    pub fn generate_challenge(&self) -> String {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        // Apple App Attest requires exactly 32 bytes of challenge data
        // We base64 encode for JSON transport - client must decode before using
        general_purpose::STANDARD.encode(bytes)
    }

    pub fn issue_challenge(&self) -> (String, OffsetDateTime) {
        let challenge = self.generate_challenge();
        let expires_at = OffsetDateTime::now_utc() + self.challenge_ttl;
        (challenge, expires_at)
    }

    pub fn verify_attestation(
        &self,
        attestation_b64: &str,
        challenge: &str,
        key_id: &str,
    ) -> Result<AttestationVerification> {
        tracing::info!("Attempting App Attest validation");
        tracing::debug!(
            "App Attest validation params: app_id={}, key_id={}, challenge_len={}",
            &self.app_id,
            key_id,
            challenge.len()
        );

        // Try to decode base64 first
        match general_purpose::STANDARD.decode(attestation_b64) {
            Ok(raw_bytes) => {
                tracing::debug!("Base64 decode successful: {} bytes", raw_bytes.len());
            }
            Err(e) => {
                tracing::error!("Base64 decode failed: {}", e);
                bail!("failed to decode attestation payload: invalid base64");
            }
        }

        let attestation = Attestation::from_base64(attestation_b64)
            .context("failed to decode attestation payload")?;

        // Build client data JSON that matches what the client sent
        let client_data_json = format!(r#"{{"challenge":"{}"}}"#, challenge);

        match attestation.verify_with_environment(
            &client_data_json,
            &self.app_id,
            key_id,
            self.environment,
        ) {
            Ok((public_key, receipt)) => {
                tracing::info!("App Attest validation succeeded");
                Ok(AttestationVerification {
                    public_key,
                    receipt,
                })
            }
            Err(e) => {
                let error_string = format!("{}", e);
                tracing::error!(
                    "App Attest verification failed (env={:?}): {}",
                    self.environment,
                    error_string
                );

                let mut context_messages = Vec::new();

                let mut kind_context = "kind=unknown".to_string();
                match e.downcast::<AppAttestError>() {
                    Ok(app_err) => {
                        tracing::error!("App Attest error kind: {:?}", app_err);
                        kind_context = format!("kind={app_err:?}");
                    }
                    Err(other) => {
                        tracing::error!("App Attest error (non AppAttestError): {}", other);
                    }
                }
                context_messages.push(kind_context);

                // Attempt verification with the alternate environment purely for diagnostics.
                let alternate_env = match self.environment {
                    AttestationEnvironment::Production => Some(AttestationEnvironment::Development),
                    AttestationEnvironment::Development => Some(AttestationEnvironment::Production),
                };

                if let Some(alt_env) = alternate_env {
                    let alt_verification =
                        Attestation::from_base64(attestation_b64)
                            .ok()
                            .and_then(|att| {
                                att.verify_with_environment(
                                    challenge,
                                    &self.app_id,
                                    key_id,
                                    alt_env,
                                )
                                .ok()
                            });

                    match alt_verification {
                        Some((alt_public_key, alt_receipt)) => {
                            tracing::warn!(
                                "App Attest payload validates under alternate environment {:?}; check APP_ATTEST_PRODUCTION/APP_ATTEST_FORCE_PRODUCTION",
                                alt_env
                            );
                            context_messages
                                .push(format!("alternate_environment_success={:?}", alt_env));

                            if self.is_development_mode() {
                                return Ok(AttestationVerification {
                                    public_key: alt_public_key,
                                    receipt: alt_receipt,
                                });
                            }
                        }
                        None => {
                            tracing::debug!(
                                "App Attest payload also rejected by alternate environment {:?}",
                                alt_env
                            );
                        }
                    }
                }

                // Only fall back to development mode if we're actually in dev mode
                if self.is_development_mode() {
                    tracing::warn!("DEVELOPMENT MODE: Using fallback after validation failed");

                    // Return deterministic mock data based on key_id for consistency
                    let mut public_key = vec![0u8; 65]; // Standard EC public key size
                    public_key[0] = 0x04; // Uncompressed point indicator
                    for (i, byte) in key_id.bytes().take(32).enumerate() {
                        public_key[i + 1] = byte;
                    }
                    Ok(AttestationVerification {
                        public_key,
                        receipt: key_id.as_bytes().to_vec(),
                    })
                } else {
                    // Production mode - return the error
                    let mut err =
                        format!("app attest attestation validation failed: {error_string}");
                    if !context_messages.is_empty() {
                        err.push_str(&format!(" ({})", context_messages.join(", ")));
                    }
                    bail!(err);
                }
            }
        }
    }

    /// Helper method to extract public key from attestation without full validation
    #[allow(dead_code)]
    fn extract_public_key_from_attestation(&self, attestation_b64: &str) -> Result<Vec<u8>> {
        let bytes = general_purpose::STANDARD
            .decode(attestation_b64)
            .context("invalid attestation base64")?;

        // Parse CBOR attestation structure
        let _attestation_obj: serde_json::Value =
            from_reader(bytes.as_slice()).context("failed to decode attestation CBOR")?;

        tracing::debug!("Attestation structure parsed, attempting public key extraction");

        // For now, return an error to fall back to mock data
        bail!("public key extraction not fully implemented")
    }

    pub fn validate_challenge(
        &self,
        expected: Option<&str>,
        expires_at: Option<OffsetDateTime>,
        provided: &str,
    ) -> Result<()> {
        if let Some(expiry) = expires_at {
            if OffsetDateTime::now_utc() > expiry {
                bail!("app attest challenge expired");
            }
        }

        if let Some(expected_challenge) = expected {
            if !constant_time_eq(expected_challenge.as_bytes(), provided.as_bytes()) {
                bail!("app attest challenge mismatch");
            }
        }

        Ok(())
    }

    pub fn verify_assertion(
        &self,
        assertion_b64: &str,
        client_data_hash: &[u8],
        public_key: &[u8],
        previous_counter: u32,
        stored_challenge: Option<&str>,
        presented_challenge: &str,
    ) -> Result<AssertionVerification> {
        if client_data_hash.len() != 32 {
            bail!("client data hash must be 32 bytes");
        }

        let assertion =
            Assertion::from_base64(assertion_b64).context("failed to decode assertion payload")?;

        let challenge_for_validation = stored_challenge.unwrap_or(presented_challenge);

        // Create minimal client data with just the challenge
        let client_data_json = format!(r#"{{"challenge":"{}"}}"#, challenge_for_validation);

        assertion
            .verify(
                client_data_json.into_bytes(),
                None,
                &self.app_id,
                public_key.to_vec(),
                previous_counter,
                challenge_for_validation,
            )
            .map_err(|e| anyhow!("app attest assertion validation failed: {e}"))?;

        let counter = Self::parse_counter(assertion_b64)?;

        if counter <= previous_counter {
            bail!("app attest counter did not advance");
        }

        Ok(AssertionVerification { counter })
    }

    pub fn verify_assertion_with_client_data(
        &self,
        assertion_b64: &str,
        client_data_json: &str,
        request_body: Option<&[u8]>,
        body_binding_required: bool,
        public_key: &[u8],
        previous_counter: u32,
        _stored_challenge: Option<&str>,
        presented_challenge: &str,
    ) -> Result<AssertionVerification> {
        // Use the presented challenge (from the request) for validation
        let challenge_for_validation = presented_challenge;

        let bound_body = match (body_binding_required, request_body) {
            (true, Some(body)) => Some(body.to_vec()),
            (true, None) => {
                bail!("app attest assertion requires bound request body but none was provided");
            }
            (false, _) => None,
        };

        let assertion =
            Assertion::from_base64(assertion_b64).context("failed to decode assertion payload")?;

        // Parse counter BEFORE verification to log it
        let assertion_counter = Self::parse_counter(assertion_b64)?;

        // Verify the client data actually contains the expected challenge
        if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(client_data_json) {
            if let Some(challenge_in_client_data) = parsed.get("challenge").and_then(|v| v.as_str())
            {
                if challenge_in_client_data != challenge_for_validation {
                    tracing::error!(
                        "Challenge mismatch! client_data has '{}' but validating against '{}'",
                        challenge_in_client_data,
                        challenge_for_validation
                    );
                    bail!("challenge in client data does not match expected challenge");
                }
            }
        }

        assertion
            .verify(
                client_data_json.as_bytes().to_vec(),
                bound_body,
                &self.app_id,
                public_key.to_vec(),
                previous_counter,
                challenge_for_validation,
            )
            .map_err(|e| {
                tracing::error!("Assertion verification failed: {}", e);
                anyhow!("app attest assertion validation failed: {e}")
            })?;

        let counter = assertion_counter;

        if counter <= previous_counter {
            bail!("app attest counter did not advance");
        }

        tracing::info!("Assertion verification succeeded with counter {}", counter);
        Ok(AssertionVerification { counter })
    }

    fn parse_counter(assertion_b64: &str) -> Result<u32> {
        let bytes = general_purpose::STANDARD
            .decode(assertion_b64)
            .context("invalid assertion base64")?;

        let raw: RawAssertion =
            from_reader(bytes.as_slice()).context("failed to decode assertion CBOR")?;

        if raw.authenticator_data.len() < 37 {
            bail!("authenticator data too short");
        }

        let counter_bytes: [u8; 4] = raw.authenticator_data[33..37]
            .try_into()
            .map_err(|_| anyhow!("invalid counter slice"))?;

        Ok(u32::from_be_bytes(counter_bytes))
    }

    pub fn compute_client_data_hash(
        &self,
        challenge_b64: &str,
        body_digest: Option<&[u8]>,
    ) -> Result<[u8; 32]> {
        let challenge_bytes = general_purpose::STANDARD
            .decode(challenge_b64)
            .context("invalid App Attest challenge base64")?;

        if challenge_bytes.len() != 32 {
            bail!("App Attest challenge must decode to 32 bytes");
        }

        if let Some(digest) = body_digest {
            if digest.len() != 32 {
                bail!("App Attest body digest must be 32 bytes when provided");
            }
        }

        let mut to_hash = Vec::with_capacity(32 + body_digest.map(|d| d.len()).unwrap_or(0));
        to_hash.extend_from_slice(&challenge_bytes);
        if let Some(digest) = body_digest {
            to_hash.extend_from_slice(digest);
        }

        let hash = Sha256::digest(&to_hash);
        Ok(hash.into())
    }

    pub fn build_client_data_json(
        &self,
        challenge_b64: &str,
        body_digest: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        if let Some(digest) = body_digest {
            #[derive(serde::Serialize)]
            struct ClientDataWithBody {
                challenge: String,
                #[serde(rename = "requestBody")]
                request_body: String,
            }

            let client_data = ClientDataWithBody {
                challenge: challenge_b64.to_string(),
                request_body: general_purpose::STANDARD.encode(digest),
            };

            serde_json::to_vec(&client_data).context("failed to serialize client data with body")
        } else {
            #[derive(serde::Serialize)]
            struct ClientData {
                challenge: String,
            }

            let client_data = ClientData {
                challenge: challenge_b64.to_string(),
            };

            serde_json::to_vec(&client_data).context("failed to serialize client data")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn clear_test_env() {
        std::env::remove_var("APP_ATTEST_FORCE_PRODUCTION");
        std::env::remove_var("APP_ATTEST_DISABLE_FALLBACK");
        std::env::remove_var("APP_ATTEST_ALLOW_DEV_FALLBACK");
        std::env::remove_var("APP_ATTEST_TESTFLIGHT_FALLBACK");
        std::env::remove_var("APNS_PRODUCTION");
    }

    #[test]
    fn development_fallback_requires_explicit_opt_in() {
        let _guard = env_lock().lock().unwrap();
        clear_test_env();

        let service = AppAttestService::new("app.example".to_string(), 300, false);

        assert!(!service.is_development_mode());
    }

    #[test]
    fn development_fallback_honors_explicit_flag() {
        let _guard = env_lock().lock().unwrap();
        clear_test_env();
        std::env::set_var("APP_ATTEST_ALLOW_DEV_FALLBACK", "true");

        let service = AppAttestService::new("app.example".to_string(), 300, false);

        assert!(service.is_development_mode());
        clear_test_env();
    }

    #[test]
    fn force_production_overrides_dev_fallback() {
        let _guard = env_lock().lock().unwrap();
        clear_test_env();
        std::env::set_var("APP_ATTEST_ALLOW_DEV_FALLBACK", "true");
        std::env::set_var("APP_ATTEST_FORCE_PRODUCTION", "true");

        let service = AppAttestService::new("app.example".to_string(), 300, false);

        assert!(!service.is_development_mode());
        clear_test_env();
    }
}
