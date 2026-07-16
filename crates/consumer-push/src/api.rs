use axum::body::Bytes;
use axum::{
    error_handling::HandleErrorLayer,
    extract::{Json, Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post, put},
    BoxError, Router,
};
use base64::{engine::general_purpose, Engine as _};
use constant_time_eq::constant_time_eq;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tower::limit::ConcurrencyLimitLayer;
use tower::timeout::TimeoutLayer;
use tower::ServiceBuilder;
use tower_http::limit::RequestBodyLimitLayer;
use tracing::{error, info, warn};

use crate::app_attest::AppAttestService;
use crate::models::{ActivitySubscription, NotificationPreference, UserDevice};
use crate::relationships::{
    ModerationList, ModerationListManager, RelationshipManager, ThreadMuteManager,
};
use crate::subscriptions::ActivitySubscriptionManager;

#[derive(Deserialize)]
struct RegisterRequest {
    did: String,
    device_token: String,
}

#[derive(Deserialize)]
struct UnregisterRequest {
    did: String,
    device_token: String,
}

#[derive(Deserialize)]
struct PreferencesQuery {
    did: String,
    device_token: String,
}

#[derive(Deserialize)]
struct PreferencesUpdateRequest {
    did: String,
    device_token: String,
    mentions: bool,
    replies: bool,
    likes: bool,
    follows: bool,
    reposts: bool,
    quotes: bool,
    via_likes: bool,
    via_reposts: bool,
    activity_subscriptions: bool,
}

#[derive(Serialize)]
struct PreferencesBody {
    did: String,
    mentions: bool,
    replies: bool,
    likes: bool,
    follows: bool,
    reposts: bool,
    quotes: bool,
    via_likes: bool,
    via_reposts: bool,
    activity_subscriptions: bool,
}

#[derive(Serialize)]
struct ChallengeEnvelope {
    challenge: String,
    #[serde(with = "time::serde::rfc3339")]
    expires_at: OffsetDateTime,
}

#[derive(Deserialize)]
struct ChallengeRequest {
    did: Option<String>,
    device_token: Option<String>,
    force_key_rotation: Option<bool>,
}

#[derive(Deserialize)]
struct SyncModerationListsRequest {
    did: String,
    device_token: String,
    lists: Vec<ModerationListDto>,
}

#[derive(Deserialize, Serialize)]
struct ModerationListDto {
    uri: String,
    purpose: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct MuteThreadRequest {
    did: String,
    device_token: String,
    thread_root_uri: String,
}

#[derive(Deserialize)]
struct UnmuteThreadRequest {
    did: String,
    device_token: String,
    thread_root_uri: String,
}

#[derive(Deserialize)]
struct GetMutedThreadsRequest {
    did: String,
    device_token: String,
}

#[derive(Serialize)]
struct MutedThreadsResponse {
    threads: Vec<String>,
}

#[derive(Serialize)]
struct RegisterResponse {
    next_challenge: ChallengeEnvelope,
}

#[derive(Serialize)]
struct PreferencesResponse {
    preferences: PreferencesBody,
    next_challenge: ChallengeEnvelope,
}

#[derive(Serialize)]
struct ActivitySubscriptionDto {
    subject_did: String,
    include_posts: bool,
    include_replies: bool,
    #[serde(with = "time::serde::rfc3339")]
    updated_at: OffsetDateTime,
}

impl From<ActivitySubscription> for ActivitySubscriptionDto {
    fn from(value: ActivitySubscription) -> Self {
        Self {
            subject_did: value.subject_did,
            include_posts: value.include_posts,
            include_replies: value.include_replies,
            updated_at: value.updated_at,
        }
    }
}

#[derive(Serialize)]
struct ActivitySubscriptionsResponse {
    subscriptions: Vec<ActivitySubscriptionDto>,
    next_challenge: ChallengeEnvelope,
}

const HEADER_APP_ATTEST_KEY_ID: &str = "X-AppAttest-KeyId";
const HEADER_APP_ATTEST_CHALLENGE: &str = "X-AppAttest-Challenge";
const HEADER_APP_ATTEST_ASSERTION: &str = "X-AppAttest-Assertion";
const HEADER_APP_ATTEST_CLIENT_DATA: &str = "X-AppAttest-ClientData";
const HEADER_APP_ATTEST_BODY_SHA256: &str = "X-AppAttest-BodySHA256";
const HEADER_APP_ATTEST_ATTESTATION: &str = "X-AppAttest-Attestation";
const MAX_API_BODY_BYTES: usize = 256 * 1024;
const MAX_DID_LEN: usize = 256;
const MAX_DEVICE_TOKEN_LEN: usize = 512;
const MIN_DEVICE_TOKEN_LEN: usize = 32;
const MAX_RELATIONSHIP_DID_LIST_LEN: usize = 1000;
const MAX_MODERATION_LISTS_LEN: usize = 1000;
const MAX_MODERATION_LIST_URI_LEN: usize = 2048;
const MAX_MODERATION_LIST_PURPOSE_LEN: usize = 64;
const MAX_MODERATION_LIST_NAME_LEN: usize = 256;
const MAX_THREAD_ROOT_URI_LEN: usize = 2048;
const MAX_AUTHENTICATED_REQUEST_CONCURRENCY: usize = 64;

struct AppAttestRequestProof {
    key_id: String,
    challenge: String,
    assertion: String,
    client_data: Option<String>,
    body_sha256: Option<Vec<u8>>,
    attestation: Option<String>,
}

impl AppAttestRequestProof {
    fn from_headers(headers: &axum::http::HeaderMap) -> Result<Self, axum::response::Response> {
        // Debug log all App Attest headers
        tracing::debug!("Received App Attest headers:");
        for (name, value) in headers.iter() {
            if name.as_str().starts_with("X-AppAttest") || name.as_str().starts_with("x-appattest")
            {
                tracing::debug!(
                    "  {}: {:?}",
                    name.as_str(),
                    value.to_str().unwrap_or("<invalid utf8>")
                );
            }
        }

        let key_id = Self::require_header(headers, HEADER_APP_ATTEST_KEY_ID)?;
        let challenge = Self::require_header(headers, HEADER_APP_ATTEST_CHALLENGE)?;
        let assertion = Self::require_header(headers, HEADER_APP_ATTEST_ASSERTION)?;

        let body_sha256 = match headers.get(HEADER_APP_ATTEST_BODY_SHA256) {
            Some(value) => {
                let value_str = value
                    .to_str()
                    .map_err(|_| {
                        error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid X-AppAttest-BodySHA256 header encoding",
                        )
                    })?
                    .trim()
                    .to_string();

                if value_str.is_empty() {
                    return Err(error_response(
                        StatusCode::BAD_REQUEST,
                        "X-AppAttest-BodySHA256 header must not be empty",
                    ));
                }

                let decoded = general_purpose::STANDARD.decode(&value_str).map_err(|_| {
                    error_response(
                        StatusCode::BAD_REQUEST,
                        "invalid X-AppAttest-BodySHA256 header value",
                    )
                })?;

                if decoded.len() != 32 {
                    return Err(error_response(
                        StatusCode::BAD_REQUEST,
                        "X-AppAttest-BodySHA256 must decode to 32 bytes",
                    ));
                }

                Some(decoded)
            }
            None => None,
        };

        let attestation = match headers.get(HEADER_APP_ATTEST_ATTESTATION) {
            Some(value) => {
                let value_str = value
                    .to_str()
                    .map_err(|_| {
                        error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid X-AppAttest-Attestation header encoding",
                        )
                    })?
                    .trim()
                    .to_string();

                if value_str.is_empty() {
                    None
                } else {
                    Some(value_str)
                }
            }
            None => None,
        };

        let client_data = match headers.get(HEADER_APP_ATTEST_CLIENT_DATA) {
            Some(value) => {
                let value_str = value
                    .to_str()
                    .map_err(|_| {
                        error_response(
                            StatusCode::BAD_REQUEST,
                            "invalid X-AppAttest-ClientData header encoding",
                        )
                    })?
                    .trim()
                    .to_string();

                if value_str.is_empty() {
                    tracing::debug!("X-AppAttest-ClientData header is empty");
                    None
                } else {
                    tracing::debug!("X-AppAttest-ClientData received: {}", value_str);
                    Some(value_str)
                }
            }
            None => {
                tracing::debug!("X-AppAttest-ClientData header not present");
                None
            }
        };

        Ok(Self {
            key_id,
            challenge,
            assertion,
            client_data,
            body_sha256,
            attestation,
        })
    }

    fn require_header(
        headers: &axum::http::HeaderMap,
        name: &str,
    ) -> Result<String, axum::response::Response> {
        let value = headers.get(name).ok_or_else(|| {
            error_response(StatusCode::UNAUTHORIZED, format!("missing {name} header"))
        })?;

        let value_str = value
            .to_str()
            .map_err(|_| error_response(StatusCode::BAD_REQUEST, format!("invalid {name} header")))?
            .trim()
            .to_string();

        if value_str.is_empty() {
            return Err(error_response(
                StatusCode::BAD_REQUEST,
                format!("{name} header must not be empty"),
            ));
        }

        Ok(value_str)
    }
}

fn error_response(status: StatusCode, message: impl Into<String>) -> axum::response::Response {
    (status, message.into()).into_response()
}

fn parse_json_body<T: DeserializeOwned>(body: &Bytes) -> Result<T, axum::response::Response> {
    serde_json::from_slice(body).map_err(|err| {
        error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid JSON body: {}", err),
        )
    })
}

fn verify_body_binding(
    body: &Bytes,
    expected_digest: Option<&[u8]>,
) -> Result<(), axum::response::Response> {
    if let Some(expected) = expected_digest {
        let actual = Sha256::digest(body);
        if !constant_time_eq(&actual, expected) {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "request body digest mismatch",
            ));
        }
    }

    Ok(())
}

fn validate_did(did: &str) -> Result<(), axum::response::Response> {
    if did.is_empty() || did.len() > MAX_DID_LEN || !did.starts_with("did:") {
        return Err(error_response(StatusCode::BAD_REQUEST, "invalid did"));
    }

    if did.chars().any(|ch| ch.is_whitespace() || ch.is_control()) {
        return Err(error_response(StatusCode::BAD_REQUEST, "invalid did"));
    }

    Ok(())
}

fn validate_device_token(device_token: &str) -> Result<(), axum::response::Response> {
    if device_token.len() < MIN_DEVICE_TOKEN_LEN || device_token.len() > MAX_DEVICE_TOKEN_LEN {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid device token",
        ));
    }

    if device_token
        .chars()
        .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid device token",
        ));
    }

    Ok(())
}

fn validate_principal(did: &str, device_token: &str) -> Result<(), axum::response::Response> {
    validate_did(did)?;
    validate_device_token(device_token)
}

fn validate_did_list(values: &[String], field_name: &str) -> Result<(), axum::response::Response> {
    for value in values {
        validate_did(value).map_err(|_| {
            error_response(
                StatusCode::BAD_REQUEST,
                format!("invalid did in {}", field_name),
            )
        })?;
    }

    Ok(())
}

fn validate_required_text_field(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), axum::response::Response> {
    let trimmed = value.trim();

    if trimmed.is_empty() || trimmed.len() > max_len || trimmed.len() != value.len() {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid {}", field_name),
        ));
    }

    if value.chars().any(char::is_control) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid {}", field_name),
        ));
    }

    Ok(())
}

fn validate_compact_text_field(
    value: &str,
    field_name: &str,
    max_len: usize,
) -> Result<(), axum::response::Response> {
    validate_required_text_field(value, field_name, max_len)?;

    if value.chars().any(char::is_whitespace) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            format!("invalid {}", field_name),
        ));
    }

    Ok(())
}

fn validate_optional_text_field(
    value: Option<&str>,
    field_name: &str,
    max_len: usize,
) -> Result<(), axum::response::Response> {
    if let Some(value) = value {
        validate_required_text_field(value, field_name, max_len)?;
    }

    Ok(())
}

fn validate_thread_root_uri(thread_root_uri: &str) -> Result<(), axum::response::Response> {
    validate_compact_text_field(thread_root_uri, "thread_root_uri", MAX_THREAD_ROOT_URI_LEN)
}

fn validate_moderation_lists(lists: &[ModerationListDto]) -> Result<(), axum::response::Response> {
    if lists.len() > MAX_MODERATION_LISTS_LEN {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "too many moderation lists",
        ));
    }

    for list in lists {
        validate_compact_text_field(&list.uri, "lists[].uri", MAX_MODERATION_LIST_URI_LEN)?;
        validate_compact_text_field(
            &list.purpose,
            "lists[].purpose",
            MAX_MODERATION_LIST_PURPOSE_LEN,
        )?;
        validate_optional_text_field(
            list.name.as_deref(),
            "lists[].name",
            MAX_MODERATION_LIST_NAME_LEN,
        )?;
    }

    Ok(())
}

fn force_key_rotation_enabled() -> bool {
    std::env::var("APP_ATTEST_ALLOW_FORCE_KEY_ROTATION").unwrap_or_default() == "true"
}

struct AuthenticatedDeviceResult {
    device_id: uuid::Uuid,
    next_challenge: String,
    next_challenge_expires_at: OffsetDateTime,
}

async fn authenticate_device_for_request(
    state: &ApiState,
    tx: &mut sqlx::Transaction<'_, Postgres>,
    did: &str,
    device_token: &str,
    proof: &AppAttestRequestProof,
    client_data_hash: Vec<u8>,
    request_body: Option<&[u8]>,
) -> Result<AuthenticatedDeviceResult, axum::response::Response> {
    validate_principal(did, device_token)?;

    let device = match sqlx::query_as::<_, UserDevice>(
        r#"
        SELECT id, did, device_token, created_at, updated_at,
               app_attest_key_id,
               app_attest_public_key,
               app_attest_receipt,
               app_attest_counter,
               app_attest_challenge,
               app_attest_challenge_expires_at,
               app_attest_last_verified_at
        FROM user_devices
        WHERE device_token = $1 AND did = $2
        FOR UPDATE
        "#,
    )
    .bind(device_token)
    .bind(did)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(Some(device)) => device,
        Ok(None) => {
            return Err(error_response(
                StatusCode::NOT_FOUND,
                "device not registered",
            ))
        }
        Err(e) => {
            tracing::error!("Failed to fetch device for authenticated request: {}", e);
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database error",
            ));
        }
    };

    if let Some(key_id) = &device.app_attest_key_id {
        if key_id != &proof.key_id {
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "app attest key mismatch",
            ));
        }
    } else {
        return Err(error_response(
            StatusCode::PRECONDITION_REQUIRED,
            "device requires re-attestation",
        ));
    }

    if let Err(err) = state.app_attest_service.validate_challenge(
        device.app_attest_challenge.as_deref(),
        device.app_attest_challenge_expires_at,
        &proof.challenge,
    ) {
        tracing::warn!("Challenge validation failed: {}", err);
        return Err(error_response(
            StatusCode::UNAUTHORIZED,
            "invalid or expired challenge",
        ));
    }

    let public_key = match &device.app_attest_public_key {
        Some(key) => key.clone(),
        None => {
            return Err(error_response(
                StatusCode::PRECONDITION_REQUIRED,
                "device requires re-attestation",
            ));
        }
    };

    let previous_counter = match u32::try_from(device.app_attest_counter) {
        Ok(value) => value,
        Err(_) => {
            return Err(error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "invalid counter state",
            ));
        }
    };

    let request_body_vec = request_body.map(|body| body.to_vec());
    let body_binding_required = proof.body_sha256.is_some();

    let assertion = match if let Some(client_data) = &proof.client_data {
        verify_assertion_async(
            &state.app_attest_service,
            proof.assertion.clone(),
            client_data.clone(),
            request_body_vec.clone(),
            body_binding_required,
            public_key,
            previous_counter,
            device.app_attest_challenge.clone(),
            proof.challenge.clone(),
        )
        .await
    } else {
        verify_assertion_legacy_async(
            &state.app_attest_service,
            proof.assertion.clone(),
            client_data_hash,
            public_key,
            previous_counter,
            device.app_attest_challenge.clone(),
            proof.challenge.clone(),
        )
        .await
    } {
        Ok(result) => result,
        Err(err) => {
            tracing::warn!("App Attest assertion failed: {}", err);
            return Err(error_response(
                StatusCode::UNAUTHORIZED,
                "invalid app attest assertion",
            ));
        }
    };

    let (next_challenge, expires_at) = state.app_attest_service.issue_challenge();

    if let Err(e) = sqlx::query(
        r#"
        UPDATE user_devices
        SET app_attest_counter = $1,
            app_attest_challenge = $2,
            app_attest_challenge_expires_at = $3,
            app_attest_last_verified_at = NOW(),
            updated_at = NOW()
        WHERE id = $4
        "#,
    )
    .bind(i64::from(assertion.counter))
    .bind(&next_challenge)
    .bind(expires_at)
    .bind(device.id)
    .execute(tx.as_mut())
    .await
    {
        tracing::error!("Failed to update device metadata: {}", e);
        return Err(error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database error",
        ));
    }

    Ok(AuthenticatedDeviceResult {
        device_id: device.id,
        next_challenge,
        next_challenge_expires_at: expires_at,
    })
}

async fn fetch_preferences_with_auth(
    state: ApiState,
    query: PreferencesQuery,
    proof: &AppAttestRequestProof,
    client_data_hash: Vec<u8>,
    request_body: Option<&[u8]>,
) -> axum::response::Response {
    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to start transaction for preferences: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let auth = match authenticate_device_for_request(
        &state,
        &mut tx,
        &query.did,
        &query.device_token,
        proof,
        client_data_hash,
        request_body,
    )
    .await
    {
        Ok(auth) => auth,
        Err(resp) => {
            tx.rollback().await.ok();
            return resp;
        }
    };

    let prefs = match sqlx::query_as::<_, NotificationPreference>(
        r#"
        SELECT
            user_id,
            mentions,
            replies,
            likes,
            follows,
            reposts,
            quotes,
            via_likes,
            via_reposts,
            activity_subscriptions
        FROM notification_preferences
        WHERE user_id = $1
        "#,
    )
    .bind(auth.device_id)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(prefs) => prefs,
        Err(e) => {
            tx.rollback().await.ok();
            tracing::error!("Failed to load preferences: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit preferences transaction: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let body = PreferencesBody {
        did: query.did,
        mentions: prefs.mentions,
        replies: prefs.replies,
        likes: prefs.likes,
        follows: prefs.follows,
        reposts: prefs.reposts,
        quotes: prefs.quotes,
        via_likes: prefs.via_likes,
        via_reposts: prefs.via_reposts,
        activity_subscriptions: prefs.activity_subscriptions,
    };

    Json(PreferencesResponse {
        preferences: body,
        next_challenge: ChallengeEnvelope {
            challenge: auth.next_challenge,
            expires_at: auth.next_challenge_expires_at,
        },
    })
    .into_response()
}

#[derive(Deserialize)]
struct RelationshipsRequest {
    did: String,
    device_token: String,
    mutes: Vec<String>,
    blocks: Vec<String>,
}

#[derive(Deserialize)]
struct ActivitySubscriptionQuery {
    did: String,
    device_token: String,
}

#[derive(Deserialize)]
struct ActivitySubscriptionUpdateRequest {
    did: String,
    device_token: String,
    subject_did: String,
    include_posts: bool,
    include_replies: bool,
}

#[derive(Deserialize)]
struct ActivitySubscriptionDeleteRequest {
    did: String,
    device_token: String,
    subject_did: String,
}

/// Shared state for the API handlers.
#[derive(Clone)]
pub struct ApiState {
    pub db_pool: Pool<Postgres>,
    pub relationship_manager: Arc<RelationshipManager>,
    pub moderation_list_manager: Arc<ModerationListManager>,
    pub thread_mute_manager: Arc<ThreadMuteManager>,
    pub activity_subscription_manager: Arc<ActivitySubscriptionManager>,
    pub app_attest_service: AppAttestService,
}

// Error handler function for timeouts
async fn handle_timeout_error(error: BoxError) -> (StatusCode, String) {
    if error.is::<tower::timeout::error::Elapsed>() {
        (
            StatusCode::REQUEST_TIMEOUT,
            "Request took too long".to_string(),
        )
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Unhandled internal error: {}", error),
        )
    }
}

/// Create the API router with all endpoints.
pub fn create_api_router(state: ApiState) -> Router {
    let public_routes = Router::new()
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler));

    let protected_routes = Router::new()
        .route("/register", post(register_device))
        .route("/unregister", post(unregister_device))
        .route(
            "/preferences",
            get(get_preferences)
                .post(get_preferences_post)
                .put(update_preferences),
        )
        .route(
            "/activity-subscriptions",
            get(list_activity_subscriptions)
                .post(list_activity_subscriptions_post)
                .put(upsert_activity_subscription)
                .delete(remove_activity_subscription),
        )
        .route("/relationships", put(update_relationships))
        .route("/sync-moderation-lists", post(sync_moderation_lists))
        .route("/mute-thread", post(mute_thread))
        .route("/unmute-thread", post(unmute_thread))
        .route(
            "/muted-threads",
            get(get_muted_threads).post(get_muted_threads_post),
        )
        .route(
            "/challenge",
            get(issue_challenge_get).post(issue_challenge_post),
        )
        .layer(ConcurrencyLimitLayer::new(
            MAX_AUTHENTICATED_REQUEST_CONCURRENCY,
        ));

    public_routes
        .merge(protected_routes)
        .with_state(state)
        .layer(
            ServiceBuilder::new()
                .layer(HandleErrorLayer::new(handle_timeout_error))
                .layer(RequestBodyLimitLayer::new(MAX_API_BODY_BYTES))
                .layer(TimeoutLayer::new(Duration::from_secs(30))),
        )
}

async fn health_handler() -> &'static str {
    "ok"
}

async fn metrics_handler() -> String {
    crate::metrics::metrics_handler()
}

async fn issue_challenge_get(
    State(state): State<ApiState>,
    Query(req): Query<ChallengeRequest>,
) -> impl IntoResponse {
    issue_challenge_common(state, req).await
}

async fn issue_challenge_post(
    State(state): State<ApiState>,
    Json(req): Json<ChallengeRequest>,
) -> impl IntoResponse {
    issue_challenge_common(state, req).await
}

async fn issue_challenge_common(state: ApiState, req: ChallengeRequest) -> impl IntoResponse {
    let (challenge, expires_at) = state.app_attest_service.issue_challenge();

    if let (Some(did), Some(device_token)) = (req.did, req.device_token) {
        if let Err(resp) = validate_principal(&did, &device_token) {
            return resp;
        }

        if req.force_key_rotation.unwrap_or(false) {
            if !force_key_rotation_enabled() {
                tracing::warn!(
                    "Force key rotation requested while APP_ATTEST_ALLOW_FORCE_KEY_ROTATION is disabled"
                );
                return error_response(StatusCode::FORBIDDEN, "force key rotation is disabled");
            }

            tracing::info!(
                "Force key rotation requested for DID: {}, clearing existing App Attest data",
                did
            );

            if let Err(e) = sqlx::query(
                r#"
                UPDATE user_devices
                SET app_attest_key_id = NULL,
                    app_attest_challenge = $1,
                    app_attest_challenge_expires_at = $2,
                    updated_at = NOW()
                WHERE did = $3 AND device_token = $4
                "#,
            )
            .bind(&challenge)
            .bind(expires_at)
            .bind(&did)
            .bind(&device_token)
            .execute(&state.db_pool)
            .await
            {
                tracing::warn!("Failed to clear App Attest data for force rotation: {}", e);
            }
        } else {
            if let Err(e) = sqlx::query(
                r#"
                UPDATE user_devices
                SET app_attest_challenge = $1,
                    app_attest_challenge_expires_at = $2,
                    updated_at = NOW()
                WHERE did = $3 AND device_token = $4
                "#,
            )
            .bind(&challenge)
            .bind(expires_at)
            .bind(did)
            .bind(device_token)
            .execute(&state.db_pool)
            .await
            {
                tracing::warn!("Failed to persist challenge for device: {}", e);
            }
        }
    }

    let body = ChallengeEnvelope {
        challenge,
        expires_at,
    };
    (StatusCode::OK, Json(body)).into_response()
}

async fn update_relationships(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: RelationshipsRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    info!(
        "Processing relationship update request for DID: {}",
        req.did
    );

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    if req.mutes.len() > MAX_RELATIONSHIP_DID_LIST_LEN
        || req.blocks.len() > MAX_RELATIONSHIP_DID_LIST_LEN
    {
        warn!(
            "Excessive relationship data: mutes={}, blocks={}",
            req.mutes.len(),
            req.blocks.len()
        );
        return (
            StatusCode::BAD_REQUEST,
            "Request exceeds maximum allowable size",
        )
            .into_response();
    }

    if let Err(resp) = validate_did_list(&req.mutes, "mutes") {
        return resp;
    }

    if let Err(resp) = validate_did_list(&req.blocks, "blocks") {
        return resp;
    }

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash for relationships on DID {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to start transaction for relationship update: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let auth = match authenticate_device_for_request(
        &state,
        &mut tx,
        &req.did,
        &req.device_token,
        &proof,
        client_data_hash,
        Some(body.as_ref()),
    )
    .await
    {
        Ok(auth) => auth,
        Err(resp) => {
            tx.rollback().await.ok();
            return resp;
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit device challenge update: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let mutes = req.mutes.clone();
    let blocks = req.blocks.clone();

    match state
        .relationship_manager
        .update_relationships_batch(&req.did, &req.device_token, mutes, blocks)
        .await
    {
        Ok(_) => {
            info!("Successfully updated relationships for DID: {}", req.did);
            let response = RegisterResponse {
                next_challenge: ChallengeEnvelope {
                    challenge: auth.next_challenge,
                    expires_at: auth.next_challenge_expires_at,
                },
            };
            (StatusCode::OK, Json(response)).into_response()
        }
        Err(e) => {
            if e.to_string().contains("Invalid device token") {
                warn!(
                    "Unauthorized relationship update attempt for DID: {}",
                    req.did
                );
                StatusCode::UNAUTHORIZED.into_response()
            } else {
                error!("Error updating relationships: {}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Internal server error: {}", e),
                )
                    .into_response()
            }
        }
    }
}

// Helper functions to handle App Attest operations in blocking context
async fn verify_attestation_async(
    app_attest: &AppAttestService,
    attestation_payload: String,
    challenge: String,
    key_id: String,
) -> Result<crate::app_attest::AttestationVerification, anyhow::Error> {
    let app_attest = app_attest.clone();
    tokio::task::spawn_blocking(move || {
        app_attest.verify_attestation(&attestation_payload, &challenge, &key_id)
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {}", e))?
}

async fn verify_assertion_async(
    app_attest: &AppAttestService,
    assertion: String,
    client_data: String,
    request_body: Option<Vec<u8>>,
    body_binding_required: bool,
    public_key: Vec<u8>,
    previous_counter: u32,
    stored_challenge: Option<String>,
    challenge: String,
) -> Result<crate::app_attest::AssertionVerification, anyhow::Error> {
    let app_attest = app_attest.clone();
    tokio::task::spawn_blocking(move || {
        app_attest.verify_assertion_with_client_data(
            &assertion,
            &client_data,
            request_body.as_deref(),
            body_binding_required,
            &public_key,
            previous_counter,
            stored_challenge.as_deref(),
            &challenge,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {}", e))?
}

async fn verify_assertion_legacy_async(
    app_attest: &AppAttestService,
    assertion: String,
    client_data_hash: Vec<u8>,
    public_key: Vec<u8>,
    previous_counter: u32,
    stored_challenge: Option<String>,
    challenge: String,
) -> Result<crate::app_attest::AssertionVerification, anyhow::Error> {
    let app_attest = app_attest.clone();
    tokio::task::spawn_blocking(move || {
        app_attest.verify_assertion(
            &assertion,
            &client_data_hash,
            &public_key,
            previous_counter,
            stored_challenge.as_deref(),
            &challenge,
        )
    })
    .await
    .map_err(|e| anyhow::anyhow!("Task join error: {}", e))?
}

/// Simplified App Attest verification for endpoints that don't need the
/// transaction-based `authenticate_device_for_request` flow (e.g. moderation
/// lists, thread mutes). Verifies the assertion and rotates the challenge.
async fn verify_app_attest_assertion(
    state: &ApiState,
    did: &str,
    device_token: &str,
    proof: &AppAttestRequestProof,
    body: &Bytes,
) -> Result<(), axum::response::Response> {
    let client_data_hash = state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
        .map_err(|err| {
            tracing::warn!("Failed to prepare clientDataHash for DID {}: {}", did, err);
            error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters")
        })?
        .to_vec();

    let mut tx = state.db_pool.begin().await.map_err(|e| {
        tracing::error!("Failed to start transaction: {}", e);
        error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error")
    })?;

    let request_body = if body.is_empty() {
        None
    } else {
        Some(body.as_ref())
    };

    let auth_result = authenticate_device_for_request(
        state,
        &mut tx,
        did,
        device_token,
        proof,
        client_data_hash,
        request_body,
    )
    .await;

    match auth_result {
        Ok(_auth) => {
            tx.commit().await.map_err(|e| {
                tracing::error!("Failed to commit transaction: {}", e);
                error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error")
            })?;
            Ok(())
        }
        Err(resp) => {
            tx.rollback().await.ok();
            Err(resp)
        }
    }
}

// API handlers
async fn register_device(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: RegisterRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    tracing::info!("Registering device for DID: {}", req.did);

    let request_body_vec = if body.is_empty() {
        None
    } else {
        Some(body.to_vec())
    };

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash during register for DID {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Error starting transaction: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            );
        }
    };

    let existing_registration = match sqlx::query_as::<_, UserDevice>(
        r#"
        SELECT id, did, device_token, created_at, updated_at,
               app_attest_key_id,
               app_attest_public_key,
               app_attest_receipt,
               app_attest_counter,
               app_attest_challenge,
               app_attest_challenge_expires_at,
               app_attest_last_verified_at
        FROM user_devices
        WHERE device_token = $1 AND did = $2
        FOR UPDATE
        "#,
    )
    .bind(&req.device_token)
    .bind(&req.did)
    .fetch_optional(tx.as_mut())
    .await
    {
        Ok(device) => device,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!("Database error: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            );
        }
    };

    if let Some(device) = existing_registration {
        if let Some(key_id) = &device.app_attest_key_id {
            if key_id != &proof.key_id {
                let _ = tx.rollback().await;
                tracing::warn!(
                    "App Attest key mismatch for DID {} (expected {}, got {})",
                    req.did,
                    key_id,
                    proof.key_id
                );
                return error_response(StatusCode::UNAUTHORIZED, "app attest key mismatch");
            }
        } else {
            // Device exists but has no key ID (likely cleared by force rotation)
            tracing::info!(
                "Device exists without App Attest key for DID {} - allowing new key registration (likely after force rotation)",
                req.did
            );

            if proof.attestation.is_none() {
                let _ = tx.rollback().await;
                tracing::warn!(
                    "Device without key missing App Attest attestation for DID {}",
                    req.did
                );
                return error_response(
                    StatusCode::PRECONDITION_REQUIRED,
                    "device requires re-attestation",
                );
            }

            let attestation_payload = proof.attestation.as_ref().unwrap();

            let attestation = match verify_attestation_async(
                &state.app_attest_service,
                attestation_payload.clone(),
                proof.challenge.clone(),
                proof.key_id.clone(),
            )
            .await
            {
                Ok(data) => data,
                Err(err) => {
                    let _ = tx.rollback().await;
                    tracing::warn!("App Attest attestation failed for DID {}: {}", req.did, err);
                    return error_response(StatusCode::UNAUTHORIZED, "invalid attestation payload");
                }
            };

            tracing::info!(
                "Attestation verified for DID {} - skipping assertion check (not needed for initial attestation)",
                req.did
            );

            let (next_challenge, expires_at) = state.app_attest_service.issue_challenge();

            if let Err(e) = sqlx::query(
                r#"
                UPDATE user_devices
                SET updated_at = NOW(),
                    app_attest_key_id = $1,
                    app_attest_public_key = $2,
                    app_attest_receipt = $3,
                    app_attest_counter = $4,
                    app_attest_challenge = $5,
                    app_attest_challenge_expires_at = $6,
                    app_attest_last_verified_at = NOW()
                WHERE id = $7
                "#,
            )
            .bind(&proof.key_id)
            .bind(attestation.public_key)
            .bind(attestation.receipt)
            .bind(0i64)
            .bind(&next_challenge)
            .bind(expires_at)
            .bind(device.id)
            .execute(tx.as_mut())
            .await
            {
                let _ = tx.rollback().await;
                tracing::error!("Error updating device with fresh attestation: {}", e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                );
            }

            if let Err(e) = tx.commit().await {
                tracing::error!("Error committing transaction: {}", e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                );
            }

            let response = RegisterResponse {
                next_challenge: ChallengeEnvelope {
                    challenge: next_challenge,
                    expires_at,
                },
            };

            return (StatusCode::OK, Json(response)).into_response();
        }

        if let Err(e) = state.app_attest_service.validate_challenge(
            device.app_attest_challenge.as_deref(),
            device.app_attest_challenge_expires_at,
            &proof.challenge,
        ) {
            let _ = tx.rollback().await;
            tracing::warn!("Challenge validation failed for DID {}: {}", req.did, e);
            return error_response(StatusCode::UNAUTHORIZED, "invalid or expired challenge");
        }

        let public_key = match &device.app_attest_public_key {
            Some(key) => key.clone(),
            None => {
                let _ = tx.rollback().await;
                tracing::warn!(
                    "Existing device missing App Attest public key for DID {}",
                    req.did
                );
                return error_response(
                    StatusCode::PRECONDITION_REQUIRED,
                    "device requires re-attestation",
                );
            }
        };

        let previous_counter = match u32::try_from(device.app_attest_counter) {
            Ok(value) => value,
            Err(_) => {
                let _ = tx.rollback().await;
                tracing::error!("Invalid stored counter for DID {}", req.did);
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "invalid counter state");
            }
        };

        // Special case: If counter is 0, device was just attested but never used
        if previous_counter == 0 {
            tracing::info!(
                "Device has counter=0 for DID {}, treating as fresh attestation case",
                req.did
            );

            if proof.attestation.is_none() {
                let _ = tx.rollback().await;
                tracing::warn!(
                    "Device with counter=0 missing App Attest attestation for DID {}",
                    req.did
                );
                return error_response(
                    StatusCode::PRECONDITION_REQUIRED,
                    "device requires re-attestation",
                );
            }

            let attestation_payload = proof.attestation.as_ref().unwrap();

            let attestation = match verify_attestation_async(
                &state.app_attest_service,
                attestation_payload.clone(),
                proof.challenge.clone(),
                proof.key_id.clone(),
            )
            .await
            {
                Ok(data) => data,
                Err(err) => {
                    let _ = tx.rollback().await;
                    tracing::warn!("App Attest attestation failed for DID {}: {}", req.did, err);
                    return error_response(StatusCode::UNAUTHORIZED, "invalid attestation payload");
                }
            };

            tracing::info!(
                "Re-attestation verified for DID {} (counter was 0)",
                req.did
            );

            let (next_challenge, expires_at) = state.app_attest_service.issue_challenge();

            if let Err(e) = sqlx::query(
                r#"
                UPDATE user_devices
                SET updated_at = NOW(),
                    app_attest_key_id = $1,
                    app_attest_public_key = $2,
                    app_attest_receipt = $3,
                    app_attest_counter = $4,
                    app_attest_challenge = $5,
                    app_attest_challenge_expires_at = $6,
                    app_attest_last_verified_at = NOW()
                WHERE id = $7
                "#,
            )
            .bind(&proof.key_id)
            .bind(attestation.public_key)
            .bind(attestation.receipt)
            .bind(0i64)
            .bind(&next_challenge)
            .bind(expires_at)
            .bind(device.id)
            .execute(tx.as_mut())
            .await
            {
                let _ = tx.rollback().await;
                tracing::error!("Error updating device with re-attestation: {}", e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                );
            }

            if let Err(e) = tx.commit().await {
                tracing::error!("Error committing transaction: {}", e);
                return error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database error: {}", e),
                );
            }

            let response = RegisterResponse {
                next_challenge: ChallengeEnvelope {
                    challenge: next_challenge,
                    expires_at,
                },
            };

            return (StatusCode::OK, Json(response)).into_response();
        }

        // Normal path: counter > 0, verify assertion
        let assertion = match if let Some(client_data) = &proof.client_data {
            verify_assertion_async(
                &state.app_attest_service,
                proof.assertion.clone(),
                client_data.clone(),
                request_body_vec.clone(),
                proof.body_sha256.is_some(),
                public_key,
                previous_counter,
                device.app_attest_challenge.clone(),
                proof.challenge.clone(),
            )
            .await
        } else {
            verify_assertion_legacy_async(
                &state.app_attest_service,
                proof.assertion.clone(),
                client_data_hash.clone(),
                public_key,
                previous_counter,
                device.app_attest_challenge.clone(),
                proof.challenge.clone(),
            )
            .await
        } {
            Ok(result) => result,
            Err(err) => {
                let _ = tx.rollback().await;
                let err_str = err.to_string();
                tracing::warn!(
                    "App Attest assertion failed for DID {}: {}",
                    req.did,
                    err_str
                );

                if err_str.contains("invalid signature") {
                    tracing::info!(
                        "Signature validation failed for DID {}, requesting re-attestation (likely key mismatch)",
                        req.did
                    );
                    return error_response(
                        StatusCode::PRECONDITION_REQUIRED,
                        "device requires re-attestation due to key mismatch",
                    );
                }

                return error_response(StatusCode::UNAUTHORIZED, "invalid app attest assertion");
            }
        };

        let (next_challenge, expires_at) = state.app_attest_service.issue_challenge();

        if let Err(e) = sqlx::query(
            r#"
            UPDATE user_devices
            SET updated_at = NOW(),
                app_attest_counter = $1,
                app_attest_challenge = $2,
                app_attest_challenge_expires_at = $3,
                app_attest_last_verified_at = NOW()
            WHERE id = $4
            "#,
        )
        .bind(i64::from(assertion.counter))
        .bind(&next_challenge)
        .bind(expires_at)
        .bind(device.id)
        .execute(tx.as_mut())
        .await
        {
            let _ = tx.rollback().await;
            tracing::error!("Error updating device: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            );
        }

        if let Err(e) = tx.commit().await {
            tracing::error!("Error committing transaction: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            );
        }

        let response = RegisterResponse {
            next_challenge: ChallengeEnvelope {
                challenge: next_challenge,
                expires_at,
            },
        };

        return (StatusCode::OK, Json(response)).into_response();
    }

    // New device registration
    let attestation_payload = match &proof.attestation {
        Some(payload) => payload,
        None => {
            let _ = tx.rollback().await;
            tracing::warn!(
                "Missing App Attest attestation for new device DID {}",
                req.did
            );
            return error_response(StatusCode::BAD_REQUEST, "attestation payload required");
        }
    };

    let attestation = match verify_attestation_async(
        &state.app_attest_service,
        attestation_payload.clone(),
        proof.challenge.clone(),
        proof.key_id.clone(),
    )
    .await
    {
        Ok(data) => data,
        Err(err) => {
            let _ = tx.rollback().await;
            tracing::warn!("App Attest attestation failed for DID {}: {}", req.did, err);
            return error_response(StatusCode::UNAUTHORIZED, "invalid attestation payload");
        }
    };

    tracing::info!(
        "New device attestation verified for DID {} - skipping assertion check",
        req.did
    );

    let (next_challenge, expires_at) = state.app_attest_service.issue_challenge();

    let new_device_id = match sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        INSERT INTO user_devices (
            did,
            device_token,
            app_attest_key_id,
            app_attest_public_key,
            app_attest_receipt,
            app_attest_counter,
            app_attest_challenge,
            app_attest_challenge_expires_at,
            app_attest_last_verified_at
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        RETURNING id
        "#,
    )
    .bind(&req.did)
    .bind(&req.device_token)
    .bind(&proof.key_id)
    .bind(attestation.public_key)
    .bind(attestation.receipt)
    .bind(0i64)
    .bind(next_challenge.clone())
    .bind(expires_at)
    .fetch_one(tx.as_mut())
    .await
    {
        Ok(id) => id,
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!("Error registering device: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            );
        }
    };

    if let Err(e) = sqlx::query(
        r#"
        INSERT INTO notification_preferences (user_id)
        VALUES ($1)
        "#,
    )
    .bind(new_device_id)
    .execute(tx.as_mut())
    .await
    {
        let _ = tx.rollback().await;
        tracing::error!("Error creating preferences: {}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        );
    }

    if let Err(e) = tx.commit().await {
        tracing::error!("Error committing transaction: {}", e);
        return error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Database error: {}", e),
        );
    }

    let response = RegisterResponse {
        next_challenge: ChallengeEnvelope {
            challenge: next_challenge,
            expires_at,
        },
    };

    (StatusCode::CREATED, Json(response)).into_response()
}

async fn unregister_device(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: UnregisterRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    let token_preview = req.device_token.get(..8).unwrap_or(&req.device_token);
    tracing::info!("Unregistering device with token: {}...", token_preview);

    let request_body_vec = if body.is_empty() {
        None
    } else {
        Some(body.to_vec())
    };

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash during unregister for DID {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Error starting transaction: {}", e);
            return error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            );
        }
    };

    let device_result = sqlx::query_as::<_, UserDevice>(
        r#"
        SELECT id, did, device_token, created_at, updated_at,
               app_attest_key_id,
               app_attest_public_key,
               app_attest_receipt,
               app_attest_counter,
               app_attest_challenge,
               app_attest_challenge_expires_at,
               app_attest_last_verified_at
        FROM user_devices
        WHERE device_token = $1 AND did = $2
        FOR UPDATE
        "#,
    )
    .bind(&req.device_token)
    .bind(&req.did)
    .fetch_optional(tx.as_mut())
    .await;

    match device_result {
        Ok(Some(device)) => {
            tracing::info!(
                "Found device for DID: {}, proceeding with deletion",
                device.did
            );

            if let Some(key_id) = &device.app_attest_key_id {
                if key_id != &proof.key_id {
                    let _ = tx.rollback().await;
                    tracing::warn!(
                        "App Attest key mismatch during unregister for DID {}",
                        req.did
                    );
                    return error_response(StatusCode::UNAUTHORIZED, "app attest key mismatch");
                }
            } else {
                let _ = tx.rollback().await;
                tracing::warn!(
                    "Device lacks App Attest provisioning during unregister for DID {}",
                    req.did
                );
                return error_response(
                    StatusCode::PRECONDITION_REQUIRED,
                    "device requires re-attestation",
                );
            }

            if let Err(e) = state.app_attest_service.validate_challenge(
                device.app_attest_challenge.as_deref(),
                device.app_attest_challenge_expires_at,
                &proof.challenge,
            ) {
                let _ = tx.rollback().await;
                tracing::warn!(
                    "Challenge validation failed during unregister for DID {}: {}",
                    req.did,
                    e
                );
                return error_response(StatusCode::UNAUTHORIZED, "invalid or expired challenge");
            }

            let public_key = match &device.app_attest_public_key {
                Some(key) => key.clone(),
                None => {
                    let _ = tx.rollback().await;
                    tracing::warn!(
                        "Missing App Attest public key during unregister for DID {}",
                        req.did
                    );
                    return error_response(
                        StatusCode::PRECONDITION_REQUIRED,
                        "device requires re-attestation",
                    );
                }
            };

            let previous_counter = match u32::try_from(device.app_attest_counter) {
                Ok(value) => value,
                Err(_) => {
                    let _ = tx.rollback().await;
                    tracing::error!("Invalid counter during unregister for DID {}", req.did);
                    return error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "invalid counter state",
                    );
                }
            };

            // Special case: If counter is 0, allow deletion without assertion verification
            if previous_counter == 0 {
                tracing::info!(
                    "Device has counter=0 for DID {}, allowing unregister without assertion verification",
                    req.did
                );

                let delete_result =
                    sqlx::query("DELETE FROM user_devices WHERE device_token = $1 AND did = $2")
                        .bind(&req.device_token)
                        .bind(&req.did)
                        .execute(tx.as_mut())
                        .await;

                match delete_result {
                    Ok(result) => {
                        if result.rows_affected() > 0 {
                            if let Err(e) = tx.commit().await {
                                tracing::error!("Error committing transaction: {}", e);
                                return error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("Database error: {}", e),
                                );
                            }

                            tracing::info!("Device unregistered successfully (counter was 0)");
                            return (StatusCode::OK, "").into_response();
                        } else {
                            let _ = tx.rollback().await;
                            tracing::warn!("Device not found during deletion");
                            return error_response(StatusCode::NOT_FOUND, "Device not found");
                        }
                    }
                    Err(e) => {
                        let _ = tx.rollback().await;
                        tracing::error!("Error deleting device: {}", e);
                        return error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("Database error: {}", e),
                        );
                    }
                }
            }

            // Normal path: counter > 0, verify assertion before deletion
            let assertion_result = if let Some(client_data) = &proof.client_data {
                verify_assertion_async(
                    &state.app_attest_service,
                    proof.assertion.clone(),
                    client_data.clone(),
                    request_body_vec.clone(),
                    proof.body_sha256.is_some(),
                    public_key,
                    previous_counter,
                    device.app_attest_challenge.clone(),
                    proof.challenge.clone(),
                )
                .await
            } else {
                verify_assertion_legacy_async(
                    &state.app_attest_service,
                    proof.assertion.clone(),
                    client_data_hash,
                    public_key,
                    previous_counter,
                    device.app_attest_challenge.clone(),
                    proof.challenge.clone(),
                )
                .await
            };

            let allow_deletion = match assertion_result {
                Ok(_) => {
                    tracing::debug!("Assertion verification succeeded for unregister");
                    true
                }
                Err(err) => {
                    let err_str = err.to_string();
                    tracing::warn!(
                        "App Attest assertion failed during unregister for DID {}: {}",
                        req.did,
                        err_str
                    );

                    if err_str.contains("invalid signature") {
                        tracing::info!(
                            "Signature validation failed during unregister for DID {}, allowing deletion anyway (user wants to unregister)",
                            req.did
                        );
                        true
                    } else {
                        let _ = tx.rollback().await;
                        return error_response(
                            StatusCode::UNAUTHORIZED,
                            "invalid app attest assertion",
                        );
                    }
                }
            };

            if !allow_deletion {
                let _ = tx.rollback().await;
                return error_response(StatusCode::INTERNAL_SERVER_ERROR, "unexpected state");
            }

            let delete_result =
                sqlx::query("DELETE FROM user_devices WHERE device_token = $1 AND did = $2")
                    .bind(&req.device_token)
                    .bind(&req.did)
                    .execute(tx.as_mut())
                    .await;

            match delete_result {
                Ok(result) => {
                    if result.rows_affected() > 0 {
                        if let Err(e) = tx.commit().await {
                            tracing::error!("Error committing transaction: {}", e);
                            return error_response(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                format!("Database error: {}", e),
                            );
                        }

                        tracing::info!("Device unregistered successfully");
                        (StatusCode::OK, "").into_response()
                    } else {
                        let _ = tx.rollback().await;
                        tracing::warn!("Device not found during deletion");
                        error_response(StatusCode::NOT_FOUND, "Device not found")
                    }
                }
                Err(e) => {
                    let _ = tx.rollback().await;
                    tracing::error!("Error deleting device: {}", e);
                    error_response(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Database error: {}", e),
                    )
                }
            }
        }
        Ok(None) => {
            let _ = tx.commit().await;
            tracing::info!("Device token not found, returning 200 OK");
            (StatusCode::OK, "").into_response()
        }
        Err(e) => {
            let _ = tx.rollback().await;
            tracing::error!("Database error during device lookup: {}", e);
            error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Database error: {}", e),
            )
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

    #[test]
    fn validate_device_token_rejects_short_and_whitespace_tokens() {
        assert!(validate_device_token("short-token").is_err());
        assert!(validate_device_token("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa bad").is_err());
        assert!(validate_device_token(&"a".repeat(64)).is_ok());
    }

    #[test]
    fn validate_did_list_rejects_invalid_entries() {
        let values = vec!["did:plc:ok".to_string(), "not-a-did".to_string()];

        assert!(validate_did_list(&values, "mutes").is_err());
    }

    #[test]
    fn validate_required_text_field_rejects_surrounding_whitespace_and_controls() {
        assert!(validate_required_text_field("  value", "field", 16).is_err());
        assert!(validate_required_text_field("value\n", "field", 16).is_err());
        assert!(validate_required_text_field("value", "field", 16).is_ok());
    }

    #[test]
    fn validate_moderation_lists_rejects_invalid_items() {
        let lists = vec![ModerationListDto {
            uri: " at://bad".to_string(),
            purpose: "modlist".to_string(),
            name: Some("valid".to_string()),
        }];

        assert!(validate_moderation_lists(&lists).is_err());
    }

    #[test]
    fn validate_thread_root_uri_rejects_whitespace() {
        assert!(validate_thread_root_uri("at://did:plc:abc/app.bsky.feed.post/123 456").is_err());
        assert!(validate_thread_root_uri("at://did:plc:abc/app.bsky.feed.post/123456").is_ok());
    }

    #[test]
    fn force_key_rotation_is_disabled_by_default() {
        let _guard = env_lock().lock().unwrap();
        std::env::remove_var("APP_ATTEST_ALLOW_FORCE_KEY_ROTATION");
        assert!(!force_key_rotation_enabled());

        std::env::set_var("APP_ATTEST_ALLOW_FORCE_KEY_ROTATION", "true");
        assert!(force_key_rotation_enabled());
        std::env::remove_var("APP_ATTEST_ALLOW_FORCE_KEY_ROTATION");
    }
}

async fn get_preferences(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<PreferencesQuery>,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if proof.body_sha256.is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "X-AppAttest-BodySHA256 is not accepted on GET requests",
        );
    }

    if let Err(resp) = validate_principal(&query.did, &query.device_token) {
        return resp;
    }

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash during preferences fetch for DID {}: {}",
                query.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    fetch_preferences_with_auth(state, query, &proof, client_data_hash, None).await
}

async fn get_preferences_post(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let query: PreferencesQuery = match parse_json_body(&body) {
        Ok(query) => query,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&query.did, &query.device_token) {
        return resp;
    }

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash during preferences POST for DID {}: {}",
                query.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    fetch_preferences_with_auth(state, query, &proof, client_data_hash, Some(body.as_ref())).await
}

async fn list_activity_subscriptions(
    State(state): State<ApiState>,
    headers: HeaderMap,
    Query(query): Query<ActivitySubscriptionQuery>,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if proof.body_sha256.is_some() {
        return error_response(
            StatusCode::BAD_REQUEST,
            "X-AppAttest-BodySHA256 is not accepted on GET requests",
        );
    }

    if let Err(resp) = validate_principal(&query.did, &query.device_token) {
        return resp;
    }

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash for activity subscription list on DID {}: {}",
                query.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(
                "Failed to start transaction for activity subscription list: {}",
                e
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let auth = match authenticate_device_for_request(
        &state,
        &mut tx,
        &query.did,
        &query.device_token,
        &proof,
        client_data_hash,
        None,
    )
    .await
    {
        Ok(auth) => auth,
        Err(resp) => {
            tx.rollback().await.ok();
            return resp;
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!(
            "Failed to commit activity subscription list transaction: {}",
            e
        );
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let subscriptions = match state
        .activity_subscription_manager
        .list_for_subscriber(&query.did)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(
                "Failed to list activity subscriptions for {}: {}",
                query.did,
                err
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let payload = ActivitySubscriptionsResponse {
        subscriptions: subscriptions
            .into_iter()
            .map(ActivitySubscriptionDto::from)
            .collect(),
        next_challenge: ChallengeEnvelope {
            challenge: auth.next_challenge,
            expires_at: auth.next_challenge_expires_at,
        },
    };

    Json(payload).into_response()
}

async fn list_activity_subscriptions_post(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let query: ActivitySubscriptionQuery = match parse_json_body(&body) {
        Ok(query) => query,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&query.did, &query.device_token) {
        return resp;
    }

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash for activity subscription list POST on DID {}: {}",
                query.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(
                "Failed to start transaction for activity subscription list POST: {}",
                e
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let auth = match authenticate_device_for_request(
        &state,
        &mut tx,
        &query.did,
        &query.device_token,
        &proof,
        client_data_hash,
        Some(body.as_ref()),
    )
    .await
    {
        Ok(auth) => auth,
        Err(resp) => {
            tx.rollback().await.ok();
            return resp;
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!(
            "Failed to commit activity subscription list POST transaction: {}",
            e
        );
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let subscriptions = match state
        .activity_subscription_manager
        .list_for_subscriber(&query.did)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(
                "Failed to list activity subscriptions for {}: {}",
                query.did,
                err
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let payload = ActivitySubscriptionsResponse {
        subscriptions: subscriptions
            .into_iter()
            .map(ActivitySubscriptionDto::from)
            .collect(),
        next_challenge: ChallengeEnvelope {
            challenge: auth.next_challenge,
            expires_at: auth.next_challenge_expires_at,
        },
    };

    Json(payload).into_response()
}

async fn update_preferences(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: PreferencesUpdateRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash for preferences update on DID {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!("Failed to start transaction for preferences update: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let auth = match authenticate_device_for_request(
        &state,
        &mut tx,
        &req.did,
        &req.device_token,
        &proof,
        client_data_hash,
        Some(body.as_ref()),
    )
    .await
    {
        Ok(auth) => auth,
        Err(resp) => {
            tx.rollback().await.ok();
            return resp;
        }
    };

    let device_ids = match sqlx::query_scalar::<_, uuid::Uuid>(
        r#"
        SELECT id
        FROM user_devices
        WHERE did = $1
        "#,
    )
    .bind(&req.did)
    .fetch_all(tx.as_mut())
    .await
    {
        Ok(ids) if !ids.is_empty() => ids,
        Ok(_) => {
            tx.rollback().await.ok();
            return error_response(StatusCode::NOT_FOUND, "no devices found for DID");
        }
        Err(e) => {
            tx.rollback().await.ok();
            tracing::error!("Failed to enumerate devices for preferences update: {}", e);
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    for device_id in device_ids {
        if let Err(e) = sqlx::query(
            r#"
            UPDATE notification_preferences
            SET mentions = $1,
                replies = $2,
                likes = $3,
                follows = $4,
                reposts = $5,
                quotes = $6,
                via_likes = $7,
                via_reposts = $8,
                activity_subscriptions = $9
            WHERE user_id = $10
            "#,
        )
        .bind(req.mentions)
        .bind(req.replies)
        .bind(req.likes)
        .bind(req.follows)
        .bind(req.reposts)
        .bind(req.quotes)
        .bind(req.via_likes)
        .bind(req.via_reposts)
        .bind(req.activity_subscriptions)
        .bind(device_id)
        .execute(tx.as_mut())
        .await
        {
            tx.rollback().await.ok();
            tracing::error!(
                "Failed to update preferences for device {}: {}",
                device_id,
                e
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    }

    if let Err(e) = tx.commit().await {
        tracing::error!("Failed to commit preferences update: {}", e);
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let response = PreferencesResponse {
        preferences: PreferencesBody {
            did: req.did,
            mentions: req.mentions,
            replies: req.replies,
            likes: req.likes,
            follows: req.follows,
            reposts: req.reposts,
            quotes: req.quotes,
            via_likes: req.via_likes,
            via_reposts: req.via_reposts,
            activity_subscriptions: req.activity_subscriptions,
        },
        next_challenge: ChallengeEnvelope {
            challenge: auth.next_challenge,
            expires_at: auth.next_challenge_expires_at,
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn upsert_activity_subscription(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: ActivitySubscriptionUpdateRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    if let Err(resp) = validate_did(&req.subject_did) {
        return resp;
    }

    let remove_only = !req.include_posts && !req.include_replies;

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash for activity subscription update on DID {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(
                "Failed to start transaction for activity subscription update: {}",
                e
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let auth = match authenticate_device_for_request(
        &state,
        &mut tx,
        &req.did,
        &req.device_token,
        &proof,
        client_data_hash,
        Some(body.as_ref()),
    )
    .await
    {
        Ok(auth) => auth,
        Err(resp) => {
            tx.rollback().await.ok();
            return resp;
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!(
            "Failed to commit activity subscription update transaction: {}",
            e
        );
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let manager = state.activity_subscription_manager.clone();

    let update_result = if remove_only {
        manager
            .delete_subscription(&req.did, &req.subject_did)
            .await
    } else {
        manager
            .upsert_subscription(
                &req.did,
                &req.subject_did,
                req.include_posts,
                req.include_replies,
            )
            .await
    };

    if let Err(err) = update_result {
        tracing::error!(
            "Failed to persist activity subscription change for {} -> {}: {}",
            req.did,
            req.subject_did,
            err
        );
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let subscriptions = match state
        .activity_subscription_manager
        .list_for_subscriber(&req.did)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(
                "Failed to list activity subscriptions after update for {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let response = ActivitySubscriptionsResponse {
        subscriptions: subscriptions
            .into_iter()
            .map(ActivitySubscriptionDto::from)
            .collect(),
        next_challenge: ChallengeEnvelope {
            challenge: auth.next_challenge,
            expires_at: auth.next_challenge_expires_at,
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}

async fn remove_activity_subscription(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: ActivitySubscriptionDeleteRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    if let Err(resp) = validate_did(&req.subject_did) {
        return resp;
    }

    let client_data_hash = match state
        .app_attest_service
        .compute_client_data_hash(&proof.challenge, proof.body_sha256.as_deref())
    {
        Ok(hash) => hash.to_vec(),
        Err(err) => {
            tracing::warn!(
                "Failed to prepare clientDataHash for activity subscription removal on DID {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::BAD_REQUEST, "invalid App Attest parameters");
        }
    };

    let mut tx = match state.db_pool.begin().await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(
                "Failed to start transaction for activity subscription removal: {}",
                e
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let auth = match authenticate_device_for_request(
        &state,
        &mut tx,
        &req.did,
        &req.device_token,
        &proof,
        client_data_hash,
        Some(body.as_ref()),
    )
    .await
    {
        Ok(auth) => auth,
        Err(resp) => {
            tx.rollback().await.ok();
            return resp;
        }
    };

    if let Err(e) = tx.commit().await {
        tracing::error!(
            "Failed to commit activity subscription removal transaction: {}",
            e
        );
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    if let Err(err) = state
        .activity_subscription_manager
        .delete_subscription(&req.did, &req.subject_did)
        .await
    {
        tracing::error!(
            "Failed to delete activity subscription for {} -> {}: {}",
            req.did,
            req.subject_did,
            err
        );
        return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
    }

    let subscriptions = match state
        .activity_subscription_manager
        .list_for_subscriber(&req.did)
        .await
    {
        Ok(list) => list,
        Err(err) => {
            tracing::error!(
                "Failed to list activity subscriptions after removal for {}: {}",
                req.did,
                err
            );
            return error_response(StatusCode::INTERNAL_SERVER_ERROR, "database error");
        }
    };

    let response = ActivitySubscriptionsResponse {
        subscriptions: subscriptions
            .into_iter()
            .map(ActivitySubscriptionDto::from)
            .collect(),
        next_challenge: ChallengeEnvelope {
            challenge: auth.next_challenge,
            expires_at: auth.next_challenge_expires_at,
        },
    };

    (StatusCode::OK, Json(response)).into_response()
}

// Sync moderation lists
async fn sync_moderation_lists(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: SyncModerationListsRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    if let Err(resp) = validate_moderation_lists(&req.lists) {
        return resp;
    }

    // Verify App Attest assertion
    if let Err(resp) =
        verify_app_attest_assertion(&state, &req.did, &req.device_token, &proof, &body).await
    {
        return resp;
    }

    // Convert DTOs to manager types
    let lists: Vec<ModerationList> = req
        .lists
        .into_iter()
        .map(|l| ModerationList {
            uri: l.uri,
            purpose: l.purpose,
            name: l.name,
        })
        .collect();

    match state
        .moderation_list_manager
        .sync_moderation_lists(&req.did, lists)
        .await
    {
        Ok(_) => {
            info!("Successfully synced moderation lists for user {}", req.did);
            (
                StatusCode::OK,
                Json(serde_json::json!({"status": "success"})),
            )
                .into_response()
        }
        Err(e) => {
            error!("Failed to sync moderation lists: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to sync lists"})),
            )
                .into_response()
        }
    }
}

// Mute thread
async fn mute_thread(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: MuteThreadRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    if let Err(resp) = validate_thread_root_uri(&req.thread_root_uri) {
        return resp;
    }

    // Verify App Attest assertion
    if let Err(resp) =
        verify_app_attest_assertion(&state, &req.did, &req.device_token, &proof, &body).await
    {
        return resp;
    }

    match state
        .thread_mute_manager
        .mute_thread(&req.did, &req.thread_root_uri)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "success"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to mute thread: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to mute thread"})),
            )
                .into_response()
        }
    }
}

// Unmute thread
async fn unmute_thread(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: UnmuteThreadRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    if let Err(resp) = validate_thread_root_uri(&req.thread_root_uri) {
        return resp;
    }

    // Verify App Attest assertion
    if let Err(resp) =
        verify_app_attest_assertion(&state, &req.did, &req.device_token, &proof, &body).await
    {
        return resp;
    }

    match state
        .thread_mute_manager
        .unmute_thread(&req.did, &req.thread_root_uri)
        .await
    {
        Ok(_) => (
            StatusCode::OK,
            Json(serde_json::json!({"status": "success"})),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to unmute thread: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to unmute thread"})),
            )
                .into_response()
        }
    }
}

// Get muted threads (GET)
async fn get_muted_threads(
    State(state): State<ApiState>,
    Query(req): Query<GetMutedThreadsRequest>,
) -> impl IntoResponse {
    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    match state.thread_mute_manager.get_muted_threads(&req.did).await {
        Ok(threads) => (StatusCode::OK, Json(MutedThreadsResponse { threads })).into_response(),
        Err(e) => {
            error!("Failed to get muted threads: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to get muted threads"})),
            )
                .into_response()
        }
    }
}

// Get muted threads (POST)
async fn get_muted_threads_post(
    State(state): State<ApiState>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let proof = match AppAttestRequestProof::from_headers(&headers) {
        Ok(proof) => proof,
        Err(resp) => return resp,
    };

    if let Err(resp) = verify_body_binding(&body, proof.body_sha256.as_deref()) {
        return resp;
    }

    let req: GetMutedThreadsRequest = match parse_json_body(&body) {
        Ok(req) => req,
        Err(resp) => return resp,
    };

    if let Err(resp) = validate_principal(&req.did, &req.device_token) {
        return resp;
    }

    // Verify App Attest assertion
    if let Err(resp) =
        verify_app_attest_assertion(&state, &req.did, &req.device_token, &proof, &body).await
    {
        return resp;
    }

    match state.thread_mute_manager.get_muted_threads(&req.did).await {
        Ok(threads) => (StatusCode::OK, Json(MutedThreadsResponse { threads })).into_response(),
        Err(e) => {
            error!("Failed to get muted threads: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": "Failed to get muted threads"})),
            )
                .into_response()
        }
    }
}
