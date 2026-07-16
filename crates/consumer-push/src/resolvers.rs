use ::time::Duration as TimeDuration;
use anyhow::{Context, Result};
use circuit_breaker::CircuitBreaker;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, Row};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, watch, Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, info, warn};
use url::Url;

// ============================================================================
// DID Resolver
// ============================================================================

/// Simplified DID Document structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidDocument {
    pub id: String,
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Option<Vec<String>>,
    pub service: Option<Vec<Service>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub service_type: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

/// Cache entry with expiration
#[derive(Clone)]
struct CachedDidInfo {
    #[allow(dead_code)]
    document: DidDocument,
    handle: String,
    expires_at: Instant,
}

// TODO: Migrate to jacquard-identity PublicResolver once the dependency is integrated.
// The current implementation uses direct HTTP calls to plc.directory and did:web endpoints.
#[derive(Clone)]
pub struct DidResolver {
    http_client: HttpClient,
    memory_cache: Arc<RwLock<HashMap<String, CachedDidInfo>>>,
    db_pool: Pool<Postgres>,
    ttl: Duration,
}

impl DidResolver {
    pub fn new(db_pool: Pool<Postgres>, ttl_hours: u64) -> Self {
        Self {
            http_client: HttpClient::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            db_pool,
            ttl: Duration::from_secs(ttl_hours * 3600),
        }
    }

    /// Get a handle from a DID
    pub async fn get_handle(&self, did: &str) -> Result<String> {
        // 1. Check memory cache first
        let handle = self.get_from_memory_cache(did).await;
        if let Some(handle) = handle {
            debug!(did = %did, handle = %handle, "Handle found in memory cache");
            return Ok(handle);
        }

        // 2. Check database cache
        let db_result = self.get_from_db_cache(did).await?;
        if let Some((document, handle)) = db_result {
            self.update_memory_cache(did.to_string(), document, handle.clone())
                .await;
            debug!(did = %did, handle = %handle, "Handle found in database cache");
            return Ok(handle);
        }

        // 3. Resolve via network
        info!(did = %did, "Resolving DID from network");
        let (document, handle) = self.resolve_did_network(did).await?;

        // 4. Update both caches
        self.update_caches(did.to_string(), document.clone(), handle.clone())
            .await?;

        Ok(handle)
    }

    async fn get_from_memory_cache(&self, did: &str) -> Option<String> {
        let cache = self.memory_cache.read().await;
        if let Some(cached) = cache.get(did) {
            if cached.expires_at > Instant::now() {
                return Some(cached.handle.clone());
            }
        }
        None
    }

    async fn get_from_db_cache(&self, did: &str) -> Result<Option<(DidDocument, String)>> {
        let row = sqlx::query(
            r#"
            SELECT document, handle, expires_at
            FROM did_cache
            WHERE did = $1 AND expires_at > NOW()
            "#,
        )
        .bind(did)
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some(row) = row {
            let doc_json: serde_json::Value = row.get("document");
            let handle: String = row.get("handle");
            let document: DidDocument = serde_json::from_value(doc_json)
                .with_context(|| "Failed to deserialize DID document from database")?;
            return Ok(Some((document, handle)));
        }

        Ok(None)
    }

    async fn update_memory_cache(&self, did: String, document: DidDocument, handle: String) {
        let mut cache = self.memory_cache.write().await;
        cache.insert(
            did,
            CachedDidInfo {
                document,
                handle,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    async fn update_caches(
        &self,
        did: String,
        document: DidDocument,
        handle: String,
    ) -> Result<()> {
        let expires_at = time::OffsetDateTime::now_utc() + time::Duration::hours(24);
        let json_doc = serde_json::to_value(document.clone())
            .with_context(|| "Failed to serialize DID document")?;

        sqlx::query(
            r#"
            INSERT INTO did_cache (did, document, handle, expires_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (did) DO UPDATE
            SET document = $2, handle = $3, expires_at = $4
            "#,
        )
        .bind(did.as_str())
        .bind(&json_doc)
        .bind(&handle)
        .bind(expires_at)
        .execute(&self.db_pool)
        .await?;

        self.update_memory_cache(did, document, handle).await;

        Ok(())
    }

    async fn resolve_did_network(&self, did: &str) -> Result<(DidDocument, String)> {
        if did.starts_with("did:plc:") {
            self.resolve_plc_did(did).await
        } else if did.starts_with("did:web:") {
            self.resolve_web_did(did).await
        } else {
            Err(anyhow::anyhow!("Unsupported DID method: {}", did))
        }
    }

    async fn resolve_plc_did(&self, did: &str) -> Result<(DidDocument, String)> {
        let url = format!("https://plc.directory/{}", did);
        let response = self
            .http_client
            .get(&url)
            .send()
            .await
            .with_context(|| "Failed to fetch PLC DID document")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch PLC DID document, status: {}",
                response.status()
            ));
        }

        let document: DidDocument = response
            .json()
            .await
            .with_context(|| "Failed to parse PLC DID document")?;

        let handle = self.extract_handle_from_document(&document)?;

        Ok((document, handle))
    }

    async fn resolve_web_did(&self, did: &str) -> Result<(DidDocument, String)> {
        let url = build_did_web_well_known_url(did)?;

        let response = self
            .http_client
            .get(url.clone())
            .send()
            .await
            .with_context(|| "Failed to fetch Web DID document")?;

        if !response.status().is_success() {
            return Err(anyhow::anyhow!(
                "Failed to fetch Web DID document, status: {}",
                response.status()
            ));
        }

        let document: DidDocument = response
            .json()
            .await
            .with_context(|| "Failed to parse Web DID document")?;

        if document.id != did {
            return Err(anyhow::anyhow!(
                "Resolved DID document id mismatch for did:web: expected {}, got {}",
                did,
                document.id
            ));
        }

        let handle = self.extract_handle_from_document(&document)?;

        Ok((document, handle))
    }

    fn extract_handle_from_document(&self, document: &DidDocument) -> Result<String> {
        if let Some(aka) = &document.also_known_as {
            for name in aka {
                if name.starts_with("at://") {
                    return Ok(name.strip_prefix("at://").unwrap_or(name).to_string());
                }
                if name.contains("/profile/") {
                    let parts: Vec<&str> = name.split("/profile/").collect();
                    if parts.len() > 1 {
                        return Ok(parts[1].to_string());
                    }
                }
            }
        }

        let fallback = did_to_fallback_handle(&document.id);
        Ok(fallback)
    }

    /// Get handles for multiple DIDs in bulk
    pub async fn get_handles_bulk(&self, dids: &[String]) -> HashMap<String, String> {
        let mut result = HashMap::new();

        // 1. Try memory cache first for all DIDs
        {
            let cache = self.memory_cache.read().await;
            for did in dids {
                if let Some(cached) = cache.get(did) {
                    if cached.expires_at > Instant::now() {
                        result.insert(did.clone(), cached.handle.clone());
                        crate::metrics::DID_CACHE_HITS.inc();
                    }
                }
            }
        }

        // 2. Find missing DIDs
        let missing_dids: Vec<String> = dids
            .iter()
            .filter(|did| !result.contains_key(*did))
            .cloned()
            .collect();

        if missing_dids.is_empty() {
            return result;
        }

        // 3. Try database cache for missing DIDs
        if let Ok(db_results) = self.get_from_db_cache_bulk(&missing_dids).await {
            for (did, doc, handle) in db_results {
                result.insert(did.clone(), handle.clone());
                self.update_memory_cache(did, doc, handle).await;
                crate::metrics::DID_CACHE_HITS.inc();
            }
        }

        // 4. Find still missing DIDs
        let still_missing: Vec<String> = dids
            .iter()
            .filter(|did| !result.contains_key(*did))
            .cloned()
            .collect();

        if still_missing.is_empty() {
            return result;
        }

        // 5. Resolve remaining DIDs with limited concurrency
        let semaphore = Arc::new(tokio::sync::Semaphore::new(5));
        let mut set = tokio::task::JoinSet::new();

        crate::metrics::DID_CACHE_MISSES.inc_by(still_missing.len() as f64);

        for did in still_missing {
            let sem = semaphore.clone();
            let resolver = self.clone();

            set.spawn(async move {
                let timer = std::time::Instant::now();
                let _permit = sem.acquire().await.unwrap();
                match resolver.resolve_did_network(&did).await {
                    Ok((doc, handle)) => {
                        let elapsed = timer.elapsed().as_secs_f64();
                        crate::metrics::DID_RESOLUTION_TIME.observe(elapsed);
                        Some((did, doc, handle))
                    }
                    Err(e) => {
                        warn!("Failed to resolve DID {}: {}", did, e);
                        None
                    }
                }
            });
        }

        while let Some(join_result) = set.join_next().await {
            if let Ok(Some((did, doc, handle))) = join_result {
                result.insert(did.clone(), handle.clone());
                if let Err(e) = self.update_caches(did, doc, handle).await {
                    warn!("Failed to update caches: {}", e);
                }
            }
        }

        result
    }

    async fn get_from_db_cache_bulk(
        &self,
        dids: &[String],
    ) -> Result<Vec<(String, DidDocument, String)>> {
        let mut results = Vec::new();

        for chunk in dids.chunks(50) {
            let placeholders: Vec<String> = (1..=chunk.len()).map(|i| format!("${}", i)).collect();

            let query = format!(
                "SELECT did, document, handle FROM did_cache
                WHERE did IN ({}) AND expires_at > NOW()",
                placeholders.join(",")
            );

            let mut q = sqlx::query(&query);
            for did in chunk {
                q = q.bind(did);
            }

            let rows = q.fetch_all(&self.db_pool).await?;

            for row in rows {
                let did: String = row.get("did");
                let doc_json: serde_json::Value = row.get("document");
                let handle: String = row.get("handle");

                if let Ok(doc) = serde_json::from_value(doc_json) {
                    results.push((did, doc, handle));
                }
            }
        }

        Ok(results)
    }

    /// Cleanup expired entries
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let mut memory_cleaned = 0;
        {
            let mut cache = self.memory_cache.write().await;
            let now = Instant::now();
            cache.retain(|_, v| {
                let keep = v.expires_at > now;
                if !keep {
                    memory_cleaned += 1;
                }
                keep
            });
        }

        let db_result = sqlx::query("DELETE FROM did_cache WHERE expires_at <= NOW()")
            .execute(&self.db_pool)
            .await?;

        let db_cleaned = db_result.rows_affected() as usize;

        info!(
            memory_cleaned = %memory_cleaned,
            db_cleaned = %db_cleaned,
            "Cleaned expired DID cache entries"
        );

        Ok(memory_cleaned + db_cleaned)
    }
}

fn build_did_web_well_known_url(did: &str) -> Result<Url> {
    let authority = did
        .strip_prefix("did:web:")
        .ok_or_else(|| anyhow::anyhow!("Invalid did:web format"))?;

    if authority.is_empty()
        || authority.contains('/')
        || authority.contains('?')
        || authority.contains('#')
        || authority.contains('@')
        || authority.contains('%')
        || authority.contains(':')
    {
        anyhow::bail!("Unsupported or unsafe did:web authority");
    }

    let url = Url::parse(&format!("https://{authority}/.well-known/did.json"))
        .with_context(|| "Invalid did:web authority")?;

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("did:web host is missing"))?;

    if host.eq_ignore_ascii_case("localhost") {
        anyhow::bail!("did:web localhost resolution is not allowed");
    }

    if host.parse::<IpAddr>().is_ok() {
        anyhow::bail!("did:web IP address resolution is not allowed");
    }

    if url.port().is_some() {
        anyhow::bail!("did:web explicit ports are not allowed");
    }

    Ok(url)
}

#[cfg(test)]
mod tests {
    use super::build_did_web_well_known_url;

    #[test]
    fn accepts_simple_did_web_domain() {
        let url = build_did_web_well_known_url("did:web:example.com").unwrap();

        assert_eq!(url.as_str(), "https://example.com/.well-known/did.json");
    }

    #[test]
    fn rejects_did_web_with_port_or_path_encoding() {
        assert!(build_did_web_well_known_url("did:web:example.com:admin").is_err());
        assert!(build_did_web_well_known_url("did:web:example.com%3A8443").is_err());
    }

    #[test]
    fn rejects_local_or_ip_hosts() {
        assert!(build_did_web_well_known_url("did:web:localhost").is_err());
        assert!(build_did_web_well_known_url("did:web:127.0.0.1").is_err());
    }
}

/// Helper function to create a fallback handle from a DID
fn did_to_fallback_handle(did: &str) -> String {
    let parts: Vec<&str> = did.split(':').collect();
    let last_part = parts.last().unwrap_or(&did);

    if last_part.len() > 8 {
        format!("user_{}", &last_part[0..8])
    } else {
        format!("user_{}", last_part)
    }
}

// ============================================================================
// Post Resolver
// ============================================================================

/// API response structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GetPostsResponse {
    pub posts: Vec<PostView>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostView {
    pub uri: String,
    pub cid: String,
    pub author: Author,
    pub record: PostRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Author {
    pub did: String,
    pub handle: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PostRecord {
    pub text: String,
    #[serde(rename = "createdAt")]
    pub created_at: String,
}

/// Cache entry with expiration
#[derive(Clone)]
struct CachedPostInfo {
    #[allow(dead_code)]
    uri: String,
    text: String,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct PostResolver {
    http_client: HttpClient,
    memory_cache: Arc<RwLock<HashMap<String, CachedPostInfo>>>,
    db_pool: Pool<Postgres>,
    ttl: Duration,
    bsky_service_url: String,
    api_circuit_breaker: Arc<RwLock<CircuitBreaker>>,
    request_queue: Arc<Mutex<HashMap<String, oneshot::Sender<Result<String>>>>>,
    trigger_send: Arc<tokio::sync::Notify>,
    processor_shutdown_tx: watch::Sender<bool>,
    processor_handle: Arc<Mutex<Option<JoinHandle<()>>>>,
}

impl PostResolver {
    pub fn new(db_pool: Pool<Postgres>, ttl_minutes: u64, bsky_service_url: String) -> Self {
        let request_queue = Arc::new(Mutex::new(HashMap::new()));
        let trigger_send = Arc::new(tokio::sync::Notify::new());
        let (processor_shutdown_tx, processor_shutdown_rx) = watch::channel(false);

        let circuit_breaker = CircuitBreaker::new(5, Duration::from_secs(30));

        let resolver = Self {
            http_client: HttpClient::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .expect("Failed to create HTTP client"),
            memory_cache: Arc::new(RwLock::new(HashMap::new())),
            db_pool,
            ttl: Duration::from_secs(ttl_minutes * 60),
            bsky_service_url,
            api_circuit_breaker: Arc::new(RwLock::new(circuit_breaker)),
            request_queue,
            trigger_send,
            processor_shutdown_tx,
            processor_handle: Arc::new(Mutex::new(None)),
        };

        // Start background task for batch processing
        let resolver_clone = resolver.clone();
        let handle = tokio::spawn(async move {
            resolver_clone
                .run_request_processor(processor_shutdown_rx)
                .await;
        });

        if let Ok(mut slot) = resolver.processor_handle.try_lock() {
            *slot = Some(handle);
        }

        resolver
    }

    pub async fn shutdown(&self) {
        if self.processor_shutdown_tx.send(true).is_err() {
            return;
        }

        let mut handle_slot = self.processor_handle.lock().await;
        if let Some(handle) = handle_slot.take() {
            if let Err(e) = handle.await {
                warn!("Post request processor task ended unexpectedly: {}", e);
            }
        }
    }

    /// Get post content from URI
    pub async fn get_post_content(&self, uri: &str) -> Result<String> {
        let timer = std::time::Instant::now();

        // 1. Check memory cache first
        let content = self.get_from_memory_cache(uri).await;
        if let Some(content) = content {
            crate::metrics::POST_CACHE_HITS.inc();
            let elapsed = timer.elapsed().as_secs_f64();
            crate::metrics::POST_FETCH_TIME.observe(elapsed);
            debug!(uri = %uri, "Post content found in memory cache");
            return Ok(content);
        }

        // 2. Check database cache
        let db_result = self.get_from_db_cache(uri).await?;
        if let Some((uri_str, text)) = db_result {
            self.update_memory_cache(uri_str, text.clone()).await;
            crate::metrics::POST_CACHE_HITS.inc();
            let elapsed = timer.elapsed().as_secs_f64();
            crate::metrics::POST_FETCH_TIME.observe(elapsed);
            debug!(uri = %uri, "Post content found in database cache");
            return Ok(text);
        }

        // 3. Record cache miss metric
        crate::metrics::POST_CACHE_MISSES.inc();

        // 4. Queue request for batch processing
        info!(uri = %uri, "Queuing post content fetch for batch processing");
        let (sender, receiver) = oneshot::channel();
        {
            let mut queue = self.request_queue.lock().await;
            queue.insert(uri.to_string(), sender);
        }

        self.trigger_send.notify_one();

        match tokio::time::timeout(Duration::from_millis(150), receiver).await {
            Ok(result) => match result {
                Ok(text) => {
                    let elapsed = timer.elapsed().as_secs_f64();
                    crate::metrics::POST_FETCH_TIME.observe(elapsed);
                    debug!(uri = %uri, "Received post content from batch processor");
                    text
                }
                Err(_) => {
                    warn!(uri = %uri, "Batch processor disappeared, falling back to direct fetch");
                    self.fetch_and_cache_individual(uri, timer).await
                }
            },
            Err(_) => {
                warn!(uri = %uri, "Batch processing timeout, falling back to direct fetch");
                self.fetch_and_cache_individual(uri, timer).await
            }
        }
    }

    async fn fetch_and_cache_individual(&self, uri: &str, timer: Instant) -> Result<String> {
        match self.fetch_post_from_network_individual(uri).await {
            Ok(text) => {
                let uri_clone = uri.to_string();
                let text_clone = text.clone();
                if let Err(e) = self.update_caches(uri_clone, text_clone).await {
                    warn!("Failed to update caches: {}", e);
                }

                let elapsed = timer.elapsed().as_secs_f64();
                crate::metrics::POST_FETCH_TIME.observe(elapsed);

                Ok(text)
            }
            Err(e) => Err(e),
        }
    }

    async fn get_from_memory_cache(&self, uri: &str) -> Option<String> {
        let cache = self.memory_cache.read().await;
        if let Some(cached) = cache.get(uri) {
            if cached.expires_at > Instant::now() {
                return Some(cached.text.clone());
            }
        }
        None
    }

    async fn get_from_db_cache(&self, uri: &str) -> Result<Option<(String, String)>> {
        let row = sqlx::query(
            r#"
            SELECT uri, text, expires_at
            FROM post_cache
            WHERE uri = $1 AND expires_at > NOW()
            "#,
        )
        .bind(uri)
        .fetch_optional(&self.db_pool)
        .await?;

        if let Some(row) = row {
            let uri: String = row.get("uri");
            let text: String = row.get("text");
            return Ok(Some((uri, text)));
        }

        Ok(None)
    }

    async fn update_memory_cache(&self, uri: String, text: String) {
        let mut cache = self.memory_cache.write().await;
        cache.insert(
            uri.clone(),
            CachedPostInfo {
                uri,
                text,
                expires_at: Instant::now() + self.ttl,
            },
        );
    }

    async fn update_caches(&self, uri: String, text: String) -> Result<()> {
        let expires_at = time::OffsetDateTime::now_utc() + TimeDuration::minutes(60);

        sqlx::query(
            r#"
            INSERT INTO post_cache (uri, text, expires_at)
            VALUES ($1, $2, $3)
            ON CONFLICT (uri) DO UPDATE
            SET text = $2, expires_at = $3
            "#,
        )
        .bind(uri.as_str())
        .bind(&text)
        .bind(expires_at)
        .execute(&self.db_pool)
        .await?;

        self.update_memory_cache(uri, text).await;

        Ok(())
    }

    async fn fetch_posts_batch(&self, uris: &[String]) -> Result<HashMap<String, String>> {
        let circuit_breaker = self.api_circuit_breaker.read().await;
        let is_open = matches!(circuit_breaker.state(), circuit_breaker::CircuitState::Open);

        if is_open {
            warn!("Circuit breaker open, returning fallback content for batch request");
            let mut results = HashMap::new();
            for uri in uris {
                results.insert(uri.clone(), "Content temporarily unavailable".to_string());
            }
            return Ok(results);
        }
        drop(circuit_breaker);

        let batch_timer = std::time::Instant::now();

        let url = format!(
            "https://{}/xrpc/app.bsky.feed.getPosts",
            self.bsky_service_url
        );

        let query_params = uris
            .iter()
            .map(|uri| ("uris", uri.as_str()))
            .collect::<Vec<_>>();

        let response_result = self.http_client.get(&url).query(&query_params).send().await;

        match response_result {
            Ok(response) => {
                if response.status().is_success() {
                    self.api_circuit_breaker.write().await.handle_success();

                    match response.json::<GetPostsResponse>().await {
                        Ok(post_data) => {
                            let mut results = HashMap::new();

                            for post in post_data.posts {
                                let text = if post.record.text.len() > 140 {
                                    format!("{}...", &post.record.text[..137])
                                } else {
                                    post.record.text
                                };

                                results.insert(post.uri, text);
                            }

                            let elapsed = batch_timer.elapsed().as_secs_f64();
                            info!(
                                "Batch request for {} URIs completed in {:.2}s, received {} posts",
                                uris.len(),
                                elapsed,
                                results.len()
                            );

                            Ok(results)
                        }
                        Err(e) => {
                            self.api_circuit_breaker.write().await.handle_failure();
                            Err(anyhow::anyhow!("Failed to parse batch post data: {}", e))
                        }
                    }
                } else {
                    self.api_circuit_breaker.write().await.handle_failure();
                    Err(anyhow::anyhow!(
                        "Failed to fetch batch posts, status: {}",
                        response.status()
                    ))
                }
            }
            Err(e) => {
                self.api_circuit_breaker.write().await.handle_failure();
                Err(anyhow::anyhow!("Failed to fetch batch post content: {}", e))
            }
        }
    }

    async fn fetch_post_from_network_individual(&self, uri: &str) -> Result<String> {
        let circuit_breaker = self.api_circuit_breaker.read().await;
        let is_open = matches!(circuit_breaker.state(), circuit_breaker::CircuitState::Open);

        if is_open {
            warn!(
                "Circuit breaker open, returning fallback content for {}",
                uri
            );
            return Ok("Content temporarily unavailable".to_string());
        }
        drop(circuit_breaker);

        let url = format!(
            "https://{}/xrpc/app.bsky.feed.getPosts",
            self.bsky_service_url
        );

        let response_result = self
            .http_client
            .get(&url)
            .query(&[("uris", uri)])
            .send()
            .await;

        match response_result {
            Ok(response) => {
                if response.status().is_success() {
                    self.api_circuit_breaker.write().await.handle_success();

                    match response.json::<GetPostsResponse>().await {
                        Ok(post_data) => {
                            let post_text = post_data
                                .posts
                                .get(0)
                                .ok_or_else(|| {
                                    anyhow::anyhow!("No posts returned for URI: {}", uri)
                                })?
                                .record
                                .text
                                .clone();

                            let truncated_text = if post_text.len() > 140 {
                                format!("{}...", &post_text[..137])
                            } else {
                                post_text
                            };

                            Ok(truncated_text)
                        }
                        Err(e) => {
                            self.api_circuit_breaker.write().await.handle_failure();
                            Err(anyhow::anyhow!(
                                "Failed to parse post data for URI {}: {}",
                                uri,
                                e
                            ))
                        }
                    }
                } else {
                    self.api_circuit_breaker.write().await.handle_failure();
                    Err(anyhow::anyhow!(
                        "Failed to fetch post, status: {}",
                        response.status()
                    ))
                }
            }
            Err(e) => {
                self.api_circuit_breaker.write().await.handle_failure();
                Err(anyhow::anyhow!(
                    "Failed to fetch post content for URI {}: {}",
                    uri,
                    e
                ))
            }
        }
    }

    /// Cleanup expired entries
    pub async fn cleanup_expired(&self) -> Result<usize> {
        let mut memory_cleaned = 0;
        {
            let mut cache = self.memory_cache.write().await;
            let now = Instant::now();
            cache.retain(|_, v| {
                let keep = v.expires_at > now;
                if !keep {
                    memory_cleaned += 1;
                }
                keep
            });
        }

        let db_result = sqlx::query("DELETE FROM post_cache WHERE expires_at <= NOW()")
            .execute(&self.db_pool)
            .await?;

        let db_cleaned = db_result.rows_affected() as usize;

        info!(
            memory_cleaned = %memory_cleaned,
            db_cleaned = %db_cleaned,
            "Cleaned expired post cache entries"
        );

        Ok(memory_cleaned + db_cleaned)
    }

    /// Background task to process batched requests
    async fn run_request_processor(&self, mut shutdown: watch::Receiver<bool>) {
        let max_batch_size = 25;
        let max_wait_time = Duration::from_millis(50);

        loop {
            tokio::select! {
                _ = self.trigger_send.notified() => {
                    // Continue immediately to process
                },
                _ = tokio::time::sleep(max_wait_time) => {
                    let queue_len = {
                        let queue = self.request_queue.lock().await;
                        queue.len()
                    };

                    if queue_len == 0 {
                        continue;
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        info!("Stopping post request processor");
                        break;
                    }
                }
            }

            let requests = {
                let mut queue = self.request_queue.lock().await;
                if queue.is_empty() {
                    continue;
                }

                let mut requests = HashMap::new();
                let keys: Vec<String> = queue.keys().cloned().take(max_batch_size).collect();
                for key in keys {
                    if let Some(sender) = queue.remove(&key) {
                        requests.insert(key, sender);
                    }
                }

                requests
            };

            if requests.is_empty() {
                continue;
            }

            let batch_size = requests.len() as f64;
            crate::metrics::POST_BATCH_SIZE.observe(batch_size);

            info!("Processing batch of {} post requests", batch_size);

            let batch_timer = std::time::Instant::now();

            let uris: Vec<String> = requests.keys().cloned().collect();
            match self.fetch_posts_batch(&uris).await {
                Ok(results) => {
                    let elapsed = batch_timer.elapsed().as_secs_f64();
                    crate::metrics::POST_BATCH_LATENCY.observe(elapsed);

                    info!(
                        "Batch request for {} URIs completed in {:.2}s, received {} posts",
                        batch_size,
                        elapsed,
                        results.len()
                    );

                    for (uri, text) in &results {
                        if let Err(e) = self.update_caches(uri.clone(), text.clone()).await {
                            warn!("Failed to update cache for {}: {}", uri, e);
                        }
                    }

                    for (uri, sender) in requests {
                        if let Some(text) = results.get(&uri) {
                            let _ = sender.send(Ok(text.clone()));
                        } else {
                            match self.fetch_post_from_network_individual(&uri).await {
                                Ok(text) => {
                                    if let Err(e) =
                                        self.update_caches(uri.clone(), text.clone()).await
                                    {
                                        warn!("Failed to update cache for {}: {}", uri, e);
                                    }
                                    let _ = sender.send(Ok(text));
                                }
                                Err(e) => {
                                    let _ = sender.send(Err(e));
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let elapsed = batch_timer.elapsed().as_secs_f64();
                    crate::metrics::POST_BATCH_LATENCY.observe(elapsed);

                    warn!("Batch request failed: {}", e);

                    for (uri, sender) in requests {
                        match self.fetch_post_from_network_individual(&uri).await {
                            Ok(text) => {
                                if let Err(cache_err) =
                                    self.update_caches(uri.clone(), text.clone()).await
                                {
                                    warn!("Failed to update cache for {}: {}", uri, cache_err);
                                }
                                let _ = sender.send(Ok(text));
                            }
                            Err(fetch_err) => {
                                let _ = sender.send(Err(fetch_err));
                            }
                        }
                    }
                }
            }
        }
    }
}
