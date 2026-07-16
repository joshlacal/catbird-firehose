use anyhow::{Context, Result};
use moka::future::Cache;
use serde::{Deserialize, Serialize};
use sqlx::{Pool, Postgres, Row};
use std::collections::HashSet;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::crypto::CryptoUtils;
use crate::models::UserDevice;

// ============================================================================
// RelationshipManager
// ============================================================================

pub struct RelationshipManager {
    mutes_cache: Cache<String, HashSet<String>>,
    blocks_cache: Cache<String, HashSet<String>>,
    db_pool: Pool<Postgres>,
    crypto: CryptoUtils,
    use_hashed_storage: bool,
}

impl RelationshipManager {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        let mutes_cache: Cache<String, HashSet<String>> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(3600))
            .build();

        let blocks_cache: Cache<String, HashSet<String>> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(3600))
            .build();

        let crypto = CryptoUtils::new().expect("Failed to initialize crypto utils");

        let use_hashed_storage = std::env::var("USE_HASHED_RELATIONSHIPS")
            .map(|v| v.to_lowercase() == "true")
            .unwrap_or(true);

        if use_hashed_storage {
            info!("Using privacy-preserving hashed relationship storage");
        }

        Self {
            mutes_cache,
            blocks_cache,
            db_pool,
            crypto,
            use_hashed_storage,
        }
    }

    /// Check if user_did has muted target_did
    pub async fn is_muted(&self, user_did: &str, target_did: &str) -> Result<bool> {
        if let Some(mutes) = self.mutes_cache.get(user_did) {
            return Ok(mutes.contains(target_did));
        }

        if self.use_hashed_storage {
            let target_hash = self.crypto.hash_did(target_did, user_did);

            match sqlx::query(
                r#"
                SELECT COUNT(*) as count
                FROM user_mutes_encrypted
                WHERE user_did = $1 AND muted_did_encrypted = pgp_sym_encrypt($2, $3)
                "#,
            )
            .bind(user_did)
            .bind(&target_hash)
            .bind(&self.crypto.server_secret)
            .fetch_one(&self.db_pool)
            .await
            {
                Ok(row) => {
                    let count: i64 = row.get("count");
                    return Ok(count > 0);
                }
                Err(e) => {
                    return Err(e).context("Failed to check muted hash");
                }
            }
        }

        match self.load_mutes_for_user(user_did).await {
            Ok(mutes) => Ok(mutes.contains(target_did)),
            Err(e) => Err(e).context("Failed to load mutes"),
        }
    }

    /// Check if user_did has blocked target_did
    pub async fn is_blocked(&self, user_did: &str, target_did: &str) -> Result<bool> {
        if let Some(blocks) = self.blocks_cache.get(user_did) {
            return Ok(blocks.contains(target_did));
        }

        if self.use_hashed_storage {
            let target_hash = self.crypto.hash_did(target_did, user_did);

            match sqlx::query(
                r#"
                SELECT COUNT(*) as count
                FROM user_blocks_encrypted
                WHERE user_did = $1 AND blocked_did_encrypted = pgp_sym_encrypt($2, $3)
                "#,
            )
            .bind(user_did)
            .bind(&target_hash)
            .bind(&self.crypto.server_secret)
            .fetch_one(&self.db_pool)
            .await
            {
                Ok(row) => {
                    let count: i64 = row.get("count");
                    return Ok(count > 0);
                }
                Err(e) => {
                    return Err(e).context("Failed to check blocked hash");
                }
            }
        }

        match self.load_blocks_for_user(user_did).await {
            Ok(blocks) => Ok(blocks.contains(target_did)),
            Err(e) => Err(e).context("Failed to load blocks"),
        }
    }

    async fn load_mutes_for_user(&self, user_did: &str) -> Result<HashSet<String>> {
        let mutes = self.load_mutes_for_user_plaintext(user_did).await?;

        self.mutes_cache
            .insert(user_did.to_string(), mutes.clone())
            .await;

        Ok(mutes)
    }

    async fn load_blocks_for_user(&self, user_did: &str) -> Result<HashSet<String>> {
        let blocks = self.load_blocks_for_user_plaintext(user_did).await?;

        self.blocks_cache
            .insert(user_did.to_string(), blocks.clone())
            .await;

        Ok(blocks)
    }

    async fn load_mutes_for_user_plaintext(&self, user_did: &str) -> Result<HashSet<String>> {
        let rows = sqlx::query(
            r#"
            SELECT muted_did FROM user_mutes
            WHERE user_did = $1
            "#,
        )
        .bind(user_did)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch user mutes")?;

        let mutes: HashSet<String> = rows
            .into_iter()
            .map(|row| row.get::<String, _>("muted_did"))
            .collect();
        Ok(mutes)
    }

    async fn load_blocks_for_user_plaintext(&self, user_did: &str) -> Result<HashSet<String>> {
        let rows = sqlx::query(
            r#"
            SELECT blocked_did FROM user_blocks
            WHERE user_did = $1
            "#,
        )
        .bind(user_did)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch user blocks")?;

        let blocks: HashSet<String> = rows
            .into_iter()
            .map(|row| row.get::<String, _>("blocked_did"))
            .collect();
        Ok(blocks)
    }

    /// Authenticate device token before updating relationships
    async fn authenticate_device(&self, did: &str, device_token: &str) -> Result<UserDevice> {
        let device = sqlx::query_as::<_, UserDevice>(
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
            WHERE did = $1 AND device_token = $2
            "#,
        )
        .bind(did)
        .bind(device_token)
        .fetch_optional(&self.db_pool)
        .await
        .context("Error querying device")?;

        match device {
            Some(d) => Ok(d),
            None => Err(anyhow::anyhow!("Invalid device token for DID")),
        }
    }

    /// Update both mutes and blocks in a single batch operation - with authentication
    pub async fn update_relationships_batch(
        &self,
        user_did: &str,
        device_token: &str,
        mutes: Vec<String>,
        blocks: Vec<String>,
    ) -> Result<()> {
        self.authenticate_device(user_did, device_token).await?;

        let mut tx = self.db_pool.begin().await?;

        if self.use_hashed_storage {
            self.update_relationships_batch_hashed(
                &mut tx,
                user_did,
                device_token,
                &mutes,
                &blocks,
            )
            .await?;
        } else {
            self.update_relationships_batch_plaintext(
                &mut tx,
                user_did,
                device_token,
                &mutes,
                &blocks,
            )
            .await?;
        }

        tx.commit()
            .await
            .context("Failed to commit relationship batch transaction")?;

        let mute_set: HashSet<String> = mutes.into_iter().collect();
        let block_set: HashSet<String> = blocks.into_iter().collect();

        self.mutes_cache
            .insert(user_did.to_string(), mute_set)
            .await;
        self.blocks_cache
            .insert(user_did.to_string(), block_set)
            .await;

        info!(user_did = %user_did, "Updated user relationships in batch");
        Ok(())
    }

    async fn update_relationships_batch_plaintext(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_did: &str,
        device_token: &str,
        mutes: &[String],
        blocks: &[String],
    ) -> Result<()> {
        sqlx::query("DELETE FROM user_mutes WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut **tx)
            .await
            .context("Failed to delete existing mutes")?;

        sqlx::query("DELETE FROM user_blocks WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut **tx)
            .await
            .context("Failed to delete existing blocks")?;

        if !mutes.is_empty() {
            let mut query_builder =
                String::from("INSERT INTO user_mutes (user_did, muted_did) VALUES ");
            let mut params = Vec::new();
            let mut param_idx = 1;

            for (i, muted_did) in mutes.iter().enumerate() {
                if i > 0 {
                    query_builder.push_str(", ");
                }
                query_builder.push_str(&format!("(${},${})", param_idx, param_idx + 1));
                params.push(user_did.to_string());
                params.push(muted_did.clone());
                param_idx += 2;
            }

            let query = sqlx::query(&query_builder);
            let query = params.iter().fold(query, |q, param| q.bind(param));

            query
                .execute(&mut **tx)
                .await
                .context("Failed to batch insert mute relationships")?;
        }

        if !blocks.is_empty() {
            let mut query_builder =
                String::from("INSERT INTO user_blocks (user_did, blocked_did) VALUES ");
            let mut params = Vec::new();
            let mut param_idx = 1;

            for (i, blocked_did) in blocks.iter().enumerate() {
                if i > 0 {
                    query_builder.push_str(", ");
                }
                query_builder.push_str(&format!("(${},${})", param_idx, param_idx + 1));
                params.push(user_did.to_string());
                params.push(blocked_did.clone());
                param_idx += 2;
            }

            let query = sqlx::query(&query_builder);
            let query = params.iter().fold(query, |q, param| q.bind(param));

            query
                .execute(&mut **tx)
                .await
                .context("Failed to batch insert block relationships")?;
        }

        let combined_details = serde_json::json!({
            "mutes_count": mutes.len(),
            "blocks_count": blocks.len(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "using_hashed_dids": false,
        });

        sqlx::query(
            r#"
            INSERT INTO relationship_audit_log (user_did, device_token, action, details, using_hashed_dids)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(user_did)
        .bind(device_token)
        .bind("update_relationships_batch")
        .bind(&combined_details)
        .bind(false)
        .execute(&mut **tx)
        .await
        .context("Failed to record audit log")?;

        Ok(())
    }

    async fn update_relationships_batch_hashed(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        user_did: &str,
        device_token: &str,
        mutes: &[String],
        blocks: &[String],
    ) -> Result<()> {
        sqlx::query("DELETE FROM user_mutes_encrypted WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut **tx)
            .await
            .context("Failed to delete existing hashed mutes")?;

        sqlx::query("DELETE FROM user_blocks_encrypted WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut **tx)
            .await
            .context("Failed to delete existing hashed blocks")?;

        sqlx::query("DELETE FROM user_mutes WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut **tx)
            .await
            .context("Failed to delete existing plaintext mutes")?;

        sqlx::query("DELETE FROM user_blocks WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut **tx)
            .await
            .context("Failed to delete existing plaintext blocks")?;

        let hashed_mutes = mutes
            .iter()
            .map(|did| (did.clone(), self.crypto.hash_did(did, user_did)))
            .collect::<Vec<(String, String)>>();

        let hashed_blocks = blocks
            .iter()
            .map(|did| (did.clone(), self.crypto.hash_did(did, user_did)))
            .collect::<Vec<(String, String)>>();

        if !mutes.is_empty() {
            // Insert into plaintext table for cache consistency
            let mut query_builder =
                String::from("INSERT INTO user_mutes (user_did, muted_did) VALUES ");
            let mut params = Vec::new();
            let mut param_idx = 1;

            for (i, muted_did) in mutes.iter().enumerate() {
                if i > 0 {
                    query_builder.push_str(", ");
                }
                query_builder.push_str(&format!("(${},${})", param_idx, param_idx + 1));
                params.push(user_did.to_string());
                params.push(muted_did.clone());
                param_idx += 2;
            }

            let query = sqlx::query(&query_builder);
            let query = params.iter().fold(query, |q, param| q.bind(param));

            query
                .execute(&mut **tx)
                .await
                .context("Failed to batch insert plaintext mute relationships")?;

            // Insert into hashed table for privacy
            let mut query_builder = String::from(
                "INSERT INTO user_mutes_encrypted (user_did, muted_did_encrypted) VALUES ",
            );
            let mut params = Vec::new();
            let mut param_idx = 1;

            for (i, (_, muted_did_hash)) in hashed_mutes.iter().enumerate() {
                if i > 0 {
                    query_builder.push_str(", ");
                }
                query_builder.push_str(&format!(
                    "(${}, pgp_sym_encrypt(${}, ${}))",
                    param_idx,
                    param_idx + 1,
                    param_idx + 2
                ));
                params.push(user_did.to_string());
                params.push(muted_did_hash.clone());
                params.push(self.crypto.server_secret.clone());
                param_idx += 3;
            }

            let query = sqlx::query(&query_builder);
            let query = params.iter().fold(query, |q, param| q.bind(param));

            query
                .execute(&mut **tx)
                .await
                .context("Failed to batch insert hashed mute relationships")?;
        }

        if !blocks.is_empty() {
            let mut query_builder =
                String::from("INSERT INTO user_blocks (user_did, blocked_did) VALUES ");
            let mut params = Vec::new();
            let mut param_idx = 1;

            for (i, blocked_did) in blocks.iter().enumerate() {
                if i > 0 {
                    query_builder.push_str(", ");
                }
                query_builder.push_str(&format!("(${},${})", param_idx, param_idx + 1));
                params.push(user_did.to_string());
                params.push(blocked_did.clone());
                param_idx += 2;
            }

            let query = sqlx::query(&query_builder);
            let query = params.iter().fold(query, |q, param| q.bind(param));

            query
                .execute(&mut **tx)
                .await
                .context("Failed to batch insert plaintext block relationships")?;

            let mut query_builder = String::from(
                "INSERT INTO user_blocks_encrypted (user_did, blocked_did_encrypted) VALUES ",
            );
            let mut params = Vec::new();
            let mut param_idx = 1;

            for (i, (_, blocked_did_hash)) in hashed_blocks.iter().enumerate() {
                if i > 0 {
                    query_builder.push_str(", ");
                }
                query_builder.push_str(&format!(
                    "(${}, pgp_sym_encrypt(${}, ${}))",
                    param_idx,
                    param_idx + 1,
                    param_idx + 2
                ));
                params.push(user_did.to_string());
                params.push(blocked_did_hash.clone());
                params.push(self.crypto.server_secret.clone());
                param_idx += 3;
            }

            let query = sqlx::query(&query_builder);
            let query = params.iter().fold(query, |q, param| q.bind(param));

            query
                .execute(&mut **tx)
                .await
                .context("Failed to batch insert hashed block relationships")?;
        }

        let combined_details = serde_json::json!({
            "mutes_count": mutes.len(),
            "blocks_count": blocks.len(),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "using_hashed_dids": true,
        });

        sqlx::query(
            r#"
            INSERT INTO relationship_audit_log (user_did, device_token, action, details, using_hashed_dids)
            VALUES ($1, $2, $3, $4, $5)
            "#,
        )
        .bind(user_did)
        .bind(device_token)
        .bind("update_relationships_batch")
        .bind(&combined_details)
        .bind(true)
        .execute(&mut **tx)
        .await
        .context("Failed to record audit log")?;

        Ok(())
    }

    /// Invalidate cache entries for maintenance
    pub async fn invalidate_cache(&self, user_did: &str) {
        self.mutes_cache.invalidate(user_did).await;
        self.blocks_cache.invalidate(user_did).await;
        debug!(user_did = %user_did, "Invalidated relationship caches");
    }

    /// Run periodic cache maintenance
    pub async fn run_cache_maintenance(&self) -> Result<()> {
        info!("Running relationship cache maintenance");

        let mute_dids: Vec<String> = sqlx::query(r#"SELECT DISTINCT user_did FROM user_mutes"#)
            .fetch_all(&self.db_pool)
            .await?
            .into_iter()
            .map(|row| row.get::<String, _>("user_did"))
            .collect();

        let block_dids: Vec<String> = sqlx::query(r#"SELECT DISTINCT user_did FROM user_blocks"#)
            .fetch_all(&self.db_pool)
            .await?
            .into_iter()
            .map(|row| row.get::<String, _>("user_did"))
            .collect();

        let mut all_dids: HashSet<String> = HashSet::new();
        all_dids.extend(mute_dids);
        all_dids.extend(block_dids);

        let mut refresh_count = 0;
        for did in all_dids {
            let _ = self.load_mutes_for_user(&did).await;
            let _ = self.load_blocks_for_user(&did).await;
            refresh_count += 1;
        }

        info!("Refreshed relationship caches for {} users", refresh_count);
        Ok(())
    }
}

// ============================================================================
// ModerationListManager
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationList {
    pub uri: String,
    pub purpose: String,
    pub name: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListMember {
    pub subject: String,
}

pub struct ModerationListManager {
    block_lists_cache: Cache<String, HashSet<String>>,
    mute_lists_cache: Cache<String, HashSet<String>>,
    db_pool: Pool<Postgres>,
}

impl ModerationListManager {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        let block_lists_cache: Cache<String, HashSet<String>> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(1800))
            .build();

        let mute_lists_cache: Cache<String, HashSet<String>> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(1800))
            .build();

        Self {
            block_lists_cache,
            mute_lists_cache,
            db_pool,
        }
    }

    /// Check if target_did is in any of user's subscribed block lists
    pub async fn is_in_block_list(&self, user_did: &str, target_did: &str) -> bool {
        if let Some(blocked_dids) = self.block_lists_cache.get(user_did) {
            return blocked_dids.contains(target_did);
        }

        match self.load_block_list_members(user_did).await {
            Ok(blocked_dids) => {
                let result = blocked_dids.contains(target_did);
                self.block_lists_cache
                    .insert(user_did.to_string(), blocked_dids)
                    .await;
                result
            }
            Err(e) => {
                error!("Failed to load block list members for {}: {}", user_did, e);
                false
            }
        }
    }

    /// Check if target_did is in any of user's subscribed mute lists
    pub async fn is_in_mute_list(&self, user_did: &str, target_did: &str) -> bool {
        if let Some(muted_dids) = self.mute_lists_cache.get(user_did) {
            return muted_dids.contains(target_did);
        }

        match self.load_mute_list_members(user_did).await {
            Ok(muted_dids) => {
                let result = muted_dids.contains(target_did);
                self.mute_lists_cache
                    .insert(user_did.to_string(), muted_dids)
                    .await;
                result
            }
            Err(e) => {
                error!("Failed to load mute list members for {}: {}", user_did, e);
                false
            }
        }
    }

    async fn load_block_list_members(&self, user_did: &str) -> Result<HashSet<String>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT m.subject_did
            FROM moderation_list_members m
            INNER JOIN moderation_list_subscriptions s ON m.list_uri = s.list_uri
            WHERE s.user_did = $1 AND s.list_purpose = 'modlist'
            "#,
        )
        .bind(user_did)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch block list members")?;

        Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>("subject_did"))
            .collect())
    }

    async fn load_mute_list_members(&self, user_did: &str) -> Result<HashSet<String>> {
        let rows = sqlx::query(
            r#"
            SELECT DISTINCT m.subject_did
            FROM moderation_list_members m
            INNER JOIN moderation_list_subscriptions s ON m.list_uri = s.list_uri
            WHERE s.user_did = $1 AND s.list_purpose = 'curatelist'
            "#,
        )
        .bind(user_did)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch mute list members")?;

        Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>("subject_did"))
            .collect())
    }

    /// Sync user's moderation list subscriptions and members
    pub async fn sync_moderation_lists(
        &self,
        user_did: &str,
        lists: Vec<ModerationList>,
    ) -> Result<()> {
        info!(
            "Syncing {} moderation lists for user {}",
            lists.len(),
            user_did
        );

        let client = reqwest::Client::new();
        let public_api = "https://public.api.bsky.app";

        let mut tx = self.db_pool.begin().await?;

        sqlx::query("DELETE FROM moderation_list_subscriptions WHERE user_did = $1")
            .bind(user_did)
            .execute(&mut *tx)
            .await?;

        for list in lists {
            sqlx::query(
                r#"
                INSERT INTO moderation_list_subscriptions
                (user_did, list_uri, list_purpose, list_name, last_synced_at)
                VALUES ($1, $2, $3, $4, NOW())
                "#,
            )
            .bind(user_did)
            .bind(&list.uri)
            .bind(&list.purpose)
            .bind(&list.name)
            .execute(&mut *tx)
            .await?;

            match self
                .fetch_list_members(&list.uri, &client, public_api)
                .await
            {
                Ok(members) => {
                    debug!("Fetched {} members for list {}", members.len(), list.uri);

                    sqlx::query("DELETE FROM moderation_list_members WHERE list_uri = $1")
                        .bind(&list.uri)
                        .execute(&mut *tx)
                        .await?;

                    for member in members {
                        sqlx::query(
                            r#"
                            INSERT INTO moderation_list_members (list_uri, subject_did)
                            VALUES ($1, $2)
                            ON CONFLICT (list_uri, subject_did) DO NOTHING
                            "#,
                        )
                        .bind(&list.uri)
                        .bind(&member.subject)
                        .execute(&mut *tx)
                        .await?;
                    }
                }
                Err(e) => {
                    warn!("Failed to fetch members for list {}: {}", list.uri, e);
                }
            }
        }

        tx.commit().await?;

        self.block_lists_cache.invalidate(user_did).await;
        self.mute_lists_cache.invalidate(user_did).await;

        info!("Successfully synced moderation lists for user {}", user_did);
        Ok(())
    }

    async fn fetch_list_members(
        &self,
        list_uri: &str,
        client: &reqwest::Client,
        api_url: &str,
    ) -> Result<Vec<ListMember>> {
        let url = format!("{}/xrpc/app.bsky.graph.getList", api_url);

        let mut all_members = Vec::new();
        let mut cursor: Option<String> = None;

        loop {
            let mut query_params =
                vec![("list", list_uri.to_string()), ("limit", "100".to_string())];
            if let Some(c) = &cursor {
                query_params.push(("cursor", c.clone()));
            }

            let response = client
                .get(&url)
                .query(&query_params)
                .send()
                .await
                .context("Failed to fetch list members")?;

            if !response.status().is_success() {
                anyhow::bail!("Failed to fetch list: HTTP {}", response.status());
            }

            #[derive(Deserialize)]
            struct ListResponse {
                cursor: Option<String>,
                items: Vec<ListItem>,
            }

            #[derive(Deserialize)]
            struct ListItem {
                subject: SubjectDid,
            }

            #[derive(Deserialize)]
            struct SubjectDid {
                did: String,
            }

            let list_response: ListResponse = response
                .json()
                .await
                .context("Failed to parse list response")?;

            all_members.extend(list_response.items.into_iter().map(|item| ListMember {
                subject: item.subject.did,
            }));

            if let Some(next_cursor) = list_response.cursor {
                cursor = Some(next_cursor);
            } else {
                break;
            }
        }

        Ok(all_members)
    }

    /// Invalidate caches for a user
    pub async fn invalidate_user_cache(&self, user_did: &str) {
        self.block_lists_cache.invalidate(user_did).await;
        self.mute_lists_cache.invalidate(user_did).await;
    }

    /// Get cache statistics for monitoring
    pub fn get_cache_stats(&self) -> (u64, u64) {
        (
            self.block_lists_cache.entry_count(),
            self.mute_lists_cache.entry_count(),
        )
    }
}

// ============================================================================
// ThreadMuteManager
// ============================================================================

pub struct ThreadMuteManager {
    thread_mutes_cache: Cache<String, HashSet<String>>,
    db_pool: Pool<Postgres>,
}

impl ThreadMuteManager {
    pub fn new(db_pool: Pool<Postgres>) -> Self {
        let thread_mutes_cache: Cache<String, HashSet<String>> = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(1800))
            .build();

        Self {
            thread_mutes_cache,
            db_pool,
        }
    }

    /// Check if user has muted this thread
    pub async fn is_thread_muted(&self, user_did: &str, thread_root_uri: &str) -> bool {
        if let Some(muted_threads) = self.thread_mutes_cache.get(user_did) {
            return muted_threads.contains(thread_root_uri);
        }

        match self.load_muted_threads(user_did).await {
            Ok(muted_threads) => {
                let result = muted_threads.contains(thread_root_uri);
                self.thread_mutes_cache
                    .insert(user_did.to_string(), muted_threads)
                    .await;
                result
            }
            Err(e) => {
                error!("Failed to load muted threads for {}: {}", user_did, e);
                false
            }
        }
    }

    async fn load_muted_threads(&self, user_did: &str) -> Result<HashSet<String>> {
        let rows = sqlx::query(
            r#"
            SELECT thread_root_uri
            FROM thread_mutes
            WHERE user_did = $1
            "#,
        )
        .bind(user_did)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch muted threads")?;

        Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>("thread_root_uri"))
            .collect())
    }

    /// Mute a thread for a user
    pub async fn mute_thread(&self, user_did: &str, thread_root_uri: &str) -> Result<()> {
        sqlx::query(
            r#"
            INSERT INTO thread_mutes (user_did, thread_root_uri)
            VALUES ($1, $2)
            ON CONFLICT (user_did, thread_root_uri) DO NOTHING
            "#,
        )
        .bind(user_did)
        .bind(thread_root_uri)
        .execute(&self.db_pool)
        .await
        .context("Failed to insert thread mute")?;

        self.thread_mutes_cache.invalidate(user_did).await;

        info!("User {} muted thread {}", user_did, thread_root_uri);
        Ok(())
    }

    /// Unmute a thread for a user
    pub async fn unmute_thread(&self, user_did: &str, thread_root_uri: &str) -> Result<()> {
        sqlx::query(
            r#"
            DELETE FROM thread_mutes
            WHERE user_did = $1 AND thread_root_uri = $2
            "#,
        )
        .bind(user_did)
        .bind(thread_root_uri)
        .execute(&self.db_pool)
        .await
        .context("Failed to delete thread mute")?;

        self.thread_mutes_cache.invalidate(user_did).await;

        info!("User {} unmuted thread {}", user_did, thread_root_uri);
        Ok(())
    }

    /// Invalidate cache for a user
    pub async fn invalidate_user_cache(&self, user_did: &str) {
        self.thread_mutes_cache.invalidate(user_did).await;
    }

    /// Get cache statistics for monitoring
    pub fn get_cache_stats(&self) -> u64 {
        self.thread_mutes_cache.entry_count()
    }

    /// Get all muted threads for a user
    pub async fn get_muted_threads(&self, user_did: &str) -> Result<Vec<String>> {
        let rows = sqlx::query(
            r#"
            SELECT thread_root_uri
            FROM thread_mutes
            WHERE user_did = $1
            ORDER BY created_at DESC
            "#,
        )
        .bind(user_did)
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to fetch muted threads")?;

        Ok(rows
            .into_iter()
            .map(|row| row.get::<String, _>("thread_root_uri"))
            .collect())
    }
}
