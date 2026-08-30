pub mod classifier;
pub mod db;
pub mod lock;
pub mod metrics;
pub mod models;
pub mod queue;
pub mod subscriptions;

use std::collections::HashSet;
use std::io::Cursor;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use atrium_repo::blockstore::{AsyncBlockStoreRead, CarStore};
use catbird_firehose_fanout::Consumer;
use jacquard_api::com_atproto::sync::subscribe_repos::SubscribeReposMessage;
use sqlx::{Pool, Postgres};
use tokio::sync::{watch, RwLock};
use tokio::task::JoinHandle;
use tracing::{debug, error, info};

use models::BlueskyEvent;
use subscriptions::ActivitySubscriptionManager;

const RELEVANT_COLLECTIONS: &[&str] = &[
    "app.bsky.feed.post",
    "app.bsky.feed.like",
    "app.bsky.graph.follow",
    "app.bsky.feed.repost",
];

fn is_relevant_path(path: &str) -> bool {
    matches!(
        path.split_once('/'),
        Some((collection, record_key))
            if !record_key.is_empty() && RELEVANT_COLLECTIONS.contains(&collection)
    )
}

/// Firehose consumer that classifies push-relevant events and enqueues candidate
/// notifications for Nest to deliver.
pub struct PushConsumer {
    db_pool: Pool<Postgres>,
    activity_subscription_manager: Arc<ActivitySubscriptionManager>,
    registered_users: Arc<RwLock<(HashSet<String>, Vec<String>)>>,
}

impl PushConsumer {
    pub fn new(
        db_pool: Pool<Postgres>,
        activity_subscription_manager: Arc<ActivitySubscriptionManager>,
    ) -> Self {
        Self {
            db_pool,
            activity_subscription_manager,
            registered_users: Arc::new(RwLock::new((HashSet::new(), Vec::new()))),
        }
    }

    /// Refresh the distinct set of registered users that currently have at least
    /// one push registration in shared Postgres.
    pub async fn start_background_tasks(
        &self,
        mut shutdown: watch::Receiver<bool>,
    ) -> JoinHandle<()> {
        match db::get_registered_users(&self.db_pool).await {
            Ok(users) => {
                let set: HashSet<String> = users.iter().cloned().collect();
                let mut guard = self.registered_users.write().await;
                *guard = (set, users);
                info!("Loaded {} registered users into cache", guard.1.len());
            }
            Err(err) => {
                error!("Failed to load initial registered users: {}", err);
            }
        }

        let db_pool = self.db_pool.clone();
        let registered_users = self.registered_users.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
            interval.tick().await;

            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    changed = shutdown.changed() => {
                        if changed.is_ok() && *shutdown.borrow() {
                            info!("Stopping registered users refresh task");
                            break;
                        }
                    }
                }

                match db::get_registered_users(&db_pool).await {
                    Ok(users) => {
                        let set: HashSet<String> = users.iter().cloned().collect();
                        let count = users.len();
                        let mut guard = registered_users.write().await;
                        *guard = (set, users);
                        debug!("Refreshed registered users cache, count: {}", count);
                    }
                    Err(err) => {
                        error!("Failed to refresh registered users cache: {}", err);
                    }
                }
            }
        })
    }

    fn deserialize_record(collection: &str, record_block: &[u8]) -> Result<serde_json::Value> {
        match collection {
            "app.bsky.feed.post"
            | "app.bsky.feed.like"
            | "app.bsky.graph.follow"
            | "app.bsky.feed.repost" => {}
            _ => return Err(anyhow!("Unsupported collection type: {}", collection)),
        }

        let value: serde_json::Value = serde_ipld_dagcbor::from_slice(record_block)
            .map_err(|err| anyhow!("Failed to deserialize {} record: {}", collection, err))?;

        Ok(value)
    }
}

impl Consumer for PushConsumer {
    fn name(&self) -> &str {
        "push-candidate-enqueuer"
    }

    fn handle_lag(&self, dropped_events: u64) {
        metrics::CONSUMER_LAG_EVENTS.inc();
        metrics::CONSUMER_DROPPED_EVENTS.inc_by(dropped_events as f64);
    }

    async fn handle_event(&self, event: Arc<SubscribeReposMessage>) -> Result<()> {
        let commit = match event.as_ref() {
            SubscribeReposMessage::Commit(commit) => commit,
            _ => return Ok(()),
        };

        let has_relevant_ops = commit.ops.iter().any(|op| {
            let path: &str = op.path.as_ref();
            is_relevant_path(path)
        });

        if !has_relevant_ops {
            return Ok(());
        }

        let mut car_store = CarStore::open(Cursor::new(&commit.blocks[..]))
            .await
            .map_err(|err| anyhow!("Failed to open CarStore: {}", err))?;

        let repo_did = commit.repo.to_string();

        for op in &commit.ops {
            let action: &str = op.action.as_ref();
            if action != "create" && action != "update" {
                continue;
            }

            let path: &str = op.path.as_ref();
            if !is_relevant_path(path) {
                continue;
            }

            let Some((collection, _)) = path.split_once('/') else {
                continue;
            };

            let cid_link = match &op.cid {
                Some(cid_link) => cid_link,
                None => continue,
            };

            let cid = match cid_link.to_ipld() {
                Ok(cid) => cid,
                Err(err) => {
                    error!("Invalid CID format: {}", err);
                    continue;
                }
            };

            let mut record_block = Vec::new();
            match car_store.read_block_into(cid, &mut record_block).await {
                Ok(()) => {}
                Err(err) => {
                    debug!(
                        "Record block not found for CID: {}, error: {}",
                        cid_link, err
                    );
                    continue;
                }
            }

            let record_data = match Self::deserialize_record(collection, &record_block) {
                Ok(data) => data,
                Err(err) => {
                    debug!("Failed to deserialize {}: {}", collection, err);
                    continue;
                }
            };

            let bluesky_event = BlueskyEvent {
                op: action.to_string(),
                path: path.to_string(),
                cid: cid.to_string(),
                author: repo_did.clone(),
                record: record_data,
                timestamp: chrono::Utc::now().timestamp(),
            };

            let (registered_users_set, registered_users_vec) = {
                let guard = self.registered_users.read().await;
                (guard.0.clone(), guard.1.clone())
            };

            queue::enqueue_candidates(
                bluesky_event,
                &self.db_pool,
                &self.activity_subscription_manager,
                &registered_users_vec,
                &registered_users_set,
            )
            .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::is_relevant_path;

    #[test]
    fn commit_path_filter_requires_an_exact_collection_segment() {
        for path in [
            "app.bsky.feed.post/record",
            "app.bsky.feed.like/record",
            "app.bsky.graph.follow/record",
            "app.bsky.feed.repost/record",
        ] {
            assert!(is_relevant_path(path), "expected relevant path: {path}");
        }

        for path in [
            "app.bsky.feed.post",
            "app.bsky.feed.postscript/record",
            "app.bsky.feed.post/",
            "/app.bsky.feed.post/record",
            "app.bsky.actor.profile/record",
        ] {
            assert!(!is_relevant_path(path), "expected irrelevant path: {path}");
        }
    }
}
