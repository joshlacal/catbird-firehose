use std::sync::Arc;

use anyhow::Result;
use jacquard_api::com_atproto::sync::subscribe_repos::SubscribeReposMessage;
use tokio::sync::broadcast;
use tracing::{error, warn};

/// Trait for firehose event consumers.
///
/// Each consumer receives all `SubscribeReposMessage` events and filters
/// internally based on the collections / event types it cares about.
pub trait Consumer: Send + Sync + 'static {
    /// Human-readable name for logging.
    fn name(&self) -> &str;

    /// Observe broadcast lag for this consumer.
    fn handle_lag(&self, _dropped_events: u64) {}

    /// Process a single firehose event.
    fn handle_event(
        &self,
        event: Arc<SubscribeReposMessage<'static>>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Spawn a consumer task that reads from a broadcast receiver.
///
/// Handles lag (lagged errors) by logging and continuing.
/// Returns a `JoinHandle` for the consumer task.
pub fn spawn_consumer<C: Consumer>(
    consumer: Arc<C>,
    mut rx: broadcast::Receiver<Arc<SubscribeReposMessage<'static>>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Err(e) = consumer.handle_event(event).await {
                        error!(consumer = consumer.name(), "Error handling event: {}", e);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    consumer.handle_lag(n);
                    warn!(
                        consumer = consumer.name(),
                        "Consumer lagged, dropped {} events", n
                    );
                }
                Err(broadcast::error::RecvError::Closed) => {
                    warn!(
                        consumer = consumer.name(),
                        "Broadcast channel closed, stopping"
                    );
                    break;
                }
            }
        }
    })
}
