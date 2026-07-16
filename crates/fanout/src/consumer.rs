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
        event: Arc<SubscribeReposMessage>,
    ) -> impl std::future::Future<Output = Result<()>> + Send;
}

/// Spawn a consumer task that reads from a broadcast receiver.
///
/// Handles lag (lagged errors) by logging and continuing.
/// Returns a `JoinHandle` for the consumer task.
pub fn spawn_consumer<C: Consumer>(
    consumer: Arc<C>,
    mut rx: broadcast::Receiver<Arc<SubscribeReposMessage>>,
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

#[cfg(test)]
mod tests {
    use super::{spawn_consumer, Consumer};
    use anyhow::Result;
    use jacquard_api::com_atproto::sync::subscribe_repos::{Info, SubscribeReposMessage};
    use std::sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    };
    use tokio::sync::broadcast;

    #[derive(Default)]
    struct RecordingConsumer {
        dropped: AtomicU64,
        handled: AtomicU64,
    }

    impl Consumer for RecordingConsumer {
        fn name(&self) -> &str {
            "test"
        }

        fn handle_lag(&self, dropped_events: u64) {
            self.dropped.fetch_add(dropped_events, Ordering::SeqCst);
        }

        async fn handle_event(&self, _event: Arc<SubscribeReposMessage>) -> Result<()> {
            self.handled.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    #[tokio::test]
    async fn reports_exact_lagged_event_count_and_continues() {
        let (sender, receiver) = broadcast::channel(1);
        let event = Arc::new(SubscribeReposMessage::Info(Box::<Info>::default()));
        sender.send(event.clone()).expect("receiver is active");
        sender.send(event.clone()).expect("receiver is active");
        sender.send(event).expect("receiver is active");

        let consumer = Arc::new(RecordingConsumer::default());
        let task = spawn_consumer(consumer.clone(), receiver);
        drop(sender);
        task.await.expect("consumer task joins");

        assert_eq!(consumer.dropped.load(Ordering::SeqCst), 2);
        assert_eq!(consumer.handled.load(Ordering::SeqCst), 1);
    }
}
