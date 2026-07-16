use std::sync::Arc;

use jacquard_api::com_atproto::sync::subscribe_repos::SubscribeReposMessage;
use tokio::sync::broadcast;

/// Broadcast capacity — handles ~20s of firehose lag at ~3K events/sec.
const BROADCAST_CAPACITY: usize = 65_536;

/// Central event dispatcher using `tokio::sync::broadcast`.
///
/// One ingest task produces events, each consumer gets its own `Receiver`.
/// `Arc` wrapper avoids cloning event payloads on broadcast.
pub struct Dispatcher {
    sender: broadcast::Sender<Arc<SubscribeReposMessage>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self { sender }
    }

    /// Get the broadcast sender (for the ingest task).
    pub fn sender(&self) -> broadcast::Sender<Arc<SubscribeReposMessage>> {
        self.sender.clone()
    }

    /// Subscribe a new consumer — returns a new `Receiver`.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<SubscribeReposMessage>> {
        self.sender.subscribe()
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Dispatcher;
    use jacquard_api::com_atproto::sync::subscribe_repos::{Info, SubscribeReposMessage};
    use std::sync::Arc;

    #[tokio::test]
    async fn broadcast_preserves_arc_ownership_for_two_receivers() {
        let dispatcher = Dispatcher::new();
        let mut first = dispatcher.subscribe();
        let mut second = dispatcher.subscribe();
        let event = Arc::new(SubscribeReposMessage::Info(Box::<Info>::default()));

        dispatcher
            .sender()
            .send(event.clone())
            .expect("two receivers are active");

        let first_event = first.recv().await.expect("first receiver gets event");
        let second_event = second.recv().await.expect("second receiver gets event");
        assert!(Arc::ptr_eq(&event, &first_event));
        assert!(Arc::ptr_eq(&event, &second_event));
    }
}
