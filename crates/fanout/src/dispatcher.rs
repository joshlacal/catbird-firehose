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
    sender: broadcast::Sender<Arc<SubscribeReposMessage<'static>>>,
}

impl Dispatcher {
    pub fn new() -> Self {
        let (sender, _) = broadcast::channel(BROADCAST_CAPACITY);
        Self { sender }
    }

    /// Get the broadcast sender (for the ingest task).
    pub fn sender(&self) -> broadcast::Sender<Arc<SubscribeReposMessage<'static>>> {
        self.sender.clone()
    }

    /// Subscribe a new consumer — returns a new `Receiver`.
    pub fn subscribe(&self) -> broadcast::Receiver<Arc<SubscribeReposMessage<'static>>> {
        self.sender.subscribe()
    }
}

impl Default for Dispatcher {
    fn default() -> Self {
        Self::new()
    }
}
