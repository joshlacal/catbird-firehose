use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::StreamExt;
use petrel_firehose::{
    FirehoseBackoffConfiguration, FirehoseCursorStorage, FirehoseEndpoint, FirehoseStreamError,
    FirehoseSubscription, FirehoseSubscriptionConfiguration, FirehoseSubscriptionError,
    FirehoseSubscriptionEvent, FirehoseWebSocketOptions, FirehoseWebSocketSession,
    FirehoseWebSocketSessionFactory, IgnoredFrameReason, RelayEvent, TungsteniteWebSocketFactory,
};
use sqlx::{Pool, Postgres};
use tokio::sync::broadcast;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::cursor::{CursorStore, PgCursorStore};

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Consecutive connection attempts without a delivered event before ingest gives up.
const MAX_RECONNECTS: u32 = 10;
/// A connection that delivers no message for this long is dropped and reopened.
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);
/// The persisted cursor is a checkpoint, written when an acknowledged seq is a multiple of this.
const CURSOR_CHECKPOINT_EVERY: i64 = 100;
const SUBSCRIBE_REPOS_NSID: &str = "com.atproto.sync.subscribeRepos";
const MAX_RECONNECTS_MESSAGE: &str = "max firehose reconnection attempts reached";

/// Run the firehose ingest loop. Subscribes to `com.atproto.sync.subscribeRepos` with Petrel's
/// firehose client and broadcasts every decoded event to all consumers via `dispatcher`.
pub async fn run_firehose_ingest(
    firehose_url: String,
    dispatcher: broadcast::Sender<Arc<RelayEvent>>,
    db_pool: Pool<Postgres>,
    shutdown: watch::Receiver<bool>,
) -> Result<()> {
    run_firehose_ingest_with_store(
        firehose_url,
        dispatcher,
        PgCursorStore::new(db_pool),
        shutdown,
    )
    .await
}

/// [`run_firehose_ingest`] with an explicit cursor checkpoint store.
///
/// Delivery semantics (unchanged from the Jacquard implementation):
/// - an event's seq is acknowledged once it has been handed to at least one consumer;
/// - reconnects resume from the latest acknowledged seq held in memory, not the periodic
///   checkpoint, so events already dispatched are not replayed;
/// - the checkpoint store is read once at startup and written when an acknowledged seq is a
///   multiple of [`CURSOR_CHECKPOINT_EVERY`];
/// - a malformed frame is skipped on the open connection (never a reconnect);
/// - after [`MAX_RECONNECTS`] consecutive connection attempts without a delivered event the
///   loop returns an error.
pub async fn run_firehose_ingest_with_store<S: CursorStore>(
    firehose_url: String,
    dispatcher: broadcast::Sender<Arc<RelayEvent>>,
    cursor_store: S,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    info!("Starting firehose ingest");

    let url =
        FirehoseEndpoint::subscription_url(&parse_ws_url(&firehose_url)?, SUBSCRIBE_REPOS_NSID);
    let attempts = Arc::new(AtomicU32::new(0));
    let subscription = FirehoseSubscription::new(subscription_configuration(
        url,
        Arc::new(CheckpointCursorStorage::new(cursor_store)),
        Arc::clone(&attempts),
    ));

    'outer: loop {
        let mut stream = subscription.events();
        let ended = loop {
            tokio::select! {
                item = stream.next() => match item {
                    Some(Ok(FirehoseSubscriptionEvent::Event(event))) => {
                        attempts.store(0, Ordering::SeqCst);
                        dispatch(&subscription, &dispatcher, event).await;
                    }
                    Some(Ok(FirehoseSubscriptionEvent::SequenceGap { expected, received })) => {
                        attempts.store(0, Ordering::SeqCst);
                        info!(expected, received, "Firehose sequence gap");
                    }
                    Some(Ok(FirehoseSubscriptionEvent::IgnoredFrame(frame))) => {
                        if !matches!(frame.reason, IgnoredFrameReason::FrameTooLarge) {
                            attempts.store(0, Ordering::SeqCst);
                        }
                        skip_ignored_frame(&subscription, frame).await;
                    }
                    Some(Err(err)) => break Some(err),
                    None => break None,
                },
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        info!("Shutdown signal received, stopping firehose ingest");
                        break 'outer;
                    }
                }
            }
        };
        drop(stream);

        match ended {
            None => warn!("Firehose stream ended, reconnecting..."),
            Some(FirehoseStreamError::Subscription(
                FirehoseSubscriptionError::WebSocketTransportUnavailable(message),
            )) if message == MAX_RECONNECTS_MESSAGE => {
                return Err(anyhow!("Max reconnection attempts reached"));
            }
            Some(FirehoseStreamError::Subscription(
                FirehoseSubscriptionError::FrameTooLargeAtCursor {
                    cursor,
                    attempts: tries,
                },
            )) => {
                // The relay keeps sending a frame we refuse to read. Without moving past it the
                // stream would fail on every reconnect, so skip one seq (decision log
                // 2026-11-27 · catbird-firehose · oversize frame policy).
                let Some(cursor) = cursor else {
                    error!(
                        attempts = tries,
                        "Oversize firehose frame before any decoded event; cannot skip it"
                    );
                    return Err(anyhow!(
                        "firehose frame exceeded maximum size before any decoded event"
                    ));
                };
                let skip_to = cursor.saturating_add(1);
                error!(
                    cursor,
                    skip_to,
                    attempts = tries,
                    "ALERT: oversize firehose frame after cursor; skipping one sequence"
                );
                if let Err(err) = subscription.acknowledge(skip_to).await {
                    error!(error = %err, "Failed to move cursor past oversize frame");
                    return Err(anyhow!("cannot move cursor past oversize frame: {err}"));
                }
                // The stream already backed off between the oversize attempts.
                continue 'outer;
            }
            Some(err) => {
                warn!(error = %err, "Firehose stream error, reconnecting...");
            }
        }

        // The stream already backs off between transport reconnects; this delay covers
        // streams that end on a protocol error (regression, server error frame).
        let attempt = attempts.load(Ordering::SeqCst);
        let delay = reconnect_delay(attempt);
        warn!(
            "Connection interrupted, retrying in {}s (attempt {}/{})",
            delay.as_secs(),
            attempt,
            MAX_RECONNECTS
        );
        let should_stop = tokio::select! {
            _ = tokio::time::sleep(delay) => false,
            changed = shutdown.changed() => changed.is_ok() && *shutdown.borrow(),
        };
        if should_stop {
            info!("Shutdown signal received while reconnecting");
            break 'outer;
        }
    }

    info!("Firehose ingest stopped");
    Ok(())
}

fn subscription_configuration(
    url: Url,
    cursor_storage: Arc<dyn FirehoseCursorStorage>,
    attempts: Arc<AtomicU32>,
) -> FirehoseSubscriptionConfiguration {
    let mut config = FirehoseSubscriptionConfiguration::new(url);
    config.cursor_storage = cursor_storage;
    config.session_factory = Arc::new(IngestSessionFactory {
        inner: TungsteniteWebSocketFactory::with_options(FirehoseWebSocketOptions::new()),
        attempts,
        idle_timeout: HEARTBEAT_TIMEOUT,
    });
    // 1s, 2s, 4s ... 60s without jitter, reset by any delivered frame.
    config.backoff = FirehoseBackoffConfiguration {
        initial_delay: Duration::from_secs(1),
        max_delay: Duration::from_secs(60),
        multiplier: 2.0,
        jitter: 0.0,
    };
    config.backoff_reset_after_frames = 1;
    config.auto_acknowledge = false;
    config.reconnects_on_consumer_too_slow = true;
    config
}

fn reconnect_delay(attempt: u32) -> Duration {
    Duration::from_secs(1u64 << attempt.min(6)).min(Duration::from_secs(60))
}

async fn dispatch(
    subscription: &FirehoseSubscription,
    dispatcher: &broadcast::Sender<Arc<RelayEvent>>,
    event: RelayEvent,
) {
    let sequence = event.sequence();
    if let (RelayEvent::Commit(commit), Some(seq)) = (&event, sequence) {
        if seq % 5000 == 0 {
            info!("Firehose seq: {}", commit.seq);
        }
    }
    if dispatcher.send(Arc::new(event)).is_err() {
        debug!("No active consumers for broadcast");
        return;
    }
    if let Some(seq) = sequence {
        acknowledge(subscription, seq).await;
    }
}

/// A skipped frame never ends or reconnects the stream. A frame whose seq was decoded is
/// acknowledged so a later reconnect does not replay it; a malformed frame's seq is only a
/// best-effort hint and is never trusted as a cursor.
async fn skip_ignored_frame(
    subscription: &FirehoseSubscription,
    frame: petrel_firehose::EventStreamIgnoredFrame,
) {
    match &frame.reason {
        IgnoredFrameReason::MalformedFrame(reason) => {
            warn!(
                seq_hint = ?frame.sequence,
                r#type = ?frame.r#type,
                "Skipping malformed firehose frame: {}",
                reason
            );
        }
        IgnoredFrameReason::UndecodablePayload(reason) => {
            warn!(
                seq = ?frame.sequence,
                r#type = ?frame.r#type,
                "Skipping undecodable firehose event: {}",
                reason
            );
            if let Some(seq) = frame.sequence {
                acknowledge(subscription, seq).await;
            }
        }
        IgnoredFrameReason::UnknownType | IgnoredFrameReason::UnknownOperation => {
            debug!(
                seq = ?frame.sequence,
                op = frame.operation,
                r#type = ?frame.r#type,
                "Skipping firehose frame of unknown kind"
            );
            if let Some(seq) = frame.sequence {
                acknowledge(subscription, seq).await;
            }
        }
        IgnoredFrameReason::FrameTooLarge => {
            warn!("Firehose frame exceeded the maximum message size; reconnecting");
        }
    }
}

async fn acknowledge(subscription: &FirehoseSubscription, seq: i64) {
    if let Err(err) = subscription.acknowledge(seq).await {
        warn!(seq, error = %err, "Failed to acknowledge firehose cursor");
    }
}

/// Petrel cursor storage over the ingest checkpoint store.
///
/// Holds the latest acknowledged seq in memory (what every reconnect resumes from) and writes
/// the durable checkpoint only every [`CURSOR_CHECKPOINT_EVERY`] seqs. Checkpoint failures are
/// logged and do not stop ingest; an unreadable checkpoint starts from the live tip.
struct CheckpointCursorStorage<S> {
    store: S,
    latest: Mutex<Option<i64>>,
}

impl<S> CheckpointCursorStorage<S> {
    fn new(store: S) -> Self {
        Self {
            store,
            latest: Mutex::new(None),
        }
    }

    fn latest(&self) -> Option<i64> {
        *self.latest.lock().expect("cursor lock")
    }
}

impl<S> fmt::Debug for CheckpointCursorStorage<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CheckpointCursorStorage")
            .field("latest", &self.latest())
            .finish_non_exhaustive()
    }
}

impl<S: CursorStore> FirehoseCursorStorage for CheckpointCursorStorage<S> {
    fn load_cursor(&self) -> BoxFuture<'_, Result<Option<i64>, FirehoseSubscriptionError>> {
        Box::pin(async move {
            if let Some(latest) = self.latest() {
                return Ok(Some(latest));
            }
            let loaded = match self.store.load().await {
                Ok(cursor) => cursor,
                Err(err) => {
                    error!("Failed to get last cursor: {}", err);
                    None
                }
            };
            let mut latest = self.latest.lock().expect("cursor lock");
            if latest.is_none() {
                *latest = loaded;
            }
            Ok(*latest)
        })
    }

    fn save_cursor(&self, cursor: i64) -> BoxFuture<'_, Result<(), FirehoseSubscriptionError>> {
        Box::pin(async move {
            *self.latest.lock().expect("cursor lock") = Some(cursor);
            if cursor % CURSOR_CHECKPOINT_EVERY == 0 {
                if let Err(err) = self.store.save(cursor).await {
                    error!("Failed to update cursor: {}", err);
                }
            }
            Ok(())
        })
    }
}

/// Session factory that caps consecutive connection attempts and adds an idle timeout.
#[derive(Debug)]
struct IngestSessionFactory {
    inner: TungsteniteWebSocketFactory,
    /// Connection attempts since the last delivered frame; reset by the ingest loop.
    attempts: Arc<AtomicU32>,
    idle_timeout: Duration,
}

impl FirehoseWebSocketSessionFactory for IngestSessionFactory {
    fn make_session(
        &self,
        url: Url,
    ) -> BoxFuture<'_, Result<Box<dyn FirehoseWebSocketSession>, FirehoseSubscriptionError>> {
        Box::pin(async move {
            let attempt = self.attempts.fetch_add(1, Ordering::SeqCst) + 1;
            if attempt > MAX_RECONNECTS {
                error!("Giving up after {} connection attempts", MAX_RECONNECTS);
                return Err(FirehoseSubscriptionError::WebSocketTransportUnavailable(
                    MAX_RECONNECTS_MESSAGE.to_string(),
                ));
            }
            info!("Connecting to firehose: {}", url);
            match self.inner.make_session(url).await {
                Ok(session) => {
                    info!("Firehose connection established");
                    Ok(Box::new(IdleTimeoutSession {
                        inner: session,
                        idle_timeout: self.idle_timeout,
                    }) as Box<dyn FirehoseWebSocketSession>)
                }
                Err(err) => {
                    error!(
                        "Failed to connect to firehose (attempt {}/{}): {}",
                        attempt, MAX_RECONNECTS, err
                    );
                    Err(err)
                }
            }
        })
    }
}

/// Ends a connection that has delivered no message for `idle_timeout` (pings and pongs do
/// not count), so a stalled relay is reconnected with backoff.
#[derive(Debug)]
struct IdleTimeoutSession {
    inner: Box<dyn FirehoseWebSocketSession>,
    idle_timeout: Duration,
}

impl FirehoseWebSocketSession for IdleTimeoutSession {
    fn receive_message(&self) -> BoxFuture<'_, Result<Vec<u8>, FirehoseSubscriptionError>> {
        Box::pin(async move {
            match tokio::time::timeout(self.idle_timeout, self.inner.receive_message()).await {
                Ok(result) => result,
                Err(_) => {
                    warn!(
                        "No firehose data for {}s, reconnecting...",
                        self.idle_timeout.as_secs()
                    );
                    Err(FirehoseSubscriptionError::Network(format!(
                        "no firehose data for {}s",
                        self.idle_timeout.as_secs()
                    )))
                }
            }
        })
    }

    fn close(&self) -> BoxFuture<'_, ()> {
        self.inner.close()
    }
}

fn parse_ws_url(url_str: &str) -> Result<Url> {
    if let Some((_, authority_and_path)) = url_str.split_once("://") {
        if authority_and_path.is_empty() || authority_and_path.starts_with('/') {
            return Err(anyhow!("Invalid firehose URL: missing authority"));
        }
    }

    // Ensure we have a WebSocket scheme
    let ws_url = if url_str.starts_with("https://") {
        url_str.replacen("https://", "wss://", 1)
    } else if url_str.starts_with("http://") {
        url_str.replacen("http://", "ws://", 1)
    } else if url_str.starts_with("wss://") || url_str.starts_with("ws://") {
        url_str.to_string()
    } else if url_str.contains("://") {
        return Err(anyhow!("Invalid firehose URL: unsupported scheme"));
    } else {
        format!("wss://{}", url_str)
    };

    let parsed = Url::parse(&ws_url).map_err(|e| anyhow!("Invalid firehose URL: {}", e))?;

    if parsed.host_str().is_none() {
        return Err(anyhow!("Invalid firehose URL: missing authority"));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(anyhow!("Invalid firehose URL: userinfo is not allowed"));
    }
    if parsed.query().is_some() {
        return Err(anyhow!("Invalid firehose URL: query is not allowed"));
    }
    if parsed.fragment().is_some() {
        return Err(anyhow!("Invalid firehose URL: fragment is not allowed"));
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use petrel_firehose::{FirehoseCursorStorage, FirehoseEndpoint};

    use super::{parse_ws_url, CheckpointCursorStorage, SUBSCRIBE_REPOS_NSID};
    use crate::cursor::MemoryCursorStore;

    #[test]
    fn normalizes_supported_firehose_url_forms() {
        let cases = [
            ("https://bsky.network", "wss://bsky.network/"),
            ("http://127.0.0.1:8080", "ws://127.0.0.1:8080/"),
            ("http://relay.example", "ws://relay.example/"),
            ("wss://bsky.network", "wss://bsky.network/"),
            ("ws://localhost:8080", "ws://localhost:8080/"),
            ("bsky.network", "wss://bsky.network/"),
            ("localhost:8080", "wss://localhost:8080/"),
        ];

        for (input, expected) in cases {
            let uri = parse_ws_url(input)
                .unwrap_or_else(|error| panic!("expected {input:?} to be valid, got {error}"));
            assert_eq!(uri.as_str(), expected, "input: {input}");
        }
    }

    #[test]
    fn subscription_url_matches_the_previous_endpoint() {
        for (input, expected) in [
            (
                "https://bsky.network",
                "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos",
            ),
            (
                "ws://127.0.0.1:8080",
                "ws://127.0.0.1:8080/xrpc/com.atproto.sync.subscribeRepos",
            ),
        ] {
            let url = FirehoseEndpoint::subscription_url(
                &parse_ws_url(input).unwrap(),
                SUBSCRIBE_REPOS_NSID,
            );
            assert_eq!(url.as_str(), expected);
        }
    }

    #[test]
    fn rejects_ambiguous_or_non_authority_firehose_urls_without_panicking() {
        let invalid = [
            "",
            "://bad",
            "ftp://bsky.network",
            "ws:///missing-host",
            "wss:missing-authority",
            "wss://bsky.network:not-a-port",
            "wss://user@bsky.network",
            "wss://user:password@bsky.network",
            "wss://bsky.network?cursor=1",
            "wss://bsky.network#fragment",
        ];

        for input in invalid {
            let result = std::panic::catch_unwind(|| parse_ws_url(input));
            assert!(result.is_ok(), "parse_ws_url panicked for {input:?}");
            assert!(
                result.expect("checked above").is_err(),
                "expected {input:?} to be rejected"
            );
        }
    }

    #[tokio::test]
    async fn checkpoint_storage_resumes_from_memory_and_persists_every_hundredth_seq() {
        let store = Arc::new(MemoryCursorStore::with_cursor(100));
        let storage = CheckpointCursorStorage::new(store.clone());
        assert_eq!(storage.load_cursor().await.unwrap(), Some(100));
        for seq in [101, 150, 199, 200, 201] {
            storage.save_cursor(seq).await.unwrap();
        }
        assert_eq!(storage.load_cursor().await.unwrap(), Some(201));
        assert_eq!(store.saves(), vec![200]);
        assert_eq!(store.current(), Some(200));
    }
}
