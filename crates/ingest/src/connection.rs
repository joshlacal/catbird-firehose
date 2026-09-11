use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::StreamExt;
use jacquard_common::deps::fluent_uri::Uri;
use jacquard_common::stream::{StreamError, StreamErrorKind};
use jacquard_common::websocket::tungstenite_client::TungsteniteClient;
use jacquard_common::xrpc::subscription::SubscriptionExt;
use sqlx::{Pool, Postgres};
use tokio::sync::broadcast;
use tokio::sync::watch;
use tracing::{debug, error, info, warn};
use url::Url;

use jacquard_api::com_atproto::sync::subscribe_repos::{
    SubscribeRepos, SubscribeReposMessage, SubscribeReposStream,
};

use crate::cursor;

const MAX_RECONNECTS: u32 = 10;
const HEARTBEAT_TIMEOUT: Duration = Duration::from_secs(60);

/// Run the firehose ingest loop. Connects to the ATProto firehose via jacquard,
/// parses messages into owned `SubscribeReposMessage`, and broadcasts
/// them to all consumers via the provided `broadcast::Sender`.
pub async fn run_firehose_ingest(
    firehose_url: String,
    dispatcher: broadcast::Sender<Arc<SubscribeReposMessage>>,
    db_pool: Pool<Postgres>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    info!("Starting firehose ingest");

    let mut reconnect_delay = 1u64;
    let mut reconnect_attempts = 0u32;
    // The persisted cursor is only a periodic checkpoint. Reading it again on
    // each reconnect replays events already dispatched since that checkpoint.
    let mut last_cursor = match cursor::get_last_cursor(&db_pool).await {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to get last cursor: {}", e);
            None
        }
    };

    'outer: loop {
        info!("Connecting to firehose, cursor: {:?}", last_cursor);

        let base_url = parse_ws_url(&firehose_url)?;
        let ws_client = TungsteniteClient::new();

        let params = SubscribeRepos::new().cursor(last_cursor).build();

        let subscription: jacquard_common::xrpc::subscription::SubscriptionStream<
            SubscribeReposStream,
        > = match ws_client.subscription(base_url).subscribe(&params).await {
            Ok(sub) => sub,
            Err(e) => {
                error!("Failed to connect to firehose: {}", e);
                reconnect_attempts += 1;
                if reconnect_attempts >= MAX_RECONNECTS {
                    return Err(anyhow!("Max reconnection attempts reached"));
                }

                let delay = Duration::from_secs(reconnect_delay);
                reconnect_delay = std::cmp::min(reconnect_delay * 2, 60);

                info!(
                    "Retrying in {}s (attempt {}/{})",
                    delay.as_secs(),
                    reconnect_attempts,
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

                continue 'outer;
            }
        };

        info!("Firehose connection established");

        let (_sink, mut stream) = subscription.into_stream();
        let mut last_activity = tokio::time::Instant::now();

        'inner: loop {
            tokio::select! {
                item = stream.next() => {
                    last_activity = tokio::time::Instant::now();

                    match item {
                        Some(Ok(message)) => {
                            let sequence = if let SubscribeReposMessage::Commit(ref commit) = message {
                                if commit.seq % 5000 == 0 {
                                    info!("Firehose seq: {}", commit.seq);
                                }
                                Some(commit.seq)
                            } else {
                                None
                            };

                            // Broadcast to all consumers
                            let event = Arc::new(message);
                            if dispatcher.send(event).is_err() {
                                debug!("No active consumers for broadcast");
                            } else if let Some(seq) = sequence {
                                last_cursor = Some(seq);
                                if seq % 100 == 0 {
                                    if let Err(e) = cursor::update_cursor(&db_pool, seq).await {
                                        error!("Failed to update cursor: {}", e);
                                    }
                                }
                            }

                            // Reset reconnect state on success
                            reconnect_attempts = 0;
                            reconnect_delay = 1;
                        }
                        Some(Err(e)) => {
                            if matches!(e.kind(), StreamErrorKind::Decode) {
                                // Jacquard has consumed this individual WebSocket
                                // frame. The connection remains usable; reconnecting
                                // here replays the preceding valid events forever.
                                warn!(cursor = ?last_cursor, "Skipping malformed firehose frame: {}", e);
                                continue 'inner;
                            }
                            if is_closed_error(&e) {
                                warn!("Firehose stream closed, reconnecting...");
                            } else {
                                error!("Firehose stream error: {}", e);
                            }
                            break 'inner;
                        }
                        None => {
                            warn!("Firehose stream ended, reconnecting...");
                            break 'inner;
                        }
                    }
                }
                _ = tokio::time::sleep_until(last_activity + HEARTBEAT_TIMEOUT) => {
                    warn!("No firehose data for {}s, reconnecting...", HEARTBEAT_TIMEOUT.as_secs());
                    break 'inner;
                }
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        info!("Shutdown signal received, stopping firehose ingest");
                        break 'outer;
                    }
                }
            }
        }

        // A successful handshake followed by an immediate close is also a
        // failed connection. Apply the same limits as connection failures.
        reconnect_attempts += 1;
        if reconnect_attempts >= MAX_RECONNECTS {
            return Err(anyhow!("Max reconnection attempts reached"));
        }
        let delay = Duration::from_secs(reconnect_delay);
        reconnect_delay = std::cmp::min(reconnect_delay * 2, 60);
        warn!(
            "Connection interrupted, retrying in {}s (attempt {}/{})",
            delay.as_secs(),
            reconnect_attempts,
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

fn parse_ws_url(url_str: &str) -> Result<Uri<String>> {
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

    Uri::parse(parsed.as_str())
        .map(|uri| uri.to_owned())
        .map_err(|e| anyhow!("Invalid firehose URI: {}", e))
}

fn is_closed_error(e: &StreamError) -> bool {
    matches!(e.kind(), StreamErrorKind::Closed)
}

#[cfg(test)]
mod tests {
    use super::parse_ws_url;

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
}
