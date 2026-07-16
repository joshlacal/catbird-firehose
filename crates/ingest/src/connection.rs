use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Result};
use futures::StreamExt;
use jacquard_common::stream::StreamError;
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
/// parses messages into typed `SubscribeReposMessage<'static>`, and broadcasts
/// them to all consumers via the provided `broadcast::Sender`.
pub async fn run_firehose_ingest(
    firehose_url: String,
    dispatcher: broadcast::Sender<Arc<SubscribeReposMessage<'static>>>,
    db_pool: Pool<Postgres>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    info!("Starting firehose ingest");

    let mut reconnect_delay = 1u64;
    let mut reconnect_attempts = 0u32;

    'outer: loop {
        let last_cursor = match cursor::get_last_cursor(&db_pool).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to get last cursor: {}", e);
                None
            }
        };

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
                            // Update cursor for commits
                            if let SubscribeReposMessage::Commit(ref commit) = message {
                                if commit.seq % 5000 == 0 {
                                    info!("Firehose seq: {}", commit.seq);
                                }
                                if commit.seq % 100 == 0 {
                                    if let Err(e) = cursor::update_cursor(&db_pool, commit.seq).await {
                                        error!("Failed to update cursor: {}", e);
                                    }
                                }
                            }

                            // Broadcast to all consumers
                            let event = Arc::new(message);
                            if dispatcher.send(event).is_err() {
                                debug!("No active consumers for broadcast");
                            }

                            // Reset reconnect state on success
                            reconnect_attempts = 0;
                            reconnect_delay = 1;
                        }
                        Some(Err(e)) => {
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

        warn!("Connection interrupted, attempting to reconnect");
    }

    info!("Firehose ingest stopped");
    Ok(())
}

fn parse_ws_url(url_str: &str) -> Result<Url> {
    // Ensure we have a WebSocket scheme
    let ws_url = if url_str.starts_with("https://") {
        url_str.replacen("https://", "wss://", 1)
    } else if url_str.starts_with("http://") {
        url_str.replacen("http://", "ws://", 1)
    } else if !url_str.starts_with("wss://") && !url_str.starts_with("ws://") {
        format!("wss://{}", url_str)
    } else {
        url_str.to_string()
    };

    Url::parse(&ws_url).map_err(|e| anyhow!("Invalid firehose URL: {}", e))
}

fn is_closed_error(e: &StreamError) -> bool {
    e.to_string().contains("closed")
}
