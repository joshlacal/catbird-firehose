mod config;
mod logging;

use anyhow::Result;
use catbird_firehose_consumer_push::subscriptions::ActivitySubscriptionManager;
use catbird_firehose_consumer_push::PushConsumer;
use catbird_firehose_fanout::{consumer::spawn_consumer, Dispatcher};
use catbird_firehose_ingest::{connection, cursor};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, info};

const SHUTDOWN_TIMEOUT_SECS: u64 = 10;

async fn join_task<T>(name: &str, handle: JoinHandle<T>) {
    match tokio::time::timeout(
        tokio::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS),
        handle,
    )
    .await
    {
        Ok(Ok(_)) => info!(task = name, "Task stopped"),
        Ok(Err(err)) => error!(task = name, "Task panicked: {}", err),
        Err(_) => error!(task = name, "Timed out waiting for task shutdown"),
    }
}

fn spawn_cursor_cleanup_task(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    mut shutdown: watch::Receiver<bool>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));

        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(err) = cursor::cleanup_old_cursors(&db_pool, 1).await {
                        error!("Error cleaning up cursor history: {}", err);
                    }
                }
                changed = shutdown.changed() => {
                    if changed.is_ok() && *shutdown.borrow() {
                        info!("Stopping cursor cleanup task");
                        break;
                    }
                }
            }
        }
    })
}

fn main() -> Result<()> {
    let worker_threads = std::env::var("TOKIO_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(num_cpus::get);

    println!("Starting with {} Tokio worker threads", worker_threads);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(worker_threads)
        .enable_all()
        .build()
        .unwrap();

    runtime.block_on(async {
        logging::setup_logging();
        dotenv::dotenv().ok();

        info!("Starting Catbird Firehose Service");

        let config = config::Config::from_env()?;
        let db_pool =
            catbird_firehose_consumer_push::db::init_db_pool(&config.database_url).await?;

        if let Err(err) = cursor::cleanup_old_cursors(&db_pool, 1).await {
            error!("Error during cursor cleanup: {}", err);
        }

        let activity_subscription_manager =
            Arc::new(ActivitySubscriptionManager::new(db_pool.clone()));
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let cursor_cleanup_handle = spawn_cursor_cleanup_task(db_pool.clone(), shutdown_rx.clone());

        let push_consumer = Arc::new(PushConsumer::new(
            db_pool.clone(),
            activity_subscription_manager,
        ));
        let push_background_handle = push_consumer
            .start_background_tasks(shutdown_rx.clone())
            .await;

        let dispatcher = Dispatcher::new();
        let push_rx = dispatcher.subscribe();
        let push_handle = spawn_consumer(push_consumer, push_rx);

        let mut ingest_handle = tokio::spawn(connection::run_firehose_ingest(
            config.bsky_service_url.clone(),
            dispatcher.sender(),
            db_pool.clone(),
            shutdown_rx.clone(),
        ));

        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Received shutdown signal");
            }
            result = &mut ingest_handle => {
                match result {
                    Ok(Ok(())) => info!("Ingest task exited cleanly"),
                    Ok(Err(err)) => error!("Ingest task failed: {}", err),
                    Err(err) => error!("Ingest task panicked: {}", err),
                }
                error!("Critical: Ingest task stopped, initiating shutdown");
            }
        }

        if shutdown_tx.send(true).is_err() {
            error!("Failed to broadcast shutdown signal");
        }

        drop(dispatcher);

        join_task("ingest", ingest_handle).await;
        join_task("push-consumer", push_handle).await;
        join_task("push-user-refresh", push_background_handle).await;
        join_task("cursor-cleanup", cursor_cleanup_handle).await;

        db_pool.close().await;

        info!("Shutdown complete");
        Ok(())
    })
}
