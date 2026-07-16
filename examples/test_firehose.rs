//! Quick integration test: connect to bsky.network firehose via jacquard,
//! receive events for 10 seconds, and print stats.
//!
//! Usage: cargo run --example test_firehose

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use jacquard_api::com_atproto::sync::subscribe_repos::{
    SubscribeRepos, SubscribeReposMessage, SubscribeReposStream,
};
use jacquard_common::websocket::tungstenite_client::TungsteniteClient;
use jacquard_common::xrpc::subscription::SubscriptionExt;
use tokio::sync::broadcast;
use url::Url;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let firehose_url =
        std::env::var("BSKY_SERVICE_URL").unwrap_or_else(|_| "wss://bsky.network".to_string());

    println!("Connecting to firehose: {}", firehose_url);

    let url = Url::parse(&firehose_url)?;
    let ws_client = TungsteniteClient::new();
    let params = SubscribeRepos::new().build();

    let subscription: jacquard_common::xrpc::subscription::SubscriptionStream<
        SubscribeReposStream,
    > = ws_client.subscription(url).subscribe(&params).await?;

    println!("Connected! Receiving events for 10 seconds...\n");

    let (_sink, mut stream) = subscription.into_stream();

    // Also test broadcast fanout
    let (tx, mut rx1) = broadcast::channel::<Arc<SubscribeReposMessage<'static>>>(4096);
    let mut rx2 = tx.subscribe();

    let mut total = 0u64;
    let mut commits = 0u64;
    let mut identities = 0u64;
    let mut accounts = 0u64;
    let mut other = 0u64;
    let mut collections: HashMap<String, u64> = HashMap::new();
    let mut consumer1_count = 0u64;
    let mut consumer2_count = 0u64;

    let start = tokio::time::Instant::now();
    let deadline = start + Duration::from_secs(10);

    loop {
        tokio::select! {
            item = stream.next() => {
                match item {
                    Some(Ok(message)) => {
                        total += 1;

                        match &message {
                            SubscribeReposMessage::Commit(commit) => {
                                commits += 1;
                                for op in &commit.ops {
                                    let path = op.path.as_ref();
                                    if let Some(col) = path.split('/').next() {
                                        *collections.entry(col.to_string()).or_insert(0) += 1;
                                    }
                                }
                                if commits == 1 {
                                    println!("First commit: repo={}, seq={}, ops={}",
                                        commit.repo, commit.seq, commit.ops.len());
                                }
                            }
                            SubscribeReposMessage::Identity(_) => identities += 1,
                            SubscribeReposMessage::Account(_) => accounts += 1,
                            _ => other += 1,
                        }

                        // Broadcast to fanout consumers
                        let event = Arc::new(message);
                        let _ = tx.send(event);
                    }
                    Some(Err(e)) => {
                        eprintln!("Stream error: {}", e);
                        break;
                    }
                    None => {
                        eprintln!("Stream ended");
                        break;
                    }
                }
            }
            _ = tokio::time::sleep_until(deadline) => {
                println!("\n--- 10 second deadline reached ---");
                break;
            }
        }

        // Drain broadcast receivers
        while let Ok(_) = rx1.try_recv() {
            consumer1_count += 1;
        }
        while let Ok(_) = rx2.try_recv() {
            consumer2_count += 1;
        }
    }

    // Final drain
    while let Ok(_) = rx1.try_recv() {
        consumer1_count += 1;
    }
    while let Ok(_) = rx2.try_recv() {
        consumer2_count += 1;
    }

    let elapsed = start.elapsed().as_secs_f64();
    let rate = total as f64 / elapsed;

    println!("\n=== Firehose Test Results ===");
    println!("Duration:    {:.1}s", elapsed);
    println!("Total msgs:  {}", total);
    println!("Rate:        {:.0} events/sec", rate);
    println!();
    println!("Message types:");
    println!("  Commits:    {}", commits);
    println!("  Identity:   {}", identities);
    println!("  Account:    {}", accounts);
    println!("  Other:      {}", other);
    println!();
    println!("Collections (top 10):");
    let mut sorted: Vec<_> = collections.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    for (col, count) in sorted.iter().take(10) {
        println!("  {}: {}", col, count);
    }
    println!();
    println!("Fanout test:");
    println!("  Consumer 1 received: {}", consumer1_count);
    println!("  Consumer 2 received: {}", consumer2_count);

    if total > 0 && commits > 0 && consumer1_count > 0 && consumer2_count > 0 {
        println!("\n✅ All checks passed — firehose + fanout working");
    } else {
        println!("\n❌ Some checks failed");
        if total == 0 {
            println!("  - No messages received");
        }
        if commits == 0 {
            println!("  - No commits received");
        }
        if consumer1_count == 0 {
            println!("  - Consumer 1 received nothing");
        }
        if consumer2_count == 0 {
            println!("  - Consumer 2 received nothing");
        }
    }

    Ok(())
}
