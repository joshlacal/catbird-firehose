//! Quick integration test: connect to bsky.network firehose via Petrel,
//! receive events for 10 seconds, and print stats.
//!
//! Usage: cargo run --example test_firehose

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use petrel_firehose::{
    FirehoseSubscription, FirehoseSubscriptionEvent, InMemoryFirehoseCursorStorage, RelayEvent,
};
use tokio::sync::broadcast;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let firehose_url =
        std::env::var("BSKY_SERVICE_URL").unwrap_or_else(|_| "wss://bsky.network".to_string());

    println!("Connecting to firehose: {}", firehose_url);

    let service = url::Url::parse(&firehose_url)?;
    let subscription = FirehoseSubscription::from_service(
        &service,
        Arc::new(InMemoryFirehoseCursorStorage::new()),
        true,
    );
    let mut stream = subscription.events();

    println!("Receiving events for 10 seconds...\n");

    // Also test broadcast fanout
    let (tx, mut rx1) = broadcast::channel::<Arc<RelayEvent>>(4096);
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
                    Some(Ok(FirehoseSubscriptionEvent::Event(message))) => {
                        total += 1;

                        match &message {
                            RelayEvent::Commit(commit) => {
                                commits += 1;
                                for op in &commit.ops {
                                    if let Some(col) = op.path.split('/').next() {
                                        *collections.entry(col.to_string()).or_insert(0) += 1;
                                    }
                                }
                                if commits == 1 {
                                    println!("First commit: repo={}, seq={}, ops={}",
                                        commit.repo, commit.seq, commit.ops.len());
                                }
                            }
                            RelayEvent::Identity(_) => identities += 1,
                            RelayEvent::Account(_) => accounts += 1,
                            _ => other += 1,
                        }

                        // Broadcast to fanout consumers
                        let event = Arc::new(message);
                        let _ = tx.send(event);
                    }
                    Some(Ok(FirehoseSubscriptionEvent::SequenceGap { .. }))
                    | Some(Ok(FirehoseSubscriptionEvent::IgnoredFrame(_))) => other += 1,
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
        while rx1.try_recv().is_ok() {
            consumer1_count += 1;
        }
        while rx2.try_recv().is_ok() {
            consumer2_count += 1;
        }
    }

    // Final drain
    while rx1.try_recv().is_ok() {
        consumer1_count += 1;
    }
    while rx2.try_recv().is_ok() {
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
