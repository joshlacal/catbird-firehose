//! Real ingest-loop regressions against a local WebSocket relay. The cursor
//! checkpoint is held in memory, so these run in the default `cargo test`
//! with no database, upstream firehose, or push service.

// Tungstenite requires its unboxed HTTP error response in handshake callbacks.
#![allow(clippy::result_large_err)]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use catbird_firehose_ingest::{
    connection::run_firehose_ingest_with_store,
    cursor::MemoryCursorStore,
    metrics::{frames_dropped, DROPPED_MALFORMED, DROPPED_OVERSIZE_SKIPPED},
};
use futures::SinkExt;
use petrel_core::{dagcbor, Cid, Value};
use petrel_firehose::RelayEvent;
use tokio::{
    net::TcpListener,
    sync::{broadcast, mpsc, watch},
    time::{timeout, Instant},
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{handshake::server::Request, Message},
};

fn object(entries: Vec<(&str, Value)>) -> Value {
    Value::Object(
        entries
            .into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect::<BTreeMap<_, _>>(),
    )
}

/// One canonical DAG-CBOR `#commit` frame (header then body).
fn commit_frame(seq: i64, rev: &str) -> Vec<u8> {
    let header = object(vec![
        ("op", Value::Integer(1)),
        ("t", Value::String("#commit".into())),
    ]);
    let body = object(vec![
        ("blobs", Value::Array(vec![])),
        ("blocks", Value::Bytes(vec![])),
        ("commit", Value::Link(Cid::for_dag_cbor(b"commit"))),
        ("ops", Value::Array(vec![])),
        ("rebase", Value::Bool(false)),
        (
            "repo",
            Value::String("did:plc:abcdefghijklmnopqrstuvwx".into()),
        ),
        ("rev", Value::String(rev.into())),
        ("seq", Value::Integer(seq)),
        ("time", Value::String("2026-09-11T12:00:00Z".into())),
        ("tooBig", Value::Bool(false)),
    ]);
    let mut bytes = dagcbor::encode(&header);
    bytes.extend(dagcbor::encode(&body));
    bytes
}

fn seeded_cursor() -> Arc<MemoryCursorStore> {
    Arc::new(MemoryCursorStore::with_cursor(100))
}

async fn next_seq(receiver: &mut broadcast::Receiver<Arc<RelayEvent>>) -> i64 {
    let event = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("ingest must dispatch the next valid commit")
        .unwrap();
    match &*event {
        RelayEvent::Commit(commit) => commit.seq,
        other => panic!("unexpected event: {other:?}"),
    }
}

#[tokio::test]
async fn malformed_tid_does_not_replay_preceding_commit() {
    let cursor = seeded_cursor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (connections, mut observed_connections) = mpsc::unbounded_channel();
    let relay = tokio::spawn(async move {
        let mut sockets = vec![];
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(tcp, |request: &Request, response| {
                connections.send(request.uri().to_string()).unwrap();
                Ok(response)
            })
            .await
            .unwrap();
            for (seq, rev) in [
                (101, "3jzfcijpj2z2a"),
                (102, "3lty3lqll8co8"),
                (103, "3jzfcijpj2z2a"),
            ] {
                ws.send(Message::Binary(commit_frame(seq, rev)))
                    .await
                    .unwrap();
            }
            // Keep the socket open: a decode failure must not disconnect it.
            sockets.push(ws);
        }
    });
    let (dispatcher, mut receiver) = broadcast::channel(16);
    let (stop, shutdown) = watch::channel(false);
    let ingest = tokio::spawn(run_firehose_ingest_with_store(
        endpoint,
        dispatcher,
        cursor.clone(),
        shutdown,
    ));

    let received = [next_seq(&mut receiver).await, next_seq(&mut receiver).await];
    stop.send(true).unwrap();
    timeout(Duration::from_secs(2), ingest)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    relay.abort();

    assert_eq!(
        received,
        [101, 103],
        "bad frame must be consumed without replaying 101"
    );
    assert!(observed_connections
        .recv()
        .await
        .unwrap()
        .ends_with("?cursor=100"));
    assert!(
        observed_connections.try_recv().is_err(),
        "decode error must not reconnect"
    );
}

#[tokio::test]
async fn transport_reconnect_resumes_latest_dispatched_cursor() {
    let cursor = seeded_cursor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (connections, mut observed_connections) = mpsc::unbounded_channel();
    let relay = tokio::spawn(async move {
        let mut sockets = vec![];
        for connection in 0..2 {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(tcp, |request: &Request, response| {
                connections.send(request.uri().to_string()).unwrap();
                Ok(response)
            })
            .await
            .unwrap();
            if connection == 0 {
                ws.send(Message::Binary(commit_frame(101, "3jzfcijpj2z2a")))
                    .await
                    .unwrap();
                ws.close(None).await.unwrap();
            } else {
                // Retain until the test shuts down the ingest task.
                sockets.push(ws);
                std::future::pending::<()>().await;
            }
        }
    });
    let (dispatcher, mut receiver) = broadcast::channel(16);
    let (stop, shutdown) = watch::channel(false);
    let ingest = tokio::spawn(run_firehose_ingest_with_store(
        endpoint,
        dispatcher,
        cursor.clone(),
        shutdown,
    ));
    assert_eq!(next_seq(&mut receiver).await, 101);
    let first = observed_connections.recv().await.unwrap();
    let second = timeout(Duration::from_secs(5), observed_connections.recv())
        .await
        .unwrap()
        .unwrap();
    stop.send(true).unwrap();
    timeout(Duration::from_secs(2), ingest)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    relay.abort();

    assert!(
        first.ends_with("?cursor=100"),
        "first subscription: {first}"
    );
    assert!(
        second.ends_with("?cursor=101"),
        "reconnect must not reread stale persisted cursor: {second}"
    );
}

#[tokio::test]
async fn immediately_closed_streams_back_off_before_reconnecting() {
    let cursor = seeded_cursor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (connections, mut observed_connections) = mpsc::unbounded_channel();
    let relay = tokio::spawn(async move {
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(tcp, |_: &Request, response| Ok(response))
                .await
                .unwrap();
            connections.send(Instant::now()).unwrap();
            ws.close(None).await.unwrap();
        }
    });
    let (dispatcher, _receiver) = broadcast::channel(16);
    let (stop, shutdown) = watch::channel(false);
    let ingest = tokio::spawn(run_firehose_ingest_with_store(
        endpoint,
        dispatcher,
        cursor.clone(),
        shutdown,
    ));
    let first = timeout(Duration::from_secs(5), observed_connections.recv())
        .await
        .unwrap()
        .unwrap();
    let second = timeout(Duration::from_secs(5), observed_connections.recv())
        .await
        .unwrap()
        .unwrap();
    stop.send(true).unwrap();
    timeout(Duration::from_secs(2), ingest)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    relay.abort();

    assert!(
        second.duration_since(first) >= Duration::from_millis(900),
        "closed streams must wait before reconnecting; actual delay {:?}",
        second.duration_since(first)
    );
}

/// A frame that fails canonical DAG-CBOR parsing (`MalformedFrame`) is skipped on the open
/// connection: no reconnect, and the following commit is still delivered.
#[tokio::test]
async fn non_canonical_frame_is_skipped_without_reconnecting() {
    let dropped_before = frames_dropped(DROPPED_MALFORMED);
    let cursor = seeded_cursor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (connections, mut observed_connections) = mpsc::unbounded_channel();
    let relay = tokio::spawn(async move {
        let mut sockets = vec![];
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut ws = accept_hdr_async(tcp, |request: &Request, response| {
                connections.send(request.uri().to_string()).unwrap();
                Ok(response)
            })
            .await
            .unwrap();
            ws.send(Message::Binary(commit_frame(101, "3jzfcijpj2z2a")))
                .await
                .unwrap();
            // Header map {"op": 1, "t": "#commit"} with the longer key first: DAG-CBOR
            // orders keys by length, so this frame is not canonical.
            let mut garbage = vec![0xa2, 0x62, b'o', b'p', 0x01, 0x61, b't'];
            garbage.extend([0x67, b'#', b'c', b'o', b'm', b'm', b'i', b't']);
            ws.send(Message::Binary(garbage)).await.unwrap();
            ws.send(Message::Binary(commit_frame(102, "3jzfcijpj2z2b")))
                .await
                .unwrap();
            sockets.push(ws);
        }
    });
    let (dispatcher, mut receiver) = broadcast::channel(16);
    let (stop, shutdown) = watch::channel(false);
    let ingest = tokio::spawn(run_firehose_ingest_with_store(
        endpoint,
        dispatcher,
        cursor.clone(),
        shutdown,
    ));

    let received = [next_seq(&mut receiver).await, next_seq(&mut receiver).await];
    stop.send(true).unwrap();
    timeout(Duration::from_secs(2), ingest)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    relay.abort();

    assert_eq!(received, [101, 102]);
    // Counters are process-wide and tests run concurrently, so only a lower bound holds.
    assert!(
        frames_dropped(DROPPED_MALFORMED) > dropped_before,
        "a dropped malformed frame must be counted"
    );
    assert!(observed_connections
        .recv()
        .await
        .unwrap()
        .ends_with("?cursor=100"));
    assert!(
        observed_connections.try_recv().is_err(),
        "malformed frame must not reconnect"
    );
}

/// A frame the transport refuses as too large on every attempt (`FrameTooLargeAtCursor`)
/// moves the cursor one past the last decoded seq instead of failing forever.
#[tokio::test]
async fn persistent_oversize_frame_skips_one_sequence() {
    let cursor = seeded_cursor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let (connections, mut observed_connections) = mpsc::unbounded_channel();
    let relay = tokio::spawn(async move {
        let mut sockets = vec![];
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (uri_tx, uri_rx) = std::sync::mpsc::channel();
            let mut ws = accept_hdr_async(tcp, |request: &Request, response| {
                let uri = request.uri().to_string();
                connections.send(uri.clone()).unwrap();
                uri_tx.send(uri).unwrap();
                Ok(response)
            })
            .await
            .unwrap();
            let uri = uri_rx.recv().unwrap();
            if uri.ends_with("?cursor=100") {
                ws.send(Message::Binary(commit_frame(101, "3jzfcijpj2z2a")))
                    .await
                    .unwrap();
            }
            if uri.ends_with("?cursor=102") {
                ws.send(Message::Binary(commit_frame(103, "3jzfcijpj2z2c")))
                    .await
                    .unwrap();
            } else {
                // Larger than the 5 MB transport limit.
                let _ = ws.send(Message::Binary(vec![0; 5_000_100])).await;
            }
            sockets.push(ws);
        }
    });
    let (dispatcher, mut receiver) = broadcast::channel(16);
    let (stop, shutdown) = watch::channel(false);
    let ingest = tokio::spawn(run_firehose_ingest_with_store(
        endpoint,
        dispatcher,
        cursor.clone(),
        shutdown,
    ));

    assert_eq!(next_seq(&mut receiver).await, 101);
    let after_skip = timeout(Duration::from_secs(15), receiver.recv())
        .await
        .expect("ingest must resume past the oversize frame")
        .unwrap();
    stop.send(true).unwrap();
    timeout(Duration::from_secs(2), ingest)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    relay.abort();

    match &*after_skip {
        RelayEvent::Commit(commit) => assert_eq!(commit.seq, 103),
        other => panic!("unexpected event: {other:?}"),
    }
    let mut uris = vec![];
    while let Ok(uri) = observed_connections.try_recv() {
        uris.push(uri);
    }
    assert!(uris[0].ends_with("?cursor=100"), "{uris:?}");
    assert!(
        uris[1..uris.len() - 1]
            .iter()
            .all(|uri| uri.ends_with("?cursor=101")),
        "{uris:?}"
    );
    assert!(uris.last().unwrap().ends_with("?cursor=102"), "{uris:?}");
}

/// Four consecutive oversize frames (seqs 102-105) each cost three connection attempts.
/// A completed skip is progress, so it must not draw down the ten-attempt reconnect budget,
/// and every skip must reach the durable checkpoint at once (none is a multiple of 100), so a
/// restart resumes past the frames instead of re-hitting them.
#[tokio::test]
async fn consecutive_oversize_frames_keep_ingesting_and_persist_each_skip() {
    let skipped_before = frames_dropped(DROPPED_OVERSIZE_SKIPPED);
    let cursor = seeded_cursor();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("ws://{}", listener.local_addr().unwrap());
    let relay = tokio::spawn(async move {
        let mut sockets = vec![];
        loop {
            let (tcp, _) = listener.accept().await.unwrap();
            let (uri_tx, uri_rx) = std::sync::mpsc::channel();
            let mut ws = accept_hdr_async(tcp, |request: &Request, response| {
                uri_tx.send(request.uri().to_string()).unwrap();
                Ok(response)
            })
            .await
            .unwrap();
            let uri = uri_rx.recv().unwrap();
            if uri.ends_with("?cursor=100") {
                ws.send(Message::Binary(commit_frame(101, "3jzfcijpj2z2a")))
                    .await
                    .unwrap();
            }
            if uri.ends_with("?cursor=105") {
                ws.send(Message::Binary(commit_frame(106, "3jzfcijpj2z2f")))
                    .await
                    .unwrap();
            } else {
                // Larger than the 5 MB transport limit.
                let _ = ws.send(Message::Binary(vec![0; 5_000_100])).await;
            }
            sockets.push(ws);
        }
    });
    let (dispatcher, mut receiver) = broadcast::channel(16);
    let (stop, shutdown) = watch::channel(false);
    let ingest = tokio::spawn(run_firehose_ingest_with_store(
        endpoint,
        dispatcher,
        cursor.clone(),
        shutdown,
    ));

    assert_eq!(next_seq(&mut receiver).await, 101);
    let after_skips = timeout(Duration::from_secs(60), receiver.recv()).await;
    // Ingest may already have exited (the failure this test guards against).
    let _ = stop.send(true);
    let ingest_result = timeout(Duration::from_secs(2), ingest).await;
    relay.abort();

    let after_skips = after_skips
        .expect("ingest must keep going past four consecutive oversize frames")
        .unwrap();
    match &*after_skips {
        RelayEvent::Commit(commit) => assert_eq!(commit.seq, 106),
        other => panic!("unexpected event: {other:?}"),
    }
    ingest_result.unwrap().unwrap().unwrap();
    assert_eq!(cursor.saves(), vec![102, 103, 104, 105]);
    assert!(frames_dropped(DROPPED_OVERSIZE_SKIPPED) >= skipped_before + 4);
}
