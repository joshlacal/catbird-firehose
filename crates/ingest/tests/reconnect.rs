//! Real ingest-loop regressions. Each test uses an isolated SQLx database and a
//! local relay; no upstream firehose, push service, or production DB is used.
//! Run with SQLX_OFFLINE=true DATABASE_URL=postgresql://localhost/postgres
//! cargo test -p catbird-firehose-ingest --test reconnect -- --ignored.

// Tungstenite requires its unboxed HTTP error response in handshake callbacks.
#![allow(clippy::result_large_err)]

use std::{sync::Arc, time::Duration};

use catbird_firehose_ingest::connection::run_firehose_ingest;
use ciborium::Value;
use futures::SinkExt;
use jacquard_api::com_atproto::sync::subscribe_repos::SubscribeReposMessage;
use sqlx::PgPool;
use tokio::{
    net::TcpListener,
    sync::{broadcast, mpsc, watch},
    time::{timeout, Instant},
};
use tokio_tungstenite::{
    accept_hdr_async,
    tungstenite::{handshake::server::Request, Message},
};

fn field(name: &str, value: Value) -> (Value, Value) {
    (Value::Text(name.into()), value)
}

fn commit_frame(seq: i64, rev: &str) -> Vec<u8> {
    // CIDv1, dag-cbor, sha2-256, 32-byte digest. Tag 42 has a leading zero.
    let mut cid = vec![0, 1, 0x71, 0x12, 0x20];
    cid.extend([0; 32]);
    let header = Value::Map(vec![
        field("op", Value::Integer(1.into())),
        field("t", Value::Text("#commit".into())),
    ]);
    let body = Value::Map(vec![
        field("blobs", Value::Array(vec![])),
        field("blocks", Value::Bytes(vec![])),
        field("commit", Value::Tag(42, Box::new(Value::Bytes(cid)))),
        field("ops", Value::Array(vec![])),
        field("rebase", Value::Bool(false)),
        field(
            "repo",
            Value::Text("did:plc:abcdefghijklmnopqrstuvwx".into()),
        ),
        field("rev", Value::Text(rev.into())),
        field("seq", Value::Integer(seq.into())),
        field("time", Value::Text("2026-09-11T12:00:00Z".into())),
        field("tooBig", Value::Bool(false)),
    ]);
    let mut bytes = vec![];
    ciborium::into_writer(&header, &mut bytes).unwrap();
    ciborium::into_writer(&body, &mut bytes).unwrap();
    bytes
}

async fn seed_cursor(pool: &PgPool) {
    sqlx::raw_sql(
        "CREATE TABLE firehose_cursor (
            id SERIAL PRIMARY KEY, cursor TEXT NOT NULL,
            updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        );
        INSERT INTO firehose_cursor (cursor) VALUES ('100');",
    )
    .execute(pool)
    .await
    .unwrap();
}

async fn next_seq(receiver: &mut broadcast::Receiver<Arc<SubscribeReposMessage>>) -> i64 {
    let event = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("ingest must dispatch the next valid commit")
        .unwrap();
    match &*event {
        SubscribeReposMessage::Commit(commit) => commit.seq,
        other => panic!("unexpected event: {other:?}"),
    }
}

#[sqlx::test(migrations = false)]
#[ignore = "requires a local PostgreSQL admin DATABASE_URL; creates an isolated test database"]
async fn malformed_tid_does_not_replay_preceding_commit(pool: PgPool) {
    seed_cursor(&pool).await;
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
    let ingest = tokio::spawn(run_firehose_ingest(endpoint, dispatcher, pool, shutdown));

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

#[sqlx::test(migrations = false)]
#[ignore = "requires a local PostgreSQL admin DATABASE_URL; creates an isolated test database"]
async fn transport_reconnect_resumes_latest_dispatched_cursor(pool: PgPool) {
    seed_cursor(&pool).await;
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
    let ingest = tokio::spawn(run_firehose_ingest(endpoint, dispatcher, pool, shutdown));
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

#[sqlx::test(migrations = false)]
#[ignore = "requires a local PostgreSQL admin DATABASE_URL; creates an isolated test database"]
async fn immediately_closed_streams_back_off_before_reconnecting(pool: PgPool) {
    seed_cursor(&pool).await;
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
    let ingest = tokio::spawn(run_firehose_ingest(endpoint, dispatcher, pool, shutdown));
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
