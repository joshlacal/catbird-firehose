# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Cargo workspace that connects to Bluesky's AT Protocol firehose, fans events out to pluggable consumers via `tokio::broadcast`, and sends push notifications. Refactored from the single-binary `bluesky-push-notifier` into a modular workspace.

## Crate Layout

| Crate | Path | Purpose |
|-------|------|---------|
| **catbird-firehose** | `src/` | Binary root -- wires ingest, fanout, consumers, API server, and background tasks |
| **catbird-firehose-ingest** | `crates/ingest/` | Firehose WebSocket connection (`connection.rs`) and cursor persistence (`cursor.rs`) |
| **catbird-firehose-fanout** | `crates/fanout/` | Broadcast dispatcher + `Consumer` trait for pluggable event consumers |
| **catbird-firehose-consumer-push** | `crates/consumer-push/` | Push notification pipeline: event classification, APNS delivery, REST API, App Attest, relationship/moderation management |

## Build Commands

```bash
cargo build                        # Build all crates
cargo check                        # Type-check without codegen
SQLX_OFFLINE=true cargo build      # Build without a live database (uses .sqlx/ metadata)
cargo fmt                          # Format code
cargo clippy                       # Lint
cargo test                         # Run tests
```

Use `SQLX_OFFLINE=true` for CI or when no PostgreSQL instance is available.

## Architecture / Data Flow

```
Bluesky firehose (WebSocket)
  --> ingest (connection.rs, cursor persistence)
    --> tokio::broadcast channel
      --> fanout dispatcher
        --> PushConsumer (implements Consumer trait)
          --> classifier --> notifier --> APNS (a2 crate)
```

The binary (`src/main.rs`) also spawns:
- **Axum API server** for device registration, preferences, App Attest, and moderation
- **Background maintenance** tasks (relationship cache, DID/post cache cleanup, cursor cleanup)
- **APNS sender** goroutine reading from an `mpsc` channel

## Key Dependencies

- **jacquard** -- AT Protocol SDK (firehose subscription, API types, identity resolution)
- **atrium-repo** + **serde_ipld_dagcbor** -- CAR block parsing and DAG-CBOR deserialization
- **a2** -- Apple Push Notification Service client
- **sqlx** -- Async PostgreSQL with compile-time query checking
- **axum** + **tower-http** -- HTTP API server
- **moka** -- Async caching (relationships, DIDs, posts)
- **appattest-rs** -- iOS App Attest verification (patched from `../bluesky-push-notifier/crates/appattest-rs-0.1.0`)

## Environment Variables

### Required
| Variable | Description |
|----------|-------------|
| `DATABASE_URL` | PostgreSQL connection string |
| `APNS_KEY_PATH` | Path to APNS `.p8` key file |
| `APNS_KEY_ID` | APNS key identifier |
| `APNS_TEAM_ID` | Apple team identifier |
| `APNS_TOPIC` | APNS topic (bundle ID) |
| `APP_ATTEST_APP_ID` | App Attest app identifier |

### Optional
| Variable | Default | Description |
|----------|---------|-------------|
| `APNS_PRODUCTION` | `false` | Use production APNS gateway |
| `APP_ATTEST_CHALLENGE_TTL_SECS` | `300` | App Attest challenge lifetime |
| `APP_ATTEST_PRODUCTION` | matches `APNS_PRODUCTION` | App Attest environment |
| `BSKY_SERVICE_URL` | `https://bsky.network` | Firehose WebSocket endpoint |
| `BSKY_API_URL` | `https://public.api.bsky.app` | Bluesky public API |
| `API_BIND_ADDRESS` | `0.0.0.0:8080` | API server listen address |
| `TOKIO_WORKER_THREADS` | CPU count | Tokio runtime worker threads |
| `LOG_LEVEL` | `info` | Base log level for `catbird_firehose` target |
| `EXTRA_LOG_DIRECTIVES` | -- | Comma-separated tracing directives (e.g. `catbird_firehose_ingest=debug`) |

## Database

- **PostgreSQL** with `pgcrypto` extension for encrypted relationship storage
- Migrations in `migrations/` (SQLx format, up/down pairs)
- Offline query metadata in `.sqlx/` (regenerate with `cargo sqlx prepare`)
- Apply migrations: `sqlx migrate run` (requires `DATABASE_URL`)

## Coding Style

- `cargo fmt` for formatting, `cargo clippy` for linting
- Standard Rust conventions (see workspace `CLAUDE.md` for shared guidelines)
