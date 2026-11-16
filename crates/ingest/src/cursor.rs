use std::future::Future;
use std::sync::Mutex;

use anyhow::Result;
use sqlx::{FromRow, Pool, Postgres};
use tracing::info;

/// Durable checkpoint of the last dispatched firehose sequence number.
///
/// The ingest loop reads the checkpoint once at startup and writes it
/// periodically while dispatching. Production uses [`PgCursorStore`];
/// [`MemoryCursorStore`] keeps the same contract in memory.
pub trait CursorStore: Send + Sync + 'static {
    fn load(&self) -> impl Future<Output = Result<Option<i64>>> + Send;
    fn save(&self, seq: i64) -> impl Future<Output = Result<()>> + Send;
}

/// `firehose_cursor` table checkpoint.
#[derive(Clone)]
pub struct PgCursorStore {
    pool: Pool<Postgres>,
}

impl PgCursorStore {
    pub fn new(pool: Pool<Postgres>) -> Self {
        Self { pool }
    }
}

impl CursorStore for PgCursorStore {
    async fn load(&self) -> Result<Option<i64>> {
        get_last_cursor(&self.pool).await
    }

    async fn save(&self, seq: i64) -> Result<()> {
        update_cursor(&self.pool, seq).await
    }
}

/// In-process checkpoint that records every save, in order.
#[derive(Debug, Default)]
pub struct MemoryCursorStore {
    cursor: Mutex<Option<i64>>,
    saves: Mutex<Vec<i64>>,
}

impl MemoryCursorStore {
    pub fn with_cursor(seq: i64) -> Self {
        Self {
            cursor: Mutex::new(Some(seq)),
            saves: Mutex::new(Vec::new()),
        }
    }

    pub fn current(&self) -> Option<i64> {
        *self.cursor.lock().expect("cursor lock")
    }

    pub fn saves(&self) -> Vec<i64> {
        self.saves.lock().expect("saves lock").clone()
    }
}

impl CursorStore for MemoryCursorStore {
    async fn load(&self) -> Result<Option<i64>> {
        Ok(self.current())
    }

    async fn save(&self, seq: i64) -> Result<()> {
        *self.cursor.lock().expect("cursor lock") = Some(seq);
        self.saves.lock().expect("saves lock").push(seq);
        Ok(())
    }
}

impl<T: CursorStore> CursorStore for std::sync::Arc<T> {
    fn load(&self) -> impl Future<Output = Result<Option<i64>>> + Send {
        T::load(self)
    }

    fn save(&self, seq: i64) -> impl Future<Output = Result<()>> + Send {
        T::save(self, seq)
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct FirehoseCursor {
    pub id: i32,
    pub cursor: String,
    pub updated_at: sqlx::types::time::OffsetDateTime,
}

pub async fn get_last_cursor(pool: &Pool<Postgres>) -> Result<Option<i64>> {
    let cursor = sqlx::query_as::<_, FirehoseCursor>(
        r#"
        SELECT id, cursor, updated_at
        FROM firehose_cursor
        ORDER BY id DESC
        LIMIT 1
        "#,
    )
    .fetch_optional(pool)
    .await?;

    Ok(cursor.and_then(|c| c.cursor.parse::<i64>().ok()))
}

pub async fn update_cursor(pool: &Pool<Postgres>, cursor: i64) -> Result<()> {
    let cursor_str = cursor.to_string();

    let exists = sqlx::query!("SELECT COUNT(*) as count FROM firehose_cursor")
        .fetch_one(pool)
        .await?
        .count
        .unwrap_or(0)
        > 0;

    if exists {
        sqlx::query!(
            r#"
            UPDATE firehose_cursor
            SET cursor = $1, updated_at = NOW()
            WHERE id = (SELECT id FROM firehose_cursor ORDER BY id DESC LIMIT 1)
            "#,
            cursor_str
        )
        .execute(pool)
        .await?;
    } else {
        sqlx::query!(
            r#"
            INSERT INTO firehose_cursor (cursor, updated_at)
            VALUES ($1, NOW())
            "#,
            cursor_str
        )
        .execute(pool)
        .await?;
    }

    Ok(())
}

pub async fn cleanup_old_cursors(pool: &Pool<Postgres>, days_to_keep: i32) -> Result<()> {
    sqlx::query!(
        r#"
        DELETE FROM firehose_cursor
        WHERE updated_at < NOW() - INTERVAL '1 day' * $1
        AND id NOT IN (SELECT id FROM firehose_cursor ORDER BY updated_at DESC LIMIT 1)
        "#,
        days_to_keep as f64
    )
    .execute(pool)
    .await?;

    info!(
        "Cleaned up old cursor entries (keeping {} days)",
        days_to_keep
    );
    Ok(())
}
