use anyhow::Result;
use sqlx::{FromRow, Pool, Postgres};
use tracing::info;

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
