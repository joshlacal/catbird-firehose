use anyhow::Result;
use sqlx::{postgres::PgPoolOptions, Pool, Postgres};
use tracing::info;

use crate::models::{ActivitySubscription, PushCandidateEvent};

pub async fn init_db_pool(database_url: &str) -> Result<Pool<Postgres>> {
    info!("Initializing database connection pool");

    // Calculate optimal connection count based on CPU cores
    let max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or_else(|| {
            let cores = num_cpus::get() as u32;
            cores * 2 + 1 // Common formula for connection pools
        });

    info!(
        "Setting database pool to {} max connections",
        max_connections
    );

    let pool = PgPoolOptions::new()
        .max_connections(max_connections)
        .connect(database_url)
        .await?;

    Ok(pool)
}

pub async fn get_registered_users(pool: &Pool<Postgres>) -> Result<Vec<String>> {
    let users = sqlx::query_as::<_, (String,)>("SELECT DISTINCT did FROM user_devices")
        .fetch_all(pool)
        .await?
        .into_iter()
        .map(|(did,)| did)
        .collect();

    Ok(users)
}

pub async fn list_activity_subscriptions_for_subscriber(
    pool: &Pool<Postgres>,
    subscriber_did: &str,
) -> Result<Vec<ActivitySubscription>> {
    let subscriptions = sqlx::query_as::<_, ActivitySubscription>(
        r#"
        SELECT
            id,
            subscriber_did,
            subject_did,
            include_posts,
            include_replies,
            created_at,
            updated_at
        FROM activity_subscriptions
        WHERE subscriber_did = $1
        ORDER BY subject_did
        "#,
    )
    .bind(subscriber_did)
    .fetch_all(pool)
    .await?;

    Ok(subscriptions)
}

pub async fn list_activity_subscribers_for_subject(
    pool: &Pool<Postgres>,
    subject_did: &str,
) -> Result<Vec<ActivitySubscription>> {
    let subscriptions = sqlx::query_as::<_, ActivitySubscription>(
        r#"
        SELECT
            id,
            subscriber_did,
            subject_did,
            include_posts,
            include_replies,
            created_at,
            updated_at
        FROM activity_subscriptions
        WHERE subject_did = $1
        "#,
    )
    .bind(subject_did)
    .fetch_all(pool)
    .await?;

    Ok(subscriptions)
}

pub async fn upsert_activity_subscription(
    pool: &Pool<Postgres>,
    subscriber_did: &str,
    subject_did: &str,
    include_posts: bool,
    include_replies: bool,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO activity_subscriptions (subscriber_did, subject_did, include_posts, include_replies)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (subscriber_did, subject_did)
        DO UPDATE
        SET include_posts = EXCLUDED.include_posts,
            include_replies = EXCLUDED.include_replies,
            updated_at = NOW()
        "#,
    )
    .bind(subscriber_did)
    .bind(subject_did)
    .bind(include_posts)
    .bind(include_replies)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn delete_activity_subscription(
    pool: &Pool<Postgres>,
    subscriber_did: &str,
    subject_did: &str,
) -> Result<()> {
    sqlx::query(
        r#"
        DELETE FROM activity_subscriptions
        WHERE subscriber_did = $1 AND subject_did = $2
        "#,
    )
    .bind(subscriber_did)
    .bind(subject_did)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn enqueue_push_candidate(
    pool: &Pool<Postgres>,
    candidate: &PushCandidateEvent,
) -> Result<bool> {
    let record_json = serde_json::to_string(&candidate.event_record)?;

    let result = sqlx::query(
        r#"
        INSERT INTO push_event_queue (
            recipient_did,
            actor_did,
            notification_type,
            event_cid,
            event_path,
            subject_uri,
            thread_root_uri,
            event_record_json,
            event_timestamp,
            dedupe_key
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, $9, $10)
        ON CONFLICT (dedupe_key) DO NOTHING
        "#,
    )
    .bind(&candidate.recipient_did)
    .bind(&candidate.actor_did)
    .bind(candidate.notification_type.as_queue_key())
    .bind(&candidate.event_cid)
    .bind(&candidate.event_path)
    .bind(&candidate.subject_uri)
    .bind(&candidate.thread_root_uri)
    .bind(record_json)
    .bind(candidate.event_timestamp)
    .bind(candidate.dedupe_key())
    .execute(pool)
    .await?;

    Ok(result.rows_affected() > 0)
}
