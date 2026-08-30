use std::collections::HashSet;

use anyhow::Result;
use sqlx::{Pool, Postgres};
use tracing::error;

use crate::{
    classifier, db, metrics,
    models::{ActivitySubscriptionKind, BlueskyEvent, NotificationType, PushCandidateEvent},
    subscriptions::ActivitySubscriptionManager,
};

fn canonical_subject_uri(event: &BlueskyEvent, notification_type: &NotificationType) -> Option<String> {
    match notification_type {
        NotificationType::Like
        | NotificationType::Repost
        | NotificationType::ViaLike
        | NotificationType::ViaRepost => event
            .record
            .get("subject")
            .and_then(|subject| subject.get("uri"))
            .and_then(|uri| uri.as_str())
            .map(str::to_owned),
        NotificationType::Follow => Some(format!("at://{}", event.author)),
        NotificationType::Mention
        | NotificationType::Reply
        | NotificationType::Quote
        | NotificationType::ActivitySubscription(_) => Some(format!(
            "at://{}/app.bsky.feed.post/{}",
            event.author,
            event.path.split('/').next_back().unwrap_or_default()
        )),
    }
}

fn thread_root_uri(event: &BlueskyEvent) -> Option<String> {
    event.record
        .get("reply")
        .and_then(|reply| reply.get("root"))
        .and_then(|root| root.get("uri"))
        .and_then(|uri| uri.as_str())
        .map(str::to_owned)
}

fn build_candidate(
    event: &BlueskyEvent,
    recipient_did: &str,
    notification_type: NotificationType,
    auth_generation: i64,
) -> PushCandidateEvent {
    PushCandidateEvent {
        recipient_did: recipient_did.to_string(),
        actor_did: event.author.clone(),
        notification_type: notification_type.clone(),
        event_cid: event.cid.clone(),
        event_path: event.path.clone(),
        subject_uri: canonical_subject_uri(event, &notification_type),
        thread_root_uri: thread_root_uri(event),
        event_record: event.record.clone(),
        event_timestamp: event.timestamp,
        auth_generation,
    }
}

async fn enqueue_candidate_set(
    db_pool: &Pool<Postgres>,
    event: &BlueskyEvent,
    notification_type: NotificationType,
    recipient_dids: Vec<String>,
) -> Result<()> {
    for recipient_did in recipient_dids {
        if recipient_did == event.author {
            continue;
        }

        let auth_gen: Option<i64> = sqlx::query_scalar(
            "SELECT auth_generation FROM push_accounts WHERE account_did = $1 AND auth_revoked_at IS NULL",
        )
        .bind(&recipient_did)
        .fetch_optional(db_pool)
        .await?;

        let Some(gen) = auth_gen else {
            continue;
        };

        if gen <= 0 {
            continue;
        }

        let candidate = build_candidate(event, &recipient_did, notification_type.clone(), gen);
        match db::enqueue_push_candidate(db_pool, &candidate).await {
            Ok(true) => metrics::PUSH_QUEUE_ENQUEUED.inc(),
            Ok(false) => metrics::PUSH_QUEUE_DEDUPED.inc(),
            Err(err) => {
                metrics::PUSH_QUEUE_ENQUEUE_FAILURES.inc();
                error!(
                    recipient = %recipient_did,
                    actor = %event.author,
                    notification_type = candidate.notification_type.as_queue_key(),
                    error = %err,
                    "Failed to enqueue push candidate"
                );
            }
        }
    }

    Ok(())
}

pub async fn enqueue_candidates(
    event: BlueskyEvent,
    db_pool: &Pool<Postgres>,
    activity_subscription_manager: &ActivitySubscriptionManager,
    registered_users_vec: &[String],
    registered_users_set: &HashSet<String>,
) -> Result<()> {
    let timer = std::time::Instant::now();
    metrics::EVENTS_PROCESSED.inc();

    if registered_users_set.is_empty() || !classifier::is_notification_relevant_event(&event.path) {
        return Ok(());
    }

    let classification =
        classifier::classify_event(&event, registered_users_vec, registered_users_set);

    let is_post_event = event.path.contains("app.bsky.feed.post");
    let is_reply_post = is_post_event && event.record.get("reply").is_some();

    let mut activity_targets = Vec::new();
    if is_post_event {
        match activity_subscription_manager
            .list_subscribers_for_subject(&event.author)
            .await
        {
            Ok(subscribers) => {
                for sub in subscribers {
                    if !registered_users_set.contains(&sub.subscriber_did)
                        || sub.subscriber_did == event.author
                    {
                        continue;
                    }

                    let include = if is_reply_post {
                        sub.include_replies
                    } else {
                        sub.include_posts
                    };

                    if include {
                        activity_targets.push(sub.subscriber_did);
                    }
                }
            }
            Err(err) => {
                metrics::PUSH_QUEUE_ENQUEUE_FAILURES.inc();
                error!(
                    actor = %event.author,
                    error = %err,
                    "Failed to load activity subscription targets"
                );
            }
        }
    }

    if let Some((notification_type, relevant_dids)) = classification {
        enqueue_candidate_set(db_pool, &event, notification_type, relevant_dids).await?;
    }

    if !activity_targets.is_empty() {
        activity_targets.sort();
        activity_targets.dedup();

        let activity_kind = if is_reply_post {
            ActivitySubscriptionKind::Reply
        } else {
            ActivitySubscriptionKind::Post
        };

        enqueue_candidate_set(
            db_pool,
            &event,
            NotificationType::ActivitySubscription(activity_kind),
            activity_targets,
        )
        .await?;
    }

    metrics::EVENT_PROCESSING_TIME.observe(timer.elapsed().as_secs_f64());
    Ok(())
}
