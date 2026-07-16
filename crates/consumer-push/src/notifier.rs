use anyhow::Result;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::{
    classifier, db, media,
    models::{ActivitySubscriptionKind, BlueskyEvent, NotificationPayload, NotificationType},
    relationships::{ModerationListManager, RelationshipManager, ThreadMuteManager},
    resolvers::{DidResolver, PostResolver},
    subscriptions::ActivitySubscriptionManager,
};
use sqlx::{Pool, Postgres};

const NOTIFICATION_QUEUE_SEND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
const NOTIFICATION_QUEUE_BACKPRESSURE_DELAY: std::time::Duration =
    std::time::Duration::from_millis(100);

fn notification_is_high_priority(notification_type: &NotificationType) -> bool {
    matches!(
        notification_type,
        NotificationType::Follow
            | NotificationType::Reply
            | NotificationType::Mention
            | NotificationType::ActivitySubscription(_)
    )
}

fn notification_queue_saturation_ratio(remaining_capacity: usize, max_capacity: usize) -> f64 {
    if max_capacity == 0 {
        return 0.0;
    }

    let used_capacity = max_capacity.saturating_sub(remaining_capacity);
    (used_capacity as f64 / max_capacity as f64).clamp(0.0, 1.0)
}

/// Create notification content (title, body, uri, media_urls, thumbnail_url)
/// from a classified event.
pub async fn create_notification_content(
    handle_map: &HashMap<String, String>,
    notification_type: &NotificationType,
    event: &BlueskyEvent,
    post_resolver: &PostResolver,
) -> Result<(
    String,
    String,
    Option<String>,
    Option<Vec<String>>,
    Option<String>,
)> {
    // Use resolved handle if available, fallback to DID
    let username = handle_map.get(&event.author).cloned().unwrap_or_else(|| {
        event
            .author
            .split(':')
            .last()
            .unwrap_or(&event.author)
            .to_string()
    });

    // Extract media from embed if present
    let (media_urls, thumbnail_url) = if let Some(embed) = event.record.get("embed") {
        media::extract_media_from_embed(embed, &event.author)
    } else {
        (None, None)
    };

    let (title, body, uri) = match notification_type {
        NotificationType::Like => {
            if let Some(subject) = event.record.get("subject").and_then(|s| s.as_object()) {
                if let Some(uri) = subject.get("uri").and_then(|u| u.as_str()) {
                    match post_resolver.get_post_content(uri).await {
                        Ok(content) => (
                            format!("@{} liked your post", username),
                            content,
                            Some(uri.to_string()),
                        ),
                        Err(e) => {
                            warn!(error = %e, "Failed to get original post content for like");
                            (
                                format!("@{} liked your post", username),
                                "".to_string(),
                                Some(uri.to_string()),
                            )
                        }
                    }
                } else {
                    (
                        format!("@{} liked your post", username),
                        "".to_string(),
                        None,
                    )
                }
            } else {
                (
                    format!("@{} liked your post", username),
                    "".to_string(),
                    None,
                )
            }
        }
        NotificationType::Repost => {
            if let Some(subject) = event.record.get("subject").and_then(|s| s.as_object()) {
                if let Some(uri) = subject.get("uri").and_then(|u| u.as_str()) {
                    match post_resolver.get_post_content(uri).await {
                        Ok(content) => (
                            format!("@{} reposted your post", username),
                            content,
                            Some(uri.to_string()),
                        ),
                        Err(e) => {
                            warn!(error = %e, "Failed to get original post content for repost");
                            (
                                format!("@{} reposted your post", username),
                                "".to_string(),
                                Some(uri.to_string()),
                            )
                        }
                    }
                } else {
                    (
                        format!("@{} reposted your post", username),
                        "".to_string(),
                        None,
                    )
                }
            } else {
                (
                    format!("@{} reposted your post", username),
                    "".to_string(),
                    None,
                )
            }
        }
        NotificationType::Reply => {
            let post_text = event
                .record
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let uri = format!(
                "at://{}/app.bsky.feed.post/{}",
                event.author,
                event.path.split('/').last().unwrap_or("")
            );

            (
                format!("@{} replied to you", username),
                post_text.to_string(),
                Some(uri),
            )
        }
        NotificationType::Mention => {
            let post_text = event
                .record
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let uri = format!(
                "at://{}/app.bsky.feed.post/{}",
                event.author,
                event.path.split('/').last().unwrap_or("")
            );

            (
                format!("@{} mentioned you", username),
                post_text.to_string(),
                Some(uri),
            )
        }
        NotificationType::Quote => {
            let post_text = event
                .record
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            let uri = format!(
                "at://{}/app.bsky.feed.post/{}",
                event.author,
                event.path.split('/').last().unwrap_or("")
            );

            (
                format!("@{} quoted your post", username),
                post_text.to_string(),
                Some(uri),
            )
        }
        NotificationType::Follow => {
            let profile_uri = format!("at://{}", event.author);

            (
                "New follower".to_string(),
                format!("@{} followed you", username),
                Some(profile_uri),
            )
        }
        NotificationType::ViaLike => {
            if let Some(subject) = event.record.get("subject").and_then(|s| s.as_object()) {
                if let Some(uri) = subject.get("uri").and_then(|u| u.as_str()) {
                    match post_resolver.get_post_content(uri).await {
                        Ok(content) => (
                            format!("@{} liked a post via your repost", username),
                            content,
                            Some(uri.to_string()),
                        ),
                        Err(e) => {
                            warn!(error = %e, "Failed to get original post content for via like");
                            (
                                format!("@{} liked a post via your repost", username),
                                "".to_string(),
                                Some(uri.to_string()),
                            )
                        }
                    }
                } else {
                    (
                        format!("@{} liked a post via your repost", username),
                        "".to_string(),
                        None,
                    )
                }
            } else {
                (
                    format!("@{} liked a post via your repost", username),
                    "".to_string(),
                    None,
                )
            }
        }
        NotificationType::ViaRepost => {
            if let Some(subject) = event.record.get("subject").and_then(|s| s.as_object()) {
                if let Some(uri) = subject.get("uri").and_then(|u| u.as_str()) {
                    match post_resolver.get_post_content(uri).await {
                        Ok(content) => (
                            format!("@{} reposted a post via your repost", username),
                            content,
                            Some(uri.to_string()),
                        ),
                        Err(e) => {
                            warn!(error = %e, "Failed to get original post content for via repost");
                            (
                                format!("@{} reposted a post via your repost", username),
                                "".to_string(),
                                Some(uri.to_string()),
                            )
                        }
                    }
                } else {
                    (
                        format!("@{} reposted a post via your repost", username),
                        "".to_string(),
                        None,
                    )
                }
            } else {
                (
                    format!("@{} reposted a post via your repost", username),
                    "".to_string(),
                    None,
                )
            }
        }
        NotificationType::ActivitySubscription(kind) => {
            let post_text = event
                .record
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");

            let uri = format!(
                "at://{}/app.bsky.feed.post/{}",
                event.author,
                event.path.split('/').last().unwrap_or("")
            );

            match kind {
                ActivitySubscriptionKind::Post => (
                    format!("@{} posted a new update", username),
                    post_text.to_string(),
                    Some(uri),
                ),
                ActivitySubscriptionKind::Reply => (
                    format!("@{} replied to a thread", username),
                    post_text.to_string(),
                    Some(uri),
                ),
            }
        }
    };

    debug!(
        notification_type = ?notification_type,
        username = %username,
        title = %title,
        body = %body,
        uri = ?uri,
        media_count = media_urls.as_ref().map(|m| m.len()).unwrap_or(0),
        has_thumbnail = thumbnail_url.is_some(),
        "Created notification content"
    );

    Ok((title, body, uri, media_urls, thumbnail_url))
}

/// Run the event filter pipeline: classify events, check relationships/preferences,
/// build notification payloads and send them to the APNS sender.
pub async fn run_event_filter(
    event: BlueskyEvent,
    notification_sender: &mpsc::Sender<NotificationPayload>,
    db_pool: &Pool<Postgres>,
    did_resolver: &Arc<DidResolver>,
    post_resolver: &Arc<PostResolver>,
    relationship_manager: &Arc<RelationshipManager>,
    activity_subscription_manager: &Arc<ActivitySubscriptionManager>,
    moderation_list_manager: &Arc<ModerationListManager>,
    thread_mute_manager: &Arc<ThreadMuteManager>,
    registered_users_vec: &[String],
    registered_users_set: &HashSet<String>,
) {
    let timer = std::time::Instant::now();
    crate::metrics::EVENTS_PROCESSED.inc();

    // Early exit if no registered users to notify
    if registered_users_set.is_empty() {
        return;
    }

    // Quick check - only process notification-relevant events
    if !classifier::is_notification_relevant_event(&event.path) {
        return;
    }

    let classification =
        classifier::classify_event(&event, registered_users_vec, registered_users_set);

    let is_post_event = event.path.contains("app.bsky.feed.post");
    let is_reply_post = is_post_event && event.record.get("reply").is_some();

    let mut subscription_targets = Vec::new();
    if is_post_event && !registered_users_set.is_empty() {
        match activity_subscription_manager
            .list_subscribers_for_subject(&event.author)
            .await
        {
            Ok(subscribers) => {
                for sub in subscribers {
                    if sub.subscriber_did == event.author {
                        continue;
                    }

                    if !registered_users_set.contains(&sub.subscriber_did) {
                        continue;
                    }

                    let include = if is_reply_post {
                        sub.include_replies
                    } else {
                        sub.include_posts
                    };

                    if include {
                        subscription_targets.push(sub.subscriber_did);
                    }
                }
            }
            Err(e) => {
                error!(
                    author = %event.author,
                    error = %e,
                    "Failed to fetch activity subscription targets"
                );
            }
        }
    }

    let mut notification_batches: Vec<(NotificationType, Vec<String>)> = Vec::new();

    if let Some((notification_type, relevant_dids)) = classification {
        if !relevant_dids.is_empty() {
            notification_batches.push((notification_type, relevant_dids));
        }
    }

    if !subscription_targets.is_empty() {
        subscription_targets.sort();
        subscription_targets.dedup();

        let kind = if is_reply_post {
            ActivitySubscriptionKind::Reply
        } else {
            ActivitySubscriptionKind::Post
        };

        notification_batches.push((
            NotificationType::ActivitySubscription(kind),
            subscription_targets.clone(),
        ));
    }

    if notification_batches.is_empty() && subscription_targets.is_empty() {
        return;
    }

    for (notification_type, relevant_dids) in notification_batches {
        if relevant_dids.is_empty() {
            continue;
        }

        let mut dids_to_resolve = Vec::new();
        dids_to_resolve.push(event.author.clone());
        dids_to_resolve.extend(relevant_dids.clone());

        let handle_map = did_resolver.get_handles_bulk(&dids_to_resolve).await;

        let devices_map = match db::get_user_devices_batch(db_pool, &relevant_dids).await {
            Ok(map) => map,
            Err(e) => {
                error!("Failed to batch fetch user devices: {}", e);
                continue;
            }
        };

        // Collect all device IDs for batched preference lookup
        let all_device_ids: Vec<uuid::Uuid> = devices_map
            .values()
            .flatten()
            .map(|device| device.id)
            .collect();

        let preferences_map =
            match db::get_notification_preferences_batch(db_pool, &all_device_ids).await {
                Ok(map) => map,
                Err(e) => {
                    error!("Failed to batch fetch notification preferences: {}", e);
                    continue;
                }
            };

        let mut notification_futures = Vec::new();

        for did in &relevant_dids {
            if did == &event.author {
                debug!(recipient = %did, "Skipping self-notification");
                continue;
            }

            match relationship_manager.is_muted(did, &event.author).await {
                Ok(true) => {
                    debug!(
                        recipient = %did,
                        author = %event.author,
                        "Skipping notification - author is muted by recipient"
                    );
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    crate::metrics::RELATIONSHIP_LOOKUP_ERRORS.inc();
                    crate::metrics::NOTIFICATIONS_DROPPED.inc();
                    error!(
                        recipient = %did,
                        author = %event.author,
                        error = %e,
                        "Skipping notification - mute lookup failed"
                    );
                    continue;
                }
            }

            match relationship_manager.is_blocked(did, &event.author).await {
                Ok(true) => {
                    debug!(
                        recipient = %did,
                        author = %event.author,
                        "Skipping notification - author is blocked by recipient"
                    );
                    continue;
                }
                Ok(false) => {}
                Err(e) => {
                    crate::metrics::RELATIONSHIP_LOOKUP_ERRORS.inc();
                    crate::metrics::NOTIFICATIONS_DROPPED.inc();
                    error!(
                        recipient = %did,
                        author = %event.author,
                        error = %e,
                        "Skipping notification - block lookup failed"
                    );
                    continue;
                }
            }

            if moderation_list_manager
                .is_in_block_list(did, &event.author)
                .await
            {
                debug!(
                    recipient = %did,
                    author = %event.author,
                    "Skipping notification - author is in recipient's block list"
                );
                continue;
            }

            if moderation_list_manager
                .is_in_mute_list(did, &event.author)
                .await
            {
                debug!(
                    recipient = %did,
                    author = %event.author,
                    "Skipping notification - author is in recipient's mute list"
                );
                continue;
            }

            // Check thread mutes (if this is a reply)
            if let Some(reply) = event.record.get("reply") {
                if let Some(root) = reply
                    .get("root")
                    .and_then(|r| r.get("uri"))
                    .and_then(|u| u.as_str())
                {
                    if thread_mute_manager.is_thread_muted(did, root).await {
                        debug!(
                            recipient = %did,
                            thread_root = %root,
                            "Skipping notification - thread is muted by recipient"
                        );
                        continue;
                    }
                }
            }

            if let Some(devices) = devices_map.get(did) {
                for device in devices {
                    let device = device.clone();
                    let notification_type = notification_type.clone();
                    let event = event.clone();
                    let handle_map = handle_map.clone();
                    let post_resolver = post_resolver.clone();
                    let notification_sender = notification_sender.clone();
                    let did = did.clone();
                    let preferences_map = preferences_map.clone();

                    notification_futures.push(async move {
                        match preferences_map.get(&device.id) {
                            Some(prefs) => {
                                let should_notify = match &notification_type {
                                    NotificationType::Mention => prefs.mentions,
                                    NotificationType::Reply => prefs.replies,
                                    NotificationType::Like => prefs.likes,
                                    NotificationType::Follow => prefs.follows,
                                    NotificationType::Repost => prefs.reposts,
                                    NotificationType::Quote => prefs.quotes,
                                    NotificationType::ViaLike => prefs.via_likes,
                                    NotificationType::ViaRepost => prefs.via_reposts,
                                    NotificationType::ActivitySubscription(_) => {
                                        prefs.activity_subscriptions
                                    }
                                };

                                if should_notify {
                                    match create_notification_content(
                                        &handle_map,
                                        &notification_type,
                                        &event,
                                        &post_resolver,
                                    )
                                    .await
                                    {
                                        Ok((title, body, uri, media_urls, thumbnail_url)) => {
                                            let mut data = HashMap::new();
                                            data.insert("did".to_string(), did.clone());
                                            data.insert(
                                                "author".to_string(),
                                                event.author.clone(),
                                            );
                                            data.insert("cid".to_string(), event.cid.clone());
                                            data.insert(
                                                "type".to_string(),
                                                format!("{:?}", notification_type),
                                            );

                                            if let Some(uri_str) = &uri {
                                                data.insert("uri".to_string(), uri_str.clone());
                                            }

                                            if let NotificationType::ActivitySubscription(kind) =
                                                &notification_type
                                            {
                                                data.insert(
                                                    "subscriptionType".to_string(),
                                                    kind.as_reason().to_string(),
                                                );
                                            }

                                            let payload = NotificationPayload {
                                                user_did: did.clone(),
                                                device_token: device.device_token.clone(),
                                                notification_type: notification_type.clone(),
                                                title,
                                                body,
                                                data,
                                                media_urls,
                                                thumbnail_url,
                                            };

                                            let remaining_capacity =
                                                notification_sender.capacity();
                                            let max_capacity = notification_sender.max_capacity();
                                            crate::metrics::NOTIFICATION_QUEUE_SATURATION.observe(
                                                notification_queue_saturation_ratio(
                                                    remaining_capacity,
                                                    max_capacity,
                                                ),
                                            );

                                            if remaining_capacity == 0 {
                                                crate::metrics::NOTIFICATION_QUEUE_BACKPRESSURE_EVENTS
                                                    .inc();
                                                warn!(
                                                    notification_type = ?notification_type,
                                                    queue_capacity = max_capacity,
                                                    "Notification channel at capacity, applying backpressure for {} notification",
                                                    format!("{:?}", notification_type)
                                                        .to_lowercase()
                                                );

                                                if !notification_is_high_priority(
                                                    &notification_type,
                                                ) {
                                                    warn!("Skipping low-priority notification due to system load");
                                                    crate::metrics::NOTIFICATIONS_DROPPED.inc();
                                                    return;
                                                }

                                                tokio::time::sleep(
                                                    NOTIFICATION_QUEUE_BACKPRESSURE_DELAY,
                                                )
                                                .await;
                                            }

                                            match tokio::time::timeout(
                                                NOTIFICATION_QUEUE_SEND_TIMEOUT,
                                                notification_sender.send(payload),
                                            )
                                            .await
                                            {
                                                Ok(Ok(_)) => {
                                                    crate::metrics::NOTIFICATIONS_SENT.inc();
                                                }
                                                Ok(Err(e)) => {
                                                    crate::metrics::NOTIFICATION_QUEUE_SEND_FAILURES
                                                        .inc();
                                                    crate::metrics::NOTIFICATIONS_DROPPED.inc();
                                                    error!(
                                                        "Failed to send notification to queue: {}",
                                                        e
                                                    );
                                                }
                                                Err(_) => {
                                                    crate::metrics::NOTIFICATION_QUEUE_SEND_TIMEOUTS
                                                        .inc();
                                                    crate::metrics::NOTIFICATIONS_DROPPED.inc();
                                                    error!(
                                                        "Timeout when sending notification to queue - system overloaded"
                                                    );
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "Failed to create notification content: {}",
                                                e
                                            );
                                        }
                                    }
                                }
                            }
                            None => {
                                error!(
                                    "Notification preferences not found for device: {}",
                                    device.id
                                );
                            }
                        }
                    });
                }
            }
        }

        futures::future::join_all(notification_futures).await;
    }

    // Record event processing time
    let elapsed = timer.elapsed().as_secs_f64();
    crate::metrics::EVENT_PROCESSING_TIME.observe(elapsed);
}

#[cfg(test)]
mod tests {
    use super::{notification_is_high_priority, notification_queue_saturation_ratio};
    use crate::models::{ActivitySubscriptionKind, NotificationType};

    #[test]
    fn high_priority_notifications_are_kept_under_backpressure() {
        assert!(notification_is_high_priority(&NotificationType::Follow));
        assert!(notification_is_high_priority(&NotificationType::Reply));
        assert!(notification_is_high_priority(&NotificationType::Mention));
        assert!(notification_is_high_priority(
            &NotificationType::ActivitySubscription(ActivitySubscriptionKind::Post)
        ));
        assert!(!notification_is_high_priority(&NotificationType::Like));
        assert!(!notification_is_high_priority(&NotificationType::Repost));
        assert!(!notification_is_high_priority(&NotificationType::Quote));
        assert!(!notification_is_high_priority(&NotificationType::ViaLike));
    }

    #[test]
    fn queue_saturation_ratio_tracks_used_capacity() {
        assert_eq!(notification_queue_saturation_ratio(10, 10), 0.0);
        assert_eq!(notification_queue_saturation_ratio(0, 10), 1.0);
        assert_eq!(notification_queue_saturation_ratio(5, 10), 0.5);
        assert_eq!(notification_queue_saturation_ratio(5, 0), 0.0);
        assert_eq!(notification_queue_saturation_ratio(20, 10), 0.0);
    }
}
