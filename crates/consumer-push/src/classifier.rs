use std::collections::HashSet;

use tracing::{debug, info};

use crate::models::{BlueskyEvent, NotificationType};

fn extract_did_from_at_uri(uri: &str) -> Option<&str> {
    let authority = uri.strip_prefix("at://")?.split('/').next()?;
    if authority.is_empty() {
        return None;
    }
    Some(authority)
}

/// Quick check for notification-relevant events to avoid processing irrelevant ones
pub fn is_notification_relevant_event(path: &str) -> bool {
    path.contains("app.bsky.feed.post")
        || path.contains("app.bsky.feed.like")
        || path.contains("app.bsky.graph.follow")
        || path.contains("app.bsky.feed.repost")
}

/// Classify a BlueskyEvent into a notification type and the relevant DIDs to notify.
pub fn classify_event(
    event: &BlueskyEvent,
    registered_users: &[String],
    registered_users_set: &HashSet<String>,
) -> Option<(NotificationType, Vec<String>)> {
    // Early exit if no registered users to notify
    if registered_users.is_empty() {
        return None;
    }

    debug!(
        path = %event.path,
        "Processing event record structure: {:?}",
        event.record
    );

    // Determine the notification type based on the event path and record
    let (notification_type, relevant_dids) = match event.path.as_str() {
        path if path.contains("app.bsky.feed.post") => {
            // Check for quote posts first
            if has_quote_embed(&event.record) {
                let quoted_dids = find_quoted_users(event, registered_users);
                if !quoted_dids.is_empty() {
                    (NotificationType::Quote, quoted_dids)
                } else if event.record.get("reply").is_some() {
                    let relevant_dids = extract_target_dids(event, registered_users);
                    if !relevant_dids.is_empty() {
                        (NotificationType::Reply, relevant_dids)
                    } else {
                        let mentioned_dids =
                            extract_mention_dids(event, registered_users, registered_users_set);
                        if !mentioned_dids.is_empty() {
                            (NotificationType::Mention, mentioned_dids)
                        } else {
                            return None;
                        }
                    }
                } else {
                    let mentioned_dids =
                        extract_mention_dids(event, registered_users, registered_users_set);
                    if !mentioned_dids.is_empty() {
                        (NotificationType::Mention, mentioned_dids)
                    } else {
                        return None;
                    }
                }
            } else if event.record.get("reply").is_some() {
                let relevant_dids = extract_target_dids(event, registered_users);
                if !relevant_dids.is_empty() {
                    (NotificationType::Reply, relevant_dids)
                } else {
                    let mentioned_dids =
                        extract_mention_dids(event, registered_users, registered_users_set);
                    if !mentioned_dids.is_empty() {
                        (NotificationType::Mention, mentioned_dids)
                    } else {
                        return None;
                    }
                }
            } else {
                let mentioned_dids =
                    extract_mention_dids(event, registered_users, registered_users_set);
                if !mentioned_dids.is_empty() {
                    (NotificationType::Mention, mentioned_dids)
                } else {
                    return None;
                }
            }
        }
        path if path.contains("app.bsky.feed.like") => {
            // Check if this is a via like (someone liked a post via someone's repost)
            if let Some(via_dids) = extract_via_dids(event, registered_users) {
                (NotificationType::ViaLike, via_dids)
            } else {
                let relevant_dids = extract_target_dids(event, registered_users);
                (NotificationType::Like, relevant_dids)
            }
        }
        path if path.contains("app.bsky.graph.follow") => {
            let relevant_dids = extract_target_dids(event, registered_users);
            (NotificationType::Follow, relevant_dids)
        }
        path if path.contains("app.bsky.feed.repost") => {
            if let Some(via_dids) = extract_via_dids(event, registered_users) {
                (NotificationType::ViaRepost, via_dids)
            } else {
                let relevant_dids = extract_target_dids(event, registered_users);
                (NotificationType::Repost, relevant_dids)
            }
        }
        _ => return None,
    };

    if relevant_dids.is_empty() {
        None
    } else {
        info!(
            notification_type = ?notification_type,
            relevant_dids_count = relevant_dids.len(),
            "Preparing notification"
        );
        Some((notification_type, relevant_dids))
    }
}

/// Check if a post has any quote embeds
pub fn has_quote_embed(record: &serde_json::Value) -> bool {
    if let Some(embed) = record.get("embed") {
        // Check for direct record embedding
        if embed.get("record").is_some() {
            return true;
        }

        // Check for embed with $type
        if let Some(embed_type) = embed.get("$type").and_then(|t| t.as_str()) {
            return embed_type == "app.bsky.embed.record"
                || embed_type == "app.bsky.embed.recordWithMedia";
        }
    }
    false
}

/// Extract DIDs of users whose content is quoted
pub fn find_quoted_users(event: &BlueskyEvent, registered_users: &[String]) -> Vec<String> {
    let mut quoted_dids = Vec::new();

    if let Some(embed) = event.record.get("embed") {
        // Direct record embedding
        if let Some(record_obj) = embed.get("record") {
            extract_quoted_dids(record_obj, registered_users, &mut quoted_dids);
        }

        // Record with media
        if embed.get("$type").and_then(|t| t.as_str()) == Some("app.bsky.embed.recordWithMedia") {
            if let Some(record_obj) = embed.get("record") {
                extract_quoted_dids(record_obj, registered_users, &mut quoted_dids);
            }
        }
    }

    quoted_dids
}

/// Helper to extract DIDs from a quoted record
pub fn extract_quoted_dids(
    record_obj: &serde_json::Value,
    registered_users: &[String],
    result: &mut Vec<String>,
) {
    // Check standard structure
    if let Some(uri) = record_obj
        .get("record")
        .and_then(|r| r.get("uri").and_then(|u| u.as_str()))
    {
        if let Some(did) = extract_did_from_at_uri(uri) {
            if registered_users.iter().any(|user| user == did)
                && !result.iter().any(|user| user == did)
            {
                result.push(did.to_string());
            }
        }
    }

    // Alternative structure
    if let Some(uri) = record_obj.get("uri").and_then(|u| u.as_str()) {
        if let Some(did) = extract_did_from_at_uri(uri) {
            if registered_users.iter().any(|user| user == did)
                && !result.iter().any(|user| user == did)
            {
                result.push(did.to_string());
            }
        }
    }
}

/// Extract mention DIDs from facets
pub fn extract_mention_dids(
    event: &BlueskyEvent,
    registered_users: &[String],
    registered_users_set: &HashSet<String>,
) -> Vec<String> {
    let mut mentioned_dids = Vec::new();

    if registered_users.is_empty() {
        return mentioned_dids;
    }

    if let Some(facets) = event.record.get("facets").and_then(|f| f.as_array()) {
        for facet in facets {
            if let Some(features) = facet.get("features").and_then(|f| f.as_array()) {
                for feature in features {
                    if let Some(feature_type) = feature.get("$type").and_then(|t| t.as_str()) {
                        if feature_type == "app.bsky.richtext.facet#mention" {
                            if let Some(did) = feature.get("did").and_then(|d| d.as_str()) {
                                if registered_users_set.contains(did)
                                    && !mentioned_dids.contains(&did.to_string())
                                {
                                    mentioned_dids.push(did.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    mentioned_dids
}

/// Extract target DIDs based on record type
pub fn extract_target_dids(event: &BlueskyEvent, registered_users: &[String]) -> Vec<String> {
    if event.path.contains("app.bsky.graph.follow") {
        // For follows, the subject is a direct DID string
        if let Some(subject) = event.record.get("subject").and_then(|s| s.as_str()) {
            return registered_users
                .iter()
                .filter(|did| subject == *did)
                .cloned()
                .collect();
        }
    } else if event.path.contains("app.bsky.feed.like")
        || event.path.contains("app.bsky.feed.repost")
    {
        // For likes and reposts, the subject is an object with a URI
        if let Some(subject) = event.record.get("subject").and_then(|s| s.as_object()) {
            if let Some(uri) = subject.get("uri").and_then(|u| u.as_str()) {
                if let Some(did) = extract_did_from_at_uri(uri) {
                    return registered_users
                        .iter()
                        .filter(|registered_did| registered_did.as_str() == did)
                        .cloned()
                        .collect();
                }
            }
        }
    } else if event.path.contains("app.bsky.feed.post") {
        // For posts with reply field, find the parent author
        if let Some(reply) = event.record.get("reply").and_then(|r| r.as_object()) {
            if let Some(parent) = reply.get("parent").and_then(|p| p.as_object()) {
                if let Some(uri) = parent.get("uri").and_then(|u| u.as_str()) {
                    let reply_targets = extract_did_from_at_uri(uri)
                        .into_iter()
                        .flat_map(|did| {
                            registered_users
                                .iter()
                                .filter(move |registered_did| registered_did.as_str() == did)
                                .cloned()
                        })
                        .collect::<Vec<String>>();

                    if !reply_targets.is_empty() {
                        return reply_targets;
                    }
                }
            }
        }
    }

    Vec::new()
}

/// Extract DIDs from via field for via notifications.
/// The via field points to a repost, and we want to notify the author of that repost.
pub fn extract_via_dids(event: &BlueskyEvent, registered_users: &[String]) -> Option<Vec<String>> {
    if let Some(via) = event.record.get("via") {
        if let Some(via_uri) = via.get("uri").and_then(|u| u.as_str()) {
            let via_dids: Vec<String> = extract_did_from_at_uri(via_uri)
                .into_iter()
                .flat_map(|did| {
                    registered_users
                        .iter()
                        .filter(move |registered_did| registered_did.as_str() == did)
                        .cloned()
                })
                .collect();

            if !via_dids.is_empty() {
                debug!(
                    via_uri = %via_uri,
                    via_dids_count = via_dids.len(),
                    "Found via notification recipients"
                );
                return Some(via_dids);
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_did_from_at_uri_returns_exact_authority() {
        assert_eq!(
            extract_did_from_at_uri("at://did:plc:target/app.bsky.feed.post/abc123"),
            Some("did:plc:target")
        );
        assert_eq!(extract_did_from_at_uri("https://example.com"), None);
    }

    #[test]
    fn quoted_did_matching_requires_exact_uri_authority() {
        let record = json!({
            "record": {
                "uri": "at://did:plc:target123/app.bsky.feed.post/abc"
            }
        });
        let registered_users = vec!["did:plc:target".to_string()];
        let mut result = Vec::new();

        extract_quoted_dids(&record, &registered_users, &mut result);

        assert!(result.is_empty());
    }

    #[test]
    fn target_did_matching_uses_exact_authority() {
        let event = BlueskyEvent {
            op: "create".to_string(),
            cid: "bafytest".to_string(),
            author: "did:plc:author".to_string(),
            path: "app.bsky.feed.like/abc".to_string(),
            record: json!({
                "subject": {
                    "uri": "at://did:plc:target123/app.bsky.feed.post/abc"
                }
            }),
            timestamp: 0,
        };
        let registered_users = vec!["did:plc:target".to_string()];

        assert!(extract_target_dids(&event, &registered_users).is_empty());
    }
}
