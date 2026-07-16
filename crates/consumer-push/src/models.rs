use serde::{Deserialize, Serialize};
use sqlx::{
    types::{time::OffsetDateTime, uuid::Uuid},
    FromRow,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NotificationType {
    Mention,
    Reply,
    Like,
    Follow,
    Repost,
    Quote,
    ViaLike,   // Someone liked a post via your repost
    ViaRepost, // Someone reposted a post via your repost
    ActivitySubscription(ActivitySubscriptionKind),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ActivitySubscriptionKind {
    Post,
    Reply,
}

impl ActivitySubscriptionKind {
    pub fn as_reason(&self) -> &'static str {
        match self {
            ActivitySubscriptionKind::Post => "post",
            ActivitySubscriptionKind::Reply => "reply",
        }
    }
}

impl NotificationType {
    pub fn as_queue_key(&self) -> &'static str {
        match self {
            NotificationType::Mention => "mention",
            NotificationType::Reply => "reply",
            NotificationType::Like => "like",
            NotificationType::Follow => "follow",
            NotificationType::Repost => "repost",
            NotificationType::Quote => "quote",
            NotificationType::ViaLike => "via_like",
            NotificationType::ViaRepost => "via_repost",
            NotificationType::ActivitySubscription(ActivitySubscriptionKind::Post) => {
                "activity_post"
            }
            NotificationType::ActivitySubscription(ActivitySubscriptionKind::Reply) => {
                "activity_reply"
            }
        }
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct ActivitySubscription {
    pub id: Uuid,
    pub subscriber_did: String,
    pub subject_did: String,
    pub include_posts: bool,
    pub include_replies: bool,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueskyEvent {
    pub op: String,
    pub path: String,
    pub cid: String,
    pub author: String,
    pub record: serde_json::Value,
    pub timestamp: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushCandidateEvent {
    pub recipient_did: String,
    pub actor_did: String,
    pub notification_type: NotificationType,
    pub event_cid: String,
    pub event_path: String,
    pub subject_uri: Option<String>,
    pub thread_root_uri: Option<String>,
    pub event_record: serde_json::Value,
    pub event_timestamp: i64,
}

impl PushCandidateEvent {
    pub fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}",
            self.recipient_did,
            self.notification_type.as_queue_key(),
            self.event_cid
        )
    }
}

#[derive(Debug, Clone, FromRow)]
pub struct FirehoseCursor {
    pub id: i32,
    pub cursor: String,
    pub updated_at: OffsetDateTime,
}
