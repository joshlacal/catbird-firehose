use lazy_static::lazy_static;
use prometheus::{register_counter, register_histogram, Counter, Histogram, HistogramOpts, Opts};

// Define metrics
lazy_static! {
    // Event metrics
    pub static ref EVENTS_PROCESSED: Counter = register_counter!(Opts::new(
        "push_events_processed_total",
        "Total number of events processed by push consumer"
    ))
    .unwrap();

    pub static ref NOTIFICATIONS_SENT: Counter = register_counter!(Opts::new(
        "push_notifications_sent_total",
        "Total number of push notifications sent"
    ))
    .unwrap();

    pub static ref PUSH_QUEUE_ENQUEUED: Counter = register_counter!(Opts::new(
        "push_queue_enqueued_total",
        "Total number of push candidate rows inserted into push_event_queue"
    ))
    .unwrap();

    pub static ref PUSH_QUEUE_DEDUPED: Counter = register_counter!(Opts::new(
        "push_queue_deduped_total",
        "Total number of push candidate rows skipped because they were already queued"
    ))
    .unwrap();

    pub static ref PUSH_QUEUE_ENQUEUE_FAILURES: Counter = register_counter!(Opts::new(
        "push_queue_enqueue_failures_total",
        "Total number of failed push candidate enqueue attempts"
    ))
    .unwrap();

    pub static ref NOTIFICATIONS_DROPPED: Counter = register_counter!(Opts::new(
        "push_notifications_dropped_total",
        "Total number of notifications dropped before APNS delivery"
    ))
    .unwrap();

    pub static ref CONSUMER_LAG_EVENTS: Counter = register_counter!(Opts::new(
        "push_consumer_lag_events_total",
        "Total number of times the push consumer lagged behind the firehose"
    ))
    .unwrap();

    pub static ref CONSUMER_DROPPED_EVENTS: Counter = register_counter!(Opts::new(
        "push_consumer_dropped_events_total",
        "Total number of firehose events dropped before reaching the push consumer"
    ))
    .unwrap();

    pub static ref NOTIFICATION_QUEUE_BACKPRESSURE_EVENTS: Counter = register_counter!(Opts::new(
        "push_notification_queue_backpressure_total",
        "Total number of notification enqueue attempts that hit queue backpressure"
    ))
    .unwrap();

    pub static ref NOTIFICATION_QUEUE_SEND_FAILURES: Counter = register_counter!(Opts::new(
        "push_notification_queue_send_failures_total",
        "Total number of notification enqueue attempts that failed because the queue was closed"
    ))
    .unwrap();

    pub static ref NOTIFICATION_QUEUE_SEND_TIMEOUTS: Counter = register_counter!(Opts::new(
        "push_notification_queue_send_timeouts_total",
        "Total number of notification enqueue attempts that timed out under load"
    ))
    .unwrap();

    pub static ref RELATIONSHIP_LOOKUP_ERRORS: Counter = register_counter!(Opts::new(
        "push_relationship_lookup_errors_total",
        "Total number of mute or block lookup failures"
    ))
    .unwrap();

    // Cache metrics
    pub static ref DID_CACHE_HITS: Counter = register_counter!(Opts::new(
        "push_did_cache_hits_total",
        "Total number of DID cache hits"
    ))
    .unwrap();

    pub static ref DID_CACHE_MISSES: Counter = register_counter!(Opts::new(
        "push_did_cache_misses_total",
        "Total number of DID cache misses"
    ))
    .unwrap();

    pub static ref POST_CACHE_HITS: Counter = register_counter!(Opts::new(
        "push_post_cache_hits_total",
        "Total number of post cache hits"
    ))
    .unwrap();

    pub static ref POST_CACHE_MISSES: Counter = register_counter!(Opts::new(
        "push_post_cache_misses_total",
        "Total number of post cache misses"
    ))
    .unwrap();

    // Timing metrics
    pub static ref EVENT_PROCESSING_TIME: Histogram = register_histogram!(
        HistogramOpts::new(
            "push_event_processing_time_seconds",
            "Time taken to process an event"
        )
        .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0])
    )
    .unwrap();

    pub static ref DID_RESOLUTION_TIME: Histogram = register_histogram!(
        HistogramOpts::new(
            "push_did_resolution_time_seconds",
            "Time taken to resolve a DID"
        )
        .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    )
    .unwrap();

    pub static ref POST_FETCH_TIME: Histogram = register_histogram!(
        HistogramOpts::new(
            "push_post_fetch_time_seconds",
            "Time taken to fetch a post"
        )
        .buckets(vec![0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0])
    )
    .unwrap();

    // Batch-specific metrics
    pub static ref POST_BATCH_SIZE: Histogram = register_histogram!(
        HistogramOpts::new(
            "push_post_batch_size",
            "Size of batched post requests"
        )
        .buckets(vec![1.0, 2.0, 5.0, 10.0, 15.0, 20.0, 25.0])
    )
    .unwrap();

    pub static ref POST_BATCH_LATENCY: Histogram = register_histogram!(
        HistogramOpts::new(
            "push_post_batch_latency_seconds",
            "Latency of batched post requests"
        )
        .buckets(vec![0.01, 0.025, 0.05, 0.075, 0.1, 0.15, 0.2, 0.3, 0.5])
    )
    .unwrap();

    pub static ref NOTIFICATION_QUEUE_SATURATION: Histogram = register_histogram!(
        HistogramOpts::new(
            "push_notification_queue_saturation_ratio",
            "Observed notification queue saturation ratio when enqueueing notifications"
        )
        .buckets(vec![0.25, 0.5, 0.75, 0.9, 0.95, 0.99, 1.0])
    )
    .unwrap();
}

/// Expose metrics endpoint
pub fn metrics_handler() -> String {
    use prometheus::Encoder;
    let encoder = prometheus::TextEncoder::new();
    let mut buffer = Vec::new();

    if let Err(e) = encoder.encode(&prometheus::gather(), &mut buffer) {
        return format!("Error encoding metrics: {}", e);
    }

    match String::from_utf8(buffer) {
        Ok(metrics) => metrics,
        Err(e) => format!("Error converting metrics to string: {}", e),
    }
}
