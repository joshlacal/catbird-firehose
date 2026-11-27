//! Ingest counters, registered in the default Prometheus registry that the push API's
//! `/metrics` endpoint serves.

use lazy_static::lazy_static;
use prometheus::{register_int_counter_vec, IntCounterVec, Opts};

/// `reason` label: a frame that failed canonical DAG-CBOR parsing; its seq is unknown.
pub const DROPPED_MALFORMED: &str = "malformed";
/// `reason` label: a frame whose envelope decoded but whose payload did not.
pub const DROPPED_UNDECODABLE: &str = "undecodable";
/// `reason` label: one seq skipped because the relay kept sending an oversize frame there.
pub const DROPPED_OVERSIZE_SKIPPED: &str = "oversize_skipped";

lazy_static! {
    /// Firehose frames ingest dropped permanently, by reason. Every increment is an event
    /// no consumer will ever see.
    pub static ref FRAMES_DROPPED: IntCounterVec = register_int_counter_vec!(
        Opts::new(
            "firehose_ingest_frames_dropped_total",
            "Firehose frames permanently dropped by ingest, by reason"
        ),
        &["reason"]
    )
    .unwrap();
}

/// Current value of [`FRAMES_DROPPED`] for `reason`.
pub fn frames_dropped(reason: &str) -> u64 {
    FRAMES_DROPPED.with_label_values(&[reason]).get()
}

pub(crate) fn record_frame_dropped(reason: &str) {
    FRAMES_DROPPED.with_label_values(&[reason]).inc();
}
