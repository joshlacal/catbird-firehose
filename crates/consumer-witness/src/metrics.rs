use lazy_static::lazy_static;
use prometheus::{register_counter, register_counter_vec, Counter, CounterVec, Opts};

lazy_static! {
    pub static ref WITNESS_COMMITS_PROCESSED: Counter = register_counter!(Opts::new(
        "firehose_witness_commits_total",
        "Total number of firehose commits containing device or mailbox key transparency ops"
    ))
    .unwrap();
    pub static ref WITNESS_RECORDS_INDEXED: CounterVec = register_counter_vec!(
        Opts::new(
            "firehose_witness_records_indexed_total",
            "Total number of transparency records witnessed and indexed by collection"
        ),
        &["collection"]
    )
    .unwrap();
    pub static ref WITNESS_ANOMALIES_DETECTED: CounterVec = register_counter_vec!(
        Opts::new(
            "firehose_witness_anomalies_total",
            "Total number of NBD device/mailbox key transparency anomalies detected by kind"
        ),
        &["kind"]
    )
    .unwrap();
    pub static ref WITNESS_CONSUMER_LAG_EVENTS: Counter = register_counter!(Opts::new(
        "firehose_witness_consumer_lag_events_total",
        "Total number of times the witness consumer lagged behind the firehose"
    ))
    .unwrap();
    pub static ref WITNESS_CONSUMER_DROPPED_EVENTS: Counter = register_counter!(Opts::new(
        "firehose_witness_consumer_dropped_events_total",
        "Total number of firehose events dropped before reaching the witness consumer"
    ))
    .unwrap();
}
