//! Spike E13 (story 1.13): content-free push alerts sent at random times through an ntfy-type
//! UnifiedPush server, acknowledged by each phone with the alert's one-time id, and evaluated
//! against the D105 criterion per phone and per server (D118).
//!
//! The pieces: [`sender`] posts the alerts, [`collector`] receives the acknowledgements,
//! [`records`] appends both to a flat results file, [`report`] computes rates, latencies and
//! verdicts, and [`phone_sim`] stands in for a phone's distributor on the simulated test network.
#![forbid(unsafe_code)]

pub mod collector;
pub mod config;
pub mod http;
pub mod payload;
pub mod phone_sim;
pub mod records;
pub mod report;
pub mod sender;
pub mod token;

use std::time::{SystemTime, UNIX_EPOCH};

/// Wall-clock time in milliseconds since the Unix epoch, the unit of every recorded time.
pub fn now_ms() -> u64 {
    let since_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since_epoch.as_millis()).unwrap_or(u64::MAX)
}
