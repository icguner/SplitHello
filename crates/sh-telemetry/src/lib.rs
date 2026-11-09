//! Local diagnostics history (port of `src/Telemetry.cpp`). The relay only
//! moves a small record into a bounded queue; SQLite work happens on one
//! writer thread that batches records into single transactions. The schema
//! (`user_version` 2, WAL) is the C++ one, so either build reads the other's
//! `telemetry.db`.
#![forbid(unsafe_code)]

mod dashboard;
mod store;

pub use dashboard::{
    Bucket, DashboardData, Day, Event, EventAttempt, HostStat, KeyCount, Percentiles, Previous,
    ProfileStat, snapshot,
};
pub use store::{ProbeRecord, Store};
