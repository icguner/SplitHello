//! Read-only dashboard snapshot over a rolling window (port of
//! `Store::dashboardSnapshot`). Safe to call from the tray/panel process while
//! the elevated engine writes through WAL.

use std::path::Path;
use std::time::Duration;

use rusqlite::{Connection, OpenFlags, params};

use crate::store::{execute, unix_seconds};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyCount {
    pub key: String,
    pub count: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProfileStat {
    pub name: String,
    pub count: i64,
    pub average_latency_ms: f64,
    pub average_attempts: f64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Day {
    /// YYYY-MM-DD, local time.
    pub day: String,
    pub total: i64,
    /// Verified differential: baseline failed, profile worked.
    pub bypassed: i64,
    /// A remembered profile was applied without new evidence.
    pub learned: i64,
    pub unresolved: i64,
    /// First differential, not yet reproduced (not learned).
    pub suspected: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventAttempt {
    pub profile: String,
    pub signal: String,
    pub elapsed_ms: i64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    pub id: i64,
    pub timestamp: i64,
    pub network: String,
    pub host: String,
    pub baseline: String,
    pub diagnosis: String,
    pub confidence: i64,
    pub winner: String,
    pub remembered: String,
    pub success: bool,
    pub forced: bool,
    pub cache_hit: bool,
    pub attempt_count: i64,
    pub total_elapsed_ms: i64,
    pub attempts: Vec<EventAttempt>,
}

/// Latency order statistics: averages hide the tail that actually hurts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Percentiles {
    pub p50: i64,
    pub p90: i64,
    pub p99: i64,
    pub worst: i64,
}

/// One histogram column; `upper_ms == 0` marks the open-ended bucket.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bucket {
    pub upper_ms: i64,
    pub count: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct HostStat {
    pub host: String,
    pub total: i64,
    pub bypassed: i64,
    pub unresolved: i64,
    pub average_latency_ms: f64,
}

/// The immediately preceding window of equal length, for trend deltas.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Previous {
    pub total: i64,
    pub bypassed: i64,
    pub learned: i64,
    pub normal: i64,
    pub unresolved: i64,
    pub average_latency_ms: f64,
    pub suspected: i64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DashboardData {
    pub ready: bool,
    pub error: String,
    pub generated_at: i64,
    pub window_days: u32,
    /// Only verified interference: the untouched baseline failed and a
    /// transformed hello worked in the same connection.
    pub total: i64,
    pub bypassed: i64,
    pub learned: i64,
    pub normal: i64,
    pub unresolved: i64,
    pub cache_hits: i64,
    pub suspected: i64,
    pub average_latency_ms: f64,
    pub latency: Percentiles,
    pub previous: Previous,
    pub diagnoses: Vec<KeyCount>,
    pub signals: Vec<KeyCount>,
    pub profiles: Vec<ProfileStat>,
    pub daily: Vec<Day>,
    pub latency_histogram: Vec<Bucket>,
    pub top_hosts: Vec<HostStat>,
    pub recent: Vec<Event>,
}

fn empty(error: &str, window_days: u32) -> DashboardData {
    DashboardData {
        ready: false,
        error: error.into(),
        generated_at: unix_seconds(),
        window_days,
        ..DashboardData::default()
    }
}

const LEARNED: &str = "diagnosis_kind IN ('learned-profile','transient-failure')";

pub fn snapshot(path: &Path, window_days: u32) -> DashboardData {
    let window_days = window_days.clamp(1, 90);
    if path.as_os_str().is_empty() || !path.exists() {
        return empty("Henüz telemetri kaydı oluşmadı.", window_days);
    }
    let conn = match Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    ) {
        Ok(conn) => conn,
        Err(error) => return empty(&error.to_string(), window_days),
    };
    let _ = conn.busy_timeout(Duration::from_millis(1000));
    let now = unix_seconds();
    let cutoff = now - i64::from(window_days) * 86400;
    execute(&conn, "BEGIN;");
    let mut data = DashboardData {
        ready: true,
        generated_at: now,
        window_days,
        ..DashboardData::default()
    };
    // Every query is best-effort: a failed one leaves its section empty.
    let _ = fill(&conn, cutoff, i64::from(window_days) * 86400, &mut data);
    execute(&conn, "COMMIT;");
    data
}

fn fill(
    conn: &Connection,
    cutoff: i64,
    window: i64,
    data: &mut DashboardData,
) -> rusqlite::Result<()> {
    let summary_sql = format!(
        "SELECT COUNT(*), COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0), \
         COALESCE(SUM(diagnosis_kind='no-interference'),0), COALESCE(SUM(success=0),0), \
         COALESCE(AVG(total_elapsed_ms),0), COALESCE(SUM(cache_hit),0), COALESCE(SUM({LEARNED}),0), \
         COALESCE(SUM(diagnosis_kind='interference-suspected'),0) FROM probe_events WHERE occurred_at>=?;"
    );
    conn.query_row(&summary_sql, [cutoff], |row| {
        data.total = row.get(0)?;
        data.bypassed = row.get(1)?;
        data.normal = row.get(2)?;
        data.unresolved = row.get(3)?;
        data.average_latency_ms = row.get(4)?;
        data.cache_hits = row.get(5)?;
        data.learned = row.get(6)?;
        data.suspected = row.get(7)?;
        Ok(())
    })?;

    let previous_sql = format!(
        "SELECT COUNT(*), COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0), \
         COALESCE(SUM(diagnosis_kind='no-interference'),0), COALESCE(SUM(success=0),0), \
         COALESCE(AVG(total_elapsed_ms),0), COALESCE(SUM({LEARNED}),0), \
         COALESCE(SUM(diagnosis_kind='interference-suspected'),0) \
         FROM probe_events WHERE occurred_at>=? AND occurred_at<?;"
    );
    conn.query_row(&previous_sql, params![cutoff - window, cutoff], |row| {
        data.previous = Previous {
            total: row.get(0)?,
            bypassed: row.get(1)?,
            normal: row.get(2)?,
            unresolved: row.get(3)?,
            average_latency_ms: row.get(4)?,
            learned: row.get(5)?,
            suspected: row.get(6)?,
        };
        Ok(())
    })?;

    // Exact percentiles: OFFSET indexes the sorted latency column directly.
    if data.total > 0 {
        let mut quantile = conn.prepare(
            "SELECT total_elapsed_ms FROM probe_events WHERE occurred_at>=? ORDER BY total_elapsed_ms LIMIT 1 OFFSET ?;",
        )?;
        let total = data.total;
        let mut at = |fraction: f64| -> i64 {
            let offset = ((fraction * (total - 1) as f64) as i64).clamp(0, total - 1);
            quantile
                .query_row(params![cutoff, offset], |row| row.get(0))
                .unwrap_or(0)
        };
        data.latency = Percentiles {
            p50: at(0.50),
            p90: at(0.90),
            p99: at(0.99),
            worst: at(1.0),
        };
    }

    // Fixed doubling buckets; the last one is open-ended.
    const EDGES: [i64; 7] = [50, 100, 200, 400, 800, 1600, 3200];
    let mut counts = [0i64; EDGES.len() + 1];
    {
        let mut histogram = conn.prepare(
            "SELECT CASE WHEN total_elapsed_ms<50 THEN 0 WHEN total_elapsed_ms<100 THEN 1 \
             WHEN total_elapsed_ms<200 THEN 2 WHEN total_elapsed_ms<400 THEN 3 WHEN total_elapsed_ms<800 THEN 4 \
             WHEN total_elapsed_ms<1600 THEN 5 WHEN total_elapsed_ms<3200 THEN 6 ELSE 7 END AS bucket, COUNT(*) \
             FROM probe_events WHERE occurred_at>=? GROUP BY bucket;",
        )?;
        let rows = histogram.query_map([cutoff], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?))
        })?;
        for (index, count) in rows.flatten() {
            if let Some(slot) = usize::try_from(index).ok().and_then(|i| counts.get_mut(i)) {
                *slot = count;
            }
        }
    }
    data.latency_histogram = counts
        .iter()
        .enumerate()
        .map(|(i, &count)| Bucket {
            upper_ms: EDGES.get(i).copied().unwrap_or(0),
            count,
        })
        .collect();

    // Hosts ranked by how often they actually needed intervention.
    data.top_hosts = conn
        .prepare(
            "SELECT host,COUNT(*), COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0), \
             COALESCE(SUM(success=0),0), COALESCE(AVG(total_elapsed_ms),0) FROM probe_events WHERE occurred_at>=? \
             GROUP BY host ORDER BY (COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0) \
             +COALESCE(SUM(success=0),0)) DESC, COUNT(*) DESC LIMIT 8;",
        )?
        .query_map([cutoff], |row| {
            Ok(HostStat {
                host: row.get(0)?,
                total: row.get(1)?,
                bypassed: row.get(2)?,
                unresolved: row.get(3)?,
                average_latency_ms: row.get(4)?,
            })
        })?
        .flatten()
        .collect();

    let breakdown = |sql: &str| -> rusqlite::Result<Vec<KeyCount>> {
        Ok(conn
            .prepare(sql)?
            .query_map([cutoff], |row| {
                Ok(KeyCount {
                    key: row.get(0)?,
                    count: row.get(1)?,
                })
            })?
            .flatten()
            .collect())
    };
    data.diagnoses = breakdown(
        "SELECT diagnosis_kind,COUNT(*) FROM probe_events WHERE occurred_at>=? GROUP BY diagnosis_kind ORDER BY COUNT(*) DESC;",
    )?;
    data.signals = breakdown(
        "SELECT COALESCE(baseline_signal,'not-tested'),COUNT(*) FROM probe_events WHERE occurred_at>=? \
         GROUP BY COALESCE(baseline_signal,'not-tested') ORDER BY COUNT(*) DESC;",
    )?;

    data.profiles = conn
        .prepare(
            "SELECT winning_profile,COUNT(*),COALESCE(AVG(total_elapsed_ms),0), COALESCE(AVG(attempt_count),0) \
             FROM probe_events WHERE occurred_at>=? AND success=1 AND winning_profile IS NOT NULL \
             GROUP BY winning_profile ORDER BY COUNT(*) DESC LIMIT 16;",
        )?
        .query_map([cutoff], |row| {
            Ok(ProfileStat {
                name: row.get(0)?,
                count: row.get(1)?,
                average_latency_ms: row.get(2)?,
                average_attempts: row.get(3)?,
            })
        })?
        .flatten()
        .collect();

    let daily_sql = format!(
        "SELECT strftime('%Y-%m-%d',occurred_at,'unixepoch','localtime'), COUNT(*), \
         COALESCE(SUM(diagnosis_kind='sni-interference-likely'),0), COALESCE(SUM({LEARNED}),0), \
         COALESCE(SUM(success=0),0), COALESCE(SUM(diagnosis_kind='interference-suspected'),0) \
         FROM probe_events WHERE occurred_at>=? GROUP BY 1 ORDER BY 1;"
    );
    data.daily = conn
        .prepare(&daily_sql)?
        .query_map([cutoff], |row| {
            Ok(Day {
                day: row.get(0)?,
                total: row.get(1)?,
                bypassed: row.get(2)?,
                learned: row.get(3)?,
                unresolved: row.get(4)?,
                suspected: row.get(5)?,
            })
        })?
        .flatten()
        .collect();

    let mut attempts = conn.prepare(
        "SELECT profile,signal,elapsed_ms FROM probe_attempts WHERE event_id=? ORDER BY ordinal;",
    )?;
    let mut recent = conn.prepare(
        "SELECT id,occurred_at,network_id,host,COALESCE(baseline_signal,''), diagnosis_kind,confidence,\
         COALESCE(winning_profile,''), COALESCE(remembered_profile,''),success,forced,attempt_count, \
         total_elapsed_ms,cache_hit FROM probe_events WHERE occurred_at>=? ORDER BY id DESC LIMIT 250;",
    )?;
    let events: Vec<Event> = recent
        .query_map([cutoff], |row| {
            Ok(Event {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                network: row.get(2)?,
                host: row.get(3)?,
                baseline: row.get(4)?,
                diagnosis: row.get(5)?,
                confidence: row.get(6)?,
                winner: row.get(7)?,
                remembered: row.get(8)?,
                success: row.get(9)?,
                forced: row.get(10)?,
                attempt_count: row.get(11)?,
                total_elapsed_ms: row.get(12)?,
                cache_hit: row.get(13)?,
                attempts: Vec::new(),
            })
        })?
        .flatten()
        .collect();
    data.recent = events
        .into_iter()
        .map(|mut event| {
            event.attempts = attempts
                .query_map([event.id], |row| {
                    Ok(EventAttempt {
                        profile: row.get(0)?,
                        signal: row.get(1)?,
                        elapsed_ms: row.get(2)?,
                    })
                })
                .map(|rows| rows.flatten().collect())
                .unwrap_or_default();
            event
        })
        .collect();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProbeRecord, Store};
    use sh_strategy::diagnosis::{Attempt, Context, Kind, ProbeSignal, infer};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

    fn test_path(name: &str) -> PathBuf {
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "sh-telemetry-{}-{name}-{}.db",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        remove(&path);
        path
    }

    fn remove(path: &Path) {
        for suffix in ["", "-wal", "-shm"] {
            let mut file = path.as_os_str().to_owned();
            file.push(suffix);
            let _ = std::fs::remove_file(file);
        }
    }

    fn record(
        host: &str,
        attempts: &[(&str, ProbeSignal, u32)],
        success: bool,
        remembered: &str,
    ) -> ProbeRecord {
        let attempts: Vec<Attempt> = attempts
            .iter()
            .map(|&(p, s, ms)| Attempt::new(p, s, ms))
            .collect();
        ProbeRecord {
            network_id: "test-network".into(),
            host: host.into(),
            remembered_profile: remembered.into(),
            verdict: infer(&attempts, &Context::default()),
            attempts,
            total_elapsed_ms: 123,
            success,
            ..ProbeRecord::default()
        }
    }

    fn blocked(host: &str) -> ProbeRecord {
        record(
            host,
            &[
                ("none", ProbeSignal::Timeout, 3000),
                ("sni-mid", ProbeSignal::ServerHello, 67),
            ],
            true,
            "",
        )
    }

    fn cache_hit(host: &str, ms: u32) -> ProbeRecord {
        record(
            host,
            &[("sni-mid", ProbeSignal::ServerHello, ms)],
            true,
            "sni-mid",
        )
    }

    fn scalar(path: &Path, sql: &str) -> i64 {
        Connection::open(path)
            .and_then(|c| c.query_row(sql, [], |row| row.get(0)))
            .unwrap_or(-1)
    }

    fn count(items: &[KeyCount], key: &str) -> i64 {
        items
            .iter()
            .find(|item| item.key == key)
            .map_or(0, |item| item.count)
    }

    #[test]
    fn persists_dashboard_evidence() {
        let path = test_path("evidence");
        let store = Store::with_limits(&path, 30, 100, 64);
        assert!(store.start());
        store.record(record(
            "healthy.example",
            &[("none", ProbeSignal::ServerHello, 42)],
            true,
            "",
        ));
        store.record(blocked("blocked.example"));
        store.record(record(
            "offline.example",
            &[
                ("none", ProbeSignal::Reset, 8),
                ("sni-mid", ProbeSignal::Timeout, 3000),
            ],
            false,
            "",
        ));
        store.stop();
        assert_eq!(store.dropped_records(), 0);

        let data = snapshot(&path, 30);
        assert!(data.ready);
        assert_eq!(
            (data.total, data.bypassed, data.normal, data.unresolved),
            (3, 1, 1, 1)
        );
        let event = data
            .recent
            .iter()
            .find(|e| e.host == "blocked.example")
            .expect("recorded");
        assert_eq!(event.winner, "sni-mid");
        assert_eq!(event.baseline, "timeout");
        assert_eq!(event.attempts[0].signal, "timeout");
        assert_eq!(data.latency_histogram.len(), 8);
        drop(store);
        remove(&path);
    }

    /// Reads the telemetry.db the C++ engine wrote on this machine (read-only).
    /// Run with `cargo test -p sh-telemetry -- --ignored --nocapture`.
    #[test]
    #[ignore = "reads the developer's real %APPDATA%\\splithello\\telemetry.db"]
    fn compat_reads_the_live_cpp_database() {
        let path = PathBuf::from(std::env::var_os("APPDATA").expect("APPDATA"))
            .join("splithello")
            .join("telemetry.db");
        let data = snapshot(&path, 30);
        assert!(data.ready, "{}", data.error);
        assert!(data.total > 0, "no events in the last 30 days");
        assert!(
            data.recent
                .iter()
                .all(|e| !e.host.is_empty() && !e.diagnosis.is_empty())
        );
        println!(
            "total={} bypassed={} learned={} p50={}ms recent={} top={:?}",
            data.total,
            data.bypassed,
            data.learned,
            data.latency.p50,
            data.recent.len(),
            data.top_hosts.first().map(|h| &h.host)
        );
    }

    #[test]
    fn missing_database_returns_safe_empty_snapshot() {
        let data = snapshot(&test_path("missing"), 7);
        assert!(!data.ready);
        assert_eq!(data.window_days, 7);
        assert_eq!(data.total, 0);
    }

    #[test]
    fn counts_only_verified_differentials_as_bypasses() {
        let path = test_path("verified");
        let store = Store::with_limits(&path, 30, 100, 64);
        assert!(store.start());
        store.record(blocked("blocked.example"));
        store.record(cache_hit("blocked.example", 40));
        store.record(cache_hit("blocked.example", 41));
        store.stop();
        let data = snapshot(&path, 30);
        assert_eq!(
            (data.total, data.bypassed, data.learned, data.cache_hits),
            (3, 1, 2, 2)
        );
        assert_eq!(count(&data.diagnoses, "learned-profile"), 2);
        drop(store);
        remove(&path);
    }

    #[test]
    fn migration_reclassifies_legacy_interference_rows() {
        let path = test_path("migration");
        {
            let store = Store::with_limits(&path, 30, 100, 64);
            assert!(store.start());
            store.record(blocked("blocked.example"));
            store.record(record(
                "flaky.example",
                &[("none", ProbeSignal::ServerHello, 30)],
                true,
                "",
            ));
            store.record(record(
                "flaky.example",
                &[
                    ("none", ProbeSignal::Timeout, 3000),
                    ("record-1", ProbeSignal::ServerHello, 31),
                ],
                true,
                "",
            ));
            store.record(cache_hit("blocked.example", 40));
            store.stop();
        }
        // Rewrite the rows the way schema 1 stored them.
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "UPDATE probe_events SET diagnosis_kind='sni-interference-likely' \
                 WHERE diagnosis_kind IN ('learned-profile','transient-failure') OR diagnosis_kind='sni-interference-likely'; \
                 PRAGMA user_version=1;",
            )
            .unwrap();
        assert_eq!(snapshot(&path, 30).bypassed, 3);

        // Opening the engine-side store performs the one-time migration.
        {
            let store = Store::with_limits(&path, 30, 100, 64);
            assert!(store.start());
            store.stop();
        }
        let data = snapshot(&path, 30);
        assert_eq!((data.total, data.bypassed, data.learned), (4, 1, 2));
        assert_eq!(count(&data.diagnoses, "transient-failure"), 1);
        assert_eq!(count(&data.diagnoses, "learned-profile"), 1);
        remove(&path);
    }

    #[test]
    fn separates_unreproduced_suspicion_from_learned_profiles() {
        let path = test_path("suspected");
        let store = Store::with_limits(&path, 30, 100, 64);
        assert!(store.start());
        let mut suspected = blocked("first-strike.example");
        suspected.verdict.kind = Kind::InterferenceSuspected;
        store.record(suspected);
        store.record(cache_hit("blocked.example", 40));
        store.stop();
        let data = snapshot(&path, 30);
        assert_eq!(
            (data.total, data.bypassed, data.learned, data.suspected),
            (2, 0, 1, 1)
        );
        assert_eq!(data.daily.len(), 1);
        assert_eq!((data.daily[0].suspected, data.daily[0].learned), (1, 1));
        drop(store);
        remove(&path);
    }

    #[test]
    fn start_stop_cycles_never_hang_or_lose_queued_records() {
        let path = test_path("cycles");
        let store = Store::with_limits(&path, 30, 5000, 64);
        for _ in 0..25 {
            assert!(store.start());
            store.record(blocked("cycle.example"));
            store.record(blocked("cycle.example"));
            store.stop();
        }
        assert_eq!(store.dropped_records(), 0);
        assert_eq!(scalar(&path, "SELECT COUNT(*) FROM probe_events;"), 50);
        drop(store);
        remove(&path);
    }

    #[test]
    fn stop_racing_a_producer_neither_hangs_nor_crashes() {
        let path = test_path("race");
        let store = Store::with_limits(&path, 30, 5000, 64);
        let run = AtomicBool::new(true);
        std::thread::scope(|scope| {
            scope.spawn(|| {
                while run.load(Ordering::Relaxed) {
                    store.record(blocked("race.example"));
                }
            });
            for _ in 0..15 {
                assert!(store.start());
                std::thread::sleep(Duration::from_millis(3));
                store.stop();
            }
            run.store(false, Ordering::Relaxed);
        });
        assert!(scalar(&path, "SELECT COUNT(*) FROM probe_events;") >= 0);
        drop(store);
        remove(&path);
    }

    #[test]
    fn start_after_a_failed_writer_does_not_terminate() {
        // A directory cannot be opened as a database: the writer gives up.
        let store = Store::with_limits(std::env::temp_dir(), 30, 100, 64);
        for _ in 0..3 {
            store.start();
            std::thread::sleep(Duration::from_millis(100));
        }
        store.stop();
    }

    #[test]
    fn queue_overflow_is_counted_not_silently_lost() {
        let path = test_path("overflow");
        const SENT: i64 = 2000;
        let store = Store::with_limits(&path, 30, 5000, 64);
        assert!(store.start());
        for _ in 0..SENT {
            store.record(blocked("flood.example"));
        }
        store.stop();
        let dropped = store.dropped_records() as i64;
        let written = scalar(&path, "SELECT COUNT(*) FROM probe_events;");
        assert!(dropped > 0);
        assert!(written > 0);
        assert_eq!(written + dropped, SENT);
        drop(store);
        remove(&path);
    }

    #[test]
    fn prune_cascades_to_attempts_and_keeps_the_newest_events() {
        let path = test_path("prune");
        let store = Store::with_limits(&path, 30, 100, 4096);
        assert!(store.start());
        for i in 0..150 {
            store.record(blocked(&format!("host-{i}.example")));
        }
        store.stop();
        assert_eq!(store.dropped_records(), 0);
        assert_eq!(scalar(&path, "SELECT COUNT(*) FROM probe_events;"), 100);
        assert_eq!(scalar(&path, "SELECT COUNT(*) FROM probe_attempts;"), 200);
        assert_eq!(
            scalar(
                &path,
                "SELECT COUNT(*) FROM probe_attempts WHERE event_id NOT IN (SELECT id FROM probe_events);"
            ),
            0
        );
        assert_eq!(
            scalar(
                &path,
                "SELECT COUNT(*) FROM probe_events WHERE host='host-149.example';"
            ),
            1
        );
        assert_eq!(
            scalar(
                &path,
                "SELECT COUNT(*) FROM probe_events WHERE host='host-0.example';"
            ),
            0
        );
        drop(store);
        remove(&path);
    }

    #[test]
    fn handles_non_ascii_paths() {
        let path =
            std::env::temp_dir().join(format!("sh-telemetry-türk-{}.db", std::process::id()));
        remove(&path);
        let store = Store::with_limits(&path, 30, 100, 64);
        assert!(store.start());
        store.record(blocked("unicode.example"));
        store.stop();
        assert!(path.exists());
        let data = snapshot(&path, 30);
        assert!(data.ready);
        assert_eq!(data.total, 1);
        drop(store);
        remove(&path);
    }
}
