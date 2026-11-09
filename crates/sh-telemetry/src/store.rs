use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};
use sh_strategy::diagnosis::{Attempt, Verdict};

/// One transaction commits many records: the writer lingers briefly after the
/// first one so a burst of connections shares a single fsync-bearing COMMIT.
const WRITE_BATCH_SIZE: usize = 256;
const BATCH_LINGER: Duration = Duration::from_millis(200);
const PRUNE_EVERY_RECORDS: usize = 2000;
const PRUNE_EVERY_INTERVAL: Duration = Duration::from_secs(60 * 60);

pub(crate) fn unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}

/// One completed adaptive decision.
#[derive(Debug, Clone, Default)]
pub struct ProbeRecord {
    /// Unix seconds; 0 = now.
    pub occurred_at: i64,
    pub network_id: String,
    pub host: String,
    pub remembered_profile: String,
    pub verdict: Verdict,
    pub attempts: Vec<Attempt>,
    pub total_elapsed_ms: u32,
    pub success: bool,
    pub forced: bool,
}

#[derive(Default)]
struct Queue {
    records: VecDeque<ProbeRecord>,
    stopping: bool,
}

#[derive(Default)]
struct Shared {
    queue: Mutex<Queue>,
    ready: Condvar,
    accepting: AtomicBool,
    dropped: AtomicUsize,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Queue> {
        self.queue.lock().unwrap_or_else(|p| p.into_inner())
    }
}

pub struct Store {
    path: PathBuf,
    retention_days: u32,
    max_events: usize,
    max_queued: usize,
    shared: Arc<Shared>,
    /// Serialises start()/stop(); never held by the writer.
    writer: Mutex<Option<JoinHandle<()>>>,
}

pub(crate) fn execute(conn: &Connection, sql: &str) -> bool {
    match conn.execute_batch(sql) {
        Ok(()) => true,
        Err(error) => {
            tracing::error!("Telemetri SQLite hatasi: {error}");
            false
        }
    }
}

/// Schema 1 recorded every reuse of a remembered profile as interference
/// although no baseline had run, and had no transient class. Reclassify the
/// history once so the panel stops presenting cache hits and hiccups as
/// interference evidence.
fn migrate(conn: &Connection) -> bool {
    let version: i64 = conn
        .query_row("PRAGMA user_version;", [], |row| row.get(0))
        .unwrap_or(0);
    if version >= 2 {
        return true;
    }
    if !execute(conn, "BEGIN;") {
        return false;
    }
    let ok = execute(
        conn,
        "UPDATE probe_events SET diagnosis_kind='learned-profile' \
         WHERE diagnosis_kind='sni-interference-likely' AND baseline_signal IS NULL;",
    ) && execute(
        conn,
        "UPDATE probe_events SET diagnosis_kind='transient-failure', confidence=70 \
         WHERE diagnosis_kind='sni-interference-likely' AND baseline_signal<>'server-hello' \
         AND EXISTS (SELECT 1 FROM probe_events AS healthy \
          WHERE healthy.network_id=probe_events.network_id AND healthy.host=probe_events.host \
          AND healthy.baseline_signal='server-hello' \
          AND healthy.occurred_at BETWEEN probe_events.occurred_at-900 AND probe_events.occurred_at+900);",
    ) && execute(conn, "PRAGMA user_version=2;");
    execute(conn, if ok { "COMMIT;" } else { "ROLLBACK;" });
    ok
}

fn initialize(conn: &Connection) -> bool {
    let _ = conn.busy_timeout(Duration::from_millis(2000));
    // journal_mode returns a row, so it cannot go through execute_batch.
    let wal = conn
        .query_row("PRAGMA journal_mode=WAL;", [], |row| {
            row.get::<_, String>(0)
        })
        .is_ok();
    wal && execute(
        conn,
        "PRAGMA synchronous=NORMAL;
         PRAGMA foreign_keys=ON;
         PRAGMA wal_autocheckpoint=1000;
         CREATE TABLE IF NOT EXISTS probe_events (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          occurred_at INTEGER NOT NULL,
          network_id TEXT NOT NULL,
          host TEXT NOT NULL,
          baseline_signal TEXT,
          diagnosis_kind TEXT NOT NULL,
          confidence INTEGER NOT NULL,
          winning_profile TEXT,
          remembered_profile TEXT,
          success INTEGER NOT NULL,
          forced INTEGER NOT NULL,
          attempt_count INTEGER NOT NULL,
          total_elapsed_ms INTEGER NOT NULL,
          cache_hit INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS probe_attempts (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          event_id INTEGER NOT NULL REFERENCES probe_events(id) ON DELETE CASCADE,
          ordinal INTEGER NOT NULL,
          profile TEXT NOT NULL,
          signal TEXT NOT NULL,
          elapsed_ms INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_probe_events_time ON probe_events(occurred_at DESC);
         CREATE INDEX IF NOT EXISTS idx_probe_events_host ON probe_events(network_id, host, occurred_at DESC);
         CREATE INDEX IF NOT EXISTS idx_probe_attempts_event ON probe_attempts(event_id, ordinal);",
    ) && migrate(conn)
}

fn non_empty(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

fn insert(conn: &Connection, record: &ProbeRecord) -> rusqlite::Result<()> {
    let baseline = record
        .attempts
        .iter()
        .find(|a| a.profile == "none")
        .map(|a| a.signal.name());
    let cache_hit = record.success
        && !record.remembered_profile.is_empty()
        && record.verdict.winning_profile == record.remembered_profile
        && record.attempts.len() == 1;
    conn.prepare_cached(
        "INSERT INTO probe_events(occurred_at,network_id,host,baseline_signal,diagnosis_kind,confidence,\
         winning_profile,remembered_profile,success,forced,attempt_count,total_elapsed_ms,cache_hit) \
         VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?);",
    )?
    .execute(params![
        record.occurred_at,
        record.network_id,
        record.host,
        baseline,
        record.verdict.kind.name(),
        record.verdict.confidence,
        non_empty(&record.verdict.winning_profile),
        non_empty(&record.remembered_profile),
        record.success,
        record.forced,
        record.attempts.len() as i64,
        record.total_elapsed_ms,
        cache_hit,
    ])?;
    let event_id = conn.last_insert_rowid();
    let mut attempt_insert = conn.prepare_cached(
        "INSERT INTO probe_attempts(event_id,ordinal,profile,signal,elapsed_ms) VALUES(?,?,?,?,?);",
    )?;
    for (ordinal, attempt) in record.attempts.iter().enumerate() {
        attempt_insert.execute(params![
            event_id,
            ordinal as i64,
            attempt.profile,
            attempt.signal.name(),
            attempt.elapsed_ms
        ])?;
    }
    Ok(())
}

fn prune(conn: &Connection, retention_days: u32, max_events: usize) {
    let cutoff = unix_seconds() - i64::from(retention_days) * 86400;
    let _ = conn.execute("DELETE FROM probe_events WHERE occurred_at < ?;", [cutoff]);
    let _ = conn.execute(
        "DELETE FROM probe_events WHERE id IN (SELECT id FROM probe_events ORDER BY id DESC LIMIT -1 OFFSET ?);",
        [max_events as i64],
    );
}

impl Store {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self::with_limits(path, 30, 20_000, 4096)
    }

    pub fn with_limits(
        path: impl Into<PathBuf>,
        retention_days: u32,
        max_events: usize,
        max_queued: usize,
    ) -> Self {
        Self {
            path: path.into(),
            retention_days: retention_days.max(1),
            max_events: max_events.max(100),
            max_queued: max_queued.max(64),
            shared: Arc::default(),
            writer: Mutex::new(None),
        }
    }

    pub fn start(&self) -> bool {
        let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        if self.path.as_os_str().is_empty() {
            return false;
        }
        if self.shared.accepting.load(Ordering::SeqCst) {
            return true;
        }
        // A writer that gave up on its own (database would not open) has exited
        // but must still be joined before a new one starts.
        if let Some(previous) = writer.take() {
            let _ = previous.join();
        }
        let parent = self.path.parent().filter(|p| !p.as_os_str().is_empty());
        if let Some(Err(error)) = parent.map(std::fs::create_dir_all) {
            tracing::error!("Telemetri dizini olusturulamadi: {error}");
            return false;
        }
        {
            let mut queue = self.shared.lock();
            queue.stopping = false;
            queue.records.clear();
        }
        self.shared.accepting.store(true, Ordering::SeqCst);
        let shared = self.shared.clone();
        let (path, retention, max_events) =
            (self.path.clone(), self.retention_days, self.max_events);
        *writer = Some(std::thread::spawn(move || {
            writer_loop(&shared, &path, retention, max_events)
        }));
        true
    }

    pub fn stop(&self) {
        let mut writer = self.writer.lock().unwrap_or_else(|p| p.into_inner());
        {
            // Flip the flags under the mutex the writer waits on, otherwise the
            // notify can land between its predicate check and the wait.
            let mut queue = self.shared.lock();
            self.shared.accepting.store(false, Ordering::SeqCst);
            queue.stopping = true;
        }
        self.shared.ready.notify_all();
        if let Some(handle) = writer.take() {
            let _ = handle.join();
        }
    }

    pub fn record(&self, mut record: ProbeRecord) {
        if !self.shared.accepting.load(Ordering::SeqCst) {
            return;
        }
        if record.occurred_at == 0 {
            record.occurred_at = unix_seconds();
        }
        {
            let mut queue = self.shared.lock();
            if !self.shared.accepting.load(Ordering::SeqCst) {
                return;
            }
            if queue.records.len() >= self.max_queued {
                self.shared.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
            queue.records.push_back(record);
        }
        self.shared.ready.notify_one();
    }

    pub fn dropped_records(&self) -> usize {
        self.shared.dropped.load(Ordering::Relaxed)
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        self.stop();
    }
}

fn writer_loop(shared: &Shared, path: &std::path::Path, retention_days: u32, max_events: usize) {
    let conn = match Connection::open(path) {
        Ok(conn) if initialize(&conn) => conn,
        result => {
            let detail = result
                .err()
                .map_or_else(|| "baslatilamadi".to_owned(), |e| e.to_string());
            tracing::error!(
                "Telemetri veritabani acilamadi: {}: {detail}",
                path.display()
            );
            shared.accepting.store(false, Ordering::SeqCst);
            shared.lock().records.clear();
            return;
        }
    };

    prune(&conn, retention_days, max_events);
    let mut since_prune = 0;
    let mut last_prune = Instant::now();

    loop {
        let batch: Vec<ProbeRecord> = {
            let mut queue = shared
                .ready
                .wait_while(shared.lock(), |q| !q.stopping && q.records.is_empty())
                .unwrap_or_else(|p| p.into_inner());
            if !queue.stopping && queue.records.len() < WRITE_BATCH_SIZE {
                // Let a burst pile up so it commits as one transaction.
                queue = shared
                    .ready
                    .wait_timeout_while(queue, BATCH_LINGER, |q| {
                        !q.stopping && q.records.len() < WRITE_BATCH_SIZE
                    })
                    .unwrap_or_else(|p| p.into_inner())
                    .0;
            }
            let take = queue.records.len().min(WRITE_BATCH_SIZE);
            let batch: Vec<_> = queue.records.drain(..take).collect();
            if batch.is_empty() && queue.stopping {
                break;
            }
            batch
        };

        let mut ok = execute(&conn, "BEGIN IMMEDIATE;");
        for record in &batch {
            if !ok {
                break;
            }
            ok = insert(&conn, record).is_ok();
        }
        if ok {
            ok = execute(&conn, "COMMIT;");
        }
        if !ok {
            execute(&conn, "ROLLBACK;");
            tracing::warn!("{} telemetri kaydi yazilamadi", batch.len());
        }

        since_prune += batch.len();
        if since_prune >= PRUNE_EVERY_RECORDS || last_prune.elapsed() >= PRUNE_EVERY_INTERVAL {
            prune(&conn, retention_days, max_events);
            since_prune = 0;
            last_prune = Instant::now();
        }
    }
    prune(&conn, retention_days, max_events);
}
