//! Learned-profile store (port of `Strategy::Store`, `src/Strategy.cpp`).
//!
//! Remembers which profile got through per network and host, so the probe cost
//! is paid once. Learning needs two independent differentials at least a
//! minute apart with no healthy baseline in between; winners are re-verified
//! against the untouched baseline every 30 minutes.
//!
//! Clocks: `now_seconds == 0` means the real clocks (wall time for persisted
//! stamps, monotonic time for in-memory gaps, so a wall-clock step cannot break
//! the gaps). An explicit value drives both, which keeps tests deterministic.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sh_proto::tls::ClientHello;

use crate::diagnosis::Kind;
use crate::profile::{PROFILES, find_profile, normalize_host, scope_key};

pub const DEFAULT_NETWORK: &str = "network-default";

const MAX_REMEMBERED_HOSTS: usize = 1000;
const LEARNING_TTL_SECONDS: u64 = 7 * 24 * 60 * 60;
/// A false positive corrects itself within one interval instead of living for
/// the full TTL; a real block pays one probe timeout per interval.
const REVERIFY_INTERVAL_SECONDS: u64 = 30 * 60;
/// While one connection re-verifies, parallel ones keep using the winner.
const REVERIFY_HOLD_SECONDS: u64 = 15;
/// DPI does not toggle within minutes; Wi-Fi, upstream and DNS hiccups do.
const BASELINE_HEALTHY_WINDOW_SECONDS: u64 = 15 * 60;
const MAX_HEALTHY_HOSTS: usize = 4096;
/// Parallel connections fail within seconds of each other during a hiccup, so
/// the confirming strike has to come from a clearly later connection.
const CONFIRM_MIN_GAP_SECONDS: u64 = 60;
const CANDIDATE_TTL_SECONDS: u64 = 6 * 60 * 60;
const MAX_CANDIDATES: usize = MAX_REMEMBERED_HOSTS;
/// Disk timestamps this far from the wall clock are not believed.
const CLOCK_SKEW_SECONDS: u64 = 5 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing to record.
    Ignored,
    /// The untouched baseline retired a winner.
    Forgotten,
    /// First differential: waiting for a second one.
    Candidate,
    /// Confirmed and persisted.
    Learned,
    /// An existing winner re-proved itself.
    Reverified,
    /// A cache hit kept the winner alive.
    Refreshed,
}

fn wall_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// Monotonic seconds, never 0 so 0 stays usable as "unset".
fn mono_seconds() -> u64 {
    static START: OnceLock<Instant> = OnceLock::new();
    1 + START.get_or_init(Instant::now).elapsed().as_secs()
}

fn resolve_now(explicit: u64) -> u64 {
    if explicit != 0 {
        explicit
    } else {
        wall_seconds()
    }
}

fn resolve_mono(explicit: u64) -> u64 {
    if explicit != 0 {
        explicit
    } else {
        mono_seconds()
    }
}

#[derive(Debug, Clone)]
struct Entry {
    profile: String,
    kind: Kind,
    confidence: u32,
    expires_at: u64,
    failures: u32,
    /// Last differential that re-proved it (wall seconds).
    verified_at: u64,
    /// In-memory only, monotonic; 0: never.
    reverify_started_at: u64,
}

/// A differential seen once. Times are monotonic seconds, except for a legacy
/// entry loaded from disk: until its first strike it has no monotonic stamps
/// and lives on `persist_until` (wall clock). Only such entries are written
/// back, until promoted, cancelled or expired, so an upgrade does not erase them.
#[derive(Debug, Clone)]
struct Candidate {
    profile: String,
    /// 0: legacy entry with no strike under the new rules yet.
    first_strike_at: u64,
    expires_at: u64,
    /// Wall seconds; 0: not persisted.
    persist_until: u64,
}

impl Candidate {
    fn live(&self, wall_now: u64, mono_now: u64) -> bool {
        if self.first_strike_at == 0 {
            self.persist_until > wall_now
        } else {
            self.expires_at > mono_now
        }
    }
}

#[derive(Default)]
struct State {
    entries: HashMap<String, Entry>,
    candidates: HashMap<String, Candidate>,
    /// Most recent successful untouched baseline per scoped host (monotonic).
    /// Never persisted: it only needs to outlive a network hiccup.
    healthy_at: HashMap<String, u64>,
    next_seq: u64,
}

/// Serialised state captured under the state lock and written after it is
/// released, so slow disk I/O never stalls the connections consulting it.
struct Snapshot {
    seq: u64,
    text: String,
}

pub struct Store {
    path: Option<PathBuf>,
    state: Mutex<State>,
    /// Sequence number of the newest snapshot on disk; serialises file writes.
    /// Never taken while `state` is held.
    written_seq: Mutex<u64>,
    save_failing: AtomicBool,
}

impl Store {
    /// An empty path keeps everything in memory.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        Self {
            path: (!path.as_os_str().is_empty()).then_some(path),
            state: Mutex::default(),
            written_seq: Mutex::new(0),
            save_failing: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Reads the file if present. A missing or corrupt file starts empty; a
    /// torn write keeps every entry before the tear.
    pub fn load(&self) {
        let Some(path) = &self.path else { return };
        let Some(bytes) = sh_core::fsutil::read_all(path) else {
            return;
        };
        let content = String::from_utf8_lossy(&bytes);
        let Some(pairs) = lenient::domains(&content) else {
            return;
        };

        let mut state = self.lock();
        state.entries.clear();
        state.candidates.clear();
        let loaded_at = wall_seconds();

        for (key, encoded) in pairs {
            let fields: Vec<&str> = encoded.split(';').collect();
            let profile = fields[0];
            if key.is_empty() || find_profile(profile).is_none() || profile == "none" {
                continue;
            }
            // Version 1 used a bare hostname key; it stays under the default
            // network (real sessions use an nla- id and only let it age out).
            let key = if key.contains('|') {
                key
            } else {
                scope_key(DEFAULT_NETWORK, &key)
            };

            let field = |index: usize| fields.get(index).and_then(|f| f.parse::<u64>().ok());
            let mut entry = Entry {
                profile: profile.to_owned(),
                kind: fields
                    .get(1)
                    .and_then(|f| Kind::from_name(f))
                    .unwrap_or_default(),
                confidence: field(2).map_or(50, |c| c.min(100) as u32),
                expires_at: field(3).unwrap_or(loaded_at + LEARNING_TTL_SECONDS),
                failures: field(4).map_or(0, |f| f.min(u64::from(u32::MAX)) as u32),
                verified_at: field(5).unwrap_or(0),
                reverify_started_at: 0,
            };
            // Nothing on disk outlives one TTL from now, and a verification stamp
            // from the future (clock was wrong when written) proves nothing.
            entry.expires_at = entry.expires_at.min(loaded_at + LEARNING_TTL_SECONDS);
            if entry.verified_at > loaded_at + CLOCK_SKEW_SECONDS {
                entry.verified_at = 0;
            }
            if entry.expires_at <= loaded_at {
                continue;
            }
            if entry.verified_at == 0 {
                // Written before winners needed a second differential: its first
                // use re-tests the baseline instead of trusting a possible hiccup.
                if state.candidates.len() < MAX_CANDIDATES {
                    state.candidates.insert(
                        key,
                        Candidate {
                            profile: entry.profile,
                            first_strike_at: 0,
                            expires_at: 0,
                            persist_until: entry.expires_at,
                        },
                    );
                }
            } else if state.entries.len() < MAX_REMEMBERED_HOSTS {
                state.entries.insert(key, entry);
            }
        }
    }

    /// Profile previously recorded for `host` on this network, or empty.
    pub fn lookup(&self, network_id: &str, host: &str) -> String {
        let key = scope_key(network_id, host);
        self.lock()
            .entries
            .get(&key)
            .filter(|e| e.expires_at > wall_seconds())
            .map(|e| e.profile.clone())
            .unwrap_or_default()
    }

    /// Records a winner under the default network with no verdict (manual and
    /// legacy callers).
    pub fn remember_default(&self, host: &str, profile: &str) {
        self.remember(DEFAULT_NETWORK, host, profile, Kind::Unknown, 50, 0);
    }

    /// Records a verdict for `host` and persists when something changed.
    /// The untouched baseline (`none`) removes a stale mapping instead of
    /// filling the cache with healthy destinations.
    pub fn remember(
        &self,
        network_id: &str,
        host: &str,
        profile: &str,
        kind: Kind,
        confidence: u32,
        now_seconds: u64,
    ) -> Outcome {
        let (outcome, snapshot) = {
            let mut state = self.lock();
            let mut dirty = false;
            let outcome = remember_locked(
                &mut state,
                network_id,
                host,
                profile,
                kind,
                confidence,
                now_seconds,
                &mut dirty,
            );
            (
                outcome,
                dirty.then(|| self.snapshot_locked(&mut state)).flatten(),
            )
        };
        self.commit(snapshot); // disk I/O happens outside the state lock
        outcome
    }

    /// The untouched baseline just succeeded: a baseline failure shortly
    /// afterwards is a hiccup, not DPI, and a pending nomination was one too.
    pub fn note_baseline_healthy(&self, network_id: &str, host: &str, now_seconds: u64) {
        let now = resolve_mono(now_seconds);
        let key = scope_key(network_id, host);
        let snapshot = {
            let mut state = self.lock();
            let persisted = state
                .candidates
                .remove(&key)
                .is_some_and(|c| c.persist_until != 0);
            let snapshot = if persisted {
                self.snapshot_locked(&mut state)
            } else {
                None
            };
            if state.healthy_at.len() >= MAX_HEALTHY_HOSTS && !state.healthy_at.contains_key(&key) {
                state
                    .healthy_at
                    .retain(|_, at| *at + BASELINE_HEALTHY_WINDOW_SECONDS > now);
                if state.healthy_at.len() >= MAX_HEALTHY_HOSTS {
                    let any = state.healthy_at.keys().next().cloned();
                    if let Some(any) = any {
                        state.healthy_at.remove(&any);
                    }
                }
            }
            state.healthy_at.insert(key, now);
            snapshot
        };
        self.commit(snapshot);
    }

    pub fn baseline_recently_healthy(
        &self,
        network_id: &str,
        host: &str,
        now_seconds: u64,
    ) -> bool {
        let now = resolve_mono(now_seconds);
        self.lock()
            .healthy_at
            .get(&scope_key(network_id, host))
            .is_some_and(|&at| at <= now && at + BASELINE_HEALTHY_WINDOW_SECONDS > now)
    }

    /// Degrades a cached profile after a failed re-check; two consecutive
    /// failures evict it so the next connection performs a fresh baseline.
    pub fn record_failure(&self, network_id: &str, host: &str, profile: &str) {
        let key = scope_key(network_id, host);
        let snapshot = {
            let mut state = self.lock();
            let Some(entry) = state.entries.get_mut(&key) else {
                return;
            };
            if entry.profile != profile {
                return;
            }
            entry.failures += 1;
            if entry.failures >= 2 {
                state.entries.remove(&key);
            } else {
                entry.confidence = entry.confidence.saturating_sub(20);
            }
            self.snapshot_locked(&mut state)
        };
        self.commit(snapshot);
    }

    /// Forgets `host` on every network.
    pub fn forget(&self, host: &str) {
        let suffix = format!("|{}", normalize_host(host));
        let snapshot = {
            let mut state = self.lock();
            let before = state.entries.len();
            state.entries.retain(|key, _| !key.ends_with(&suffix));
            let mut changed = state.entries.len() != before;
            state.candidates.retain(|key, candidate| {
                let matches = key.ends_with(&suffix);
                changed |= matches && candidate.persist_until != 0;
                !matches
            });
            if changed {
                self.snapshot_locked(&mut state)
            } else {
                None
            }
        };
        self.commit(snapshot);
    }

    /// Drops every learned mapping and persists the empty store.
    pub fn clear(&self) {
        let snapshot = {
            let mut state = self.lock();
            state.entries.clear();
            state.candidates.clear();
            state.healthy_at.clear();
            self.snapshot_locked(&mut state)
        };
        self.commit(snapshot);
    }

    pub fn len(&self) -> usize {
        let now = wall_seconds();
        self.lock()
            .entries
            .values()
            .filter(|e| e.expires_at > now)
            .count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn candidate_count(&self) -> usize {
        self.lock().candidates.len()
    }

    /// Probe order for a host: the remembered profile first, then the rest. A
    /// winner not re-proven for a while is re-verified (baseline first; only one
    /// connection per host at a time). A pending candidate rides right behind
    /// the baseline, so confirming or clearing it costs at most one timeout.
    pub fn probe_order(
        &self,
        network_id: &str,
        host: &str,
        hello: &ClientHello,
        now_seconds: u64,
    ) -> Vec<&'static str> {
        // A hello already spanning records may still be incomplete in our
        // buffer, so replaying it is unsafe.
        if hello.spans_records {
            return vec!["none"];
        }
        let now = resolve_now(now_seconds);
        let mono = resolve_mono(now_seconds);
        let mut remembered: Option<&'static str> = None;
        let mut pending: Option<&'static str> = None;
        let mut reverify = false;
        {
            let key = scope_key(network_id, host);
            let mut state = self.lock();
            if let Some(entry) = state.entries.get_mut(&key).filter(|e| e.expires_at > now) {
                remembered = find_profile(&entry.profile).map(|p| p.name);
                // A stamp far in the future means the wall clock stepped back:
                // treat the winner as overdue instead of waiting out the step.
                let due = entry.verified_at > now + CLOCK_SKEW_SECONDS
                    || entry.verified_at + REVERIFY_INTERVAL_SECONDS <= now;
                if due
                    && (entry.reverify_started_at == 0
                        || entry.reverify_started_at + REVERIFY_HOLD_SECONDS <= mono)
                {
                    entry.reverify_started_at = mono;
                    reverify = true;
                }
            } else if let Some(candidate) = state.candidates.get(&key).filter(|c| c.live(now, mono))
            {
                pending = find_profile(&candidate.profile).map(|p| p.name);
            }
        }

        let mut order = Vec::with_capacity(PROFILES.len() + 1);
        let mut baseline_queued = false;
        let lead = if let Some(remembered) = remembered {
            if reverify {
                order.push("none");
                baseline_queued = true;
            }
            order.push(remembered);
            Some(remembered)
        } else if let Some(pending) = pending {
            order.extend(["none", pending]);
            baseline_queued = true;
            Some(pending)
        } else {
            None
        };
        for profile in PROFILES {
            if Some(profile.name) == lead
                || (baseline_queued && profile.name == "none")
                || (profile.requires_sni && !hello.has_sni())
            {
                continue;
            }
            order.push(profile.name);
        }
        order
    }

    fn snapshot_locked(&self, state: &mut State) -> Option<Snapshot> {
        self.path.as_ref()?;
        let now = wall_seconds();
        let mut lines = Vec::with_capacity(state.entries.len() + state.candidates.len());
        for (key, entry) in &state.entries {
            if entry.expires_at > now {
                lines.push((
                    key,
                    format!(
                        "{};{};{};{};{};{}",
                        entry.profile,
                        entry.kind.name(),
                        entry.confidence,
                        entry.expires_at,
                        entry.failures,
                        entry.verified_at
                    ),
                ));
            }
        }
        // Legacy nominations keep their verified_at==0 shape, so a reload brings
        // them back as candidates until promoted, cancelled or expired.
        for (key, candidate) in &state.candidates {
            if candidate.persist_until > now && !state.entries.contains_key(key) {
                lines.push((
                    key,
                    format!(
                        "{};unknown;50;{};0;0",
                        candidate.profile, candidate.persist_until
                    ),
                ));
            }
        }
        let body: Vec<String> = lines
            .into_iter()
            .map(|(key, value)| {
                format!(
                    "    \"{}\": \"{}\"",
                    lenient::escape(key),
                    lenient::escape(&value)
                )
            })
            .collect();
        state.next_seq += 1;
        Some(Snapshot {
            seq: state.next_seq,
            text: format!(
                "{{\n  \"version\": 2,\n  \"domains\": {{\n{}\n  }}\n}}\n",
                body.join(",\n")
            ),
        })
    }

    fn commit(&self, snapshot: Option<Snapshot>) {
        let (Some(snapshot), Some(path)) = (snapshot, &self.path) else {
            return;
        };
        let mut written = self.written_seq.lock().unwrap_or_else(|p| p.into_inner());
        // Snapshots are complete states: writing an older one after a newer one
        // would roll the file back.
        if snapshot.seq <= *written {
            return;
        }
        match sh_core::fsutil::write_atomic(path, snapshot.text.as_bytes()) {
            Ok(()) => {
                *written = snapshot.seq;
                self.save_failing.store(false, Ordering::Relaxed);
            }
            Err(error) => {
                // Once per failure burst; the next successful save restores it.
                if !self.save_failing.swap(true, Ordering::Relaxed) {
                    tracing::warn!("Strateji dosyasi yazilamadi: {}: {error}", path.display());
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn remember_locked(
    state: &mut State,
    network_id: &str,
    host: &str,
    profile: &str,
    kind: Kind,
    confidence: u32,
    explicit_now: u64,
    dirty: &mut bool,
) -> Outcome {
    let host = normalize_host(host);
    if host.is_empty() || find_profile(profile).is_none() {
        return Outcome::Ignored;
    }
    let now = resolve_now(explicit_now);
    let mono = resolve_mono(explicit_now);
    let key = scope_key(network_id, &host);

    if profile == "none" {
        let had_entry = state.entries.remove(&key).is_some();
        let had_persisted_candidate = state
            .candidates
            .remove(&key)
            .is_some_and(|c| c.persist_until != 0);
        *dirty = had_entry || had_persisted_candidate;
        return if had_entry {
            Outcome::Forgotten
        } else {
            Outcome::Ignored
        };
    }

    // A hiccup is not a bypass: whatever profile happened to be tried when the
    // path came back must not become the remembered winner.
    if kind == Kind::TransientFailure {
        return Outcome::Ignored;
    }

    let live_same = state
        .entries
        .get(&key)
        .filter(|e| e.expires_at > now)
        .map(|e| e.profile == profile);

    if kind == Kind::LearnedProfile {
        // The winner worked again without a fresh baseline: that keeps it alive,
        // but can neither create a winner nor count as re-proof.
        if live_same != Some(true) {
            return Outcome::Ignored;
        }
        let entry = state.entries.get_mut(&key).expect("checked above");
        if entry.failures != 0 {
            entry.failures = 0;
            *dirty = true;
        }
        return Outcome::Refreshed;
    }

    if live_same == Some(true) {
        // A confirmed winner re-proved itself against a fresh baseline.
        let entry = state.entries.get_mut(&key).expect("checked above");
        entry.failures = 0;
        entry.verified_at = now;
        entry.reverify_started_at = 0;
        entry.expires_at = now + LEARNING_TTL_SECONDS;
        if confidence > entry.confidence {
            entry.confidence = confidence.min(100);
            entry.kind = kind;
        }
        *dirty = true;
        return Outcome::Reverified;
    }

    if kind == Kind::SniInterferenceLikely {
        // One differential nominates; a second one at least a minute later, with
        // no healthy baseline in between, confirms.
        if state
            .candidates
            .get(&key)
            .is_some_and(|c| !c.live(now, mono))
        {
            state.candidates.remove(&key);
        }
        match state.candidates.get_mut(&key) {
            None => {
                make_room_for_candidate(state, now, mono);
                state.candidates.insert(
                    key,
                    Candidate {
                        profile: profile.to_owned(),
                        first_strike_at: mono,
                        expires_at: mono + CANDIDATE_TTL_SECONDS,
                        persist_until: 0,
                    },
                );
                return Outcome::Candidate;
            }
            Some(pending) => {
                pending.profile = profile.to_owned(); // the latest winner is worth keeping
                if pending.first_strike_at == 0 {
                    // Legacy entry: this was its first real strike.
                    pending.first_strike_at = mono;
                    pending.expires_at = mono + CANDIDATE_TTL_SECONDS;
                    return Outcome::Candidate;
                }
                if mono < pending.first_strike_at + CONFIRM_MIN_GAP_SECONDS {
                    return Outcome::Candidate;
                }
                state.candidates.remove(&key);
            }
        }
    }

    if !state.entries.contains_key(&key) {
        make_room_for_entry(state, now); // bounded cache; evicted paths are relearned
    }
    state.candidates.remove(&key); // a winner supersedes any pending nomination
    state.entries.insert(
        key,
        Entry {
            profile: profile.to_owned(),
            kind,
            confidence: confidence.min(100),
            expires_at: now + LEARNING_TTL_SECONDS,
            failures: 0,
            verified_at: now,
            reverify_started_at: 0,
        },
    );
    *dirty = true;
    Outcome::Learned
}

/// Expired winners go first; only then the one verified longest ago, so a
/// freshly proven path is never the victim.
fn make_room_for_entry(state: &mut State, wall_now: u64) {
    if state.entries.len() < MAX_REMEMBERED_HOSTS {
        return;
    }
    state.entries.retain(|_, e| e.expires_at > wall_now);
    if state.entries.len() < MAX_REMEMBERED_HOSTS {
        return;
    }
    let oldest = state
        .entries
        .iter()
        .min_by_key(|(_, e)| e.verified_at)
        .map(|(k, _)| k.clone());
    if let Some(oldest) = oldest {
        state.entries.remove(&oldest);
    }
}

/// Expired nominations first, then the stalest strike (legacy entries carry no
/// strike and go before any real one).
fn make_room_for_candidate(state: &mut State, wall_now: u64, mono_now: u64) {
    if state.candidates.len() < MAX_CANDIDATES {
        return;
    }
    state.candidates.retain(|_, c| c.live(wall_now, mono_now));
    if state.candidates.len() < MAX_CANDIDATES {
        return;
    }
    let oldest = state
        .candidates
        .iter()
        .min_by_key(|(_, c)| c.first_strike_at)
        .map(|(k, _)| k.clone());
    if let Some(oldest) = oldest {
        state.candidates.remove(&oldest);
    }
}

/// Just enough JSON to read `{"domains": {"key": "value", ...}}` leniently (a
/// torn write keeps the pairs before the tear) and to escape what we write.
mod lenient {
    pub fn escape(text: &str) -> String {
        let mut out = String::with_capacity(text.len());
        for c in text.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out
    }

    fn skip_ws(bytes: &[u8], mut pos: usize) -> usize {
        while pos < bytes.len() && bytes[pos].is_ascii_whitespace() {
            pos += 1;
        }
        pos
    }

    /// Parses a string starting at the opening quote. Returns the text and the
    /// position after the closing quote, or None if it never closes.
    fn string(text: &str, start: usize) -> Option<(String, usize)> {
        let bytes = text.as_bytes();
        if bytes.get(start) != Some(&b'"') {
            return None;
        }
        let mut out = String::new();
        let mut chars = text[start + 1..].char_indices();
        while let Some((offset, c)) = chars.next() {
            match c {
                '"' => return Some((out, start + 1 + offset + 1)),
                '\\' => match chars.next()?.1 {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'b' => out.push('\u{8}'),
                    'f' => out.push('\u{c}'),
                    'u' => {
                        let hex: String = (0..4)
                            .filter_map(|_| chars.next().map(|(_, h)| h))
                            .collect();
                        let code = u32::from_str_radix(&hex, 16).ok()?;
                        out.push(char::from_u32(code).unwrap_or('\u{fffd}'));
                    }
                    other => out.push(other),
                },
                c => out.push(c),
            }
        }
        None
    }

    /// The `"domains"` object's string pairs, in file order, up to the first
    /// thing that is not a well-formed pair. None when there is no object.
    pub fn domains(text: &str) -> Option<Vec<(String, String)>> {
        let bytes = text.as_bytes();
        let mut search = 0;
        let mut pos = loop {
            let found = search + text[search..].find("\"domains\"")?;
            let colon = skip_ws(bytes, found + "\"domains\"".len());
            if bytes.get(colon) == Some(&b':') {
                break skip_ws(bytes, colon + 1);
            }
            search = found + 1;
        };
        if bytes.get(pos) != Some(&b'{') {
            return None;
        }
        pos += 1;
        let mut pairs = Vec::new();
        loop {
            pos = skip_ws(bytes, pos);
            match bytes.get(pos) {
                Some(b',') => {
                    pos += 1;
                    continue;
                }
                Some(b'"') => {}
                _ => break,
            }
            let Some((key, after_key)) = string(text, pos) else {
                break;
            };
            let colon = skip_ws(bytes, after_key);
            if bytes.get(colon) != Some(&b':') {
                break;
            }
            let value_start = skip_ws(bytes, colon + 1);
            // A value cut off by a torn write has no closing quote: not trusted.
            let Some((value, after_value)) = string(text, value_start) else {
                break;
            };
            pairs.push((key, value));
            pos = after_value;
        }
        Some(pairs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_proto::testing::{HelloOptions, build_client_hello};
    use sh_proto::tls::{RECORD_HEADER_SIZE, parse_client_hello};
    use std::fs;
    use std::path::Path;

    /// Explicit clocks keep interval tests deterministic. Entries still expire
    /// against the wall clock in lookup(), so the timeline sits in the future.
    const EPOCH: u64 = 1_900_000_000;
    const SNI: Kind = Kind::SniInterferenceLikely;

    fn hello(options: &HelloOptions) -> ClientHello {
        let mut hello = ClientHello::default();
        parse_client_hello(&build_client_hello(options), &mut hello);
        hello
    }

    fn discord() -> ClientHello {
        hello(&HelloOptions::default())
    }

    fn temp_path(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!("sh-strategy-{}-{name}", std::process::id()));
        let _ = fs::remove_file(&path);
        path
    }

    /// Two independent differentials a minute apart: what it takes to learn.
    fn learn(store: &Store, network: &str, host: &str, profile: &str, at: u64) {
        let first = if at != 0 { at } else { wall_seconds() };
        store.remember(network, host, profile, SNI, 92, first);
        store.remember(network, host, profile, SNI, 92, first + 61);
    }

    fn entry_line(key: &str, profile: &str, expires_at: u64, verified_at: u64) -> String {
        format!("\"{key}\":\"{profile};sni-interference-likely;92;{expires_at};0;{verified_at}\"")
    }

    fn write(path: &Path, content: &str) {
        fs::write(path, content).unwrap();
    }

    #[test]
    fn ech_extension_alone_does_not_disable_profiles() {
        let hello = hello(&HelloOptions {
            server_name: "cloudflare-ech.com".into(),
            with_ech: true,
            ..Default::default()
        });
        assert!(hello.has_ech);
        assert!(crate::build_plan("sni-mid", &hello, 20).is_some());
        let order = Store::new("").probe_order(DEFAULT_NETWORK, "cloudflare-ech.com", &hello, 0);
        assert_eq!(order.len(), PROFILES.len());
        assert_eq!(order[0], "none");
    }

    #[test]
    fn probe_order_skips_sni_profiles_when_there_is_no_sni() {
        let hello = hello(&HelloOptions {
            server_name: String::new(),
            with_sni: false,
            ..Default::default()
        });
        assert!(!hello.has_sni());
        let order = Store::new("").probe_order(DEFAULT_NETWORK, "example.com", &hello, 0);
        assert!(!order.is_empty());
        assert!(
            order
                .iter()
                .all(|name| !find_profile(name).unwrap().requires_sni)
        );
    }

    #[test]
    fn unknown_path_starts_with_untouched_baseline() {
        let order = Store::new("").probe_order("network-a", "new.example", &discord(), 0);
        assert_eq!(order[0], "none");
        assert_eq!(order.len(), PROFILES.len());
    }

    #[test]
    fn learned_profiles_are_scoped_to_the_current_network() {
        let store = Store::new(temp_path("scope.json"));
        learn(&store, "home-network", "discord.com", "sni-mid", 0);
        assert_eq!(store.lookup("home-network", "discord.com"), "sni-mid");
        assert_eq!(store.lookup("mobile-network", "discord.com"), "");
        assert_eq!(
            store.probe_order("home-network", "discord.com", &discord(), 0)[0],
            "sni-mid"
        );
        assert_eq!(
            store.probe_order("mobile-network", "discord.com", &discord(), 0)[0],
            "none"
        );
    }

    #[test]
    fn cached_profile_is_evicted_after_two_consecutive_failures() {
        let store = Store::new(temp_path("failures.json"));
        learn(&store, "home-network", "discord.com", "sni-mid", 0);
        store.record_failure("home-network", "discord.com", "sni-mid");
        assert_eq!(store.lookup("home-network", "discord.com"), "sni-mid");
        store.record_failure("home-network", "discord.com", "sni-mid");
        assert_eq!(store.lookup("home-network", "discord.com"), "");
    }

    #[test]
    fn store_remembers_across_reloads() {
        let path = temp_path("reload.json");
        {
            let store = Store::new(&path);
            store.load();
            store.remember_default("Discord.com.", "record-1");
            store.remember_default("example.org", "sni-mid");
            assert_eq!(store.len(), 2);
        }
        let reloaded = Store::new(&path);
        reloaded.load();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.lookup(DEFAULT_NETWORK, "discord.com"), "record-1");
        assert_eq!(reloaded.lookup(DEFAULT_NETWORK, "DISCORD.COM"), "record-1");
        assert_eq!(reloaded.lookup(DEFAULT_NETWORK, "unknown.test"), "");
        reloaded.forget("discord.com");
        assert_eq!(reloaded.lookup(DEFAULT_NETWORK, "discord.com"), "");
        reloaded.clear();
        assert_eq!(reloaded.len(), 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn untouched_baseline_is_not_persisted_as_learned_state() {
        let path = temp_path("clean-baseline.json");
        {
            let store = Store::new(&path);
            learn(&store, "home-network", "discord.com", "sni-mid", 0);
            assert_eq!(store.len(), 1);
            store.remember(
                "home-network",
                "discord.com",
                "none",
                Kind::NoInterference,
                95,
                0,
            );
            assert_eq!(store.len(), 0);
            assert_eq!(store.lookup("home-network", "discord.com"), "");
        }
        let reloaded = Store::new(&path);
        reloaded.load();
        assert_eq!(reloaded.len(), 0);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn store_drops_profiles_this_build_does_not_know() {
        let path = temp_path("unknown-profile.json");
        write(
            &path,
            r#"{"version":1,"domains":{"a.test":"sni-mid","b.test":"retired-profile","c.test":"none"}}"#,
        );
        let store = Store::new(&path);
        store.load();
        // Version 1 entries carry no verification time: they come back as
        // candidates that must re-prove themselves, never as trusted winners.
        assert_eq!(store.len(), 0);
        for host in ["a.test", "b.test", "c.test"] {
            assert_eq!(store.lookup(DEFAULT_NETWORK, host), "");
        }
        let pending = store.probe_order(DEFAULT_NETWORK, "a.test", &discord(), 0);
        assert_eq!(&pending[..2], ["none", "sni-mid"]);
        assert!(
            store
                .probe_order(DEFAULT_NETWORK, "b.test", &discord(), 0)
                .iter()
                .all(|n| find_profile(n).is_some())
        );
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn remembered_profile_is_probed_first() {
        let store = Store::new(temp_path("order.json"));
        store.remember_default("discord.com", "sni-multi");
        let order = store.probe_order(DEFAULT_NETWORK, "discord.com", &discord(), 0);
        assert_eq!(order[0], "sni-multi");
        assert_eq!(order.iter().filter(|&&n| n == "sni-multi").count(), 1);
    }

    #[test]
    fn learned_winner_is_reverified_after_the_interval() {
        let store = Store::new("");
        let hello = discord();
        learn(&store, "home", "blocked.test", "sni-mid", EPOCH);
        let learned_at = EPOCH + 61;

        // A fresh winner leads and nothing is re-tested.
        assert_eq!(
            store.probe_order("home", "blocked.test", &hello, learned_at + 60)[0],
            "sni-mid"
        );

        // Half an hour later the baseline leads and the winner is the immediate
        // retry, listed exactly once.
        let later = learned_at + 30 * 60;
        let order = store.probe_order("home", "blocked.test", &hello, later);
        assert_eq!(&order[..2], ["none", "sni-mid"]);
        assert_eq!(order.iter().filter(|&&n| n == "none").count(), 1);
        assert_eq!(order.iter().filter(|&&n| n == "sni-mid").count(), 1);

        // A parallel connection seconds later does not start a second re-check.
        assert_eq!(
            store.probe_order("home", "blocked.test", &hello, later + 2)[0],
            "sni-mid"
        );

        // Re-proving the winner restarts the interval.
        assert_eq!(
            store.remember("home", "blocked.test", "sni-mid", SNI, 92, later + 3),
            Outcome::Reverified
        );
        assert_eq!(
            store.probe_order("home", "blocked.test", &hello, later + 20 * 60)[0],
            "sni-mid"
        );

        // A baseline that succeeds on re-check retires the winner.
        assert_eq!(
            store.remember(
                "home",
                "blocked.test",
                "none",
                Kind::NoInterference,
                95,
                later + 4
            ),
            Outcome::Forgotten
        );
        assert_eq!(store.lookup("home", "blocked.test"), "");
    }

    #[test]
    fn transient_verdict_is_never_learned() {
        let store = Store::new("");
        store.remember(
            "home",
            "flaky.test",
            "record-1",
            Kind::TransientFailure,
            70,
            EPOCH,
        );
        assert_eq!(store.lookup("home", "flaky.test"), "");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn cache_hit_keeps_a_winner_alive_but_cannot_create_one() {
        let store = Store::new("");
        assert_eq!(
            store.remember(
                "home",
                "cached.test",
                "sni-mid",
                Kind::LearnedProfile,
                65,
                EPOCH
            ),
            Outcome::Ignored
        );
        assert_eq!(store.lookup("home", "cached.test"), "");

        learn(&store, "home", "cached.test", "sni-mid", EPOCH);
        let learned_at = EPOCH + 61;
        store.record_failure("home", "cached.test", "sni-mid");
        assert_eq!(
            store.remember(
                "home",
                "cached.test",
                "sni-mid",
                Kind::LearnedProfile,
                65,
                learned_at + 10
            ),
            Outcome::Refreshed
        );
        // Failures reset, but the cache hit did not count as re-verification.
        assert_eq!(
            store.probe_order("home", "cached.test", &discord(), learned_at + 31 * 60)[0],
            "none"
        );
        store.record_failure("home", "cached.test", "sni-mid");
        assert_eq!(store.lookup("home", "cached.test"), "sni-mid");
    }

    #[test]
    fn healthy_baseline_vouches_for_a_host_for_a_while() {
        let store = Store::new("");
        assert!(!store.baseline_recently_healthy("home", "api.test", EPOCH));
        store.note_baseline_healthy("home", "API.test.", EPOCH);
        assert!(store.baseline_recently_healthy("home", "api.test", EPOCH + 60));
        assert!(store.baseline_recently_healthy("home", "api.test", EPOCH + 14 * 60));
        assert!(!store.baseline_recently_healthy("home", "api.test", EPOCH + 16 * 60));
        assert!(!store.baseline_recently_healthy("hotspot", "api.test", EPOCH + 60));
    }

    #[test]
    fn verification_time_survives_reload_and_legacy_entries_become_candidates() {
        let path = temp_path("verified-reload.json");
        let now = wall_seconds();
        let hello = discord();
        learn(&Store::new(&path), "home", "blocked.test", "sni-mid", now);
        {
            let reloaded = Store::new(&path);
            reloaded.load();
            assert_eq!(reloaded.lookup("home", "blocked.test"), "sni-mid");
            assert_eq!(
                reloaded.probe_order("home", "blocked.test", &hello, now + 120)[0],
                "sni-mid"
            );
        }

        // An entry from before verification times existed is not trusted.
        write(
            &path,
            &format!(
                "{{\"version\":2,\"domains\":{{\"home|old.test\":\"record-1;sni-interference-likely;92;{};0\"}}}}",
                now + 3600
            ),
        );
        let upgraded = Store::new(&path);
        upgraded.load();
        assert_eq!(upgraded.lookup("home", "old.test"), "");
        assert_eq!(
            &upgraded.probe_order("home", "old.test", &hello, now + 60)[..2],
            ["none", "record-1"]
        );
        assert_eq!(
            upgraded.remember("home", "old.test", "record-1", SNI, 92, now + 70),
            Outcome::Candidate
        );
        assert_eq!(upgraded.lookup("home", "old.test"), "");
        assert_eq!(
            upgraded.remember("home", "old.test", "record-1", SNI, 92, now + 140),
            Outcome::Learned
        );
        assert_eq!(upgraded.lookup("home", "old.test"), "record-1");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn single_differential_only_nominates_a_candidate() {
        let store = Store::new("");
        let hello = discord();
        assert_eq!(
            store.remember("home", "maybe.test", "sni-mid", SNI, 92, EPOCH),
            Outcome::Candidate
        );
        assert_eq!(store.lookup("home", "maybe.test"), "");
        assert_eq!(store.len(), 0);

        // The candidate rides right behind the baseline so confirming is cheap.
        let order = store.probe_order("home", "maybe.test", &hello, EPOCH + 5);
        assert_eq!(&order[..2], ["none", "sni-mid"]);
        assert_eq!(order.iter().filter(|&&n| n == "sni-mid").count(), 1);

        // A parallel connection failing seconds later is the same hiccup.
        assert_eq!(
            store.remember("home", "maybe.test", "record-1", SNI, 92, EPOCH + 30),
            Outcome::Candidate
        );
        assert_eq!(store.lookup("home", "maybe.test"), "");

        // A clearly later connection reproducing the differential confirms it.
        assert_eq!(
            store.remember("home", "maybe.test", "record-1", SNI, 92, EPOCH + 61),
            Outcome::Learned
        );
        assert_eq!(store.lookup("home", "maybe.test"), "record-1");
        assert_eq!(
            store.probe_order("home", "maybe.test", &hello, EPOCH + 70)[0],
            "record-1"
        );
    }

    #[test]
    fn healthy_baseline_cancels_a_candidate() {
        let store = Store::new("");
        store.remember("home", "flaky.test", "sni-mid", SNI, 92, EPOCH);
        store.note_baseline_healthy("home", "flaky.test", EPOCH + 10);
        // The next strike starts over: a first strike, not a confirmation.
        assert_eq!(
            store.remember("home", "flaky.test", "sni-mid", SNI, 92, EPOCH + 120),
            Outcome::Candidate
        );
        assert_eq!(store.lookup("home", "flaky.test"), "");
        assert_eq!(
            store.remember("home", "flaky.test", "sni-mid", SNI, 92, EPOCH + 200),
            Outcome::Learned
        );
    }

    #[test]
    fn stale_candidate_does_not_confirm() {
        let store = Store::new("");
        store.remember("home", "rare.test", "sni-mid", SNI, 92, EPOCH);
        assert_eq!(
            store.remember("home", "rare.test", "sni-mid", SNI, 92, EPOCH + 7 * 3600),
            Outcome::Candidate
        );
        assert_eq!(store.lookup("home", "rare.test"), "");
    }

    #[test]
    fn reverify_with_failing_baseline_then_winner_succeeds_is_reverified() {
        let store = Store::new("");
        let hello = discord();
        learn(&store, "home", "blocked.test", "sni-mid", EPOCH);
        let later = EPOCH + 61 + 31 * 60;
        assert_eq!(
            &store.probe_order("home", "blocked.test", &hello, later)[..2],
            ["none", "sni-mid"]
        );
        // The baseline failed again and the winner got through: it re-proves
        // itself instead of being replaced.
        assert_eq!(
            store.remember("home", "blocked.test", "sni-mid", SNI, 92, later + 3),
            Outcome::Reverified
        );
        assert_eq!(store.lookup("home", "blocked.test"), "sni-mid");
        assert_eq!(store.candidate_count(), 0);
        assert_eq!(
            store.probe_order("home", "blocked.test", &hello, later + 60)[0],
            "sni-mid"
        );
        assert_eq!(
            store.probe_order("home", "blocked.test", &hello, later + 3 + 31 * 60)[0],
            "none"
        );
    }

    #[test]
    fn strikes_inside_the_confirmation_gap_never_learn() {
        let store = Store::new("");
        // A hiccup fails a burst of parallel connections within seconds.
        for offset in (0..60).step_by(3) {
            assert_eq!(
                store.remember("home", "burst.test", "sni-mid", SNI, 92, EPOCH + offset),
                Outcome::Candidate
            );
        }
        assert_eq!(store.lookup("home", "burst.test"), "");
        assert_eq!(store.len(), 0);
        // The first strike's clock was never refreshed by the burst.
        assert_eq!(
            store.remember("home", "burst.test", "sni-mid", SNI, 92, EPOCH + 60),
            Outcome::Learned
        );
    }

    #[test]
    fn candidates_are_capped_and_the_stalest_is_evicted_first() {
        let store = Store::new("");
        let host = |i: u64| format!("h{i}.test");
        let cap = MAX_CANDIDATES as u64;
        for i in 0..cap + 100 {
            assert_eq!(
                store.remember("home", &host(i), "sni-mid", SNI, 92, EPOCH + i),
                Outcome::Candidate
            );
        }
        assert_eq!(store.candidate_count(), MAX_CANDIDATES);
        // The oldest nomination is gone: its next strike starts over.
        assert_eq!(
            store.remember("home", &host(0), "sni-mid", SNI, 92, EPOCH + 5000),
            Outcome::Candidate
        );
        assert_eq!(store.candidate_count(), MAX_CANDIDATES);
        // The newest one survived and still confirms.
        assert_eq!(
            store.remember(
                "home",
                &host(cap + 99),
                "sni-mid",
                SNI,
                92,
                EPOCH + cap + 99 + 61
            ),
            Outcome::Learned
        );
    }

    #[test]
    fn full_cache_evicts_the_oldest_verified_winner_not_a_random_one() {
        let store = Store::new("");
        let host = |i: u64| format!("e{i}.test");
        let cap = MAX_REMEMBERED_HOSTS as u64;
        for i in 0..cap {
            learn(&store, "home", &host(i), "sni-mid", EPOCH + i * 200);
        }
        assert_eq!(store.len(), MAX_REMEMBERED_HOSTS);
        learn(&store, "home", &host(cap), "sni-mid", EPOCH + cap * 200);
        assert_eq!(store.len(), MAX_REMEMBERED_HOSTS);
        assert_eq!(store.lookup("home", &host(0)), "");
        assert_eq!(store.lookup("home", &host(1)), "sni-mid");
        assert_eq!(store.lookup("home", &host(cap - 1)), "sni-mid");
        assert_eq!(store.lookup("home", &host(cap)), "sni-mid");
    }

    #[test]
    fn corrupt_or_partial_strategy_files_load_what_is_intact() {
        let path = temp_path("corrupt.json");
        let now = wall_seconds();
        let good = entry_line("home|a.test", "sni-mid", now + 3600, now);

        // Torn write: the second value has no closing quote and is not trusted.
        write(
            &path,
            &format!("{{\"version\":2,\"domains\":{{{good},\"home|b.test\":\"record-1;sni-interf"),
        );
        {
            let store = Store::new(&path);
            store.load();
            assert_eq!(store.lookup("home", "a.test"), "sni-mid");
            assert_eq!(store.lookup("home", "b.test"), "");
            assert_eq!(store.candidate_count(), 0);
        }

        // Garbage and an empty file leave an empty, usable store.
        for junk in [
            "",
            "not json at all {{{",
            "{\"domains\":{\"x\":",
            "{\"domains\":[1,2]}",
        ] {
            write(&path, junk);
            let store = Store::new(&path);
            store.load();
            assert_eq!(store.len(), 0);
            assert_eq!(store.candidate_count(), 0);
            store.remember_default("after.test", "sni-mid");
            assert_eq!(store.lookup(DEFAULT_NETWORK, "after.test"), "sni-mid");
        }

        // Fields that do not parse fall back to defaults and never earn trust.
        write(
            &path,
            "{\"domains\":{\"home|c.test\":\"sni-mid;bogus-kind;abc;xyz;?;-5\"}}",
        );
        let store = Store::new(&path);
        store.load();
        assert_eq!(store.lookup("home", "c.test"), "");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn disk_timestamps_are_clamped_and_future_verification_is_not_trusted() {
        let path = temp_path("clamp.json");
        let now = wall_seconds();
        let far_future = now + 365 * 86400;
        write(
            &path,
            &format!(
                "{{\"version\":2,\"domains\":{{{},{}}}}}",
                entry_line("home|far.test", "sni-mid", far_future, now),
                entry_line("home|skewed.test", "record-1", now + 3600, now + 10 * 86400)
            ),
        );
        let store = Store::new(&path);
        store.load();

        // A verification stamp from the future proves nothing: candidate.
        assert_eq!(store.lookup("home", "skewed.test"), "");
        assert_eq!(
            &store.probe_order("home", "skewed.test", &discord(), 0)[..2],
            ["none", "record-1"]
        );

        // The absurd expiry is cut to one TTL; saving shows what was kept.
        assert_eq!(store.lookup("home", "far.test"), "sni-mid");
        store.remember_default("trigger.test", "sni-mid");
        let saved = fs::read_to_string(&path).unwrap();
        assert!(!saved.contains(&far_future.to_string()));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn wall_clock_step_back_makes_a_winner_overdue_instead_of_immortal() {
        let store = Store::new("");
        learn(&store, "home", "blocked.test", "sni-mid", EPOCH);
        // The persisted stamp is hours ahead of the (stepped-back) clock.
        assert_eq!(
            store.probe_order("home", "blocked.test", &discord(), EPOCH - 3 * 3600)[0],
            "none"
        );
    }

    #[test]
    fn legacy_candidates_survive_saves_until_promoted_or_cancelled() {
        let path = temp_path("legacy-persist.json");
        let now = wall_seconds();
        let hello = discord();
        write(
            &path,
            &format!(
                "{{\"version\":2,\"domains\":{{{}}}}}",
                entry_line("home|old.test", "record-1", now + 3600, 0)
            ),
        );

        let is_pending = |host: &str| {
            let reloaded = Store::new(&path);
            reloaded.load();
            let order = reloaded.probe_order("home", host, &hello, now + 60);
            order.len() >= 2 && order[0] == "none" && order[1] == "record-1"
        };

        let store = Store::new(&path);
        store.load();
        assert!(is_pending("old.test"));
        // An unrelated save rewrites the file; the nomination must still be in it.
        learn(&store, "home", "other.test", "sni-mid", now);
        assert!(is_pending("old.test"));
        // A healthy baseline cancels it for good.
        store.note_baseline_healthy("home", "old.test", 0);
        assert!(!is_pending("old.test"));
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn sequential_saves_leave_the_newest_state_on_disk() {
        let path = temp_path("snapshot-order.json");
        let store = Store::new(&path);
        store.remember_default("first.test", "sni-mid");
        store.remember_default("second.test", "record-1");
        let reloaded = Store::new(&path);
        reloaded.load();
        assert_eq!(reloaded.lookup(DEFAULT_NETWORK, "first.test"), "sni-mid");
        assert_eq!(reloaded.lookup(DEFAULT_NETWORK, "second.test"), "record-1");
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn written_file_is_readable_by_the_cpp_format_rules() {
        let path = temp_path("format.json");
        let store = Store::new(&path);
        learn(
            &store,
            "nla-0123456789abcdef",
            "blocked.test",
            "sni-mid",
            wall_seconds(),
        );
        let saved = fs::read_to_string(&path).unwrap();
        assert!(saved.starts_with("{\n  \"version\": 2,\n  \"domains\": {\n"));
        assert!(saved.contains(
            "\"nla-0123456789abcdef|blocked.test\": \"sni-mid;sni-interference-likely;92;"
        ));
        let _ = fs::remove_file(&path);
        let _ = RECORD_HEADER_SIZE;
    }
}
