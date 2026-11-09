use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;
use sh_core::recovery::WorkerHealth;
use sh_net::http::{Fetch, Request, Response, host_from_url};
use sh_net::is_ip_literal;
use sh_proto::dns::{self, Query};
use tokio::sync::Notify;

/// Very short TTLs would re-query on every connection; very long ones would pin
/// an address that has since moved.
const MIN_TTL_SECONDS: u32 = 60;
const MAX_TTL_SECONDS: u32 = 3600;
const NEGATIVE_CACHE_SECONDS: u32 = 30;
/// Failures and half-answers: long enough to absorb the A/AAAA pair and an
/// app's immediate retry, short enough not to delay recovery.
const TRANSIENT_CACHE_SECONDS: u32 = 3;
const MAX_CACHE_ENTRIES: usize = 2048;
const MAX_WIRE_CACHE_ENTRIES: usize = 1024;
const MAX_CACHED_WIRE_BYTES: usize = 4096;
const WIRE_MIN_TTL_SECONDS: u32 = 10;
const WIRE_MAX_TTL_SECONDS: u32 = 3600;
const WIRE_NEGATIVE_MAX_SECONDS: u32 = 60;
const REQUEST_TIMEOUT_MS: u64 = 4000;
const MIN_REQUEST_TIMEOUT_MS: u64 = 500;
/// The Worker host's own addresses cannot be looked up through the Worker, so
/// they are refreshed out of band and served stale rather than ever failing.
const BOOTSTRAP_TTL_MS: u64 = 10 * 60 * 1000;
const BOOTSTRAP_RETRY_MS: u64 = 30 * 1000;
const BOOTSTRAP_TIMEOUT: Duration = Duration::from_millis(2000);
/// Reached by IP literal, so no DNS (and no captured UDP/53) is involved.
const BOOTSTRAP_DOH_HOST: &str = "1.1.1.1";
const NEVER_EXPIRES: u64 = u64::MAX;

/// Monotonic milliseconds; injectable for tests.
pub type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;

fn default_clock() -> Clock {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    let origin = *ORIGIN.get_or_init(Instant::now);
    Arc::new(move || 1 + origin.elapsed().as_millis() as u64)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DnsResult {
    pub v4: Vec<String>,
    pub v6: Vec<String>,
    pub ttl_seconds: u32,
    pub allow_wire_fallback: bool,
    /// RCODE the Worker reported for an empty answer (3 = NXDOMAIN).
    pub rcode: u8,
    /// The lookup failed or only half succeeded: cached for seconds, not a TTL.
    pub transient: bool,
}

impl DnsResult {
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Connect order per RFC 8305: one AAAA first, then alternating families.
    pub fn candidates(&self, limit: usize) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let (mut v6, mut v4) = (self.v6.iter(), self.v4.iter());
        let mut prefer_v6 = true;
        while out.len() < limit {
            let next = if prefer_v6 {
                v6.next().or_else(|| v4.next())
            } else {
                v4.next().or_else(|| v6.next())
            };
            let Some(address) = next else { break };
            if let Ok(ip) = address.parse() {
                out.push(ip);
            }
            prefer_v6 = !prefer_v6;
        }
        out
    }
}

struct Entry {
    result: DnsResult,
    expires_ms: u64,
}

struct WireEntry {
    response: Vec<u8>,
    stored_ms: u64,
    expires_ms: u64,
}

#[derive(Default)]
struct State {
    cache: HashMap<String, Entry>,
    wire_cache: HashMap<String, WireEntry>,
    in_flight: HashSet<String>,
}

pub struct Resolver {
    worker_host: String,
    shared_secret: String,
    connect_port: u16,
    fetcher: Arc<dyn Fetch>,
    clock: Clock,
    bootstrap_needed: bool,
    state: Mutex<State>,
    ready: Notify,
    health: WorkerHealth,
    bootstrap_next_ms: AtomicU64,
    bootstrap_busy: AtomicBool,
}

fn lowercase(value: &str) -> String {
    value.trim_end_matches('.').to_ascii_lowercase()
}

/// Only these bytes may go into `/resolve?host=`; the Worker accepts the same
/// set, so nothing needs escaping and nothing can smuggle `&`, `#` or CRLF.
fn is_resolvable_host(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host
            .bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-' || c == b'.')
}

/// Remaining lifetime of a cache entry, so a hit does not hand out the full TTL
/// again (clients would cache the record for up to twice its lifetime).
fn aged(mut result: DnsResult, expires_ms: u64, now: u64) -> DnsResult {
    if expires_ms == NEVER_EXPIRES || result.ttl_seconds == 0 {
        return result;
    }
    let remaining = expires_ms.saturating_sub(now).div_ceil(1000);
    result.ttl_seconds = remaining.min(u64::from(result.ttl_seconds)).max(1) as u32;
    result
}

fn wire_key(query: &Query) -> String {
    format!(
        "{}|{}|{}{}{}",
        query.name,
        query.qtype,
        if query.recursion_desired { "r" } else { "-" },
        if query.dnssec_ok { "d" } else { "-" },
        if query.edns_payload != 0 { "e" } else { "-" }
    )
}

/// Seconds a relayed response may be served from cache; 0 = do not cache.
fn wire_lifetime(info: &dns::ResponseInfo) -> u32 {
    if info.truncated {
        return 0;
    }
    if info.rcode == dns::RCODE_NO_ERROR && info.answers > 0 {
        return if info.has_answer_ttl && info.answer_ttl != 0 {
            info.answer_ttl
                .clamp(WIRE_MIN_TTL_SECONDS, WIRE_MAX_TTL_SECONDS)
        } else {
            0
        };
    }
    if info.rcode == dns::RCODE_NO_ERROR || info.rcode == dns::RCODE_NX_DOMAIN {
        return if info.has_authority_ttl {
            info.authority_ttl
                .clamp(WIRE_MIN_TTL_SECONDS, WIRE_NEGATIVE_MAX_SECONDS)
        } else {
            NEGATIVE_CACHE_SECONDS
        };
    }
    0
}

fn push_unique(list: &mut Vec<String>, value: String) {
    if !list.contains(&value) {
        list.push(value);
    }
}

fn string_array(body: &Value, key: &str) -> Vec<String> {
    body.get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

impl Resolver {
    /// `worker_url` empty: no Worker (system DNS mode). Bootstraps the Worker
    /// host's addresses with the system resolver; call this before packet
    /// interception starts.
    pub fn new(
        worker_url: &str,
        shared_secret: String,
        connect_port: u16,
        fetcher: Arc<dyn Fetch>,
        clock: Option<Clock>,
    ) -> Self {
        let worker_host = host_from_url(worker_url);
        let clock = clock.unwrap_or_else(default_clock);
        let resolver = Self {
            bootstrap_needed: !worker_host.is_empty() && !is_ip_literal(&lowercase(&worker_host)),
            worker_host,
            shared_secret,
            connect_port,
            fetcher,
            clock,
            state: Mutex::default(),
            ready: Notify::new(),
            health: WorkerHealth::default(),
            bootstrap_next_ms: AtomicU64::new(0),
            bootstrap_busy: AtomicBool::new(false),
        };
        if resolver.worker_host.is_empty() {
            if !worker_url.is_empty() {
                tracing::warn!(
                    "DNS: Worker URL cozumlenemedi ({worker_url}), sistem DNS kullanilacak"
                );
            }
            return resolver;
        }
        if resolver.bootstrap_needed {
            match resolver.lookup_via_system() {
                Some(bootstrap) => {
                    tracing::debug!(
                        "DNS bootstrap: Worker -> {} A, {} AAAA",
                        bootstrap.v4.len(),
                        bootstrap.v6.len()
                    );
                    resolver.lock().cache.insert(
                        lowercase(&resolver.worker_host),
                        Entry {
                            result: bootstrap,
                            expires_ms: NEVER_EXPIRES,
                        },
                    );
                    resolver
                        .bootstrap_next_ms
                        .store(resolver.now() + BOOTSTRAP_TTL_MS, Ordering::Relaxed);
                }
                None => tracing::warn!(
                    "DNS bootstrap: Worker adresi simdi cozulemedi; sonra tekrar denenecek"
                ),
            }
        }
        resolver
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    /// The resolver's clock: deadlines passed to `resolve`/`query_wire` must be
    /// on this scale.
    pub fn now_ms(&self) -> u64 {
        self.now()
    }

    pub fn worker_host(&self) -> &str {
        &self.worker_host
    }

    pub fn is_bootstrap_host(&self, host: &str) -> bool {
        !self.worker_host.is_empty() && lowercase(host) == lowercase(&self.worker_host)
    }

    pub fn worker_unavailable(&self) -> bool {
        self.health.unavailable()
    }

    pub fn cache_len(&self) -> usize {
        self.lock().cache.len()
    }

    pub fn wire_cache_len(&self) -> usize {
        self.lock().wire_cache.len()
    }

    /// The pinned Worker addresses (for the tunnel and HTTPS connect override).
    pub fn worker_addresses(&self) -> Vec<IpAddr> {
        let host = lowercase(&self.worker_host);
        if is_ip_literal(&host) {
            return host.parse().into_iter().collect();
        }
        self.lock()
            .cache
            .get(&host)
            .map(|e| e.result.candidates(16))
            .unwrap_or_default()
    }

    /// WinHTTP-style per-phase timeout that shrinks toward the deadline.
    fn request_timeout(&self, deadline_ms: u64) -> Duration {
        if deadline_ms == 0 {
            return Duration::from_millis(REQUEST_TIMEOUT_MS);
        }
        let left = deadline_ms.saturating_sub(self.now());
        Duration::from_millis(left.clamp(MIN_REQUEST_TIMEOUT_MS, REQUEST_TIMEOUT_MS))
    }

    fn lookup_via_system(&self) -> Option<DnsResult> {
        let mut out = DnsResult {
            ttl_seconds: (BOOTSTRAP_TTL_MS / 1000) as u32,
            ..DnsResult::default()
        };
        for address in (self.worker_host.as_str(), 443).to_socket_addrs().ok()? {
            match address.ip() {
                IpAddr::V4(v4) => push_unique(&mut out.v4, v4.to_string()),
                IpAddr::V6(v6) => push_unique(&mut out.v6, v6.to_string()),
            }
        }
        (!out.is_empty()).then_some(out)
    }

    /// Resolves the Worker host through Cloudflare's JSON DoH reached by IP
    /// literal: getaddrinfo cannot be used once interception is active (its
    /// query would be answered from the very cache being refreshed). No secret
    /// is sent: this request goes to 1.1.1.1, not to the Worker.
    async fn lookup_via_doh_by_address(&self) -> Option<DnsResult> {
        let name = lowercase(&self.worker_host);
        if !is_resolvable_host(&name) {
            return None;
        }
        let mut out = DnsResult {
            ttl_seconds: (BOOTSTRAP_TTL_MS / 1000) as u32,
            ..DnsResult::default()
        };
        for record_type in ["A", "AAAA"] {
            let mut request = Request::get(
                BOOTSTRAP_DOH_HOST,
                format!("/dns-query?name={name}&type={record_type}"),
            )
            .header("Accept", "application/dns-json");
            request.timeout = BOOTSTRAP_TIMEOUT;
            let response = self.fetcher.fetch(request).await;
            if !response.ok() {
                continue;
            }
            let Ok(body) = serde_json::from_slice::<Value>(&response.body) else {
                continue;
            };
            let answers = body
                .get("Answer")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            for data in answers
                .iter()
                .filter_map(|a| a.get("data").and_then(Value::as_str))
            {
                // CNAME targets and the like are skipped.
                match data.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) if record_type == "A" => {
                        push_unique(&mut out.v4, data.to_owned())
                    }
                    Ok(IpAddr::V6(_)) if record_type == "AAAA" => {
                        push_unique(&mut out.v6, data.to_owned())
                    }
                    _ => {}
                }
            }
        }
        (!out.is_empty()).then_some(out)
    }

    fn has_bootstrap(&self) -> bool {
        !self.bootstrap_needed
            || self
                .lock()
                .cache
                .get(&lowercase(&self.worker_host))
                .is_some_and(|e| !e.result.is_empty())
    }

    /// Rate-limited lazy (re)fetch of the Worker host's addresses; a failed
    /// refresh keeps serving the previous ones.
    async fn refresh_bootstrap(&self) {
        if !self.bootstrap_needed || self.now() < self.bootstrap_next_ms.load(Ordering::Relaxed) {
            return;
        }
        if self.bootstrap_busy.swap(true, Ordering::SeqCst) {
            return;
        }
        let refreshed = match self.lookup_via_doh_by_address().await {
            Some(fresh) => {
                tracing::debug!(
                    "DNS bootstrap yenilendi: {} A, {} AAAA",
                    fresh.v4.len(),
                    fresh.v6.len()
                );
                self.lock().cache.insert(
                    lowercase(&self.worker_host),
                    Entry {
                        result: fresh,
                        expires_ms: NEVER_EXPIRES,
                    },
                );
                true
            }
            None => false,
        };
        self.bootstrap_next_ms.store(
            self.now()
                + if refreshed {
                    BOOTSTRAP_TTL_MS
                } else {
                    BOOTSTRAP_RETRY_MS
                },
            Ordering::Relaxed,
        );
        self.bootstrap_busy.store(false, Ordering::SeqCst);
    }

    /// Gate before every Worker call: refreshes the bootstrap, and refuses when
    /// there is nothing to connect to (offline: not counted against the
    /// Worker's health), a 429 back-off runs, or the deadline has passed.
    async fn prepare_worker_call(&self, deadline_ms: u64) -> bool {
        if deadline_ms != 0 && self.now() >= deadline_ms {
            return false;
        }
        self.refresh_bootstrap().await;
        self.has_bootstrap() && !self.health.backing_off(self.now())
    }

    fn worker_request(&self, method: &'static str, path: String, deadline_ms: u64) -> Request {
        let mut request = Request::get(self.worker_host.clone(), path);
        request.method = method;
        request.timeout = self.request_timeout(deadline_ms);
        if self.connect_port != 0 {
            request.connect = Some((self.worker_addresses(), self.connect_port));
        }
        if !self.shared_secret.is_empty() {
            request.headers.push((
                "Authorization".into(),
                format!("Bearer {}", self.shared_secret),
            ));
        }
        request
    }

    fn observe(&self, response: &Response) {
        self.health
            .observe(response.status, self.now(), response.retry_after_seconds);
    }

    async fn query(&self, host: &str, deadline_ms: u64) -> DnsResult {
        let mut result = DnsResult::default();
        if self.worker_host.is_empty() {
            return result;
        }
        // '_' (service labels) and anything outside [a-z0-9.-] is not a
        // /resolve host; the raw wire path handles any name.
        if !is_resolvable_host(host) {
            result.allow_wire_fallback = true;
            return result;
        }
        if !self.prepare_worker_call(deadline_ms).await {
            result.transient = true;
            return result;
        }
        let response = self
            .fetcher
            .fetch(self.worker_request("GET", format!("/resolve?host={host}"), deadline_ms))
            .await;
        self.observe(&response);

        match response.status {
            401 | 403 => {
                tracing::error!(
                    "DNS: Worker kimlik dogrulamasi reddetti (HTTP {}). --redeploy ile worker'i guncelleyin.",
                    response.status
                );
                result.transient = true;
                return result;
            }
            429 => {
                tracing::warn!("DNS: Worker rate limit (HTTP 429)");
                result.transient = true;
                return result;
            }
            // Workers deployed before the rcode field answered 404 for NXDOMAIN,
            // SERVFAIL and empty answers alike: ask the wire path.
            404 => {
                result.allow_wire_fallback = true;
                return result;
            }
            _ if !response.ok() => {
                tracing::warn!("DNS: /resolve HTTP {} ({host})", response.status);
                result.transient = true;
                return result;
            }
            _ => {}
        }

        let body = serde_json::from_slice::<Value>(&response.body).unwrap_or(Value::Null);
        result.v4 = string_array(&body, "a");
        result.v6 = string_array(&body, "aaaa");
        if result.is_empty() {
            // Workers deployed before the multi-address response shape.
            if let Some(legacy) = body
                .get("ip")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
            {
                result.v4.push(legacy.to_owned());
            }
        }
        // Never trust the endpoint to return something connectable.
        result.v4.retain(|a| is_ip_literal(a));
        result.v6.retain(|a| is_ip_literal(a));

        match body.get("rcode").and_then(Value::as_i64) {
            Some(rcode) if rcode >= 0 => result.rcode = rcode.min(15) as u8,
            _ => result.allow_wire_fallback = result.is_empty(), // old shape: no rcode to trust
        }
        result.transient = body
            .get("partial")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let ttl = body
            .get("ttl")
            .and_then(Value::as_i64)
            .unwrap_or(i64::from(MIN_TTL_SECONDS));
        result.ttl_seconds =
            ttl.clamp(i64::from(MIN_TTL_SECONDS), i64::from(MAX_TTL_SECONDS)) as u32;
        if result.transient {
            result.ttl_seconds = result.ttl_seconds.min(TRANSIENT_CACHE_SECONDS);
        }
        if result.is_empty() {
            match result.rcode {
                dns::RCODE_NX_DOMAIN => tracing::debug!("DNS: {host} NXDOMAIN"),
                dns::RCODE_NO_ERROR => tracing::debug!("DNS: {host} icin adres yok (NODATA)"),
                rcode => tracing::warn!("DNS: {host} icin adres yok (rcode {rcode})"),
            }
        }
        result
    }

    /// Cached lookup. An empty result means the Worker could not answer; the
    /// caller falls back to the system resolver. `deadline_ms` (clock scale,
    /// 0 = none) bounds the network time.
    pub async fn resolve(&self, host: &str, deadline_ms: u64) -> DnsResult {
        let key = lowercase(host);
        if key.is_empty() {
            return DnsResult::default();
        }
        // An address literal needs no lookup.
        if let Ok(ip) = key.parse::<IpAddr>() {
            let mut direct = DnsResult::default();
            match ip {
                IpAddr::V4(_) => direct.v4.push(key),
                IpAddr::V6(_) => direct.v6.push(key),
            }
            return direct;
        }

        // A and AAAA for the same name usually arrive together: only one caller
        // asks the Worker while the others wait for its shared result.
        loop {
            let notified = self.ready.notified();
            let mut notified = std::pin::pin!(notified);
            notified.as_mut().enable();
            {
                let mut state = self.lock();
                let now = self.now();
                if let Some(entry) = state.cache.get(&key).filter(|e| e.expires_ms > now) {
                    return aged(entry.result.clone(), entry.expires_ms, now);
                }
                if key == lowercase(&self.worker_host) {
                    // No bootstrap address yet: SERVFAIL, not NODATA.
                    return DnsResult {
                        transient: true,
                        ..DnsResult::default()
                    };
                }
                if state.in_flight.insert(key.clone()) {
                    break;
                }
            }
            notified.await;
        }

        let result = self.query(&key, deadline_ms).await;
        {
            let mut state = self.lock();
            if !state.cache.contains_key(&key) && state.cache.len() >= MAX_CACHE_ENTRIES {
                // Evict the soonest-to-expire entry, never the bootstrap one: a
                // full clear would recurse the Worker's own lookup through DNS.
                let bootstrap = lowercase(&self.worker_host);
                let victim = state
                    .cache
                    .iter()
                    .filter(|(k, _)| **k != bootstrap)
                    .min_by_key(|(_, e)| e.expires_ms)
                    .map(|(k, _)| k.clone());
                if let Some(victim) = victim {
                    state.cache.remove(&victim);
                }
            }
            let lifetime = if result.transient {
                TRANSIENT_CACHE_SECONDS
            } else if result.is_empty() {
                NEGATIVE_CACHE_SECONDS
            } else {
                result.ttl_seconds
            };
            let expires_ms = self.now() + u64::from(lifetime) * 1000;
            state.cache.insert(
                key.clone(),
                Entry {
                    result: result.clone(),
                    expires_ms,
                },
            );
            state.in_flight.remove(&key);
        }
        self.ready.notify_waiters();
        result
    }

    /// Authenticated DoH wire relay; the exact response is preserved so every
    /// record type works. Cached for its TTL; the reply carries the query's ID.
    pub async fn query_wire(&self, message: &[u8], deadline_ms: u64) -> Vec<u8> {
        let mut parsed = Query::default();
        if !dns::parse_query(message, &mut parsed) || self.worker_host.is_empty() {
            return Vec::new();
        }
        // A lookup of the Worker host itself is answered from the bootstrap
        // cache instead of recursively asking the Worker about itself.
        if self.is_bootstrap_host(&parsed.name) {
            let bootstrap = Box::pin(self.resolve(&parsed.name, 0)).await;
            let addresses = match parsed.qtype {
                dns::TYPE_A => bootstrap.v4.clone(),
                dns::TYPE_AAAA => bootstrap.v6.clone(),
                _ => Vec::new(),
            };
            let ttl = if bootstrap.ttl_seconds == 0 {
                MIN_TTL_SECONDS
            } else {
                bootstrap.ttl_seconds
            };
            return dns::build_response(&parsed, &addresses, ttl, bootstrap.is_empty(), 0);
        }

        // Cache first: an HTTPS/SVCB burst per page load would otherwise trip
        // the Worker's rate limit.
        let key = wire_key(&parsed);
        {
            let mut state = self.lock();
            let now = self.now();
            if let Some(entry) = state.wire_cache.get(&key) {
                if entry.expires_ms > now {
                    let mut cached = entry.response.clone();
                    let age = ((now - entry.stored_ms) / 1000).min(u64::from(WIRE_MAX_TTL_SECONDS))
                        as u32;
                    drop(state);
                    dns::set_id(&mut cached, parsed.id);
                    dns::age_ttls(&mut cached, age);
                    return cached;
                }
                state.wire_cache.remove(&key);
            }
        }

        if !self.prepare_worker_call(deadline_ms).await {
            return Vec::new();
        }
        let mut request = self.worker_request("POST", "/dns-query".into(), deadline_ms);
        request
            .headers
            .push(("Accept".into(), "application/dns-message".into()));
        request
            .headers
            .push(("Content-Type".into(), "application/dns-message".into()));
        request.body = message.to_vec();
        let response = self.fetcher.fetch(request).await;
        self.observe(&response);
        if response.status == 401 || response.status == 403 {
            tracing::error!(
                "DNS wire: Worker kimlik dogrulamasi reddetti (HTTP {})",
                response.status
            );
            return Vec::new();
        }
        if !response.ok() || response.body.len() < 12 || response.body.len() > 65535 {
            tracing::warn!("DNS wire: Worker HTTP {}", response.status);
            return Vec::new();
        }
        let mut answer = response.body;
        // The relay must answer *this* question; never pass anything else on.
        let Some(info) = dns::inspect_response(&answer)
            .filter(|i| i.response && dns::echoes_question(&answer, &parsed))
        else {
            tracing::warn!(
                "DNS wire: Worker gecersiz veya eslesmeyen cevap dondurdu ({})",
                parsed.name
            );
            return Vec::new();
        };
        dns::set_id(&mut answer, parsed.id);

        let lifetime = wire_lifetime(&info);
        // Normal answers are a few hundred bytes; caching rare 64 KiB ones
        // would let 1024 entries pin ~64 MiB.
        if lifetime != 0 && answer.len() <= MAX_CACHED_WIRE_BYTES {
            let mut state = self.lock();
            if !state.wire_cache.contains_key(&key)
                && state.wire_cache.len() >= MAX_WIRE_CACHE_ENTRIES
            {
                let victim = state
                    .wire_cache
                    .iter()
                    .min_by_key(|(_, e)| e.expires_ms)
                    .map(|(k, _)| k.clone());
                if let Some(victim) = victim {
                    state.wire_cache.remove(&victim);
                }
            }
            let now = self.now();
            state.wire_cache.insert(
                key,
                WireEntry {
                    response: answer.clone(),
                    stored_ms: now,
                    expires_ms: now + u64::from(lifetime) * 1000,
                },
            );
        }
        answer
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sh_net::http::FetchFuture;
    use sh_proto::testing::dns_query;
    use std::sync::atomic::AtomicI32;

    pub type Handler = Box<dyn Fn(&Request) -> Response + Send + Sync>;

    pub fn status(code: i32, retry_after_seconds: u32) -> Response {
        Response {
            status: code,
            body: Vec::new(),
            retry_after_seconds,
        }
    }

    pub fn ok(body: impl Into<Vec<u8>>) -> Response {
        Response {
            status: 200,
            body: body.into(),
            retry_after_seconds: 0,
        }
    }

    /// What the DoH upstream would say to the posted query.
    pub fn upstream_answer(
        request: &Request,
        addresses: &[&str],
        ttl: u32,
        failed: bool,
        rcode: u8,
    ) -> Response {
        let mut query = Query::default();
        if !dns::parse_query(&request.body, &mut query) {
            return status(400, 0);
        }
        ok(dns::build_response(&query, addresses, ttl, failed, rcode))
    }

    /// Fake Worker: no network, a hand-driven clock.
    pub struct FakeWorker {
        pub seen: Mutex<Vec<Request>>,
        pub resolve_calls: AtomicI32,
        pub wire_calls: AtomicI32,
        pub bootstrap_calls: AtomicI32,
        pub clock: Arc<AtomicU64>,
        pub resolve: Mutex<Handler>,
        pub wire: Mutex<Handler>,
        pub bootstrap: Mutex<Handler>,
        pub delay: Mutex<Duration>,
    }

    impl FakeWorker {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::default(),
                resolve_calls: AtomicI32::new(0),
                wire_calls: AtomicI32::new(0),
                bootstrap_calls: AtomicI32::new(0),
                clock: Arc::new(AtomicU64::new(1_000_000)),
                resolve: Mutex::new(Box::new(|_| {
                    ok(r#"{"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0}"#)
                })),
                wire: Mutex::new(Box::new(|r| {
                    upstream_answer(r, &["203.0.113.9"], 120, false, 0)
                })),
                bootstrap: Mutex::new(Box::new(|_| status(-1, 0))),
                delay: Mutex::new(Duration::ZERO),
            })
        }

        pub fn set(
            slot: &Mutex<Handler>,
            handler: impl Fn(&Request) -> Response + Send + Sync + 'static,
        ) {
            *slot.lock().unwrap() = Box::new(handler);
        }

        pub fn advance(&self, ms: u64) {
            self.clock.fetch_add(ms, Ordering::SeqCst);
        }

        pub fn calls(&self) -> (i32, i32) {
            (
                self.resolve_calls.load(Ordering::SeqCst),
                self.wire_calls.load(Ordering::SeqCst),
            )
        }

        pub fn clock(&self) -> Clock {
            let clock = self.clock.clone();
            Arc::new(move || clock.load(Ordering::SeqCst))
        }
    }

    impl Fetch for FakeWorker {
        fn fetch(&self, request: Request) -> FetchFuture<'_> {
            Box::pin(async move {
                let delay = *self.delay.lock().unwrap();
                if !delay.is_zero() {
                    tokio::time::sleep(delay).await;
                }
                self.seen.lock().unwrap().push(request.clone());
                if request.host == "1.1.1.1" {
                    self.bootstrap_calls.fetch_add(1, Ordering::SeqCst);
                    return (self.bootstrap.lock().unwrap())(&request);
                }
                if request.path == "/dns-query" {
                    self.wire_calls.fetch_add(1, Ordering::SeqCst);
                    return (self.wire.lock().unwrap())(&request);
                }
                self.resolve_calls.fetch_add(1, Ordering::SeqCst);
                (self.resolve.lock().unwrap())(&request)
            })
        }
    }

    /// "localhost" always resolves, so the bootstrap cache is populated by the
    /// constructor exactly like a normal start-up.
    pub const WORKER_URL: &str = "https://localhost";

    pub fn resolver(worker: &Arc<FakeWorker>) -> Resolver {
        Resolver::new(
            WORKER_URL,
            "secret".into(),
            0,
            worker.clone(),
            Some(worker.clock()),
        )
    }

    fn read16(data: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([data[at], data[at + 1]])
    }

    #[tokio::test]
    async fn caches_results_and_ages_the_ttl() {
        let worker = FakeWorker::new();
        let resolver = resolver(&worker);
        let first = resolver.resolve("Example.COM.", 0).await;
        assert_eq!(first.v4.len(), 1);
        assert_eq!(first.ttl_seconds, 300);
        assert_eq!(worker.calls().0, 1);
        {
            let seen = worker.seen.lock().unwrap();
            let last = seen.last().unwrap();
            assert_eq!(last.path, "/resolve?host=example.com");
            assert_eq!(
                last.headers[0],
                ("Authorization".into(), "Bearer secret".into())
            );
        }
        worker.advance(100_000);
        let cached = resolver.resolve("example.com", 0).await;
        assert_eq!(worker.calls().0, 1);
        assert_eq!(cached.ttl_seconds, 200); // 300 s minus 100 s in the cache
        worker.advance(201_000);
        resolver.resolve("example.com", 0).await;
        assert_eq!(worker.calls().0, 2);
    }

    #[tokio::test]
    async fn negative_caches_nxdomain_briefly() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| {
            ok(r#"{"host":"nope.example","a":[],"aaaa":[],"ttl":60,"rcode":3}"#)
        });
        let resolver = resolver(&worker);
        let result = resolver.resolve("nope.example", 0).await;
        assert!(result.is_empty());
        assert_eq!(result.rcode, dns::RCODE_NX_DOMAIN);
        assert!(!result.transient);
        assert!(!result.allow_wire_fallback);
        worker.advance(29_000);
        assert_eq!(resolver.resolve("nope.example", 0).await.rcode, 3);
        assert_eq!(worker.calls().0, 1);
        worker.advance(2_000);
        resolver.resolve("nope.example", 0).await;
        assert_eq!(worker.calls().0, 2);
    }

    #[tokio::test]
    async fn caches_half_failed_answers_only_for_a_moment() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| {
            ok(r#"{"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":3600,"rcode":0,"partial":true}"#)
        });
        let resolver = resolver(&worker);
        let partial = resolver.resolve("half.example", 0).await;
        assert!(partial.transient);
        assert!(partial.ttl_seconds <= 5);
        worker.advance(2_000);
        resolver.resolve("half.example", 0).await;
        assert_eq!(worker.calls().0, 1);
        worker.advance(2_000);
        resolver.resolve("half.example", 0).await;
        assert_eq!(worker.calls().0, 2);
    }

    #[tokio::test]
    async fn falls_back_to_wire_for_old_workers_and_unsafe_names() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| status(404, 0));
        let resolver = resolver(&worker);
        let legacy = resolver.resolve("old-worker.example", 0).await;
        assert!(legacy.is_empty() && legacy.allow_wire_fallback);
        let before = worker.calls().0;
        for bad in [
            "a&b=c.example",
            "evil.example/../x",
            "with space.example",
            "under_score.example",
            "x.example\r\nHost: y",
            "h?x=1.example",
        ] {
            let result = resolver.resolve(bad, 0).await;
            assert!(result.is_empty() && result.allow_wire_fallback, "{bad}");
        }
        assert_eq!(worker.calls().0, before);
    }

    #[tokio::test]
    async fn backs_off_on_rate_limit_without_counting_it_as_failure() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| status(429, 10));
        let resolver = resolver(&worker);
        assert!(resolver.resolve("a.example", 0).await.transient);
        assert_eq!(worker.calls().0, 1);
        // During the Retry-After window nothing else is sent to the Worker.
        assert!(resolver.resolve("b.example", 0).await.transient);
        assert!(
            resolver
                .query_wire(&dns_query("c.example", 16).build(), 0)
                .await
                .is_empty()
        );
        assert_eq!(worker.calls(), (1, 0));
        worker.advance(11_000);
        resolver.resolve("d.example", 0).await;
        assert_eq!(worker.calls().0, 2);
        for i in 0..20 {
            worker.advance(11_000);
            resolver.resolve(&format!("e{i}.example"), 0).await;
        }
        assert!(!resolver.worker_unavailable());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn shares_one_lookup_between_concurrent_callers() {
        let worker = FakeWorker::new();
        *worker.delay.lock().unwrap() = Duration::from_millis(150);
        FakeWorker::set(&worker.resolve, |_| {
            ok(r#"{"host":"x","a":["203.0.113.5"],"aaaa":["2001:db8::5"],"ttl":300,"rcode":0}"#)
        });
        let resolver = Arc::new(resolver(&worker));
        let tasks: Vec<_> = (0..4)
            .map(|_| {
                let resolver = resolver.clone();
                tokio::spawn(async move { !resolver.resolve("shared.example", 0).await.is_empty() })
            })
            .collect();
        let mut answered = 0;
        for task in tasks {
            answered += i32::from(task.await.unwrap());
        }
        assert_eq!(answered, 4);
        assert_eq!(worker.calls().0, 1);
    }

    #[tokio::test]
    async fn evicts_old_entries_but_never_the_bootstrap_address() {
        let worker = FakeWorker::new();
        let resolver = resolver(&worker);
        assert!(!resolver.resolve("localhost", 0).await.is_empty());
        for i in 0..2100 {
            worker.advance(1);
            resolver.resolve(&format!("h{i}.example"), 0).await;
        }
        assert_eq!(worker.calls().0, 2100);
        assert!(resolver.cache_len() <= 2048);
        assert!(!resolver.resolve("localhost", 0).await.is_empty());
        assert_eq!(worker.calls().0, 2100); // still served from the bootstrap entry
    }

    #[tokio::test]
    async fn caches_wire_responses_rewrites_id_and_ages_ttls() {
        let worker = FakeWorker::new();
        let resolver = resolver(&worker);
        let one = resolver
            .query_wire(
                &dns_query("www.example.com", dns::TYPE_A).id(0x1111).build(),
                0,
            )
            .await;
        assert!(!one.is_empty());
        assert_eq!(read16(&one, 0), 0x1111);
        {
            let seen = worker.seen.lock().unwrap();
            assert!(
                seen.last()
                    .unwrap()
                    .headers
                    .iter()
                    .any(|(name, _)| name == "Authorization")
            );
            assert_eq!(seen.last().unwrap().method, "POST");
        }
        worker.advance(30_000);
        let two = resolver
            .query_wire(
                &dns_query("WWW.Example.com", dns::TYPE_A).id(0x2222).build(),
                0,
            )
            .await;
        assert_eq!(worker.calls().1, 1);
        assert_eq!(read16(&two, 0), 0x2222); // each client sees its own ID
        assert_eq!(dns::inspect_response(&two).unwrap().answer_ttl, 90);

        resolver
            .query_wire(
                &dns_query("www.example.com", dns::TYPE_AAAA)
                    .id(0x3333)
                    .build(),
                0,
            )
            .await;
        assert_eq!(worker.calls().1, 2); // a different type is a different key
        worker.advance(91_000);
        resolver
            .query_wire(
                &dns_query("www.example.com", dns::TYPE_A).id(0x1111).build(),
                0,
            )
            .await;
        assert_eq!(worker.calls().1, 3);
    }

    #[tokio::test]
    async fn wire_cache_keeps_negatives_short_and_never_caches_errors() {
        let worker = FakeWorker::new();
        let resolver = resolver(&worker);
        FakeWorker::set(&worker.wire, |r| {
            upstream_answer(r, &[], 0, false, dns::RCODE_NX_DOMAIN)
        });
        let nx = dns_query("missing.example", dns::TYPE_A).build();
        resolver.query_wire(&nx, 0).await;
        worker.advance(29_000);
        resolver.query_wire(&nx, 0).await;
        assert_eq!(worker.calls().1, 1);
        worker.advance(2_000);
        resolver.query_wire(&nx, 0).await;
        assert_eq!(worker.calls().1, 2);

        // SERVFAIL is never remembered.
        FakeWorker::set(&worker.wire, |r| upstream_answer(r, &[], 0, true, 0));
        let servfail = dns_query("broken.example", dns::TYPE_A).build();
        let before = worker.calls().1;
        resolver.query_wire(&servfail, 0).await;
        resolver.query_wire(&servfail, 0).await;
        assert_eq!(worker.calls().1, before + 2);
    }

    #[tokio::test]
    async fn wire_rejects_answers_to_a_different_question() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.wire, |_| {
            let mut other = Query::default();
            dns::parse_query(&dns_query("other.example", dns::TYPE_A).build(), &mut other);
            ok(dns::build_response(&other, &["203.0.113.9"], 60, false, 0))
        });
        let resolver = resolver(&worker);
        assert!(
            resolver
                .query_wire(&dns_query("asked.example", dns::TYPE_A).build(), 0)
                .await
                .is_empty()
        );
        assert_eq!(resolver.wire_cache_len(), 0);
    }

    #[tokio::test]
    async fn retries_bootstrap_lazily_after_an_offline_start() {
        let worker = FakeWorker::new();
        let host = "splithello-bootstrap-test.invalid";
        let resolver = Resolver::new(
            &format!("https://{host}"),
            "secret".into(),
            0,
            worker.clone(),
            Some(worker.clock()),
        );
        // A network that rewrites NXDOMAIN makes the start-up lookup succeed.
        if !resolver.resolve(host, 0).await.is_empty() {
            return;
        }
        // Offline: no connection attempt to the Worker, and not a health failure.
        let offline = resolver.resolve("first.example", 0).await;
        assert!(offline.is_empty() && offline.transient);
        assert_eq!(worker.calls().0, 0);
        let attempts = worker.bootstrap_calls.load(Ordering::SeqCst);
        assert!(attempts >= 1);
        resolver.resolve("second.example", 0).await;
        assert_eq!(worker.bootstrap_calls.load(Ordering::SeqCst), attempts); // rate limited
        assert!(!resolver.worker_unavailable());

        // Network is back: the next call after the retry interval goes through.
        FakeWorker::set(&worker.bootstrap, |request| {
            if request.path.contains("type=AAAA") {
                return ok(r#"{"Status":0}"#);
            }
            ok(
                r#"{"Status":0,"Answer":[{"name":"splithello-bootstrap-test.invalid","type":1,"TTL":60,"data":"203.0.113.77"}]}"#,
            )
        });
        worker.advance(31_000);
        assert!(!resolver.resolve("third.example", 0).await.is_empty());
        assert_eq!(worker.calls().0, 1);
        let bootstrap = resolver.resolve(host, 0).await;
        assert_eq!(bootstrap.v4, ["203.0.113.77"]);
        // The secret goes to the Worker only, never to the bootstrap resolver.
        for request in worker
            .seen
            .lock()
            .unwrap()
            .iter()
            .filter(|r| r.host == "1.1.1.1")
        {
            assert!(
                !request
                    .headers
                    .iter()
                    .any(|(name, _)| name == "Authorization")
            );
        }
    }

    #[test]
    fn candidates_alternate_families_starting_with_v6() {
        let result = DnsResult {
            v4: vec!["1.1.1.1".into(), "1.1.1.2".into()],
            v6: vec!["2001:db8::1".into()],
            ..DnsResult::default()
        };
        let order: Vec<String> = result
            .candidates(8)
            .iter()
            .map(ToString::to_string)
            .collect();
        assert_eq!(order, ["2001:db8::1", "1.1.1.1", "1.1.1.2"]);
    }
}
