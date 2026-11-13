use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use serde_json::Value;
use sh_core::config::DNS_PROVIDERS;
use sh_core::recovery::WorkerHealth;
use sh_net::http::{Fetch, Request, Response, host_from_url};
use sh_net::is_ip_literal;
use sh_proto::dns::{self, Query};
use tokio::sync::Notify;

/// Very short TTLs would re-query on every connection; very long ones would pin
/// an address that has since moved.
const MIN_TTL_SECONDS: u32 = 60;
const MAX_TTL_SECONDS: u32 = 3600;
const MAX_CNAMES: usize = 16;
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
/// Short enough that the next upstream still fits in the proxy's 8 s budget.
const DIRECT_TIMEOUT: Duration = Duration::from_millis(2000);
/// Upstream index of the Worker: always asked last, after `DNS_PROVIDERS`.
const WORKER: usize = DNS_PROVIDERS.len();
/// A failed upstream is skipped this long so later queries do not pay its timeout.
const UPSTREAM_COOLDOWN_MS: u64 = 60 * 1000;
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
    /// RCODE the upstream reported for an empty answer (3 = NXDOMAIN).
    pub rcode: u8,
    /// The lookup failed or only half succeeded: cached for seconds, not a TTL.
    pub transient: bool,
    /// Names the answer was reached through (CNAME chain); empty from a
    /// Worker deployed before it reported them.
    pub cnames: Vec<String>,
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
    /// Index into `DNS_PROVIDERS` asked first.
    preferred: usize,
    /// Per upstream index: clock time until which it is skipped.
    cooldown_until: [AtomicU64; WORKER + 1],
}

/// Transport error, timeout or 5xx: the upstream is down, not the name.
fn is_failure(status: i32) -> bool {
    !(0..500).contains(&status)
}

fn upstream_name(index: usize) -> &'static str {
    DNS_PROVIDERS.get(index).map_or("Worker", |p| p.name)
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
    /// `worker_url` empty: no Worker, the public resolvers only. `preferred`
    /// indexes `DNS_PROVIDERS` (out of range: the first). Bootstraps the
    /// Worker host's addresses with the system resolver; call this before
    /// packet interception starts.
    pub fn new(
        worker_url: &str,
        shared_secret: String,
        connect_port: u16,
        fetcher: Arc<dyn Fetch>,
        preferred: usize,
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
            preferred: if preferred < WORKER { preferred } else { 0 },
            cooldown_until: Default::default(),
        };
        if resolver.worker_host.is_empty() {
            if !worker_url.is_empty() {
                tracing::warn!(
                    "DNS: Worker URL cozumlenemedi ({worker_url}), Worker kullanilmayacak"
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

    /// One uncached lookup through the upstream chain; true once one answers.
    pub async fn probe(&self) -> bool {
        self.query("example.com", 0).await;
        !self.health.unavailable()
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

    /// One record type from a public JSON DoH resolver: the body, or the HTTP
    /// status when it gave no usable answer (a SERVFAIL body counts as 200).
    /// No secret is sent: only the Worker gets it.
    async fn doh_json(
        &self,
        index: usize,
        name: &str,
        record_type: &str,
        timeout: Duration,
    ) -> Result<Value, i32> {
        let provider = &DNS_PROVIDERS[index];
        let mut request = Request::get(
            provider.host,
            format!("{}?name={name}&type={record_type}", provider.json_path),
        )
        .header("Accept", "application/dns-json");
        request.timeout = timeout;
        let response = self.fetcher.fetch(request).await;
        if !response.ok() {
            return Err(response.status);
        }
        match serde_json::from_slice::<Value>(&response.body) {
            Ok(body)
                if body.get("Status").and_then(Value::as_i64)
                    != Some(i64::from(dns::RCODE_SERV_FAIL)) =>
            {
                Ok(body)
            }
            _ => Err(response.status),
        }
    }

    /// A and AAAA from one public resolver, merged the way the Worker's
    /// `/resolve` does. Err(true): the resolver is down.
    async fn query_direct(
        &self,
        index: usize,
        host: &str,
        deadline_ms: u64,
    ) -> Result<DnsResult, bool> {
        let timeout = self.request_timeout(deadline_ms).min(DIRECT_TIMEOUT);
        let (v4, v6) = tokio::join!(
            self.doh_json(index, host, "A", timeout),
            self.doh_json(index, host, "AAAA", timeout)
        );
        if let (Err(a), Err(b)) = (&v4, &v6) {
            return Err(is_failure(*a) && is_failure(*b));
        }
        let mut result = DnsResult {
            transient: v4.is_err() != v6.is_err(),
            ..DnsResult::default()
        };
        let mut ttl: Option<i64> = None;
        for (body, wanted) in [(&v4, 1), (&v6, 28)] {
            let Ok(body) = body else { continue };
            for answer in body
                .get("Answer")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                let data = answer.get("data").and_then(Value::as_str).unwrap_or("");
                let kind = answer.get("type").and_then(Value::as_i64);
                if kind == Some(5) && !data.is_empty() {
                    push_unique(&mut result.cnames, lowercase(data));
                    continue;
                }
                // Never trust the endpoint to return something connectable.
                match data.parse::<IpAddr>() {
                    Ok(IpAddr::V4(_)) if kind == Some(1) && wanted == 1 => {
                        push_unique(&mut result.v4, data.to_owned())
                    }
                    Ok(IpAddr::V6(_)) if kind == Some(28) && wanted == 28 => {
                        push_unique(&mut result.v6, data.to_owned())
                    }
                    _ => continue,
                }
                if let Some(seconds) = answer.get("TTL").and_then(Value::as_i64).filter(|t| *t > 0)
                {
                    ttl = Some(ttl.map_or(seconds, |t| t.min(seconds)));
                }
            }
        }
        result.cnames.truncate(MAX_CNAMES);
        if result.is_empty() {
            // A family that errored says nothing about the name.
            let answered = v4.as_ref().or(v6.as_ref()).ok();
            let status = answered
                .and_then(|b| b.get("Status"))
                .and_then(Value::as_i64);
            result.rcode = status.unwrap_or(0).clamp(0, 15) as u8;
        }
        result.ttl_seconds =
            ttl.unwrap_or(i64::from(MIN_TTL_SECONDS))
                .clamp(i64::from(MIN_TTL_SECONDS), i64::from(MAX_TTL_SECONDS)) as u32;
        Ok(result)
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
        // The public resolvers only: getaddrinfo cannot be used once
        // interception is active (its query would be answered from the very
        // cache being refreshed), and the Worker cannot be asked about itself.
        let name = lowercase(&self.worker_host);
        let fresh = if is_resolvable_host(&name) {
            Box::pin(self.query_upstreams(&name, 0, false)).await.ok()
        } else {
            None
        };
        let refreshed = match fresh.filter(|fresh| !fresh.is_empty()) {
            Some(fresh) => {
                tracing::debug!(
                    "DNS bootstrap yenilendi: {} A, {} AAAA",
                    fresh.v4.len(),
                    fresh.v6.len()
                );
                self.lock().cache.insert(
                    name,
                    Entry {
                        result: DnsResult {
                            v4: fresh.v4,
                            v6: fresh.v6,
                            ttl_seconds: (BOOTSTRAP_TTL_MS / 1000) as u32,
                            ..DnsResult::default()
                        },
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
    /// there is nothing to connect to (not counted as a Worker failure), a 429
    /// back-off runs, or the deadline has passed.
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

    /// The preferred provider, the others in table order, then the Worker
    /// (`with_worker` and one is configured).
    fn upstream_chain(&self, with_worker: bool) -> Vec<usize> {
        std::iter::once(self.preferred)
            .chain((0..WORKER).filter(|&i| i != self.preferred))
            .chain((with_worker && !self.worker_host.is_empty()).then_some(WORKER))
            .collect()
    }

    /// Upstream names in the order they are asked (for the start-up log).
    pub fn upstream_names(&self) -> Vec<&'static str> {
        self.upstream_chain(true)
            .into_iter()
            .map(upstream_name)
            .collect()
    }

    /// `upstream_chain` without those cooling down (all of them when every
    /// one is).
    fn upstream_order(&self, with_worker: bool) -> Vec<usize> {
        let chain = self.upstream_chain(with_worker);
        let now = self.now();
        let ready: Vec<usize> = chain
            .iter()
            .copied()
            .filter(|&i| self.cooldown_until[i].load(Ordering::Relaxed) <= now)
            .collect();
        if ready.is_empty() { chain } else { ready }
    }

    /// An answer ends an upstream's cool-down; a failure starts or extends it.
    fn note(&self, index: usize, failed: bool) {
        if !failed {
            self.cooldown_until[index].store(0, Ordering::Relaxed);
            return;
        }
        let now = self.now();
        if self.cooldown_until[index].swap(now + UPSTREAM_COOLDOWN_MS, Ordering::Relaxed) <= now {
            tracing::warn!(
                "DNS: {} yanit vermiyor; {} sn atlanacak",
                upstream_name(index),
                UPSTREAM_COOLDOWN_MS / 1000
            );
        }
    }

    /// The Worker's refusals: 429 starts the back-off (alive, not a failure),
    /// 401/403 is a failure. None: not a refusal.
    fn worker_refusal(&self, response: &Response) -> Option<bool> {
        match response.status {
            429 => {
                self.health
                    .observe(429, self.now(), response.retry_after_seconds);
                tracing::warn!("DNS: Worker rate limit (HTTP 429)");
                Some(false)
            }
            401 | 403 => {
                tracing::error!(
                    "DNS: Worker kimlik dogrulamasi reddetti (HTTP {}). --redeploy ile worker'i guncelleyin.",
                    response.status
                );
                Some(true)
            }
            _ => None,
        }
    }

    /// Health counts lookups, not attempts: one answer from any upstream is a
    /// success, a lookup where every tried upstream failed is one failure.
    fn observe_lookup(&self, answered: bool, failed: bool) {
        if answered {
            self.health.observe(200, self.now(), 0);
        } else if failed {
            self.health.observe(-1, self.now(), 0);
        }
    }

    /// Asks the public resolvers, then the Worker (`with_worker`), until one
    /// answers. Err(true): one failed and none answered.
    async fn query_upstreams(
        &self,
        host: &str,
        deadline_ms: u64,
        with_worker: bool,
    ) -> Result<DnsResult, bool> {
        let mut failed = false;
        for index in self.upstream_order(with_worker) {
            if deadline_ms != 0 && self.now() >= deadline_ms {
                break;
            }
            let attempt = if index == WORKER {
                self.query_worker(host, deadline_ms).await
            } else {
                self.query_direct(index, host, deadline_ms).await
            };
            match attempt {
                Ok(result) => {
                    self.note(index, false);
                    return Ok(result);
                }
                Err(true) => {
                    self.note(index, true);
                    failed = true;
                }
                Err(false) => {}
            }
        }
        Err(failed)
    }

    async fn query(&self, host: &str, deadline_ms: u64) -> DnsResult {
        // '_' (service labels) and anything outside [a-z0-9.-] does not go
        // into a URL; the raw wire path handles any name.
        if !is_resolvable_host(host) {
            return DnsResult {
                allow_wire_fallback: true,
                ..DnsResult::default()
            };
        }
        let answer = self.query_upstreams(host, deadline_ms, true).await;
        self.observe_lookup(answer.is_ok(), matches!(answer, Err(true)));
        let Ok(mut result) = answer else {
            return DnsResult {
                transient: true,
                ..DnsResult::default()
            };
        };
        if result.transient {
            result.ttl_seconds = result.ttl_seconds.min(TRANSIENT_CACHE_SECONDS);
        }
        if result.is_empty() && !result.allow_wire_fallback {
            match result.rcode {
                dns::RCODE_NX_DOMAIN => tracing::debug!("DNS: {host} NXDOMAIN"),
                dns::RCODE_NO_ERROR => tracing::debug!("DNS: {host} icin adres yok (NODATA)"),
                rcode => tracing::warn!("DNS: {host} icin adres yok (rcode {rcode})"),
            }
        }
        result
    }

    /// The Worker's `/resolve`. Err(true): the Worker failed.
    async fn query_worker(&self, host: &str, deadline_ms: u64) -> Result<DnsResult, bool> {
        let mut result = DnsResult::default();
        if !self.prepare_worker_call(deadline_ms).await {
            return Err(false);
        }
        let response = self
            .fetcher
            .fetch(self.worker_request("GET", format!("/resolve?host={host}"), deadline_ms))
            .await;
        if let Some(failed) = self.worker_refusal(&response) {
            return Err(failed);
        }
        // Workers deployed before the rcode field answered 404 for NXDOMAIN,
        // SERVFAIL and empty answers alike: ask the wire path.
        if response.status == 404 {
            result.allow_wire_fallback = true;
            return Ok(result);
        }
        if !response.ok() {
            tracing::debug!("DNS: Worker /resolve HTTP {} ({host})", response.status);
            return Err(is_failure(response.status));
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
        result.cnames = string_array(&body, "cnames");
        result.cnames.truncate(MAX_CNAMES);
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
        Ok(result)
    }

    /// Cached lookup. An empty transient result means no upstream answered. `deadline_ms` (clock scale,
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
        // asks upstream while the others wait for its shared result.
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

    /// DoH wire relay through the same upstream chain; the exact response is
    /// preserved so every record type works. Cached for its TTL; the reply
    /// carries the query's ID.
    pub async fn query_wire(&self, message: &[u8], deadline_ms: u64) -> Vec<u8> {
        let mut parsed = Query::default();
        if !dns::parse_query(message, &mut parsed) {
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

        let mut failed = false;
        let mut reply = None;
        for index in self.upstream_order(true) {
            if deadline_ms != 0 && self.now() >= deadline_ms {
                break;
            }
            match self
                .query_wire_at(index, message, &parsed, deadline_ms)
                .await
            {
                Ok(answer) => {
                    self.note(index, false);
                    reply = Some(answer);
                    break;
                }
                Err(true) => {
                    self.note(index, true);
                    failed = true;
                }
                Err(false) => {}
            }
        }
        self.observe_lookup(reply.is_some(), failed);
        let Some((mut answer, info)) = reply else {
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

    /// One wire query at upstream `index`. Err(true): the upstream failed.
    async fn query_wire_at(
        &self,
        index: usize,
        message: &[u8],
        parsed: &Query,
        deadline_ms: u64,
    ) -> Result<(Vec<u8>, dns::ResponseInfo), bool> {
        let mut request = if index == WORKER {
            if !self.prepare_worker_call(deadline_ms).await {
                return Err(false);
            }
            self.worker_request("POST", "/dns-query".into(), deadline_ms)
        } else {
            let mut request = Request::get(DNS_PROVIDERS[index].host, "/dns-query");
            request.method = "POST";
            request.timeout = self.request_timeout(deadline_ms).min(DIRECT_TIMEOUT);
            request
        };
        request
            .headers
            .push(("Accept".into(), "application/dns-message".into()));
        request
            .headers
            .push(("Content-Type".into(), "application/dns-message".into()));
        request.body = message.to_vec();
        let response = self.fetcher.fetch(request).await;
        if index == WORKER
            && let Some(failed) = self.worker_refusal(&response)
        {
            return Err(failed);
        }
        if !response.ok() || response.body.len() < 12 || response.body.len() > 65535 {
            tracing::debug!(
                "DNS wire: {} HTTP {}",
                upstream_name(index),
                response.status
            );
            return Err(is_failure(response.status));
        }
        let answer = response.body;
        // The relay must answer *this* question; never pass anything else on.
        let Some(info) = dns::inspect_response(&answer)
            .filter(|i| i.response && dns::echoes_question(&answer, parsed))
        else {
            tracing::warn!(
                "DNS wire: {} gecersiz veya eslesmeyen cevap dondurdu ({})",
                upstream_name(index),
                parsed.name
            );
            return Err(true);
        };
        Ok((answer, info))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use sh_core::config::dns_provider_index;
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

    /// A JSON DoH answer: `v4` for type=A, NODATA for type=AAAA.
    pub fn doh(request: &Request, v4: &str) -> Response {
        if request.path.contains("type=AAAA") {
            return ok(r#"{"Status":0}"#);
        }
        ok(format!(
            r#"{{"Status":0,"Answer":[{{"name":"x","type":1,"TTL":120,"data":"{v4}"}}]}}"#
        ))
    }

    pub fn is_direct(request: &Request) -> bool {
        DNS_PROVIDERS.iter().any(|p| request.host == p.host)
    }

    fn carries_secret(request: &Request) -> bool {
        request
            .headers
            .iter()
            .any(|(name, _)| name == "Authorization")
    }

    /// Fake upstreams: the public resolvers (`direct`, failing by default) and
    /// the Worker. No network, a hand-driven clock.
    pub struct FakeWorker {
        pub seen: Mutex<Vec<Request>>,
        pub resolve_calls: AtomicI32,
        pub wire_calls: AtomicI32,
        pub direct_calls: AtomicI32,
        pub clock: Arc<AtomicU64>,
        pub resolve: Mutex<Handler>,
        pub wire: Mutex<Handler>,
        pub direct: Mutex<Handler>,
        pub delay: Mutex<Duration>,
    }

    impl FakeWorker {
        pub fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::default(),
                resolve_calls: AtomicI32::new(0),
                wire_calls: AtomicI32::new(0),
                direct_calls: AtomicI32::new(0),
                clock: Arc::new(AtomicU64::new(1_000_000)),
                resolve: Mutex::new(Box::new(|_| {
                    ok(r#"{"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0}"#)
                })),
                wire: Mutex::new(Box::new(|r| {
                    upstream_answer(r, &["203.0.113.9"], 120, false, 0)
                })),
                direct: Mutex::new(Box::new(|_| status(-1, 0))),
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
                if is_direct(&request) {
                    self.direct_calls.fetch_add(1, Ordering::SeqCst);
                    return (self.direct.lock().unwrap())(&request);
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
            0,
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
        // Public resolvers alive but without an answer: only the 429 is in play.
        FakeWorker::set(&worker.direct, |_| status(400, 0));
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
            0,
            Some(worker.clock()),
        );
        // A network that rewrites NXDOMAIN makes the start-up lookup succeed.
        if !resolver.resolve(host, 0).await.is_empty() {
            return;
        }
        // Offline: no connection attempt to the Worker, and no outage yet.
        let offline = resolver.resolve("first.example", 0).await;
        assert!(offline.is_empty() && offline.transient);
        assert_eq!(worker.calls().0, 0);
        let attempts = worker.direct_calls.load(Ordering::SeqCst);
        assert!(attempts >= 1);
        resolver.resolve("second.example", 0).await;
        assert_eq!(worker.direct_calls.load(Ordering::SeqCst), attempts); // rate limited
        assert!(!resolver.worker_unavailable());

        // Network is back: the next call after the retry interval goes through.
        FakeWorker::set(&worker.direct, |request| {
            if request
                .path
                .contains("name=splithello-bootstrap-test.invalid&")
            {
                doh(request, "203.0.113.77")
            } else {
                status(-1, 0)
            }
        });
        worker.advance(31_000);
        assert!(!resolver.resolve("third.example", 0).await.is_empty());
        assert_eq!(worker.calls().0, 1);
        let bootstrap = resolver.resolve(host, 0).await;
        assert_eq!(bootstrap.v4, ["203.0.113.77"]);
        let seen = worker.seen.lock().unwrap();
        assert!(!seen.iter().any(|r| is_direct(r) && carries_secret(r)));
    }

    #[tokio::test]
    async fn a_public_resolver_answers_without_the_worker() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.direct, |r| doh(r, "198.51.100.1"));
        let resolver = resolver(&worker);
        let result = resolver.resolve("site.example", 0).await;
        assert_eq!(result.v4, ["198.51.100.1"]);
        assert!(result.v6.is_empty() && !result.transient);
        assert_eq!(result.ttl_seconds, 120);
        assert_eq!(worker.calls(), (0, 0));
        let seen = worker.seen.lock().unwrap();
        assert_eq!(seen.len(), 2); // A and AAAA, Cloudflare only
        for request in seen.iter() {
            assert_eq!(request.host, "1.1.1.1");
            assert!(
                request
                    .path
                    .starts_with("/dns-query?name=site.example&type=")
            );
            assert!(
                request
                    .headers
                    .contains(&("Accept".into(), "application/dns-json".into()))
            );
            assert!(!carries_secret(request));
        }
    }

    #[tokio::test]
    async fn fails_over_to_google_and_skips_a_failed_upstream_for_a_while() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.direct, |r| {
            if r.host == "8.8.8.8" && r.path.starts_with("/resolve?name=") {
                doh(r, "198.51.100.2")
            } else {
                status(503, 0)
            }
        });
        let resolver = resolver(&worker);
        let cloudflare_calls = || {
            worker
                .seen
                .lock()
                .unwrap()
                .iter()
                .filter(|r| r.host == "1.1.1.1")
                .count()
        };
        assert_eq!(
            resolver.resolve("one.example", 0).await.v4,
            ["198.51.100.2"]
        );
        assert_eq!(cloudflare_calls(), 2);
        worker.advance(10_000);
        assert_eq!(
            resolver.resolve("two.example", 0).await.v4,
            ["198.51.100.2"]
        );
        assert_eq!(cloudflare_calls(), 2); // cooling down: not asked again
        worker.advance(UPSTREAM_COOLDOWN_MS);
        resolver.resolve("three.example", 0).await;
        assert_eq!(cloudflare_calls(), 4);
        assert_eq!(worker.calls(), (0, 0));
    }

    #[tokio::test]
    async fn asks_the_chosen_provider_first_and_falls_back_in_table_order() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.direct, |r| {
            if r.host == "94.140.14.14" {
                status(-1, 0)
            } else {
                doh(r, "198.51.100.5")
            }
        });
        let resolver = Resolver::new(
            WORKER_URL,
            "secret".into(),
            0,
            worker.clone(),
            dns_provider_index("adguard"),
            Some(worker.clock()),
        );
        assert_eq!(
            resolver.upstream_names(),
            ["AdGuard", "Cloudflare", "Google", "DNS.SB", "Worker"]
        );
        assert_eq!(
            resolver.resolve("pick.example", 0).await.v4,
            ["198.51.100.5"]
        );
        let hosts: Vec<String> = worker
            .seen
            .lock()
            .unwrap()
            .iter()
            .map(|r| r.host.clone())
            .collect();
        assert_eq!(
            hosts,
            ["94.140.14.14", "94.140.14.14", "1.1.1.1", "1.1.1.1"]
        );
        assert_eq!(worker.calls(), (0, 0));
    }

    #[tokio::test]
    async fn only_the_worker_gets_the_secret_when_it_is_the_last_resort() {
        let worker = FakeWorker::new();
        let resolver = resolver(&worker);
        assert_eq!(
            resolver.resolve("last.example", 0).await.v4,
            ["203.0.113.5"]
        );
        worker.advance(UPSTREAM_COOLDOWN_MS + 1);
        assert!(
            !resolver
                .query_wire(&dns_query("last.example", 16).build(), 0)
                .await
                .is_empty()
        );
        assert_eq!(worker.calls(), (1, 1));
        let seen = worker.seen.lock().unwrap();
        // Every public resolver was asked first, over JSON and over wire.
        for host in DNS_PROVIDERS.map(|p| p.host) {
            assert!(seen.iter().any(|r| r.host == host && r.method == "GET"));
            assert!(seen.iter().any(|r| r.host == host && r.method == "POST"));
        }
        assert!(
            seen.iter()
                .filter(|r| carries_secret(r))
                .all(|r| r.host == "localhost")
        );
        assert_eq!(seen.iter().filter(|r| carries_secret(r)).count(), 2);
    }

    #[tokio::test]
    async fn parses_cnames_rcode_and_half_answers_from_doh_json() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.direct, |r| {
            let name = r.path.split(['=', '&']).nth(1).unwrap_or("");
            match (name, r.path.contains("type=AAAA")) {
                ("cloaked.example", false) => ok(
                    r#"{"Status":0,"Answer":[{"type":5,"TTL":300,"data":"Edge.Tracker.Example."},{"type":1,"TTL":90,"data":"203.0.113.8"},{"type":1,"TTL":10,"data":"not-an-ip"}]}"#,
                ),
                ("cloaked.example", true) => ok(
                    r#"{"Status":0,"Answer":[{"type":5,"TTL":300,"data":"edge.tracker.example."}]}"#,
                ),
                ("gone.example", _) => ok(r#"{"Status":3}"#),
                // AdGuard's shape: a null Answer next to the status.
                ("adguard-gone.example", _) => ok(
                    r#"{"Question":[{"name":"adguard-gone.example.","type":1}],"Answer":null,"Extra":null,"TC":false,"Status":3}"#,
                ),
                ("half.example", false) => doh(r, "203.0.113.9"),
                _ => status(-1, 0),
            }
        });
        let resolver = resolver(&worker);
        let cloaked = resolver.resolve("cloaked.example", 0).await;
        assert_eq!(cloaked.v4, ["203.0.113.8"]);
        assert_eq!(cloaked.cnames, ["edge.tracker.example"]);
        assert_eq!(cloaked.ttl_seconds, 90);
        assert!(!cloaked.transient);
        let gone = resolver.resolve("gone.example", 0).await;
        assert!(gone.is_empty() && !gone.transient && !gone.allow_wire_fallback);
        assert_eq!(gone.rcode, dns::RCODE_NX_DOMAIN);
        let adguard_gone = resolver.resolve("adguard-gone.example", 0).await;
        assert!(adguard_gone.is_empty() && !adguard_gone.transient);
        assert_eq!(adguard_gone.rcode, dns::RCODE_NX_DOMAIN);
        let half = resolver.resolve("half.example", 0).await;
        assert_eq!(half.v4, ["203.0.113.9"]);
        assert!(half.transient && half.ttl_seconds <= TRANSIENT_CACHE_SECONDS);
        assert_eq!(worker.calls(), (0, 0));
    }

    #[tokio::test]
    async fn resolves_with_no_worker_configured() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.direct, |r| {
            if r.method == "POST" {
                upstream_answer(r, &["203.0.113.10"], 120, false, 0)
            } else {
                doh(r, "198.51.100.3")
            }
        });
        let resolver = Resolver::new(
            "",
            String::new(),
            0,
            worker.clone(),
            0,
            Some(worker.clock()),
        );
        assert_eq!(
            resolver.resolve("plain.example", 0).await.v4,
            ["198.51.100.3"]
        );
        assert!(
            !resolver
                .query_wire(&dns_query("plain.example", 16).build(), 0)
                .await
                .is_empty()
        );
        FakeWorker::set(&worker.direct, |_| status(-1, 0));
        assert!(resolver.resolve("down.example", 0).await.transient);
        assert_eq!(worker.calls(), (0, 0));
        assert!(worker.seen.lock().unwrap().iter().all(is_direct));
    }

    #[tokio::test]
    async fn latches_when_nothing_answers_and_recovers_on_an_answer() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| status(-1, 0));
        let resolver = resolver(&worker);
        for i in 0..6 {
            assert!(
                resolver
                    .resolve(&format!("x{i}.example"), 0)
                    .await
                    .transient
            );
            worker.advance(4_000);
        }
        assert!(resolver.worker_unavailable());
        assert!(!resolver.probe().await);
        FakeWorker::set(&worker.direct, |r| doh(r, "198.51.100.4"));
        assert!(resolver.probe().await);
        assert!(!resolver.worker_unavailable());
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
