//! One proxied TCP connection (port of `DirectRelay`): collect the complete
//! ClientHello, connect to the target, run an untouched differential baseline
//! before trying bounded transformations, learn the winner, then pump bytes.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use sh_core::live_stats::{Flow, Publisher};
use sh_dns::Resolver;
use sh_flow::{PeerAddr, PolicyRegistry};
use sh_proto::packet::{is_packet_profile, policy_for_profile};
use sh_proto::tls::{self, ClientHello, ParseStatus, ServerResponseStatus};
use sh_strategy::diagnosis::{self, Attempt, Context, Kind, ProbeSignal, Verdict};
use sh_strategy::{FragmentPlan, Outcome, PROFILES, Store, build_plan, normalize_host};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::pump::{PumpEnd, pump};

/// A TLS record cannot exceed 16 KiB; the rest absorbs what the client
/// pipelines behind it.
const MAX_HELLO_BUFFER: usize = 64 * 1024;
/// Server-first protocols tunnelled through CONNECT never send anything, so
/// this must expire rather than hang.
const CLIENT_FIRST_BYTE_TIMEOUT: Duration = Duration::from_millis(4000);
const CLIENT_CONTINUATION_TIMEOUT: Duration = Duration::from_millis(2000);
const CONNECT_ATTEMPT_DELAY: Duration = Duration::from_millis(250);
const CONNECT_TIMEOUT: Duration = Duration::from_millis(10_000);
const ORIGINAL_CONNECT_TIMEOUT: Duration = Duration::from_millis(2000);
/// Unknown paths may need both packet-level and record families.
const MAX_PROBE_ATTEMPTS: usize = 12;
/// After a blocked attempt DPI often keeps resetting the same 5-tuple for a
/// moment; retrying instantly makes the next profile look broken.
const RETRY_PAUSE: Duration = Duration::from_millis(150);
const PROBE_READ_BUFFER: usize = 32 * 1024;
const MAX_PROBE_RESPONSE: usize = 64 * 1024;
/// A dead peer after a network change is detected in about 2.5 min.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);
/// 1 in this many healthy single-attempt flows is persisted.
const HEALTHY_SAMPLE_RATE: u32 = 20;

static HEALTHY_SAMPLE_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Worker tunnel settings (only when tunnel fallback is on and a Worker exists).
#[derive(Debug, Clone)]
pub struct TunnelSettings {
    pub worker_host: String,
    pub shared_secret: String,
    pub connect_port: u16,
}

/// Shared, read-only state handed to every connection.
pub struct RelayContext {
    pub resolver: Option<Arc<Resolver>>,
    pub strategies: Arc<Store>,
    /// None in manual mode: there is no packet loop to apply packet profiles.
    pub packet_policies: Option<Arc<PolicyRegistry>>,
    pub telemetry: Option<Arc<sh_telemetry::Store>>,
    pub live_stats: Option<Arc<Publisher>>,
    /// Asked once per connection, so a roaming laptop learns per network.
    pub network_id: Arc<dyn Fn() -> String + Send + Sync>,
    pub split_delay_ms: u32,
    pub probe_timeout: Duration,
    pub tunnel: Option<TunnelSettings>,
    pub idle_timeout: Duration,
    pub handshake_timeout: Duration,
    /// When set, this profile is used for every connection and nothing is learned.
    pub forced_profile: String,
}

fn profile_slot(name: &str) -> Option<usize> {
    PROFILES.iter().position(|p| p.name == name)
}

fn set_abortive(stream: &TcpStream) {
    let _ = SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

fn prepare_socket(stream: &TcpStream) {
    // Nagle plus delayed ACK would stall small back-to-back writes, and every
    // record of a fragment plan must leave as its own segment.
    let _ = stream.set_nodelay(true);
    let _ = SockRef::from(stream).set_tcp_keepalive(
        &TcpKeepalive::new()
            .with_time(KEEPALIVE_IDLE)
            .with_interval(KEEPALIVE_INTERVAL),
    );
}

async fn system_resolve(host: &str, port: u16) -> Vec<IpAddr> {
    let mut out: Vec<IpAddr> = Vec::new();
    if let Ok(addresses) = tokio::net::lookup_host((host, port)).await {
        for address in addresses {
            if out.len() < 8 && !out.contains(&address.ip()) {
                out.push(address.ip());
            }
        }
    }
    out
}

struct Session<'a> {
    ctx: &'a RelayContext,
    client: TcpStream,
    target: Option<TcpStream>,
    target_host: String,
    target_port: u16,
    original: Option<IpAddr>,
    connect_port: u16,
    network_id: String,
    candidates: Vec<IpAddr>,
    connected: Option<IpAddr>,
    buffer: Vec<u8>,
    hello: ClientHello,
    hello_complete: bool,
    first_response: Vec<u8>,
    armed_local_port: u16,
    live: Flow,
    abortive: bool,
}

enum Collected {
    Ready,
    Blocked,
    Failed,
}

/// Serves one connection. `initial` holds bytes a CONNECT handshake already
/// read past its end.
pub async fn relay(
    client: TcpStream,
    ctx: &RelayContext,
    target_host: String,
    target_port: u16,
    original: Option<IpAddr>,
    connect_port: u16,
    initial: Vec<u8>,
) {
    let _ = client.set_nodelay(true);
    let mut session = Session {
        ctx,
        client,
        target: None,
        target_host,
        target_port,
        original,
        connect_port: if connect_port == 0 {
            target_port
        } else {
            connect_port
        },
        // One lookup per connection: every decision below agrees on the network.
        network_id: (ctx.network_id)(),
        candidates: Vec::new(),
        connected: None,
        buffer: initial,
        hello: ClientHello::default(),
        hello_complete: false,
        first_response: Vec::new(),
        armed_local_port: 0,
        live: Flow::default(),
        abortive: false,
    };
    session.live.begin(ctx.live_stats.clone());
    session.run().await;
}

impl Session<'_> {
    async fn run(&mut self) {
        // Transparent connections carry only an IP: buffer first to recover the
        // SNI and scope resolution and learning to the hostname. Manual
        // SOCKS/CONNECT keeps connect-first for server-first protocols.
        let prepared = if self.original.is_none() {
            self.prepare_candidates().await
                && self.connect_target().await
                && matches!(self.collect_client_hello().await, Collected::Ready)
        } else {
            matches!(self.collect_client_hello().await, Collected::Ready)
                && self.prepare_candidates().await
                && self.connect_target().await
        };
        tracing::trace!(
            "{}: hazir={prepared} hello_tam={} tampon={} bayt",
            self.target_host,
            self.hello_complete,
            self.buffer.len()
        );
        if prepared {
            if self.deliver_hello().await && self.flush_trailing_client_data().await {
                // Whatever the probe already read has to reach the client first.
                let flushed = self.first_response.is_empty()
                    || self.client.write_all(&self.first_response).await.is_ok();
                self.first_response = Vec::new();
                self.buffer = Vec::new();
                if flushed {
                    if let Some(target) = self.target.as_mut() {
                        match pump(&mut self.client, target, self.ctx.idle_timeout).await {
                            PumpEnd::Aborted => self.abortive = true,
                            PumpEnd::Idle => tracing::debug!(
                                "{}:{} sessiz kaldi, kapatiliyor",
                                self.target_host,
                                self.target_port
                            ),
                            PumpEnd::Closed => {}
                        }
                    }
                } else {
                    self.abortive = true;
                }
            } else {
                self.hand_off_to_tunnel().await;
            }
        }
        if self.abortive {
            set_abortive(&self.client);
            if let Some(target) = &self.target {
                set_abortive(target);
            }
        }
    }

    async fn prepare_candidates(&mut self) -> bool {
        self.candidates.clear();
        // The address the application chose comes first: redirecting its SYN to
        // the relay defeated its own Happy Eyeballs fallback.
        if let Some(original) = self.original {
            self.candidates.push(original);
        }
        let literal = self.target_host.parse::<IpAddr>().is_ok();
        // In system-DNS mode the app already supplied the IP; a second lookup
        // would delay every new HTTPS connection.
        if !literal && (self.ctx.resolver.is_some() || self.original.is_none()) {
            let found = match &self.ctx.resolver {
                Some(resolver) => resolver.resolve(&self.target_host, 0).await.candidates(8),
                None => system_resolve(&self.target_host, self.target_port).await,
            };
            for address in found {
                if !self.candidates.contains(&address) {
                    self.candidates.push(address);
                }
            }
        }
        if self.candidates.is_empty() && (self.ctx.resolver.is_some() || literal) {
            if self.ctx.resolver.is_some() {
                tracing::warn!(
                    "DNS: {} Worker uzerinden cozulemedi, sistem cozumleyicisi deneniyor",
                    self.target_host
                );
            }
            self.candidates = system_resolve(&self.target_host, self.target_port).await;
        }
        if self.candidates.is_empty() {
            tracing::error!("Adres cozumlenemedi: {}", self.target_host);
            return false;
        }
        true
    }

    async fn connect_target(&mut self) -> bool {
        let selected_by_application = self.ctx.resolver.is_none()
            && self.original.is_some()
            && self.target_host.parse::<IpAddr>().is_err()
            && self.candidates.len() == 1;
        let budget = if selected_by_application {
            ORIGINAL_CONNECT_TIMEOUT
        } else {
            CONNECT_TIMEOUT
        };
        let mut connected = sh_net::connect_any(
            &self.candidates,
            self.connect_port,
            CONNECT_ATTEMPT_DELAY,
            budget,
        )
        .await;
        if connected.is_none() && selected_by_application {
            for address in system_resolve(&self.target_host, self.target_port).await {
                if !self.candidates.contains(&address) {
                    self.candidates.push(address);
                }
            }
            if self.candidates.len() > 1 {
                self.candidates.rotate_left(1);
                tracing::debug!(
                    "{}: secilen IP baglanmadi, diger sistem adresleri deneniyor",
                    self.target_host
                );
                connected = sh_net::connect_any(
                    &self.candidates,
                    self.connect_port,
                    CONNECT_ATTEMPT_DELAY,
                    CONNECT_TIMEOUT - ORIGINAL_CONNECT_TIMEOUT,
                )
                .await;
            }
        }
        let Some((stream, address)) = connected else {
            tracing::error!(
                "Baglanti kurulamadi: {}:{}",
                self.target_host,
                self.target_port
            );
            return false;
        };
        prepare_socket(&stream);
        tracing::debug!(
            "Baglandi: {address} ({}:{})",
            self.target_host,
            self.target_port
        );
        self.target = Some(stream);
        self.connected = Some(address);
        true
    }

    async fn reconnect(&mut self) -> bool {
        if let Some(old) = self.target.take() {
            set_abortive(&old);
        }
        self.connect_target().await
    }

    async fn collect_client_hello(&mut self) -> Collected {
        self.hello_complete = false;
        let mut chunk = vec![0u8; 16 * 1024];
        let mut timeout = CLIENT_FIRST_BYTE_TIMEOUT;
        loop {
            if !self.buffer.is_empty() {
                match tls::parse_client_hello(&self.buffer, &mut self.hello) {
                    ParseStatus::Ok => {
                        self.hello_complete = true;
                        if !self.hello.server_name.is_empty() {
                            self.target_host = normalize_host(&self.hello.server_name);
                        }
                        if sh_adblock::global().blocks(&self.target_host) {
                            // Closing both sockets: the client fails fast and
                            // nothing is ever sent to the ad host.
                            sh_adblock::record_blocked(&self.target_host);
                            tracing::debug!("Reklam/izleyici engellendi: {}", self.target_host);
                            return Collected::Blocked;
                        }
                        if self.hello.has_ech {
                            tracing::debug!(
                                "{}: ECH uzantisi var (gercek ECH veya GREASE)",
                                self.target_host
                            );
                        }
                        return Collected::Ready;
                    }
                    ParseStatus::NeedMore if self.buffer.len() >= MAX_HELLO_BUFFER => {
                        tracing::warn!(
                            "ClientHello {MAX_HELLO_BUFFER} bayti asti, parcalanmadan iletiliyor"
                        );
                        return Collected::Ready;
                    }
                    ParseStatus::NeedMore => {}
                    ParseStatus::NotTls | ParseStatus::Malformed => {
                        tracing::debug!(
                            "{}:{} TLS degil veya bozuk, duz iletim",
                            self.target_host,
                            self.target_port
                        );
                        return Collected::Ready;
                    }
                }
            }
            match tokio::time::timeout(timeout, self.client.read(&mut chunk)).await {
                // A server-first protocol, or a client that stopped mid-hello:
                // forward whatever we have.
                Err(_) => return Collected::Ready,
                Ok(read @ (Ok(0) | Err(_))) => {
                    tracing::debug!(
                        "{}: istemci ClientHello'dan once kapandi ({read:?}, {} bayt)",
                        self.target_host,
                        self.buffer.len()
                    );
                    return if self.buffer.is_empty() {
                        Collected::Failed
                    } else {
                        Collected::Ready
                    };
                }
                Ok(Ok(n)) => {
                    self.buffer.extend_from_slice(&chunk[..n]);
                    timeout = CLIENT_CONTINUATION_TIMEOUT;
                }
            }
        }
    }

    async fn write_fragmented(&mut self, plan: &FragmentPlan) -> bool {
        let Some(target) = self.target.as_mut() else {
            return false;
        };
        let header = [self.buffer[0], self.buffer[1], self.buffer[2]];
        let payload = &self.buffer
            [tls::RECORD_HEADER_SIZE..tls::RECORD_HEADER_SIZE + self.hello.record_payload_length];
        let mut start = 0;
        for end in plan
            .record_splits
            .iter()
            .copied()
            .chain(std::iter::once(payload.len()))
        {
            let length = end - start;
            let record_header = [
                header[0],
                header[1],
                header[2],
                (length >> 8) as u8,
                length as u8,
            ];
            if target.write_all(&record_header).await.is_err() {
                return false;
            }
            if plan.write_chunk == 0 {
                if target.write_all(&payload[start..end]).await.is_err() {
                    return false;
                }
            } else {
                let mut offset = start;
                while offset < end {
                    let piece = plan.write_chunk.min(end - offset);
                    if target
                        .write_all(&payload[offset..offset + piece])
                        .await
                        .is_err()
                    {
                        return false;
                    }
                    offset += piece;
                    if offset < end {
                        tokio::time::sleep(Duration::from_millis(1)).await;
                    }
                }
            }
            start = end;
            if start < payload.len() && plan.delay_ms > 0 {
                tokio::time::sleep(Duration::from_millis(u64::from(plan.delay_ms))).await;
            }
        }
        true
    }

    async fn write_plan(&mut self, plan: &FragmentPlan) -> bool {
        if !self.hello_complete {
            return true;
        }
        if plan.splits_anything() {
            return self.write_fragmented(plan).await;
        }
        let total = self.hello.record_total_length;
        match self.target.as_mut() {
            Some(target) => target.write_all(&self.buffer[..total]).await.is_ok(),
            None => false,
        }
    }

    async fn await_response(&mut self) -> ProbeSignal {
        self.first_response.clear();
        let Some(target) = self.target.as_mut() else {
            return ProbeSignal::Reset;
        };
        let deadline = tokio::time::Instant::now() + self.ctx.probe_timeout;
        let mut buffer = vec![0u8; PROBE_READ_BUFFER];
        while self.first_response.len() < MAX_PROBE_RESPONSE {
            match tokio::time::timeout_at(deadline, target.read(&mut buffer)).await {
                Err(_) => return ProbeSignal::Timeout,
                Ok(Ok(0)) => return ProbeSignal::Closed,
                Ok(Err(_)) => return ProbeSignal::Reset,
                Ok(Ok(n)) => {
                    self.first_response.extend_from_slice(&buffer[..n]);
                    match tls::classify_server_response(&self.first_response) {
                        ServerResponseStatus::ServerHello => return ProbeSignal::ServerHello,
                        ServerResponseStatus::Alert => return ProbeSignal::Alert,
                        ServerResponseStatus::Unexpected => return ProbeSignal::Unexpected,
                        ServerResponseStatus::NeedMore => {}
                    }
                }
            }
        }
        ProbeSignal::Unexpected
    }

    /// A no-op packet-* "win" (the policy never rewrote a packet) is not learned.
    fn packet_policy_applied(&self) -> bool {
        match (&self.ctx.packet_policies, self.connected) {
            (Some(policies), Some(address)) if self.armed_local_port != 0 => policies
                .consume_applied(
                    PeerAddr::from(address),
                    self.armed_local_port,
                    sh_core::clock::now_ms(),
                ),
            _ => false,
        }
    }

    async fn flush_trailing_client_data(&mut self) -> bool {
        if !self.hello_complete
            || self.hello.spans_records
            || self.buffer.len() <= self.hello.record_total_length
        {
            return true;
        }
        // 0-RTT data goes only to the winning connection: replaying it on every
        // diagnostic attempt could repeat a non-idempotent request.
        let total = self.hello.record_total_length;
        match self.target.as_mut() {
            Some(target) => target.write_all(&self.buffer[total..]).await.is_ok(),
            None => false,
        }
    }

    fn record_telemetry(
        &mut self,
        evidence: &[Attempt],
        verdict: &Verdict,
        remembered: &str,
        success: bool,
        started: Instant,
    ) {
        if success && !verdict.winning_profile.is_empty() {
            self.live
                .set_profile(profile_slot(&verdict.winning_profile));
        }
        // Only a verified bypass counts, matching the dashboard's definition.
        self.live.decision(
            success,
            success && diagnosis::is_verified_bypass(verdict.kind),
        );

        let Some(telemetry) = &self.ctx.telemetry else {
            return;
        };
        // A healthy first-try baseline carries no information beyond its count
        // and would fill the event cap within hours: persist one in 20.
        let healthy = success
            && evidence.len() == 1
            && verdict.kind == Kind::NoInterference
            && verdict.winning_profile == "none"
            && remembered.is_empty();
        if healthy
            && !HEALTHY_SAMPLE_COUNTER
                .fetch_add(1, Ordering::Relaxed)
                .is_multiple_of(HEALTHY_SAMPLE_RATE)
        {
            return;
        }
        telemetry.record(sh_telemetry::ProbeRecord {
            occurred_at: 0,
            network_id: self.network_id.clone(),
            host: self.target_host.clone(),
            remembered_profile: remembered.to_owned(),
            verdict: verdict.clone(),
            attempts: evidence.to_vec(),
            total_elapsed_ms: started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32,
            success,
            forced: !self.ctx.forced_profile.is_empty(),
        });
    }

    fn arm_packet_policy(&mut self, profile: &str) {
        self.armed_local_port = 0;
        let (Some(policies), Some(address), Some(target)) =
            (&self.ctx.packet_policies, self.connected, &self.target)
        else {
            return;
        };
        if let Some(policy) = policy_for_profile(profile, &self.hello) {
            let local_port = target.local_addr().map(|a| a.port()).unwrap_or(0);
            self.armed_local_port = local_port;
            policies.arm(
                PeerAddr::from(address),
                local_port,
                policy,
                sh_core::clock::now_ms(),
            );
        }
    }

    async fn deliver_hello(&mut self) -> bool {
        if self.buffer.is_empty() {
            return true; // server-first protocol: nothing to send yet
        }
        if !self.hello_complete || self.hello.spans_records {
            // Not safely re-frameable (or the rest of the handshake is still in
            // the client socket): forward byte for byte and start streaming.
            let Some(target) = self.target.as_mut() else {
                return false;
            };
            return target.write_all(&self.buffer).await.is_ok();
        }

        let strategies = self.ctx.strategies.clone();
        let forced = &self.ctx.forced_profile;
        // --strategy pins one profile; "none" trails it so a hello the forced
        // profile cannot describe still goes out.
        let order: Vec<String> = if forced.is_empty() {
            strategies
                .probe_order(&self.network_id, &self.target_host, &self.hello, 0)
                .into_iter()
                .map(str::to_owned)
                .collect()
        } else if forced == "none" {
            vec!["none".into()]
        } else {
            vec![forced.clone(), "none".into()]
        };
        let remembered = strategies.lookup(&self.network_id, &self.target_host);
        let started = Instant::now();
        // A pinned profile is a controlled experiment, not learning.
        let learning = forced.is_empty();
        let context = if learning {
            Context {
                remembered_profile: remembered.clone(),
                baseline_recently_healthy: strategies.baseline_recently_healthy(
                    &self.network_id,
                    &self.target_host,
                    0,
                ),
            }
        } else {
            Context::default()
        };
        // A failed remembered profile is held against it only once the whole
        // event is classified: during a hiccup it fails with the baseline.
        let mut remembered_failed = false;
        let settle_failure = |failed: bool, network: &str, host: &str| {
            if learning && failed {
                strategies.record_failure(network, host, &remembered);
            }
        };

        let mut attempts = 0;
        let mut evidence: Vec<Attempt> = Vec::new();
        for profile in &order {
            if attempts >= MAX_PROBE_ATTEMPTS {
                break;
            }
            let plan = build_plan(profile, &self.hello, self.ctx.split_delay_ms);
            if plan.is_none() && profile != "none" {
                continue;
            }
            // Without a packet driver a packet-* profile would send the hello
            // untouched: it could only "win" falsely.
            if self.ctx.packet_policies.is_none() && is_packet_profile(profile) {
                continue;
            }
            // Every retry needs a fresh connection: the previous one was reset or
            // black-holed, and the server already saw a partial handshake.
            if attempts > 0 {
                tokio::time::sleep(RETRY_PAUSE).await;
                if !self.reconnect().await {
                    let verdict = diagnosis::infer(&evidence, &context);
                    settle_failure(remembered_failed, &self.network_id, &self.target_host);
                    self.record_telemetry(&evidence, &verdict, &remembered, false, started);
                    return false;
                }
            }
            attempts += 1;
            self.arm_packet_policy(profile);

            let probe_started = Instant::now();
            if !self.write_plan(&plan.unwrap_or_default()).await {
                tracing::debug!("{}: '{profile}' profili gonderilemedi", self.target_host);
                continue;
            }
            let outcome = self.await_response().await;
            evidence.push(Attempt::new(
                profile,
                outcome,
                probe_started
                    .elapsed()
                    .as_millis()
                    .min(u128::from(u32::MAX)) as u32,
            ));

            if outcome == ProbeSignal::ServerHello {
                let mut verdict = diagnosis::infer(&evidence, &context);
                let elapsed_ms = evidence.last().map_or(0, |a| a.elapsed_ms);
                let host = self.target_host.clone();
                if !learning {
                    tracing::debug!("{host}: '{profile}' (zorlanan)");
                } else if profile == "none" {
                    // A healthy baseline vouches for the host for a while and
                    // retires a winner that is no longer needed.
                    strategies.note_baseline_healthy(&self.network_id, &host, 0);
                    if !remembered.is_empty() {
                        strategies.remember(
                            &self.network_id,
                            &host,
                            profile,
                            verdict.kind,
                            verdict.confidence,
                            0,
                        );
                        tracing::info!(
                            "{host}: baz cizgi yeniden gecti, '{remembered}' profili unutuldu"
                        );
                    } else if verdict.kind != Kind::NoInterference {
                        tracing::info!(
                            "{host}: teshis={} guven={}% sure={elapsed_ms}ms",
                            verdict.kind.name(),
                            verdict.confidence
                        );
                    }
                } else if is_packet_profile(profile) && !self.packet_policy_applied() {
                    tracing::info!(
                        "{host}: '{profile}' yanit aldi ama paket politikasi uygulanmadi, ogrenilmedi ({attempts}. deneme)"
                    );
                } else if verdict.kind == Kind::TransientFailure {
                    tracing::info!(
                        "{host}: gecici ag hatasi, '{profile}' ile devam edildi, ogrenilmedi ({attempts}. deneme)"
                    );
                } else {
                    settle_failure(remembered_failed, &self.network_id, &host);
                    let learned = strategies.remember(
                        &self.network_id,
                        &host,
                        profile,
                        verdict.kind,
                        verdict.confidence,
                        0,
                    );
                    if learned == Outcome::Candidate {
                        // One differential is a suspicion until a later
                        // connection reproduces it.
                        verdict.kind = Kind::InterferenceSuspected;
                        verdict.confidence = verdict.confidence.min(55);
                        tracing::info!(
                            "{host}: baz cizgi gecmedi, '{profile}' gecti; ogrenmek icin ikinci dogrulama bekleniyor ({attempts}. deneme)"
                        );
                    } else if diagnosis::is_verified_bypass(verdict.kind) {
                        tracing::info!(
                            "{host}: teshis={} guven={}% profil='{profile}' sure={elapsed_ms}ms ({attempts}. deneme{})",
                            verdict.kind.name(),
                            verdict.confidence,
                            if learned == Outcome::Learned {
                                ", dogrulandi"
                            } else {
                                ""
                            }
                        );
                    }
                }
                self.live.set_profile(profile_slot(profile));
                self.record_telemetry(&evidence, &verdict, &remembered, true, started);
                return true;
            }
            if learning && *profile == remembered {
                remembered_failed = true;
            }
            tracing::debug!(
                "{}: '{profile}' basarisiz - {}",
                self.target_host,
                outcome.describe()
            );
            self.first_response.clear();
        }

        let verdict = diagnosis::infer(&evidence, &context);
        settle_failure(remembered_failed, &self.network_id, &self.target_host);
        self.record_telemetry(&evidence, &verdict, &remembered, false, started);
        tracing::warn!(
            "{}:{} icin sonuc yok; teshis={} guven={}%",
            self.target_host,
            self.target_port,
            verdict.kind.name(),
            verdict.confidence
        );
        false
    }

    async fn hand_off_to_tunnel(&mut self) {
        let Some(settings) = &self.ctx.tunnel else {
            return;
        };
        let Some(resolver) = &self.ctx.resolver else {
            return;
        };
        tracing::info!(
            "{}:{} Worker tuneline devrediliyor",
            self.target_host,
            self.target_port
        );
        let target = sh_net::tunnel::TunnelTarget {
            worker_host: settings.worker_host.clone(),
            worker_addresses: resolver.worker_addresses(),
            connect_port: settings.connect_port,
            shared_secret: settings.shared_secret.clone(),
        };
        let initial = std::mem::take(&mut self.buffer);
        if let Some(old) = self.target.take() {
            set_abortive(&old);
        }
        sh_net::tunnel::run(
            &mut self.client,
            &target,
            &self.target_host,
            self.target_port,
            &initial,
        )
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sh_proto::testing::{HelloOptions, build_client_hello};
    use tokio::net::TcpListener;

    fn context(store: Arc<Store>) -> RelayContext {
        RelayContext {
            resolver: None,
            strategies: store,
            packet_policies: None,
            telemetry: None,
            live_stats: None,
            network_id: Arc::new(|| "test-network".into()),
            split_delay_ms: 0,
            probe_timeout: Duration::from_millis(1500),
            tunnel: None,
            idle_timeout: Duration::from_secs(30),
            handshake_timeout: Duration::from_secs(10),
            forced_profile: String::new(),
        }
    }

    async fn pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connect = TcpStream::connect(listener.local_addr().unwrap());
        let (accepted, connected) = tokio::join!(listener.accept(), connect);
        (accepted.unwrap().0, connected.unwrap())
    }

    const SERVER_HELLO: [u8; 9] = [0x16, 0x03, 0x03, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];

    /// A fake origin whose "DPI" drops any connection whose first record holds
    /// the whole hostname, then answers ServerHello and echoes.
    async fn censoring_server(listener: TcpListener, host: &'static str) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut first = vec![0u8; 4096];
                let Ok(n) = socket.read(&mut first).await else {
                    return;
                };
                if n == 0 {
                    return;
                }
                let record_len = usize::from(u16::from_be_bytes([first[3], first[4]]));
                let first_record = &first[5..(5 + record_len).min(n)];
                if first_record
                    .windows(host.len())
                    .any(|w| w == host.as_bytes())
                {
                    return; // blocked: drop the connection
                }
                if socket.write_all(&SERVER_HELLO).await.is_err() {
                    return;
                }
                let mut rest = vec![0u8; 4096];
                while let Ok(n) = socket.read(&mut rest).await {
                    if n == 0 || socket.write_all(&rest[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    }

    #[tokio::test]
    async fn learns_a_fragmenting_profile_against_a_censoring_origin() {
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        tokio::spawn(censoring_server(origin, "blocked.test"));

        let store = Arc::new(Store::new(""));
        let ctx = Arc::new(context(store.clone()));
        let (relay_side, mut app) = pair().await;
        let task = {
            let ctx = ctx.clone();
            tokio::spawn(async move {
                relay(
                    relay_side,
                    &ctx,
                    "127.0.0.1".into(),
                    port,
                    None,
                    port,
                    Vec::new(),
                )
                .await
            })
        };

        let hello = build_client_hello(&HelloOptions {
            server_name: "blocked.test".into(),
            ..Default::default()
        });
        app.write_all(&hello).await.unwrap();
        let mut reply = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), app.read_exact(&mut reply))
            .await
            .expect("server answered")
            .unwrap();
        assert_eq!(reply, SERVER_HELLO);

        // Application data now flows through the pump.
        app.write_all(b"ping").await.unwrap();
        let mut echo = [0u8; 4];
        app.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"ping");
        drop(app);
        task.await.unwrap();

        // One differential is only a candidate.
        assert_eq!(store.lookup("test-network", "blocked.test"), "");
        assert_eq!(store.candidate_count(), 1);
    }

    #[tokio::test]
    async fn blocked_ad_host_is_closed_without_contacting_the_origin() {
        sh_adblock::global().replace(sh_adblock::parse_domains("ads.relay-test.example\n"));
        let origin = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = origin.local_addr().unwrap().port();
        let ctx = context(Arc::new(Store::new("")));
        let (relay_side, mut app) = pair().await;
        let hello = build_client_hello(&HelloOptions {
            server_name: "x.ads.relay-test.example".into(),
            ..Default::default()
        });
        app.write_all(&hello).await.unwrap();
        relay(
            relay_side,
            &ctx,
            "127.0.0.1".into(),
            port,
            Some("127.0.0.1".parse().unwrap()),
            port,
            Vec::new(),
        )
        .await;
        let mut rest = Vec::new();
        let _ = app.read_to_end(&mut rest).await;
        assert!(rest.is_empty());
        // The origin never saw a connection.
        assert!(
            tokio::time::timeout(Duration::from_millis(200), origin.accept())
                .await
                .is_err()
        );
        sh_adblock::global().replace(sh_adblock::DomainSet::new());
    }
}
