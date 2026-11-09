//! The packet loop (port of `WinDivertInterceptor`, `src/WinDivertInterceptor.cpp`).
//!
//! TCP/443 is reflected into the relay, UDP/53 into the DNS proxy, and the
//! relay's private connect port is mapped back to TCP/443. Only tuples whose
//! SYN passed through here are rewritten, so engine (re)starts leave existing
//! connections alone. `Processor` holds all per-packet logic and is driven by
//! tests without the driver; `Interceptor` owns the handles and the thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use sh_core::clock::now_ms;
use sh_core::recovery;
use sh_flow::quic::{AdaptiveRegistry, Decision};
use sh_flow::{
    DatagramRegistry, DatagramRoute, FlowKind, FlowRegistry, PacketRoute, PolicyRegistry,
    TcpFlowTable, route_datagram, route_packet,
};
use sh_proto::packet::{self as strategy, Mode};

use crate::ffi::{self, Address, Divert};
use crate::packet::{self, MTU_MAX, Parsed, TCP_ACK, TCP_FIN, TCP_RST, TCP_SYN, Transport};
use crate::process::{Endpoint, Filter};

const HTTPS_PORT: u16 = 443;
const DNS_PORT: u16 = 53;
const PRIORITY: i16 = 123;
const BATCH: usize = 64;

// Re-injection fails per packet far more often than per engine (an
// unreachable peer, a packet the stack refuses). Only a long unbroken run of
// failures is treated as a dead handle and stops the engine.
const FATAL_SEND_FAILURES: u32 = 16;
const FATAL_SEND_WINDOW_MS: u64 = 500;
const SEND_STREAK_GAP_MS: u64 = 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QuicMode {
    #[default]
    Allow,
    Adaptive,
    Block,
}

#[derive(Debug, Clone, Copy)]
pub struct Settings {
    pub proxy_port: u16,
    pub dns_proxy_port: u16,
    pub connect_port: u16,
    pub quic_mode: QuicMode,
    pub capture_dns: bool,
}

impl Settings {
    fn valid(&self) -> bool {
        let (p, d, c) = (self.proxy_port, self.dns_proxy_port, self.connect_port);
        p != 0
            && d != 0
            && c != 0
            && p != c
            && p != d
            && d != c
            && ![p, d, c].contains(&HTTPS_PORT)
            && d != DNS_PORT
    }

    fn process_aware_quic_block(&self, filter: Option<&Filter>) -> bool {
        self.quic_mode == QuicMode::Block && filter.is_some_and(Filter::enabled)
    }

    pub fn filter(&self, process_filter: Option<&Filter>) -> String {
        let quic = if self.quic_mode == QuicMode::Adaptive
            || self.process_aware_quic_block(process_filter)
        {
            " or (udp and ((outbound and udp.DstPort == 443) or (inbound and udp.SrcPort == 443)))"
        } else {
            ""
        };
        let dns = if self.capture_dns {
            format!(
                " or (udp and outbound and (udp.DstPort == {DNS_PORT} or udp.SrcPort == {}))",
                self.dns_proxy_port
            )
        } else {
            String::new()
        };
        format!(
            "!loopback and ((tcp and ((outbound and (tcp.DstPort == {HTTPS_PORT} or \
             tcp.DstPort == {} or tcp.SrcPort == {})) or \
             (inbound and tcp.SrcPort == {HTTPS_PORT}))){dns}{quic})",
            self.connect_port, self.proxy_port
        )
    }
}

/// Shared state the relay, DNS proxy and packet loop all see.
#[derive(Clone)]
pub struct Registries {
    pub flows: Arc<FlowRegistry>,
    pub datagrams: Arc<DatagramRegistry>,
    pub policies: Arc<PolicyRegistry>,
    pub process_filter: Option<Arc<Filter>>,
}

/// Packets queued for re-injection after one read batch. Lengths are kept so
/// a failed batch send can resume packet by packet.
#[derive(Default)]
pub struct Batch {
    pub bytes: Vec<u8>,
    pub addresses: Vec<Address>,
    pub lengths: Vec<usize>,
}

impl Batch {
    fn clear(&mut self) {
        self.bytes.clear();
        self.addresses.clear();
        self.lengths.clear();
    }

    fn push(&mut self, packet: &[u8], address: Address) {
        self.bytes.extend_from_slice(packet);
        self.addresses.push(address);
        self.lengths.push(packet.len());
    }

    fn rollback(&mut self, packets: usize, bytes: usize) {
        self.addresses.truncate(packets);
        self.lengths.truncate(packets);
        self.bytes.truncate(bytes);
    }

    /// The i-th queued packet (tests).
    pub fn packet(&self, index: usize) -> &[u8] {
        let start: usize = self.lengths[..index].iter().sum();
        &self.bytes[start..start + self.lengths[index]]
    }
}

fn random_bytes() -> [u8; 32] {
    use std::hash::{BuildHasher, Hasher};
    // A QUIC prime only needs unpredictable-looking connection IDs, not
    // cryptographic strength; RandomState is seeded from the OS.
    let mut out = [0u8; 32];
    for chunk in out.chunks_mut(8) {
        let value = std::collections::hash_map::RandomState::new()
            .build_hasher()
            .finish();
        chunk.copy_from_slice(&value.to_ne_bytes());
    }
    out
}

pub struct Processor {
    settings: Settings,
    registries: Registries,
    quic: AdaptiveRegistry,
    // Tuples whose SYN this engine rewrote; only these keep being rewritten.
    tcp_flows: TcpFlowTable,
}

impl Processor {
    pub fn new(settings: Settings, registries: Registries) -> Self {
        Self {
            settings,
            registries,
            quic: AdaptiveRegistry::default(),
            tcp_flows: TcpFlowTable::default(),
        }
    }

    fn filter(&self) -> Option<&Filter> {
        self.registries
            .process_filter
            .as_deref()
            .filter(|f| f.enabled())
    }

    fn endpoint(data: &[u8], p: &Parsed, outbound: bool) -> Endpoint {
        let (source, destination) = (
            packet::address_bytes(data, p, false),
            packet::address_bytes(data, p, true),
        );
        let (sp, dp) = (
            packet::source_port(data, p),
            packet::destination_port(data, p),
        );
        Endpoint {
            ipv6: p.ipv6,
            udp: p.transport == Some(Transport::Udp),
            local_address: if outbound { source } else { destination },
            remote_address: if outbound { destination } else { source },
            local_port: if outbound { sp } else { dp },
            remote_port: if outbound { dp } else { sp },
        }
    }

    /// Handles one captured packet, queueing what must be sent in `out`.
    pub fn process(&self, data: &mut [u8], mut address: Address, out: &mut Batch, now: u64) {
        let Some(p) = packet::parse(data) else {
            out.push(data, address);
            return;
        };
        match p.transport {
            Some(Transport::Tcp) => self.process_tcp(data, &p, address, out, now),
            Some(Transport::Udp) => self.process_udp(data, &p, &mut address, out, now),
            None => out.push(data, address),
        }
    }

    fn process_tcp(
        &self,
        data: &mut [u8],
        p: &Parsed,
        mut address: Address,
        out: &mut Batch,
        now: u64,
    ) {
        let s = &self.settings;
        let (sp, dp) = (
            packet::source_port(data, p),
            packet::destination_port(data, p),
        );
        let flags = packet::tcp_flags(data, p);
        let (fin, rst) = (flags & TCP_FIN != 0, flags & TCP_RST != 0);
        let syn = flags & TCP_SYN != 0 && flags & TCP_ACK == 0;
        let outbound = address.outbound();
        let route = route_packet(outbound, sp, dp, HTTPS_PORT, s.proxy_port, s.connect_port);
        let source = packet::address(data, p, false);
        let destination = packet::address(data, p, true);

        // The port alone never decides: a packet is rewritten only when it
        // belongs to a tuple whose SYN passed through here (and, for client
        // flows, the process rules). Connections that predate the engine,
        // processes a rule leaves alone and the relay's own server-side
        // replies are forwarded untouched.
        let owned = match route {
            PacketRoute::ReflectClientToProxy => {
                let filter = self.filter();
                if syn {
                    let bypass = filter.is_some_and(|f| {
                        !f.should_intercept(&Self::endpoint(data, p, true), true, true, now)
                    });
                    if bypass {
                        self.tcp_flows.remove(FlowKind::Client, destination, sp);
                    } else {
                        self.tcp_flows.add(FlowKind::Client, destination, sp, now);
                    }
                    !bypass
                } else {
                    let owned =
                        self.tcp_flows
                            .track(FlowKind::Client, destination, sp, fin, rst, now);
                    if owned
                        && rst
                        && let Some(f) = filter
                    {
                        f.forget(&Self::endpoint(data, p, true));
                    }
                    owned
                }
            }
            PacketRoute::ReflectProxyToClient => {
                self.tcp_flows
                    .track(FlowKind::Client, destination, dp, fin, rst, now)
            }
            PacketRoute::RedirectProxyToTarget => {
                // shortcut: any local program dialing the private connect port
                // is mapped to :443 (a high private port); upgrade to an
                // owner-PID check on the SYN if that ever collides.
                if syn {
                    self.tcp_flows.add(FlowKind::Upstream, destination, sp, now);
                } else {
                    self.tcp_flows
                        .track(FlowKind::Upstream, destination, sp, fin, rst, now);
                }
                true
            }
            PacketRoute::RedirectTargetToProxy => {
                self.tcp_flows
                    .track(FlowKind::Upstream, source, dp, fin, rst, now)
            }
            PacketRoute::Pass => false,
        };

        if !owned {
            out.push(data, address);
            return;
        }
        match route {
            PacketRoute::ReflectClientToProxy => {
                if syn {
                    self.registries
                        .flows
                        .observe(destination, sp, HTTPS_PORT, s.connect_port, now);
                }
                packet::set_destination_port(data, p, s.proxy_port);
                packet::swap_addresses(data, p);
                address.set_outbound(false);
            }
            PacketRoute::ReflectProxyToClient => {
                packet::set_source_port(data, p, HTTPS_PORT);
                packet::swap_addresses(data, p);
                address.set_outbound(false);
            }
            PacketRoute::RedirectProxyToTarget => {
                packet::set_destination_port(data, p, HTTPS_PORT);
            }
            PacketRoute::RedirectTargetToProxy => {
                // Only the SYN-ACK carries a clean TTL sample of the path.
                if flags & TCP_SYN != 0 && flags & TCP_ACK != 0 {
                    self.registries
                        .policies
                        .observe_hop(source, dp, packet::ttl(data, p), now);
                }
                packet::set_source_port(data, p, s.connect_port);
            }
            PacketRoute::Pass => {}
        }
        packet::fix_checksums(data, p);
        address.set_checksums_valid();

        let payload = &data[p.payload_offset..];
        let appended = route == PacketRoute::RedirectProxyToTarget
            && payload.len() >= 2
            && sh_proto::tls::looks_like_tls_record(payload)
            && self.apply_strategy(data, p, address, destination, sp, out, now);
        if !appended {
            out.push(data, address);
        }
    }

    /// Applies the armed packet profile to an outgoing ClientHello. Returns
    /// true when the packet was replaced by its transformed form in `out`.
    #[allow(clippy::too_many_arguments)]
    fn apply_strategy(
        &self,
        data: &[u8],
        p: &Parsed,
        address: Address,
        target: sh_flow::PeerAddr,
        source_port: u16,
        out: &mut Batch,
        now: u64,
    ) -> bool {
        let policies = &self.registries.policies;
        let sequence = packet::tcp_sequence(data, p);
        let Some(policy) = policies.take(target, source_port, Some(sequence), now) else {
            return false;
        };
        let payload = &data[p.payload_offset..];
        let (appended, applied) = match policy.mode {
            Mode::None => (false, false),
            Mode::IpFragment if !p.ipv6 => {
                let header = p.transport_offset;
                // The cut must be a multiple of 8 and still inside the
                // hostname; a very short name has no such cut and is sent
                // whole (and reported as not applied).
                let boundary = strategy::ipv4_fragment_boundary(
                    p.payload_offset - header,
                    &policy,
                    payload.len(),
                );
                let fragments = if boundary == 0 {
                    Vec::new()
                } else {
                    strategy::build_ipv4_fragments(data, header, header + boundary)
                };
                let ok = fragments.len() == 2;
                if ok {
                    for fragment in &fragments {
                        out.push(fragment, address);
                    }
                }
                (ok, ok)
            }
            Mode::ReverseOrder | Mode::SequenceOverlap | Mode::IpFragment => {
                let (before, bytes_before) = (out.addresses.len(), out.bytes.len());
                let mut segment_policy = policy.clone();
                if segment_policy.mode == Mode::IpFragment {
                    segment_policy.mode = Mode::ReverseOrder;
                }
                let segments = strategy::build_segments(payload, &segment_policy);
                for segment in &segments {
                    if let Some(variant) = packet::build_variant(
                        data,
                        p,
                        &segment.payload,
                        segment.sequence_offset,
                        0,
                        false,
                    ) {
                        out.push(&variant, address);
                    }
                }
                let ok = !segments.is_empty() && out.addresses.len() - before == segments.len();
                if !ok {
                    out.rollback(before, bytes_before);
                }
                // Reordered segments only count as the profile when the cut
                // really lands inside the hostname.
                let split = strategy::segment_split(&policy, payload.len());
                (ok, ok && strategy::splits_sni(&policy, split))
            }
            Mode::FakeBadSequence | Mode::FakeBadChecksum | Mode::FakeAutoTtl => {
                let fake = strategy::build_fake_client_hello(&policy.cover_sni);
                let offset = if policy.mode == Mode::FakeBadSequence {
                    policy.fake_sequence_delta
                } else {
                    0
                };
                let ttl = if policy.mode == Mode::FakeAutoTtl {
                    policy.fake_ttl
                } else {
                    0
                };
                // The checksum flags are already "valid" on an owned packet, so
                // WinDivert injects a deliberately wrong checksum as it is.
                let corrupt = policy.mode == Mode::FakeBadChecksum;
                match packet::build_variant(data, p, &fake, offset, ttl, corrupt) {
                    Some(variant) => {
                        out.push(&variant, address);
                        tracing::trace!(
                            "Paket profili uygulandi: mod={:?} hedef={target}:443",
                            policy.mode
                        );
                        (false, true) // the real hello follows the fake
                    }
                    None => (false, false),
                }
            }
        };
        if applied {
            policies.note_applied(target, source_port, now);
        }
        appended
    }

    fn process_udp(
        &self,
        data: &mut [u8],
        p: &Parsed,
        address: &mut Address,
        out: &mut Batch,
        now: u64,
    ) {
        let s = &self.settings;
        let (sp, dp) = (
            packet::source_port(data, p),
            packet::destination_port(data, p),
        );
        let outbound = address.outbound();
        let route = route_datagram(outbound, sp, dp, DNS_PORT, s.dns_proxy_port);
        let scoped =
            (outbound && (dp == DNS_PORT || dp == HTTPS_PORT)) || (!outbound && sp == HTTPS_PORT);
        let bypass = scoped
            && self.filter().is_some_and(|f| {
                !f.should_intercept(&Self::endpoint(data, p, outbound), outbound, false, now)
            });
        if bypass {
            out.push(data, *address);
            return;
        }

        match route {
            DatagramRoute::ReflectDnsToProxy => {
                let server = packet::address(data, p, true);
                self.registries.datagrams.observe(server, sp, now);
                packet::set_destination_port(data, p, s.dns_proxy_port);
                packet::swap_addresses(data, p);
                address.set_outbound(false);
            }
            DatagramRoute::ReflectProxyToClient => {
                packet::set_source_port(data, p, DNS_PORT);
                packet::swap_addresses(data, p);
                address.set_outbound(false);
            }
            DatagramRoute::Pass => {}
        }
        if route != DatagramRoute::Pass {
            packet::fix_checksums(data, p);
            address.set_checksums_valid();
        }

        let quic = (outbound && dp == HTTPS_PORT) || (!outbound && sp == HTTPS_PORT);
        let mut drop = false;
        if route == DatagramRoute::Pass && quic {
            match s.quic_mode {
                QuicMode::Block => drop = true,
                QuicMode::Adaptive if outbound => {
                    // Established QUIC flows dominate here; the lock-free
                    // pre-check keeps them off the registry mutex.
                    let initial = sh_proto::quic::looks_like_initial(&data[p.payload_offset..]);
                    if self.quic.needs_outbound(initial) {
                        let server = packet::address(data, p, true);
                        match self.quic.outbound(server, sp, initial, now) {
                            Decision::PrimeAndPass => {
                                let prime = sh_proto::quic::build_prime_payload(random_bytes());
                                if let Some(variant) =
                                    packet::build_variant(data, p, &prime, 0, 0, false)
                                {
                                    let mut prime_address = *address;
                                    prime_address.set_checksums_valid();
                                    out.push(&variant, prime_address);
                                    tracing::trace!("QUIC Initial prime: {server}:{sp}");
                                }
                            }
                            Decision::Drop => {
                                drop = true;
                                tracing::info!("QUIC yanitsiz; TCP fallback: {server}:{sp}");
                            }
                            Decision::Pass => {}
                        }
                    }
                }
                QuicMode::Adaptive => {
                    if self.quic.needs_inbound() {
                        self.quic.inbound(packet::address(data, p, false), dp, now);
                    }
                }
                QuicMode::Allow => {}
            }
        }
        if !drop {
            out.push(data, *address);
        }
    }

    fn clear(&self) {
        self.tcp_flows.clear();
        self.quic.clear();
        self.registries.flows.clear();
        self.registries.datagrams.clear();
        self.registries.policies.clear();
        if let Some(filter) = &self.registries.process_filter {
            filter.clear();
        }
    }
}

/// Owns the WinDivert handles and the packet thread.
pub struct Interceptor {
    handle: Arc<Divert>,
    _quic_drop: Option<Divert>,
    processor: Arc<Processor>,
    running: Arc<AtomicBool>,
    fatal_error: Arc<AtomicU32>,
    worker: std::sync::Mutex<Option<JoinHandle<()>>>,
}

impl Interceptor {
    pub fn start(settings: Settings, registries: Registries) -> Result<Self, String> {
        if !settings.valid() {
            return Err("WinDivert port yapilandirmasi gecersiz".into());
        }
        let filter_text = settings.filter(registries.process_filter.as_deref());
        ffi::compile_filter(&filter_text)
            .map_err(|e| format!("WinDivert filtresi gecersiz {e}"))?;
        let handle = Divert::open(&filter_text, PRIORITY, 0)
            .map_err(|e| format!("WinDivert acilamadi: {}", ffi::open_error_text(&e)))?;

        // A short queue absorbs scheduling jitter without retaining much live
        // traffic if the process is suspended. A refused parameter is not
        // fatal (the driver keeps its default) but changes loss under load.
        for (param, value, name) in [
            (ffi::PARAM_QUEUE_LENGTH, 8192, "QUEUE_LENGTH"),
            (ffi::PARAM_QUEUE_SIZE, 8 * 1024 * 1024, "QUEUE_SIZE"),
            (ffi::PARAM_QUEUE_TIME, 1000, "QUEUE_TIME"),
        ] {
            if let Err(error) = handle.set_param(param, value) {
                tracing::warn!(
                    "WinDivert {name} ayarlanamadi: hata={error}; surucu varsayilani kullaniliyor"
                );
            }
        }

        let process_aware = settings.process_aware_quic_block(registries.process_filter.as_deref());
        let quic_drop = if settings.quic_mode == QuicMode::Block && !process_aware {
            const QUIC_FILTER: &str = "udp and !loopback and ((outbound and udp.DstPort == 443) or \
                                       (inbound and udp.SrcPort == 443))";
            ffi::compile_filter(QUIC_FILTER)
                .map_err(|e| format!("WinDivert QUIC filtresi gecersiz {e}"))?;
            Some(
                Divert::open(QUIC_FILTER, PRIORITY + 1, ffi::FLAG_DROP).map_err(|e| {
                    format!("QUIC filtresi acilamadi: {}", ffi::open_error_text(&e))
                })?,
            )
        } else {
            None
        };

        let handle = Arc::new(handle);
        let processor = Arc::new(Processor::new(settings, registries));
        let running = Arc::new(AtomicBool::new(true));
        let fatal_error = Arc::new(AtomicU32::new(0));
        let worker = {
            let (handle, processor, running, fatal) = (
                handle.clone(),
                processor.clone(),
                running.clone(),
                fatal_error.clone(),
            );
            std::thread::Builder::new()
                .name("windivert".into())
                .spawn(move || run(&handle, &processor, &running, &fatal))
                .map_err(|e| format!("WinDivert thread baslatilamadi: {e}"))?
        };

        if settings.capture_dns {
            tracing::info!(
                "WinDivert aktif: TCP/443 -> localhost:{}, DNS/53 -> localhost:{}",
                settings.proxy_port,
                settings.dns_proxy_port
            );
        } else {
            tracing::info!(
                "WinDivert aktif: TCP/443 -> localhost:{}, DNS sistemde kalir",
                settings.proxy_port
            );
        }
        match settings.quic_mode {
            QuicMode::Block if process_aware => tracing::info!(
                "QUIC modu=block: yalniz surec kuraliyla secilen UDP/443 akislari dusurulecek"
            ),
            QuicMode::Block => {
                tracing::info!("QUIC modu=block: UDP/443 istemcileri TCP'ye dusecek")
            }
            QuicMode::Adaptive => tracing::info!(
                "QUIC modu=adaptive: Initial prime, yanitsiz hedefte otomatik TCP fallback"
            ),
            QuicMode::Allow => tracing::info!("QUIC modu=allow: UDP/443 degistirilmeden geciyor"),
        }
        Ok(Self {
            handle,
            _quic_drop: quic_drop,
            processor,
            running,
            fatal_error,
            worker: std::sync::Mutex::new(Some(worker)),
        })
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Win32 error that stopped the loop (0 while healthy).
    pub fn fatal_error_code(&self) -> u32 {
        self.fatal_error.load(Ordering::SeqCst)
    }

    /// Idempotent; callable from any thread.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
        self.handle.shutdown();
        let worker = self.worker.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(worker) = worker {
            let _ = worker.join();
            self.processor.clear();
        }
    }
}

impl Drop for Interceptor {
    fn drop(&mut self) {
        self.stop();
    }
}

fn run(handle: &Divert, processor: &Processor, running: &AtomicBool, fatal: &AtomicU32) {
    let mut buffer = vec![0u8; MTU_MAX * BATCH];
    let mut addresses = [Address::default(); BATCH];
    let mut batch = Batch::default();
    let mut read_retries = 0u32;
    let mut sends = SendAccounting::default();
    let sleep = |ms: u32| std::thread::sleep(Duration::from_millis(u64::from(ms)));

    while running.load(Ordering::SeqCst) {
        let (received, count) = match handle.recv(&mut buffer, &mut addresses) {
            Ok(value) => value,
            Err(error) => {
                if !running.load(Ordering::SeqCst) {
                    break;
                }
                if recovery::should_retry_windivert_read(error, read_retries) {
                    let delay = recovery::windivert_retry_delay_ms(read_retries);
                    read_retries += 1;
                    tracing::warn!(
                        "WinDivert paket okuma gecici hata={error} yeniden deneme={read_retries}/{} ({delay} ms)",
                        recovery::MAX_WINDIVERT_READ_RETRIES
                    );
                    sleep(delay);
                    continue;
                }
                fatal.store(error, Ordering::SeqCst);
                running.store(false, Ordering::SeqCst);
                tracing::error!(
                    "WinDivert paket okuyucusu durdu: hata={error}; fail-open ile filtre kapatiliyor"
                );
                break;
            }
        };
        if read_retries != 0 {
            tracing::info!("WinDivert paket okuyucusu {read_retries} denemede toparlandi");
            read_retries = 0;
        }

        batch.clear();
        let now = now_ms();
        let mut rest = &mut buffer[..received];
        for address in &addresses[..count] {
            if rest.is_empty() {
                break;
            }
            // A malformed length forwards the remainder as one packet, as
            // WinDivertHelperParsePacket would.
            let length = packet::packet_len(rest).unwrap_or(rest.len());
            let (current, tail) = std::mem::take(&mut rest).split_at_mut(length);
            processor.process(current, *address, &mut batch, now);
            rest = tail;
        }
        if batch.addresses.is_empty() {
            continue;
        }
        if !send_batch(handle, &batch, running, fatal, &mut sends) {
            break;
        }
    }
}

#[derive(Default)]
struct SendAccounting {
    failed: u32,
    streak_start_ms: u64,
    last_failure_ms: u64,
}

impl SendAccounting {
    /// False when the run of failures says the handle is gone.
    fn failed(&mut self, error: u32, now: u64) -> bool {
        if self.failed == 0 || now - self.last_failure_ms > SEND_STREAK_GAP_MS {
            self.failed = 0;
            self.streak_start_ms = now;
        }
        self.last_failure_ms = now;
        self.failed += 1;
        if self.failed == 1 {
            tracing::warn!("WinDivert paket geri gonderme hatasi: {error}");
        }
        !(self.failed >= FATAL_SEND_FAILURES && now - self.streak_start_ms >= FATAL_SEND_WINDOW_MS)
    }
}

/// One send for the whole batch is the fast path. If it fails part-way, the
/// packets before the failing one are already on the wire, so the rest are
/// resent one by one: a single bad packet must not take its neighbours (other
/// connections) down with it. Returns false when the engine must stop.
fn send_batch(
    handle: &Divert,
    batch: &Batch,
    running: &AtomicBool,
    fatal: &AtomicU32,
    sends: &mut SendAccounting,
) -> bool {
    let count = batch.addresses.len();
    let mut next = 0;
    if count > 1 {
        match handle.send(&batch.bytes, &batch.addresses) {
            Ok(()) => {
                sends.failed = 0;
                return true;
            }
            Err((_, sent)) => {
                if !running.load(Ordering::SeqCst) {
                    return false;
                }
                let mut covered = 0;
                while next < count && covered + batch.lengths[next] <= sent {
                    covered += batch.lengths[next];
                    next += 1;
                }
                if covered != sent {
                    next = 0; // unreliable count: resend all
                }
            }
        }
    }
    let mut offset: usize = batch.lengths[..next].iter().sum();
    for index in next..count {
        if !running.load(Ordering::SeqCst) {
            return false;
        }
        let packet = &batch.bytes[offset..offset + batch.lengths[index]];
        offset += batch.lengths[index];
        let address = std::slice::from_ref(&batch.addresses[index]);
        // Retry only resource exhaustion (the class the read side treats as
        // transient); anything else is that packet's own failure.
        let mut retries = 0;
        let result = loop {
            match handle.send(packet, address) {
                Ok(()) => break Ok(()),
                Err((error, _))
                    if running.load(Ordering::SeqCst)
                        && recovery::should_retry_windivert_read(error, retries) =>
                {
                    std::thread::sleep(Duration::from_millis(u64::from(
                        recovery::windivert_retry_delay_ms(retries),
                    )));
                    retries += 1;
                }
                Err((error, _)) => break Err(error),
            }
        };
        match result {
            Ok(()) => sends.failed = 0,
            Err(error) if running.load(Ordering::SeqCst) => {
                if !sends.failed(error, now_ms()) {
                    fatal.store(error, Ordering::SeqCst);
                    running.store(false, Ordering::SeqCst);
                    return false;
                }
            }
            Err(_) => return false,
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::tests::build;
    use sh_flow::PeerAddr;
    use sh_proto::packet::Policy;

    const PROXY: u16 = 18080;
    const DNS_PROXY: u16 = 18053;
    const CONNECT: u16 = 65534;

    fn processor(quic_mode: QuicMode) -> Processor {
        Processor::new(
            Settings {
                proxy_port: PROXY,
                dns_proxy_port: DNS_PROXY,
                connect_port: CONNECT,
                quic_mode,
                capture_dns: true,
            },
            Registries {
                flows: Arc::default(),
                datagrams: Arc::default(),
                policies: Arc::default(),
                process_filter: None,
            },
        )
    }

    fn outbound() -> Address {
        let mut address = Address::default();
        address.set_outbound(true);
        address
    }

    fn run_one(p: &Processor, mut packet: Vec<u8>, address: Address) -> Batch {
        let mut out = Batch::default();
        p.process(&mut packet, address, &mut out, 1000);
        out
    }

    fn ports_and_addresses(data: &[u8]) -> (u16, u16, PeerAddr, PeerAddr) {
        let p = packet::parse(data).unwrap();
        (
            packet::source_port(data, &p),
            packet::destination_port(data, &p),
            packet::address(data, &p, false),
            packet::address(data, &p, true),
        )
    }

    #[test]
    fn filter_text_matches_the_cpp_engine() {
        let settings = Settings {
            proxy_port: 1080,
            dns_proxy_port: 5353,
            connect_port: 65534,
            quic_mode: QuicMode::Allow,
            capture_dns: true,
        };
        assert_eq!(
            settings.filter(None),
            "!loopback and ((tcp and ((outbound and (tcp.DstPort == 443 or tcp.DstPort == 65534 \
             or tcp.SrcPort == 1080)) or (inbound and tcp.SrcPort == 443))) or (udp and outbound \
             and (udp.DstPort == 53 or udp.SrcPort == 5353)))"
        );
        assert!(
            !Settings {
                proxy_port: 443,
                ..settings
            }
            .valid()
        );
        assert!(settings.valid());
    }

    #[test]
    fn syn_is_reflected_and_announced_and_unknown_flows_pass() {
        let p = processor(QuicMode::Allow);
        // A mid-flow packet of a connection that predates the engine.
        let old = build(
            false,
            true,
            ("10.0.0.5", 50001),
            ("1.2.3.4", 443),
            TCP_ACK,
            b"",
        );
        let out = run_one(&p, old.clone(), outbound());
        assert_eq!(out.packet(0), &old[..]);

        let syn = build(
            false,
            true,
            ("10.0.0.5", 50000),
            ("1.2.3.4", 443),
            TCP_SYN,
            b"",
        );
        let out = run_one(&p, syn, outbound());
        let (sp, dp, src, dst) = ports_and_addresses(out.packet(0));
        assert_eq!((sp, dp), (50000, PROXY));
        assert_eq!(src, PeerAddr::parse("1.2.3.4").unwrap());
        assert_eq!(dst, PeerAddr::parse("10.0.0.5").unwrap());
        assert!(!out.addresses[0].outbound());
        let target = p.registries.flows.claim(src, 50000, 1000).unwrap();
        assert_eq!(target.address, PeerAddr::parse("1.2.3.4").unwrap());
        assert_eq!(target.connect_port, CONNECT);

        // The relay's answer goes back looking like it came from :443.
        let reply = build(
            false,
            true,
            ("10.0.0.5", PROXY),
            ("1.2.3.4", 50000),
            TCP_SYN | TCP_ACK,
            b"",
        );
        let out = run_one(&p, reply, outbound());
        let (sp, dp, src, dst) = ports_and_addresses(out.packet(0));
        assert_eq!((sp, dp), (443, 50000));
        assert_eq!(src, PeerAddr::parse("1.2.3.4").unwrap());
        assert_eq!(dst, PeerAddr::parse("10.0.0.5").unwrap());
    }

    #[test]
    fn connect_port_maps_to_443_and_back() {
        let p = processor(QuicMode::Allow);
        let syn = build(
            true,
            true,
            ("2001:db8::5", 40000),
            ("2001:db8::9", CONNECT),
            TCP_SYN,
            b"",
        );
        let out = run_one(&p, syn, outbound());
        assert_eq!(ports_and_addresses(out.packet(0)).1, 443);

        let mut inbound = Address::default();
        inbound.set_outbound(false);
        let syn_ack = build(
            true,
            true,
            ("2001:db8::9", 443),
            ("2001:db8::5", 40000),
            TCP_SYN | TCP_ACK,
            b"",
        );
        let out = run_one(&p, syn_ack, inbound);
        assert_eq!(ports_and_addresses(out.packet(0)).0, CONNECT);
    }

    #[test]
    fn armed_fake_profile_sends_a_fake_before_the_real_hello() {
        let p = processor(QuicMode::Allow);
        let target = PeerAddr::parse("1.2.3.4").unwrap();
        let syn = build(
            false,
            true,
            ("10.0.0.5", 40000),
            ("1.2.3.4", CONNECT),
            TCP_SYN,
            b"",
        );
        run_one(&p, syn, outbound());
        let policy = Policy {
            mode: Mode::FakeBadSequence,
            ..Policy::default()
        };
        p.registries.policies.arm(target, 40000, policy, 1000);
        let hello =
            sh_proto::testing::build_client_hello(&sh_proto::testing::HelloOptions::default());
        let data = build(
            false,
            true,
            ("10.0.0.5", 40000),
            ("1.2.3.4", CONNECT),
            TCP_ACK,
            &hello,
        );
        let out = run_one(&p, data, outbound());
        assert_eq!(out.addresses.len(), 2);
        let fake = packet::parse(out.packet(0)).unwrap();
        assert_eq!(
            packet::tcp_sequence(out.packet(0), &fake),
            1000u32.wrapping_sub(10000)
        );
        assert_eq!(&out.packet(1)[fake.payload_offset..], &hello[..]);
        assert!(p.registries.policies.consume_applied(target, 40000, 1000));
    }

    #[test]
    fn dns_is_reflected_and_quic_block_drops() {
        let p = processor(QuicMode::Block);
        let query = build(false, false, ("10.0.0.5", 5555), ("8.8.8.8", 53), 0, b"q");
        let out = run_one(&p, query, outbound());
        let (sp, dp, src, _) = ports_and_addresses(out.packet(0));
        assert_eq!((sp, dp), (5555, DNS_PROXY));
        assert!(p.registries.datagrams.claim(src, 5555, 1000));

        let quic = build(false, false, ("10.0.0.5", 5556), ("8.8.8.8", 443), 0, b"x");
        assert!(run_one(&p, quic, outbound()).addresses.is_empty());
    }
}
