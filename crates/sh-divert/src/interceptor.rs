//! The packet loop (port of `WinDivertInterceptor`, `src/WinDivertInterceptor.cpp`).
//!
//! Connections stay between the application and the server: of TCP/443 the
//! driver hands over only the packet that starts a TLS ClientHello, which is
//! re-injected transformed (a decoy first, or cut inside the hostname), and
//! the SYN-ACK, whose TTL gives the path length. UDP/53 is reflected into the
//! DNS proxy. Nothing else is captured, so a dead engine cannot hold traffic.
//! `Processor` holds all per-packet logic and is driven by tests without the
//! driver; `Interceptor` owns the handles and the thread.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use sh_core::clock::now_ms;
use sh_core::recovery;
use sh_flow::quic::{AdaptiveRegistry, Decision};
use sh_flow::{DatagramRegistry, DatagramRoute, HopRegistry, route_datagram};
use sh_proto::packet::{self as strategy, Mode};
use sh_proto::tls::ClientHello;
use sh_strategy::Learner;

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
    /// A profile applied to every ClientHello; None: learn per site.
    pub forced: Option<Mode>,
    pub dns_proxy_port: u16,
    pub quic_mode: QuicMode,
    /// Worker DNS: every query is reflected into the DNS proxy.
    pub capture_dns: bool,
    /// System DNS with protection lists: queries are read on their way to
    /// the system's resolver and only listed names are answered here.
    pub filter_dns: bool,
}

const CLIENT_HELLO: u8 = 0x01;
const SERVER_HELLO: u8 = 0x02;

/// The first bytes of a TLS record that starts this handshake message.
fn starts_handshake(payload: &[u8], message: u8) -> bool {
    payload.len() > 5 && payload[0] == 0x16 && payload[5] == message
}

impl Settings {
    fn valid(&self) -> bool {
        let d = self.dns_proxy_port;
        self.forced != Some(Mode::None) && d != 0 && d != HTTPS_PORT && d != DNS_PORT
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
        } else if self.filter_dns {
            format!(" or (udp and outbound and udp.DstPort == {DNS_PORT})")
        } else {
            String::new()
        };
        // Keep in step with `starts_handshake` and `observe_server`.
        format!(
            "!loopback and ((tcp and ((outbound and tcp.DstPort == {HTTPS_PORT} and \
             tcp.PayloadLength > 5 and tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01) or \
             (inbound and tcp.SrcPort == {HTTPS_PORT} and (tcp.Syn or tcp.Rst or tcp.Fin or \
             (tcp.PayloadLength > 5 and tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x02))))){dns}{quic})"
        )
    }
}

/// Shared state the DNS proxy and the packet loop both see.
#[derive(Clone)]
pub struct Registries {
    pub datagrams: Arc<DatagramRegistry>,
    pub hops: Arc<HopRegistry>,
    pub learner: Arc<Learner>,
    /// The current network's id: sites are learned per network.
    pub network: Arc<dyn Fn() -> String + Send + Sync>,
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
    /// Worker down: queries go on to the system's resolver, as in system DNS.
    dns_bypass: AtomicBool,
    hellos: AtomicU64,
    transformed: AtomicU64,
}

impl Processor {
    pub fn new(settings: Settings, registries: Registries) -> Self {
        Self {
            settings,
            registries,
            dns_bypass: AtomicBool::new(false),
            quic: AdaptiveRegistry::default(),
            hellos: AtomicU64::new(0),
            transformed: AtomicU64::new(0),
        }
    }

    /// (ClientHellos seen, ClientHellos really transformed) since start.
    pub fn hello_counts(&self) -> (u64, u64) {
        (
            self.hellos.load(Ordering::Relaxed),
            self.transformed.load(Ordering::Relaxed),
        )
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
        if !address.outbound() {
            self.observe_server(data, p, now);
            out.push(data, address);
            return;
        }

        // The filter already selects these; anything else is forwarded as it
        // came, as are the processes a rule leaves alone.
        let wanted = packet::destination_port(data, p) == HTTPS_PORT
            && starts_handshake(&data[p.payload_offset..], CLIENT_HELLO)
            && self.filter().is_none_or(|f| {
                f.should_intercept(&Self::endpoint(data, p, true), true, true, now)
            });
        if !wanted {
            out.push(data, address);
            return;
        }
        self.hellos.fetch_add(1, Ordering::Relaxed);
        // A long hello spans packets and only its first is here: the hostname
        // is known only when it sits in this one.
        let hello = sh_proto::tls::client_hello_prefix(&data[p.payload_offset..]);
        // shortcut: a name that sits in a later packet of a long hello is not
        // seen here (the DNS proxy still refuses it in Worker DNS mode); hold
        // the first packet for the second if that gap matters.
        if hello.has_sni() && sh_adblock::global().blocks(&hello.server_name) {
            sh_adblock::record_blocked(&hello.server_name);
            tracing::debug!("Reklam/izleyici engellendi: {}", hello.server_name);
            // Nothing reaches the ad host, and the application fails fast.
            if let Some((to_server, to_client)) = packet::build_resets(data, p) {
                address.set_checksums_valid();
                out.push(&to_server, address);
                address.set_outbound(false);
                out.push(&to_client, address);
            }
            return;
        }
        let mode = self.settings.forced.unwrap_or_else(|| {
            self.registries.learner.on_hello(
                &(self.registries.network)(),
                packet::address(data, p, true),
                packet::source_port(data, p),
                hello.has_sni().then_some(hello.server_name.as_str()),
                now,
            )
        });
        if mode == Mode::None {
            out.push(data, address);
            return;
        }
        // Variants are copies of this packet and are injected as they are (a
        // deliberately wrong checksum included), so its own must be final.
        packet::fix_checksums(data, p);
        address.set_checksums_valid();
        let (replaced, applied) = self.apply_strategy(data, p, address, mode, &hello, out, now);
        if applied {
            self.transformed.fetch_add(1, Ordering::Relaxed);
        }
        if !replaced {
            out.push(data, address);
        }
    }

    /// Inbound packets are only read: the SYN-ACK's TTL gives the path
    /// length, and what follows a hello (a ServerHello, or a reset or close
    /// before one) is the learner's verdict.
    fn observe_server(&self, data: &[u8], p: &Parsed, now: u64) {
        let flags = packet::tcp_flags(data, p);
        let server = packet::address(data, p, false);
        let client_port = packet::destination_port(data, p);
        if flags & TCP_SYN != 0 {
            if flags & TCP_ACK != 0 {
                self.registries
                    .hops
                    .observe(server, client_port, packet::ttl(data, p), now);
            }
        } else if self.settings.forced.is_some() {
            // A fixed profile learns nothing.
        } else if starts_handshake(&data[p.payload_offset..], SERVER_HELLO) {
            self.registries
                .learner
                .on_server_hello(server, client_port, now);
        } else if flags & (TCP_RST | TCP_FIN) != 0 {
            self.registries.learner.on_close(server, client_port, now);
        }
    }

    /// Transforms an outgoing ClientHello packet. Returns (the packet was
    /// replaced in `out`, the wire really changed). A retransmission is the
    /// same packet again and gets the same treatment.
    #[allow(clippy::too_many_arguments)]
    fn apply_strategy(
        &self,
        data: &[u8],
        p: &Parsed,
        address: Address,
        mode: Mode,
        hello: &ClientHello,
        out: &mut Batch,
        now: u64,
    ) -> (bool, bool) {
        let target = packet::address(data, p, true);
        let payload = &data[p.payload_offset..];
        let mut policy = strategy::policy_for(mode, hello);
        if policy.mode == Mode::FakeAutoTtl {
            let source_port = packet::source_port(data, p);
            match self.registries.hops.fake_ttl(target, source_port, now) {
                Some(ttl) => policy.fake_ttl = ttl,
                // No path sample, or a server too close for a decoy to die on
                // the way: send one the server discards by its sequence number.
                None => policy.mode = Mode::FakeBadSequence,
            }
        }
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
        (appended, applied)
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
        if outbound && dp == DNS_PORT && (!s.capture_dns || self.dns_bypass.load(Ordering::Relaxed))
        {
            // The name never resolves, so nothing is ever sent to the host,
            // over TCP or QUIC, whichever packet would have carried its name.
            match Self::blocked_dns_reply(data, p) {
                Some(reply) => {
                    address.set_outbound(false);
                    address.set_checksums_valid();
                    out.push(&reply, *address);
                }
                None => out.push(data, *address),
            }
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
                            Decision::Drop => drop = true,
                            Decision::Fallback => {
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

    /// The reply to a DNS query for a name on a protection list, addressed
    /// back to the application as if the resolver had sent it. None for
    /// every other query, which then goes on to the resolver untouched.
    fn blocked_dns_reply(data: &[u8], p: &Parsed) -> Option<Vec<u8>> {
        let mut query = sh_proto::dns::Query::default();
        if !sh_proto::dns::parse_query(&data[p.payload_offset..], &mut query)
            || !sh_adblock::global().blocks(&query.name)
        {
            return None;
        }
        sh_adblock::record_blocked(&query.name);
        let (client_port, server_port) = (
            packet::source_port(data, p),
            packet::destination_port(data, p),
        );
        let answer = sh_proto::dns::build_blocked(&query);
        let mut reply = packet::build_variant(data, p, &answer, 0, 0, false)?;
        packet::swap_addresses(&mut reply, p);
        packet::set_source_port(&mut reply, p, server_port);
        packet::set_destination_port(&mut reply, p, client_port);
        packet::fix_checksums(&mut reply, p);
        Some(reply)
    }

    fn clear(&self) {
        self.quic.clear();
        self.registries.datagrams.clear();
        self.registries.hops.clear();
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
                .spawn(move || {
                    let looped = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        run(&handle, &processor, &running, &fatal)
                    }));
                    // A dead loop with an open handle captures packets nobody
                    // reinjects: report it so the engine fails open.
                    if looped.is_err() {
                        fatal.store(u32::MAX, Ordering::SeqCst);
                        running.store(false, Ordering::SeqCst);
                    }
                })
                .map_err(|e| format!("WinDivert thread baslatilamadi: {e}"))?
        };

        let what = match settings.forced {
            Some(mode) => format!("sabit profil {mode:?}"),
            None => "site basina ogrenme".to_owned(),
        };
        if settings.capture_dns {
            tracing::info!(
                "WinDivert aktif: TLS ClientHello paketleri ({}), DNS/53 -> localhost:{}",
                what,
                settings.dns_proxy_port
            );
        } else {
            tracing::info!(
                "WinDivert aktif: TLS ClientHello paketleri ({}), DNS sistemde kalir",
                what
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

    /// (ClientHellos seen, ClientHellos really transformed) since start.
    pub fn hello_counts(&self) -> (u64, u64) {
        self.processor.hello_counts()
    }

    /// On: DNS queries are no longer reflected into the DNS proxy.
    pub fn set_dns_bypass(&self, on: bool) {
        self.processor.dns_bypass.store(on, Ordering::Relaxed);
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

    const DNS_PROXY: u16 = 18053;
    /// The protection list is process-wide: tests that fill it take turns.
    static LIST: std::sync::Mutex<()> = std::sync::Mutex::new(());
    const CLIENT: (&str, u16) = ("10.0.0.5", 40000);
    const SERVER: (&str, u16) = ("1.2.3.4", 443);

    /// `forced` None: the learner decides per site.
    fn processor(forced: Option<Mode>, quic_mode: QuicMode) -> Processor {
        Processor::new(
            Settings {
                forced,
                dns_proxy_port: DNS_PROXY,
                quic_mode,
                capture_dns: true,
                filter_dns: false,
            },
            Registries {
                datagrams: Arc::default(),
                hops: Arc::default(),
                learner: Arc::new(Learner::new("")),
                network: Arc::new(|| "test".into()),
                process_filter: None,
            },
        )
    }

    fn outbound() -> Address {
        let mut address = Address::default();
        address.set_outbound(true);
        address
    }

    fn inbound() -> Address {
        let mut address = Address::default();
        address.set_outbound(false);
        address
    }

    fn run_one(p: &Processor, mut packet: Vec<u8>, address: Address) -> Batch {
        let mut out = Batch::default();
        p.process(&mut packet, address, &mut out, 1000);
        out
    }

    fn hello() -> Vec<u8> {
        sh_proto::testing::build_client_hello(&sh_proto::testing::HelloOptions::default())
    }

    fn from_client(port: u16, payload: &[u8]) -> Vec<u8> {
        build(false, true, (CLIENT.0, port), SERVER, TCP_ACK, payload)
    }

    fn from_server(port: u16, flags: u8, payload: &[u8]) -> Vec<u8> {
        build(false, true, SERVER, (CLIENT.0, port), flags, payload)
    }

    /// The server's SYN-ACK as it arrives after `hops` routers.
    fn syn_ack(port: u16, hops: u8) -> Vec<u8> {
        let mut packet = from_server(port, TCP_SYN | TCP_ACK, b"");
        packet[8] = 64 - hops;
        packet
    }

    fn payload_of(data: &[u8]) -> &[u8] {
        &data[packet::parse(data).unwrap().payload_offset..]
    }

    /// `cargo test --release -p sh-divert -- --ignored --nocapture per_packet`
    #[test]
    #[ignore]
    fn per_packet_cost() {
        let p = processor(Some(Mode::FakeAutoTtl), QuicMode::Allow);
        let hello = from_client(CLIENT.1, &hello());
        let handshake = syn_ack(CLIENT.1, 8);
        let mut out = Batch::default();
        let rounds = 200_000;
        let started = std::time::Instant::now();
        for _ in 0..rounds {
            out.clear();
            for (packet, address) in [(&handshake, inbound()), (&hello, outbound())] {
                let mut data = packet.clone();
                p.process(&mut data, address, &mut out, 1000);
            }
        }
        let per = started.elapsed().as_nanos() / (rounds * 2);
        println!("per packet: {per} ns (SYN-ACK sample, and hello with decoy)");
    }

    #[test]
    fn filter_captures_only_handshake_packets() {
        let settings = Settings {
            forced: None,
            dns_proxy_port: 5353,
            quic_mode: QuicMode::Allow,
            capture_dns: true,
            filter_dns: false,
        };
        assert_eq!(
            settings.filter(None),
            "!loopback and ((tcp and ((outbound and tcp.DstPort == 443 and tcp.PayloadLength > 5 \
             and tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x01) or (inbound and tcp.SrcPort \
             == 443 and (tcp.Syn or tcp.Rst or tcp.Fin or (tcp.PayloadLength > 5 and \
             tcp.Payload[0] == 0x16 and tcp.Payload[5] == 0x02))))) or (udp and outbound and \
             (udp.DstPort == 53 or udp.SrcPort == 5353)))"
        );
        assert!(settings.valid());
        assert!(
            !Settings {
                dns_proxy_port: 443,
                ..settings
            }
            .valid()
        );
        assert!(
            !Settings {
                forced: Some(Mode::None),
                ..settings
            }
            .valid()
        );
    }

    #[test]
    fn decoy_goes_first_and_expires_before_the_server() {
        let p = processor(Some(Mode::FakeAutoTtl), QuicMode::Allow);
        let handshake = syn_ack(CLIENT.1, 8);
        assert_eq!(
            run_one(&p, handshake.clone(), inbound()).packet(0),
            &handshake[..]
        );

        let hello = hello();
        let data = from_client(CLIENT.1, &hello);
        // Twice: a retransmitted hello gets the same treatment.
        for _ in 0..2 {
            let out = run_one(&p, data.clone(), outbound());
            assert_eq!(out.addresses.len(), 2);
            let decoy = out.packet(0);
            let parsed = packet::parse(decoy).unwrap();
            assert_eq!(packet::ttl(decoy, &parsed), 6);
            assert_eq!(packet::tcp_sequence(decoy, &parsed), 1000);
            assert_ne!(payload_of(decoy), &hello[..]);
            assert!(starts_handshake(payload_of(decoy), CLIENT_HELLO));
            // The real hello follows untouched, with the stack's own TTL.
            assert_eq!(payload_of(out.packet(1)), &hello[..]);
            assert_eq!(out.packet(1)[8], 64);
        }
        assert_eq!(p.hello_counts(), (2, 2));
    }

    #[test]
    fn without_a_path_sample_the_decoy_is_out_of_window() {
        let p = processor(Some(Mode::FakeAutoTtl), QuicMode::Allow);
        // Three hops away: no router left for a decoy to expire at.
        run_one(&p, syn_ack(CLIENT.1, 3), inbound());
        let hello = hello();
        for port in [CLIENT.1, 40001] {
            let out = run_one(&p, from_client(port, &hello), outbound());
            assert_eq!(out.addresses.len(), 2);
            let decoy = packet::parse(out.packet(0)).unwrap();
            assert_eq!(
                packet::tcp_sequence(out.packet(0), &decoy),
                1000u32.wrapping_sub(10000)
            );
            assert_eq!(out.packet(0)[8], 64);
            assert_eq!(payload_of(out.packet(1)), &hello[..]);
        }
    }

    #[test]
    fn split_profile_replaces_the_hello_with_two_segments() {
        let p = processor(Some(Mode::SequenceOverlap), QuicMode::Allow);
        let hello = hello();
        let out = run_one(&p, from_client(CLIENT.1, &hello), outbound());
        assert_eq!(out.addresses.len(), 2);
        // The tail is sent first; the head completes the stream from byte 0.
        let head = packet::parse(out.packet(1)).unwrap();
        assert_eq!(packet::tcp_sequence(out.packet(1), &head), 1000);
        let head = payload_of(out.packet(1));
        assert!(!head.is_empty() && head.len() < hello.len());
        assert_eq!(head, &hello[..head.len()]);
        assert!(payload_of(out.packet(0)).ends_with(&hello[head.len()..]));
        assert_eq!(p.hello_counts(), (1, 1));
    }

    #[test]
    fn a_site_is_left_alone_until_its_hello_is_torn_down() {
        let p = processor(None, QuicMode::Allow);
        let hello = hello();
        let server_hello = [0x16, 3, 3, 0, 0x30, 0x02, 0, 0, 0x2C];

        // An open site: answered, so never touched, however often.
        for port in [40000, 40001] {
            run_one(&p, syn_ack(port, 8), inbound());
            let data = from_client(port, &hello);
            let out = run_one(&p, data.clone(), outbound());
            assert_eq!(out.addresses.len(), 1);
            assert_eq!(out.packet(0), &data[..]);
            let answer = from_server(port, TCP_ACK, &server_hello);
            assert_eq!(
                run_one(&p, answer.clone(), inbound()).packet(0),
                &answer[..]
            );
            // The close of a finished handshake says nothing.
            run_one(&p, from_server(port, TCP_ACK | TCP_FIN, b""), inbound());
        }
        assert_eq!(p.hello_counts(), (2, 0));

        // The DPI box resets the next hello: the reset passes, the site is marked.
        run_one(&p, syn_ack(40002, 8), inbound());
        assert_eq!(
            run_one(&p, from_client(40002, &hello), outbound())
                .addresses
                .len(),
            1
        );
        let reset = from_server(40002, TCP_RST, b"");
        assert_eq!(run_one(&p, reset.clone(), inbound()).packet(0), &reset[..]);

        // Its next connection gets the decoy, and the answer makes it stick.
        run_one(&p, syn_ack(40003, 8), inbound());
        let out = run_one(&p, from_client(40003, &hello), outbound());
        assert_eq!(out.addresses.len(), 2);
        assert_eq!(out.packet(0)[8], 6);
        assert!(p.registries.learner.is_empty());
        run_one(&p, from_server(40003, TCP_ACK, &server_hello), inbound());
        assert_eq!(
            p.registries.learner.learned(),
            vec![("test|discord.com".to_owned(), "packet-autottl")]
        );
        assert_eq!(p.hello_counts(), (4, 1));
    }

    #[test]
    fn a_blocked_ad_host_is_reset_on_both_sides_and_never_contacted() {
        let _turn = LIST.lock().unwrap_or_else(|p| p.into_inner());
        sh_adblock::global().replace(sh_adblock::parse_domains("ads.packet-test.example\n"));
        let p = processor(None, QuicMode::Allow);
        let hello = sh_proto::testing::build_client_hello(&sh_proto::testing::HelloOptions {
            server_name: "x.ads.packet-test.example".into(),
            ..Default::default()
        });
        let out = run_one(&p, from_client(CLIENT.1, &hello), outbound());
        sh_adblock::global().replace(sh_adblock::DomainSet::new());

        assert_eq!(out.addresses.len(), 2);
        let reset = TCP_RST | TCP_ACK;
        let (to_server, to_client) = (out.packet(0), out.packet(1));
        let parsed = packet::parse(to_server).unwrap();
        assert!(out.addresses[0].outbound() && !out.addresses[1].outbound());
        assert!(payload_of(to_server).is_empty() && payload_of(to_client).is_empty());
        assert_eq!(packet::tcp_flags(to_server, &parsed), reset);
        assert_eq!(packet::tcp_flags(to_client, &parsed), reset);
        assert_eq!(packet::tcp_sequence(to_server, &parsed), 1000);
        assert_eq!(packet::destination_port(to_server, &parsed), 443);
        // In the server's name: its sequence is what the client acknowledged
        // (0 in these packets), and it acknowledges the hello it never got.
        assert_eq!(packet::source_port(to_client, &parsed), 443);
        assert_eq!(packet::destination_port(to_client, &parsed), CLIENT.1);
        assert_eq!(
            packet::address(to_client, &parsed, false),
            PeerAddr::parse(SERVER.0).unwrap()
        );
        assert_eq!(packet::tcp_sequence(to_client, &parsed), 0);
        let at = parsed.transport_offset + 8;
        assert_eq!(
            u32::from_be_bytes(to_client[at..at + 4].try_into().unwrap()),
            1000 + hello.len() as u32
        );
        assert_eq!(p.hello_counts(), (1, 0));
    }

    #[test]
    fn everything_else_passes_as_it_came() {
        let p = processor(Some(Mode::FakeAutoTtl), QuicMode::Allow);
        let hello = hello();
        for (packet, address) in [
            // Application data and a TLS 1.2 key exchange on an open connection.
            (from_client(CLIENT.1, &[0x17; 64]), outbound()),
            (from_client(CLIENT.1, &[0x16, 3, 3, 0, 1, 16]), outbound()),
            // A hello to another port, and one coming in.
            (
                build(false, true, CLIENT, ("1.2.3.4", 8443), TCP_ACK, &hello),
                outbound(),
            ),
            (from_server(CLIENT.1, TCP_ACK, &hello), inbound()),
            (from_server(CLIENT.1, TCP_RST, b""), inbound()),
        ] {
            let out = run_one(&p, packet.clone(), address);
            assert_eq!(out.addresses.len(), 1);
            assert_eq!(out.packet(0), &packet[..]);
        }
        assert_eq!(p.hello_counts(), (0, 0));
    }

    #[test]
    fn dns_bypass_lets_queries_reach_the_system_resolver() {
        use sh_proto::testing::dns_query;
        let _turn = LIST.lock().unwrap_or_else(|p| p.into_inner());
        let p = processor(None, QuicMode::Allow);
        assert!(p.settings.capture_dns);
        let query = dns_query("www.dns-test.example", sh_proto::dns::TYPE_A).build();
        let packet = build(
            false,
            false,
            ("10.0.0.5", 5555),
            ("192.168.1.1", 53),
            0,
            &query,
        );

        let reflected = run_one(&p, packet.clone(), outbound());
        assert!(!reflected.addresses[0].outbound());

        p.dns_bypass.store(true, Ordering::Relaxed);
        let passed = run_one(&p, packet.clone(), outbound());
        assert_eq!(passed.packet(0), &packet[..]);
        assert!(passed.addresses[0].outbound());
    }

    #[test]
    fn system_dns_answers_only_listed_names_itself() {
        use sh_proto::testing::dns_query;
        let _turn = LIST.lock().unwrap_or_else(|p| p.into_inner());
        sh_adblock::global().replace(sh_adblock::parse_domains("ads.dns-test.example\n"));
        let mut p = processor(None, QuicMode::Allow);
        p.settings.capture_dns = false;
        p.settings.filter_dns = true;
        assert!(
            p.settings
                .filter(None)
                .ends_with(" or (udp and outbound and udp.DstPort == 53))")
        );
        let resolver = ("192.168.1.1", 53);
        let ask = |name: &str| {
            let query = dns_query(name, sh_proto::dns::TYPE_A).id(0x7777).build();
            let packet = build(false, false, ("10.0.0.5", 5555), resolver, 0, &query);
            (run_one(&p, packet.clone(), outbound()), packet)
        };
        let (blocked, _) = ask("x.ads.dns-test.example");
        let (passed, original) = ask("www.dns-test.example");
        sh_adblock::global().replace(sh_adblock::DomainSet::new());

        // Everything else goes to the resolver as it came.
        assert_eq!(passed.addresses.len(), 1);
        assert_eq!(passed.packet(0), &original[..]);
        assert!(passed.addresses[0].outbound());

        // The listed name is answered in the resolver's name with 0.0.0.0.
        assert_eq!(blocked.addresses.len(), 1);
        assert!(!blocked.addresses[0].outbound());
        let reply = blocked.packet(0);
        let parsed = packet::parse(reply).unwrap();
        assert_eq!(packet::source_port(reply, &parsed), 53);
        assert_eq!(packet::destination_port(reply, &parsed), 5555);
        assert_eq!(
            packet::address(reply, &parsed, false),
            PeerAddr::parse(resolver.0).unwrap()
        );
        let answer = payload_of(reply);
        assert_eq!(&answer[..2], &[0x77, 0x77]);
        assert_eq!(sh_proto::dns::inspect_response(answer).unwrap().answers, 1);
        assert_eq!(&answer[answer.len() - 4..], &[0, 0, 0, 0]);
    }

    #[test]
    fn dns_is_reflected_and_quic_block_drops() {
        let p = processor(None, QuicMode::Block);
        let query = build(false, false, ("10.0.0.5", 5555), ("8.8.8.8", 53), 0, b"q");
        let out = run_one(&p, query, outbound());
        let parsed = packet::parse(out.packet(0)).unwrap();
        assert_eq!(packet::source_port(out.packet(0), &parsed), 5555);
        assert_eq!(packet::destination_port(out.packet(0), &parsed), DNS_PROXY);
        let server: PeerAddr = packet::address(out.packet(0), &parsed, false);
        assert!(p.registries.datagrams.claim(server, 5555, 1000));

        let quic = build(false, false, ("10.0.0.5", 5556), ("8.8.8.8", 443), 0, b"x");
        assert!(run_one(&p, quic, outbound()).addresses.is_empty());
    }
}
