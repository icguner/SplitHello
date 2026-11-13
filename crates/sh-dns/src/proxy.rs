//! Transparent DNS proxy (port of `src/TransparentDnsProxy.cpp`). WinDivert
//! reflects UDP/53 here; only datagrams the packet loop announced (the
//! `DatagramRegistry`) are answered, so this is never an open resolver.

use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use sh_flow::{DatagramRegistry, PeerAddr};
use sh_proto::dns::{self, Query};
use tokio::net::UdpSocket;
use tokio::sync::{Semaphore, watch};

use crate::Resolver;

/// Each query can sit in a slow DoH call, so a few slow ones must not starve
/// the rest; still bounded.
const WORKERS: usize = 8;
const MAX_QUEUED_QUERIES: usize = 1024;
const MAX_DNS_DATAGRAM: usize = 4096;
/// The OS resolver retries within ~1-2 s and gives up in a few more; an answer
/// produced after that is wasted work and a spurious Worker request.
const MAX_QUEUE_AGE: Duration = Duration::from_millis(3000);
/// Overall budget per query, on top of the per-phase HTTP timeouts.
const JOB_DEADLINE_MS: u64 = 8000;

/// Builds the reply for one query (empty: send nothing). `deadline_ms` is in
/// the resolver's clock.
pub async fn build_reply(resolver: &Resolver, data: &[u8], deadline_ms: u64) -> Vec<u8> {
    let mut query = Query::default();
    if !dns::parse_query(data, &mut query) {
        // FORMERR/NOTIMP when the header is readable so the client does not
        // wait out its timeout; garbage without a usable header is dropped.
        tracing::debug!(
            "Desteklenmeyen veya bozuk DNS sorgusu (rcode {})",
            query.error
        );
        return if query.error != 0 {
            dns::build_error(&query, query.error)
        } else {
            Vec::new()
        };
    }

    // The Worker's own bootstrap names are never filtered, whatever the list says.
    let bootstrap = resolver.is_bootstrap_host(&query.name);
    if !bootstrap && sh_adblock::global().blocks(&query.name) {
        sh_adblock::record_blocked(&query.name);
        return dns::build_blocked(&query);
    }

    let mut response = Vec::new();
    if query.qtype == dns::TYPE_A || query.qtype == dns::TYPE_AAAA {
        // /resolve returns both families at once and warms the cache the relay
        // uses, restoring Happy Eyeballs without a second lookup per connection.
        let resolved = resolver.resolve(&query.name, deadline_ms).await;
        // A tracker hidden behind a first-party alias (CNAME cloaking) is given
        // away by the names the answer was reached through. Allow-listing the
        // site itself lets it through.
        let list = sh_adblock::global();
        if !bootstrap
            && !list.allows(&query.name)
            && resolved.cnames.iter().any(|name| list.blocks(name))
        {
            sh_adblock::record_blocked(&query.name);
            return dns::build_blocked(&query);
        }
        let addresses = if query.qtype == dns::TYPE_A {
            &resolved.v4
        } else {
            &resolved.v6
        };
        let ttl = if resolved.ttl_seconds == 0 {
            60
        } else {
            resolved.ttl_seconds
        };
        if !resolved.is_empty() {
            // One family's lookup errored: NODATA for it would be a lie.
            if !addresses.is_empty() || !resolved.transient {
                response = dns::build_response(&query, addresses, ttl, false, 0);
            }
        } else if resolved.allow_wire_fallback {
            // An older Worker, or a name /resolve cannot carry: the raw DoH
            // path yields the real RCODE.
            response = resolver.query_wire(data, deadline_ms).await;
        } else if !resolved.transient {
            // The Worker's verdict (NXDOMAIN / NODATA) reaches the app unchanged.
            response = dns::build_response(&query, &[] as &[&str], ttl, false, resolved.rcode);
        }
    } else {
        response = resolver.query_wire(data, deadline_ms).await;
        // ECH would hide the SNI from the filter and the DPI bypass; without the
        // key the browser sends a normal ClientHello.
        if (query.qtype == dns::TYPE_HTTPS || query.qtype == dns::TYPE_SVCB)
            && dns::strip_ech(&mut response)
        {
            tracing::debug!("DNS relay: {} icin ECH anahtari kaldirildi", query.name);
        }
    }
    if response.is_empty() {
        response = dns::build_response(&query, &[] as &[&str], 60, true, 0);
    }
    let limit = dns::CLASSIC_UDP_PAYLOAD.max(usize::from(query.edns_payload));
    dns::truncate_for_udp(&mut response, limit);
    response
}

pub struct DnsProxy {
    resolver: Arc<Resolver>,
    datagrams: Arc<DatagramRegistry>,
    running: AtomicBool,
    queued: AtomicUsize,
}

fn peer(address: SocketAddr) -> PeerAddr {
    PeerAddr::from(address.ip()).to_ip().into() // v4-mapped peers compare as v4
}

impl DnsProxy {
    pub fn new(resolver: Arc<Resolver>, datagrams: Arc<DatagramRegistry>) -> Arc<Self> {
        Arc::new(Self {
            resolver,
            datagrams,
            running: AtomicBool::new(false),
            queued: AtomicUsize::new(0),
        })
    }

    pub fn running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }

    /// Binds `[::]:port` dual-stack. Call before packet interception starts.
    pub fn bind(port: u16) -> std::io::Result<UdpSocket> {
        use socket2::{Domain, Protocol, Socket, Type};
        // shortcut: no SO_EXCLUSIVEADDRUSE (the engine probes for a free port
        // first); add it through raw setsockopt if port hijacking is reported.
        let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_only_v6(false)?;
        socket
            .bind(&SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0)).into())?;
        socket.set_nonblocking(true)?;
        UdpSocket::from_std(socket.into())
    }

    /// Serves until `shutdown` turns true or the socket fails.
    pub async fn run(self: Arc<Self>, socket: UdpSocket, mut shutdown: watch::Receiver<bool>) {
        let socket = Arc::new(socket);
        let workers = Arc::new(Semaphore::new(WORKERS));
        let mut buffer = vec![0u8; MAX_DNS_DATAGRAM];
        self.running.store(true, Ordering::SeqCst);
        tracing::info!(
            "Transparent DNS relay dinliyor: {:?}",
            socket.local_addr().ok()
        );

        loop {
            let received = tokio::select! {
                received = socket.recv_from(&mut buffer) => received,
                _ = shutdown.changed() => break,
            };
            let (length, from) = match received {
                Ok(value) => value,
                // ICMP port-unreachable surfaces as WSAECONNRESET on Windows UDP.
                Err(error)
                    if sh_core::recovery::should_continue_dns_receive(
                        error.raw_os_error().unwrap_or(0),
                    ) =>
                {
                    continue;
                }
                Err(error) => {
                    tracing::error!("DNS relay alicisi durdu: {error}");
                    break;
                }
            };
            if !self.datagrams.claim(peer(from), from.port(), now_ms()) {
                tracing::debug!("Yetkisiz transparent DNS datagrami reddedildi");
                continue;
            }
            let data = buffer[..length].to_vec();

            let mut query = Query::default();
            if dns::parse_query(&data, &mut query) && self.resolver.is_bootstrap_host(&query.name) {
                // Answer the Worker host from the bootstrap cache right away
                // rather than queueing it behind lookups that may need it.
                let reply = build_reply(&self.resolver, &data, 0).await;
                let _ = socket.send_to(&reply, from).await;
                continue;
            }
            if self.queued.load(Ordering::SeqCst) >= MAX_QUEUED_QUERIES {
                tracing::warn!("DNS relay kuyrugu dolu; sorgu dusuruldu");
                continue;
            }
            self.queued.fetch_add(1, Ordering::SeqCst);
            let (proxy, socket, workers) = (self.clone(), socket.clone(), workers.clone());
            let enqueued = Instant::now();
            tokio::spawn(async move {
                let permit = workers.acquire_owned().await;
                proxy.queued.fetch_sub(1, Ordering::SeqCst);
                if permit.is_err() || enqueued.elapsed() > MAX_QUEUE_AGE {
                    tracing::debug!("DNS relay: bayat sorgu atlandi (istemci vazgecmis olmali)");
                    return;
                }
                let deadline = proxy.resolver.now_ms() + JOB_DEADLINE_MS;
                let reply = build_reply(&proxy.resolver, &data, deadline).await;
                if reply.is_empty() {
                    return;
                }
                if let Err(error) = socket.send_to(&reply, from).await {
                    tracing::warn!("DNS relay cevap gonderme hatasi: {error}");
                }
            });
        }
        self.running.store(false, Ordering::SeqCst);
    }
}

fn now_ms() -> u64 {
    use std::sync::OnceLock;
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    1 + ORIGIN.get_or_init(Instant::now).elapsed().as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolver::tests::{FakeWorker, ok, resolver, status, upstream_answer};
    use sh_proto::testing::dns_query;

    fn read16(data: &[u8], at: usize) -> u16 {
        u16::from_be_bytes([data[at], data[at + 1]])
    }

    fn rcode(reply: &[u8]) -> u16 {
        read16(reply, 2) & 0x000F
    }

    /// A TXT answer with `payload` bytes of RDATA, to exceed UDP size limits.
    fn big_txt_answer(request: &sh_net::Request, payload: usize) -> sh_net::Response {
        let mut query = Query::default();
        if !dns::parse_query(&request.body, &mut query) {
            return status(400, 0);
        }
        query.edns_payload = 0; // an OPT record built here would precede the TXT answer
        let mut message = dns::build_response(&query, &[] as &[&str], 60, false, 0);
        message[7] = 1; // ANCOUNT = 1
        message.extend([0xC0, 0x0C, 0, 16, 0, 1, 0, 0, 0, 60]);
        message.extend((payload as u16).to_be_bytes());
        message.extend(std::iter::repeat_n(b'x', payload));
        ok(message)
    }

    #[tokio::test]
    async fn a_tracker_behind_a_first_party_alias_is_sinkholed_unless_the_site_is_allowed() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| {
            ok(
                r#"{"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0,"cnames":["edge.cloak-test.example"]}"#,
            )
        });
        let resolver = resolver(&worker);
        sh_adblock::global().replace(sh_adblock::parse_domains("cloak-test.example\n"));
        let cloaked = build_reply(
            &resolver,
            &dns_query("metrics.shop-test.example", dns::TYPE_A).build(),
            0,
        )
        .await;
        sh_adblock::global().set_allow(&["shop-test.example"]);
        let allowed = build_reply(
            &resolver,
            &dns_query("metrics.shop-test.example", dns::TYPE_A).build(),
            0,
        )
        .await;
        sh_adblock::global().set_allow(&[] as &[&str]);
        sh_adblock::global().replace(sh_adblock::DomainSet::new());

        // 0.0.0.0, not the real address.
        assert_eq!(read16(&cloaked, 6), 1);
        assert_eq!(&cloaked[cloaked.len() - 4..], &[0, 0, 0, 0]);
        assert_eq!(&allowed[allowed.len() - 4..], &[203, 0, 113, 5]);
    }

    #[tokio::test]
    async fn answers_address_queries_from_the_worker_with_edns_and_aged_ttls() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| {
            ok(
                r#"{"host":"x","a":["203.0.113.5","203.0.113.6"],"aaaa":["2001:db8::5"],"ttl":300,"rcode":0}"#,
            )
        });
        let resolver = resolver(&worker);
        let a = build_reply(
            &resolver,
            &dns_query("example.com", dns::TYPE_A)
                .id(0x4242)
                .edns(1232, false)
                .build(),
            0,
        )
        .await;
        assert_eq!(read16(&a, 0), 0x4242);
        assert_eq!(rcode(&a), 0);
        assert_eq!(read16(&a, 6), 2);
        assert_eq!(read16(&a, 10), 1); // OPT answers the client's OPT
        let aaaa = build_reply(
            &resolver,
            &dns_query("example.com", dns::TYPE_AAAA).build(),
            0,
        )
        .await;
        assert_eq!(read16(&aaaa, 6), 1);
        assert_eq!(read16(&aaaa, 10), 0);
        assert_eq!(worker.calls().0, 1); // one /resolve served both
        worker.advance(100_000);
        let later = build_reply(&resolver, &dns_query("example.com", dns::TYPE_A).build(), 0).await;
        assert_eq!(dns::inspect_response(&later).unwrap().answer_ttl, 200);
    }

    #[tokio::test]
    async fn passes_nxdomain_and_nodata_to_the_application() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |request| {
            if request.path.contains("nope.example") {
                ok(r#"{"host":"nope.example","a":[],"aaaa":[],"ttl":60,"rcode":3}"#)
            } else {
                ok(r#"{"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0}"#)
            }
        });
        let resolver = resolver(&worker);
        let nx = build_reply(
            &resolver,
            &dns_query("nope.example", dns::TYPE_A).id(1).build(),
            0,
        )
        .await;
        assert_eq!(rcode(&nx), u16::from(dns::RCODE_NX_DOMAIN));
        assert_eq!((read16(&nx, 6), read16(&nx, 0)), (0, 1));
        // The name exists but has no AAAA: NOERROR with an empty answer.
        let nodata = build_reply(
            &resolver,
            &dns_query("v4only.example", dns::TYPE_AAAA).build(),
            0,
        )
        .await;
        assert_eq!((rcode(&nodata), read16(&nodata, 6)), (0, 0));
    }

    #[tokio::test]
    async fn does_not_report_a_half_failed_lookup_as_nodata() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| {
            ok(r#"{"host":"x","a":["203.0.113.5"],"aaaa":[],"ttl":300,"rcode":0,"partial":true}"#)
        });
        let resolver = resolver(&worker);
        let aaaa = build_reply(
            &resolver,
            &dns_query("half.example", dns::TYPE_AAAA).build(),
            0,
        )
        .await;
        assert_eq!(rcode(&aaaa), u16::from(dns::RCODE_SERV_FAIL));
        let a = build_reply(
            &resolver,
            &dns_query("half.example", dns::TYPE_A).build(),
            0,
        )
        .await;
        assert_eq!((rcode(&a), read16(&a, 6)), (0, 1));
    }

    #[tokio::test]
    async fn uses_the_wire_relay_for_old_workers_and_other_types() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| status(404, 0));
        FakeWorker::set(&worker.wire, |r| {
            upstream_answer(r, &[], 0, false, dns::RCODE_NX_DOMAIN)
        });
        let resolver = resolver(&worker);
        let nx = build_reply(
            &resolver,
            &dns_query("gone.example", dns::TYPE_A).id(0x0A0A).build(),
            0,
        )
        .await;
        assert_eq!(rcode(&nx), u16::from(dns::RCODE_NX_DOMAIN));
        assert_eq!(read16(&nx, 0), 0x0A0A);
        assert_eq!(worker.calls().1, 1);
        let https = build_reply(
            &resolver,
            &dns_query("www.example.com", 65).id(0x0B0B).build(),
            0,
        )
        .await;
        assert_eq!(read16(&https, 0), 0x0B0B);
        assert_eq!(worker.calls(), (1, 2)); // only the A query used /resolve
    }

    #[tokio::test]
    async fn answers_servfail_when_the_worker_is_unreachable() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.resolve, |_| status(-1, 0));
        FakeWorker::set(&worker.wire, |_| status(-1, 0));
        let resolver = resolver(&worker);
        let a = build_reply(
            &resolver,
            &dns_query("down.example", dns::TYPE_A).id(0x0C0C).build(),
            0,
        )
        .await;
        assert_eq!(rcode(&a), u16::from(dns::RCODE_SERV_FAIL));
        assert_eq!(read16(&a, 0), 0x0C0C);
        let txt = build_reply(&resolver, &dns_query("down.example", 16).build(), 0).await;
        assert_eq!(rcode(&txt), u16::from(dns::RCODE_SERV_FAIL));
        assert!(!resolver.worker_unavailable()); // a blip is not an outage
    }

    #[tokio::test]
    async fn replies_formerr_notimp_or_nothing() {
        let worker = FakeWorker::new();
        let resolver = resolver(&worker);
        let status_query = build_reply(
            &resolver,
            &dns_query("example.com", dns::TYPE_A)
                .id(0x7777)
                .flags(0x1100)
                .build(),
            0,
        )
        .await;
        assert_eq!(status_query.len(), 12);
        assert_eq!(rcode(&status_query), u16::from(dns::RCODE_NOT_IMP));
        assert_eq!(read16(&status_query, 0), 0x7777);
        let chaos = build_reply(
            &resolver,
            &dns_query("version.bind", 16).id(0x5555).class(3).build(),
            0,
        )
        .await;
        assert_eq!(rcode(&chaos), u16::from(dns::RCODE_NOT_IMP));
        let bad_name = build_reply(
            &resolver,
            &dns_query("bad name.example", dns::TYPE_A)
                .id(0x6666)
                .build(),
            0,
        )
        .await;
        assert_eq!(rcode(&bad_name), u16::from(dns::RCODE_FORM_ERR));
        assert_eq!(read16(&bad_name, 0), 0x6666);
        // Nothing to address a reply to: a response packet, or a runt.
        assert!(
            build_reply(
                &resolver,
                &dns_query("example.com", dns::TYPE_A)
                    .id(1)
                    .flags(0x8180)
                    .build(),
                0
            )
            .await
            .is_empty()
        );
        assert!(build_reply(&resolver, &[1, 2, 3, 4, 5], 0).await.is_empty());
        assert_eq!(worker.calls(), (0, 0));
    }

    #[tokio::test]
    async fn truncates_oversized_answers_to_the_clients_udp_size() {
        let worker = FakeWorker::new();
        FakeWorker::set(&worker.wire, |r| big_txt_answer(r, 700));
        let resolver = resolver(&worker);
        // No EDNS: 512 bytes; header + question with TC=1 tells it to use TCP.
        let plain_query = dns_query("big.example", 16).id(0x0D0D).build();
        let plain = build_reply(&resolver, &plain_query, 0).await;
        assert_ne!(read16(&plain, 2) & 0x0200, 0);
        assert_eq!(read16(&plain, 6), 0);
        assert_eq!(plain.len(), plain_query.len());
        assert_eq!(read16(&plain, 0), 0x0D0D);
        // An advertised 4096 holds the whole answer; 600 still does not.
        let large = build_reply(
            &resolver,
            &dns_query("big.example", 16)
                .id(0x0E0E)
                .edns(4096, false)
                .build(),
            0,
        )
        .await;
        assert_eq!(read16(&large, 2) & 0x0200, 0);
        assert_eq!(read16(&large, 6), 1);
        assert!(large.len() > 700);
        let small = build_reply(
            &resolver,
            &dns_query("big.example", 16)
                .id(0x0F0F)
                .edns(600, false)
                .build(),
            0,
        )
        .await;
        assert_ne!(read16(&small, 2) & 0x0200, 0);
        // The plain and EDNS flavours are separate cache keys; 4096 and 600 share one.
        assert_eq!(worker.calls().1, 2);
    }

    #[tokio::test]
    async fn serves_only_announced_datagrams_over_udp() {
        let worker = FakeWorker::new();
        let resolver = Arc::new(resolver(&worker));
        let datagrams = Arc::new(DatagramRegistry::default());
        let proxy = DnsProxy::new(resolver, datagrams.clone());
        let socket = DnsProxy::bind(0).unwrap();
        let port = socket.local_addr().unwrap().port();
        let (stop, shutdown) = watch::channel(false);
        let server = tokio::spawn(proxy.clone().run(socket, shutdown));

        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let query = dns_query("example.com", dns::TYPE_A).id(0x5151).build();
        let target: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut reply = [0u8; 512];

        // Not announced: dropped silently.
        client.send_to(&query, target).await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(300), client.recv_from(&mut reply))
                .await
                .is_err()
        );

        // Announced by the packet loop: answered.
        datagrams.observe(
            PeerAddr::parse("127.0.0.1").unwrap(),
            client.local_addr().unwrap().port(),
            now_ms(),
        );
        client.send_to(&query, target).await.unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(5), client.recv_from(&mut reply))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(read16(&reply[..length], 0), 0x5151);
        assert_eq!(read16(&reply[..length], 6), 1);

        stop.send(true).unwrap();
        server.await.unwrap();
        assert!(!proxy.running());
    }
}
