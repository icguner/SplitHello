use std::collections::HashMap;
use std::sync::Mutex;

use crate::PeerAddr;

const PENDING_FLOW_TTL_MS: u64 = 15_000;
const MAX_PENDING_FLOWS: usize = 8192;
const MAX_PENDING_DATAGRAMS_PER_TUPLE: u32 = 32;
/// Registries are swept at most this often; each lookup also checks its own
/// entry's expiry, so a late claim can never be authorized by a stale entry.
const PRUNE_INTERVAL_MS: u64 = 1000;
/// A live HTTPS connection can sit idle for hours (keep-alive, push channels);
/// losing its entry would turn the next packet into an unexplained RST.
const TCP_FLOW_IDLE_MS: u64 = 4 * 60 * 60 * 1000;
const TCP_FLOW_CLOSING_MS: u64 = 2 * 60 * 1000;
const MAX_TCP_FLOWS: usize = 65536;

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    // A panic while holding the lock cannot leave these maps inconsistent
    // (every update is a single insert/remove), so keep serving.
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The map is genuinely full of live entries: drop the 1/16 closest to
/// expiry. One O(n) pass frees room for n/16 inserts, so a connection storm
/// costs amortized O(1) per insert instead of a full scan on every one.
pub(crate) fn evict_oldest<K: Clone + Eq + std::hash::Hash, V>(
    map: &mut HashMap<K, V>,
    expires: impl Fn(&V) -> u64,
) {
    let mut oldest: Vec<(u64, K)> = map.iter().map(|(k, v)| (expires(v), k.clone())).collect();
    if oldest.is_empty() {
        return;
    }
    let evict = (oldest.len() / 16).max(1);
    oldest.select_nth_unstable_by_key(evict - 1, |(expires, _)| *expires);
    for (_, key) in &oldest[..evict] {
        map.remove(key);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    pub address: PeerAddr,
    pub target_port: u16,
    pub connect_port: u16,
}

struct Expiring<T> {
    entries: HashMap<(PeerAddr, u16), (T, u64)>,
    next_prune_ms: u64,
}

impl<T> Default for Expiring<T> {
    fn default() -> Self {
        Self {
            entries: HashMap::new(),
            next_prune_ms: 0,
        }
    }
}

impl<T> Expiring<T> {
    fn prune(&mut self, now_ms: u64) {
        self.entries.retain(|_, (_, expires)| *expires > now_ms);
    }

    fn prune_if_due(&mut self, now_ms: u64) {
        if now_ms >= self.next_prune_ms {
            self.prune(now_ms);
            self.next_prune_ms = now_ms + PRUNE_INTERVAL_MS;
        }
    }

    /// Call after `prune_if_due`: expired entries are swept at most once a
    /// second, never on every insert.
    fn make_room(&mut self, _now_ms: u64) {
        if self.entries.len() >= MAX_PENDING_FLOWS {
            evict_oldest(&mut self.entries, |(_, expires)| *expires);
        }
    }
}

/// The network-layer reflector makes the original server address appear as the
/// accepted socket's peer and preserves the application's source port. This
/// short-lived registry proves an accepted connection came from a SYN observed
/// by WinDivert, and carries the original destination into the relay. It is
/// what keeps the listener from being an open proxy.
#[derive(Default)]
pub struct FlowRegistry {
    inner: Mutex<Expiring<Target>>,
}

impl FlowRegistry {
    pub fn observe(
        &self,
        server: PeerAddr,
        client_port: u16,
        target_port: u16,
        connect_port: u16,
        now_ms: u64,
    ) {
        if client_port == 0 || target_port == 0 || connect_port == 0 {
            return;
        }
        let mut inner = lock(&self.inner);
        inner.prune_if_due(now_ms);
        inner.make_room(now_ms);
        inner.entries.insert(
            (server, client_port),
            (
                Target {
                    address: server,
                    target_port,
                    connect_port,
                },
                now_ms + PENDING_FLOW_TTL_MS,
            ),
        );
    }

    /// One-shot: a claimed (or expired) entry is gone afterwards.
    pub fn claim(&self, peer: PeerAddr, peer_port: u16, now_ms: u64) -> Option<Target> {
        let (target, expires) = lock(&self.inner).entries.remove(&(peer, peer_port))?;
        (expires > now_ms).then_some(target)
    }

    pub fn len(&self, now_ms: u64) -> usize {
        let mut inner = lock(&self.inner);
        inner.prune(now_ms);
        inner.entries.len()
    }

    pub fn is_empty(&self, now_ms: u64) -> bool {
        self.len(now_ms) == 0
    }

    pub fn clear(&self) {
        lock(&self.inner).entries.clear();
    }
}

/// UDP DNS clients commonly reuse one socket for several concurrent queries, so
/// each reflected (server, client port) tuple keeps a bounded pending count
/// instead of being consumed by the first datagram.
#[derive(Default)]
pub struct DatagramRegistry {
    inner: Mutex<Expiring<u32>>,
}

impl DatagramRegistry {
    pub fn observe(&self, server: PeerAddr, client_port: u16, now_ms: u64) {
        if client_port == 0 {
            return;
        }
        let mut inner = lock(&self.inner);
        inner.prune_if_due(now_ms);
        if let Some((pending, expires)) = inner.entries.get_mut(&(server, client_port)) {
            // An expired tuple between sweeps must not lend its count to a new query.
            if *expires <= now_ms {
                *pending = 0;
            }
            *pending = (*pending + 1).min(MAX_PENDING_DATAGRAMS_PER_TUPLE);
            *expires = now_ms + PENDING_FLOW_TTL_MS;
            return;
        }
        inner.make_room(now_ms);
        inner
            .entries
            .insert((server, client_port), (1, now_ms + PENDING_FLOW_TTL_MS));
    }

    pub fn claim(&self, peer: PeerAddr, peer_port: u16, now_ms: u64) -> bool {
        let mut inner = lock(&self.inner);
        let key = (peer, peer_port);
        let Some((pending, expires)) = inner.entries.get_mut(&key) else {
            return false;
        };
        if *expires <= now_ms || *pending == 0 {
            inner.entries.remove(&key);
            return false;
        }
        *pending -= 1;
        if *pending == 0 {
            inner.entries.remove(&key);
        }
        true
    }

    pub fn len(&self, now_ms: u64) -> usize {
        let mut inner = lock(&self.inner);
        inner.prune(now_ms);
        inner.entries.len()
    }

    pub fn is_empty(&self, now_ms: u64) -> bool {
        self.len(now_ms) == 0
    }

    pub fn clear(&self) {
        lock(&self.inner).entries.clear();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowKind {
    /// Application <-> relay, keyed by (server address, client port).
    Client,
    /// Relay <-> server, keyed by (server address, relay port).
    Upstream,
}

#[derive(Default)]
struct TcpTable {
    entries: HashMap<(FlowKind, PeerAddr, u16), TcpEntry>,
    next_sweep_ms: u64,
}

#[derive(Clone, Copy)]
struct TcpEntry {
    expires_ms: u64,
    closing: bool,
}

/// Live TCP tuples the packet loop rewrites. Only packets of a tuple added on
/// its SYN are rewritten afterwards; connections that predate the engine, flows
/// a process rule left alone and foreign traffic on SplitHello ports pass
/// untouched. An entry lives until RST, a short grace after FIN, or a long idle
/// timeout; every packet refreshes it.
#[derive(Default)]
pub struct TcpFlowTable {
    inner: Mutex<TcpTable>,
}

impl TcpFlowTable {
    pub fn add(&self, kind: FlowKind, server: PeerAddr, local_port: u16, now_ms: u64) {
        if local_port == 0 {
            return;
        }
        let mut table = lock(&self.inner);
        let key = (kind, server, local_port);
        if !table.entries.contains_key(&key) && table.entries.len() >= MAX_TCP_FLOWS {
            table.make_room(now_ms);
        }
        // A new SYN on a reused tuple starts a fresh, non-closing flow.
        table.entries.insert(
            key,
            TcpEntry {
                expires_ms: now_ms + TCP_FLOW_IDLE_MS,
                closing: false,
            },
        );
    }

    /// True when the tuple is live; refreshes it. RST removes it, but the RST
    /// packet itself still counts as belonging to the flow.
    pub fn track(
        &self,
        kind: FlowKind,
        server: PeerAddr,
        local_port: u16,
        fin: bool,
        rst: bool,
        now_ms: u64,
    ) -> bool {
        let mut table = lock(&self.inner);
        let key = (kind, server, local_port);
        let Some(entry) = table.entries.get_mut(&key) else {
            return false;
        };
        if entry.expires_ms <= now_ms || rst {
            let live = entry.expires_ms > now_ms;
            table.entries.remove(&key);
            return live;
        }
        entry.closing |= fin;
        entry.expires_ms = now_ms
            + if entry.closing {
                TCP_FLOW_CLOSING_MS
            } else {
                TCP_FLOW_IDLE_MS
            };
        true
    }

    pub fn remove(&self, kind: FlowKind, server: PeerAddr, local_port: u16) {
        lock(&self.inner)
            .entries
            .remove(&(kind, server, local_port));
    }

    pub fn len(&self) -> usize {
        lock(&self.inner).entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn clear(&self) {
        let mut table = lock(&self.inner);
        table.entries.clear();
        table.next_sweep_ms = 0;
    }
}

impl TcpTable {
    /// Called with the table full. Expired entries go first (at most one full
    /// scan per second); only a table genuinely full of live flows loses its
    /// least-recently-seen 1/16, which keeps the cost amortized O(1).
    fn make_room(&mut self, now_ms: u64) {
        if now_ms >= self.next_sweep_ms {
            self.next_sweep_ms = now_ms + PRUNE_INTERVAL_MS;
            self.entries.retain(|_, entry| entry.expires_ms > now_ms);
            if self.entries.len() < MAX_TCP_FLOWS {
                return;
            }
        }
        let mut oldest: Vec<_> = self
            .entries
            .iter()
            .map(|(key, entry)| (entry.expires_ms, *key))
            .collect();
        let evict = (oldest.len() / 16).max(1);
        oldest.select_nth_unstable_by_key(evict - 1, |(expires, _)| *expires);
        for (_, key) in &oldest[..evict] {
            self.entries.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eviction_frees_a_sixteenth_closest_to_expiry() {
        let mut map: HashMap<u32, u64> = (0..160).map(|i| (i, u64::from(i))).collect();
        evict_oldest(&mut map, |expires| *expires);
        assert_eq!(map.len(), 150);
        assert!((0..10).all(|i| !map.contains_key(&i)));
        assert!(map.contains_key(&10));
    }

    #[test]
    fn a_full_flow_registry_keeps_accepting_new_flows() {
        let flows = FlowRegistry::default();
        let server = addr("203.0.113.9");
        for port in 1..=(MAX_PENDING_FLOWS as u16 + 100) {
            flows.observe(server, port, 443, 65534, 1000);
        }
        assert!(flows.len(1000) <= MAX_PENDING_FLOWS);
        assert!(
            flows
                .claim(server, MAX_PENDING_FLOWS as u16 + 100, 1000)
                .is_some()
        );
    }

    fn addr(text: &str) -> PeerAddr {
        PeerAddr::parse(text).unwrap()
    }

    #[test]
    fn flow_must_be_observed_before_it_can_be_claimed() {
        let flows = FlowRegistry::default();
        let server = addr("203.0.113.8");
        assert!(flows.claim(server, 52000, 1000).is_none());

        flows.observe(server, 52000, 443, 65534, 1000);
        let target = flows.claim(server, 52000, 1001).expect("observed");
        assert_eq!(target.address, server);
        assert_eq!(target.target_port, 443);
        assert_eq!(target.connect_port, 65534);
        assert!(flows.claim(server, 52000, 1002).is_none());
    }

    #[test]
    fn flow_expires_instead_of_authorizing_late_connections() {
        let flows = FlowRegistry::default();
        flows.observe(addr("2001:db8::1"), 53000, 443, 65534, 1000);
        assert_eq!(flows.len(15999), 1);
        assert!(flows.claim(addr("2001:db8::1"), 53000, 16000).is_none());
        assert_eq!(flows.len(16001), 0);
    }

    #[test]
    fn flow_claim_rejects_expired_entries_between_sweeps() {
        let flows = FlowRegistry::default();
        flows.observe(addr("203.0.113.20"), 52010, 443, 65534, 1000);
        // Inside the sweep interval: no prune ran, expiry is still enforced.
        flows.observe(addr("203.0.113.21"), 52011, 443, 65534, 1500);
        assert!(flows.claim(addr("203.0.113.20"), 52010, 16000).is_none());
        assert!(flows.claim(addr("203.0.113.21"), 52011, 16499).is_some());
    }

    #[test]
    fn dns_registry_counts_concurrent_queries_on_one_socket() {
        let datagrams = DatagramRegistry::default();
        let server = addr("192.0.2.53");
        datagrams.observe(server, 54000, 1000);
        datagrams.observe(server, 54000, 1001);
        assert_eq!(datagrams.len(1002), 1);
        assert!(datagrams.claim(server, 54000, 1002));
        assert_eq!(datagrams.len(1003), 1);
        assert!(datagrams.claim(server, 54000, 1003));
        assert_eq!(datagrams.len(1004), 0);
        assert!(!datagrams.claim(server, 54000, 1004));
    }

    #[test]
    fn dns_registry_rejects_expired_datagrams() {
        let datagrams = DatagramRegistry::default();
        datagrams.observe(addr("2001:db8::53"), 55000, 1000);
        assert!(!datagrams.claim(addr("2001:db8::53"), 55000, 16000));
        assert_eq!(datagrams.len(16001), 0);
    }

    #[test]
    fn dns_registry_does_not_revive_pending_counts_of_expired_tuples() {
        let datagrams = DatagramRegistry::default();
        let stale = addr("192.0.2.54");
        datagrams.observe(stale, 54001, 1000);
        datagrams.observe(stale, 54001, 1001); // two pending, expire at 16001
        datagrams.observe(addr("192.0.2.55"), 54002, 15500); // sweeps; next at 16500
        // Still inside the sweep interval: the new query starts from one.
        datagrams.observe(stale, 54001, 16100);
        assert!(datagrams.claim(stale, 54001, 16101));
        assert!(!datagrams.claim(stale, 54001, 16102));
    }

    #[test]
    fn tcp_table_only_knows_tuples_whose_syn_it_saw() {
        let flows = TcpFlowTable::default();
        let server = addr("203.0.113.30");
        assert!(!flows.track(FlowKind::Client, server, 52000, false, false, 1000));

        flows.add(FlowKind::Client, server, 52000, 1000);
        assert!(flows.track(FlowKind::Client, server, 52000, false, false, 1001));
        // Same server and port, other side of the relay: a different flow.
        assert!(!flows.track(FlowKind::Upstream, server, 52000, false, false, 1002));
        assert!(!flows.track(FlowKind::Client, server, 52001, false, false, 1002));
        assert!(!flows.track(
            FlowKind::Client,
            addr("203.0.113.31"),
            52000,
            false,
            false,
            1002
        ));

        flows.remove(FlowKind::Client, server, 52000);
        assert!(!flows.track(FlowKind::Client, server, 52000, false, false, 1003));
    }

    #[test]
    fn tcp_table_keeps_a_quiet_connection_alive_while_it_carries_traffic() {
        let flows = TcpFlowTable::default();
        let server = addr("2001:db8::30");
        let hour = 60 * 60 * 1000;
        flows.add(FlowKind::Upstream, server, 52001, 1000);
        // Idle three hours (a keep-alive), then active: still tracked, and the
        // idle deadline moves out from the last packet, not from the SYN.
        assert!(flows.track(
            FlowKind::Upstream,
            server,
            52001,
            false,
            false,
            1000 + 3 * hour
        ));
        assert!(flows.track(
            FlowKind::Upstream,
            server,
            52001,
            false,
            false,
            1000 + 6 * hour
        ));
        assert!(!flows.track(
            FlowKind::Upstream,
            server,
            52001,
            false,
            false,
            1000 + 11 * hour
        ));
    }

    #[test]
    fn tcp_table_rst_ends_the_flow_and_fin_only_shortens_it() {
        let flows = TcpFlowTable::default();
        let server = addr("203.0.113.32");
        flows.add(FlowKind::Client, server, 52002, 1000);
        // The RST itself still belongs to the flow, later packets do not.
        assert!(flows.track(FlowKind::Client, server, 52002, false, true, 1001));
        assert!(!flows.track(FlowKind::Client, server, 52002, false, false, 1002));

        flows.add(FlowKind::Client, server, 52003, 1000);
        assert!(flows.track(FlowKind::Client, server, 52003, true, false, 2000));
        // The final ACKs after FIN still belong to it ...
        assert!(flows.track(FlowKind::Client, server, 52003, false, false, 60000));
        // ... but it does not linger for hours.
        assert!(!flows.track(
            FlowKind::Client,
            server,
            52003,
            false,
            false,
            60000 + 3 * 60 * 1000
        ));
    }

    #[test]
    fn tcp_table_reused_port_starts_a_fresh_flow() {
        let flows = TcpFlowTable::default();
        let server = addr("203.0.113.33");
        flows.add(FlowKind::Client, server, 52004, 1000);
        assert!(flows.track(FlowKind::Client, server, 52004, true, false, 2000));
        flows.add(FlowKind::Client, server, 52004, 3000); // new SYN, same tuple
        assert!(flows.track(
            FlowKind::Client,
            server,
            52004,
            false,
            false,
            3000 + 30 * 60 * 1000
        ));
    }

    #[test]
    fn tcp_table_evicts_least_recently_seen_when_full() {
        let flows = TcpFlowTable::default();
        let make = |index: u32| PeerAddr::from_v4_bytes(index.to_be_bytes());
        let capacity = MAX_TCP_FLOWS as u32;
        for i in 0..=capacity {
            flows.add(FlowKind::Client, make(i), 52005, 1000 + u64::from(i));
        }
        assert!(flows.len() <= MAX_TCP_FLOWS);
        assert!(flows.len() > MAX_TCP_FLOWS / 2);
        let now = 1000 + u64::from(capacity);
        // Bounded eviction took the stalest tuples, not the one just added.
        assert!(!flows.track(FlowKind::Client, make(0), 52005, false, false, now));
        assert!(flows.track(FlowKind::Client, make(capacity), 52005, false, false, now));
        assert!(flows.track(
            FlowKind::Client,
            make(capacity - 1),
            52005,
            false,
            false,
            now
        ));
    }
}
