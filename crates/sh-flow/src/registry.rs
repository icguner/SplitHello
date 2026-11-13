use std::collections::HashMap;
use std::sync::Mutex;

use crate::PeerAddr;

const PENDING_FLOW_TTL_MS: u64 = 15_000;
const MAX_PENDING_FLOWS: usize = 8192;
const MAX_PENDING_DATAGRAMS_PER_TUPLE: u32 = 32;
/// Registries are swept at most this often; each lookup also checks its own
/// entry's expiry, so a late claim can never be authorized by a stale entry.
const PRUNE_INTERVAL_MS: u64 = 1000;

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

#[derive(Default)]
struct Pending {
    /// (pending count, expiry)
    entries: HashMap<(PeerAddr, u16), (u32, u64)>,
    next_prune_ms: u64,
}

impl Pending {
    fn prune(&mut self, now_ms: u64) {
        self.entries.retain(|_, (_, expires)| *expires > now_ms);
    }

    fn prune_if_due(&mut self, now_ms: u64) {
        if now_ms >= self.next_prune_ms {
            self.prune(now_ms);
            self.next_prune_ms = now_ms + PRUNE_INTERVAL_MS;
        }
    }
}

/// The network-layer reflector makes the original DNS server appear as the
/// datagram's peer and preserves the application's source port. This
/// short-lived registry proves a datagram the DNS proxy received came from a
/// query WinDivert reflected, so the proxy is never an open resolver. UDP DNS
/// clients commonly reuse one socket for several concurrent queries, so each
/// (server, client port) tuple keeps a bounded pending count instead of being
/// consumed by the first datagram.
#[derive(Default)]
pub struct DatagramRegistry {
    inner: Mutex<Pending>,
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
        if inner.entries.len() >= MAX_PENDING_FLOWS {
            evict_oldest(&mut inner.entries, |(_, expires)| *expires);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> PeerAddr {
        PeerAddr::parse(text).unwrap()
    }

    #[test]
    fn eviction_frees_a_sixteenth_closest_to_expiry() {
        let mut map: HashMap<u32, u64> = (0..160).map(|i| (i, u64::from(i))).collect();
        evict_oldest(&mut map, |expires| *expires);
        assert_eq!(map.len(), 150);
        assert!((0..10).all(|i| !map.contains_key(&i)));
        assert!(map.contains_key(&10));
    }

    #[test]
    fn a_full_registry_keeps_accepting_new_queries() {
        let datagrams = DatagramRegistry::default();
        let server = addr("192.0.2.9");
        for port in 1..=(MAX_PENDING_FLOWS as u16 + 100) {
            datagrams.observe(server, port, 1000);
        }
        assert!(datagrams.len(1000) <= MAX_PENDING_FLOWS);
        assert!(datagrams.claim(server, MAX_PENDING_FLOWS as u16 + 100, 1000));
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
}
