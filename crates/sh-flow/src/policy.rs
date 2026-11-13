use std::collections::HashMap;
use std::sync::Mutex;

use crate::PeerAddr;

const HOP_TTL_MS: u64 = 15_000;
const PRUNE_INTERVAL_MS: u64 = 1000;
const MAX_ENTRIES: usize = 8192;
/// A decoy never travels further than this, however long the path looks.
const MAX_FAKE_TTL: u8 = 12;

type Key = (PeerAddr, u16);

#[derive(Default)]
struct State {
    /// (path hops, expiry)
    hops: HashMap<Key, (u8, u64)>,
    next_prune_ms: u64,
}

/// Path length of each fresh connection, inferred from the TTL of its
/// SYN-ACK. The packet loop asks for it when the ClientHello leaves, to give a
/// decoy a TTL that passes the DPI box but expires before the server. A
/// missing or expired sample only means "no decoy": nothing depends on it.
#[derive(Default)]
pub struct HopRegistry {
    state: Mutex<State>,
}

fn infer_path_hops(received_ttl: u8) -> u8 {
    [64u16, 128, 255]
        .into_iter()
        .find(|&initial| u16::from(received_ttl) <= initial)
        .map_or(0, |initial| (initial - u16::from(received_ttl)) as u8)
}

/// The decoy must die before the server: one that arrives is a valid hello
/// with the wrong name and breaks the connection. The SYN-ACK measures the
/// return path, which can be a hop or two longer than the way out, so the
/// margin grows with the path.
///
/// shortcut: fixed margins (2 hops, a quarter of long paths, at most 12);
/// make them configurable if a network's DPI sits deeper than that.
fn fake_ttl_for(path_hops: u8) -> Option<u8> {
    let ttl = path_hops
        .saturating_sub((path_hops / 4).max(2))
        .min(MAX_FAKE_TTL);
    (ttl >= 2).then_some(ttl)
}

impl HopRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Records the path length seen in a SYN-ACK from `server`.
    pub fn observe(&self, server: PeerAddr, client_port: u16, received_ttl: u8, now_ms: u64) {
        let path_hops = infer_path_hops(received_ttl);
        if client_port == 0 || path_hops == 0 {
            return;
        }
        let key = (server, client_port);
        let mut state = self.lock();
        if now_ms >= state.next_prune_ms {
            state.next_prune_ms = now_ms + PRUNE_INTERVAL_MS;
            state.hops.retain(|_, (_, expires)| *expires > now_ms);
        }
        if state.hops.len() >= MAX_ENTRIES && !state.hops.contains_key(&key) {
            crate::registry::evict_oldest(&mut state.hops, |(_, expires)| *expires);
        }
        state.hops.insert(key, (path_hops, now_ms + HOP_TTL_MS));
    }

    /// TTL for a decoy on this connection; None without a usable sample.
    pub fn fake_ttl(&self, server: PeerAddr, client_port: u16, now_ms: u64) -> Option<u8> {
        let (path_hops, expires) = *self.lock().hops.get(&(server, client_port))?;
        if expires <= now_ms {
            return None;
        }
        fake_ttl_for(path_hops)
    }

    pub fn clear(&self) {
        let mut state = self.lock();
        state.hops.clear();
        state.next_prune_ms = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> PeerAddr {
        PeerAddr::parse(text).unwrap()
    }

    #[test]
    fn decoy_ttl_stays_short_of_the_server() {
        // Too close to place a decoy between the DPI box and the server.
        assert_eq!(fake_ttl_for(0), None);
        assert_eq!(fake_ttl_for(3), None);
        assert_eq!(fake_ttl_for(4), Some(2));
        assert_eq!(fake_ttl_for(8), Some(6));
        assert_eq!(fake_ttl_for(12), Some(9));
        assert_eq!(fake_ttl_for(16), Some(12));
        assert_eq!(fake_ttl_for(40), Some(12));
        for hops in 4..=64u8 {
            assert!(fake_ttl_for(hops).unwrap() + 2 <= hops);
        }
    }

    #[test]
    fn infers_the_path_from_the_syn_ack_and_forgets_it() {
        let hops = HopRegistry::default();
        let server = addr("203.0.113.8");
        assert_eq!(hops.fake_ttl(server, 52000, 1000), None);
        hops.observe(server, 52000, 120, 1000); // 128 - 120 = 8 hops
        assert_eq!(hops.fake_ttl(server, 52000, 1001), Some(6));
        assert_eq!(hops.fake_ttl(server, 52001, 1001), None);
        assert_eq!(hops.fake_ttl(server, 52000, 1000 + HOP_TTL_MS), None);
        hops.observe(server, 52002, 56, 2000); // 64 - 56 = 8 hops
        assert_eq!(hops.fake_ttl(server, 52002, 2001), Some(6));
    }

    #[test]
    fn addresses_compare_in_canonical_form() {
        let hops = HopRegistry::default();
        hops.observe(addr("::ffff:203.0.113.11"), 53002, 120, 1000);
        assert!(
            hops.fake_ttl(PeerAddr::from_v4_bytes([203, 0, 113, 11]), 53002, 1001)
                .is_some()
        );
    }
}
