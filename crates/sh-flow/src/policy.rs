use std::collections::HashMap;
use std::sync::Mutex;

use sh_proto::packet::{Mode, Policy};

use crate::PeerAddr;

const POLICY_TTL_MS: u64 = 15_000;
const APPLIED_TTL_MS: u64 = 60_000;
const PRUNE_INTERVAL_MS: u64 = 1000;
const MAX_ENTRIES: usize = 8192;

type Key = (PeerAddr, u16);

#[derive(Debug, Clone)]
struct Entry {
    policy: Policy,
    expires_ms: u64,
    taken: bool,
    sequence: Option<u32>,
    applied: bool,
}

#[derive(Debug, Clone, Copy)]
struct Hop {
    path_hops: u8,
    expires_ms: u64,
}

#[derive(Default)]
struct State {
    policies: HashMap<Key, Entry>,
    hops: HashMap<Key, Hop>,
    next_prune_ms: u64,
}

/// Joins the relay socket chosen by the prober with the packet seen on the
/// private connect port. A policy transforms the first TLS payload of that
/// fresh connection and any retransmission of the same segment (same TCP
/// sequence number); later records pass untouched. The packet loop reports a
/// real wire change with `note_applied`, and the prober asks once with
/// `consume_applied`: a profile whose policy was never applied (expired,
/// address mismatch, hello split across packets, hostname too short to cut) was
/// a plain unmodified hello and must not be learned.
#[derive(Default)]
pub struct PolicyRegistry {
    state: Mutex<State>,
}

fn infer_path_hops(received_ttl: u8) -> u8 {
    [64u16, 128, 255]
        .into_iter()
        .find(|&initial| u16::from(received_ttl) <= initial)
        .map_or(0, |initial| (initial - u16::from(received_ttl)) as u8)
}

/// Called with the map full, right after `prune_if_due` (expired entries
/// are swept at most once a second): drop the 1/16 closest to expiry
/// instead of wiping every in-flight policy or rescanning on every insert.
fn make_room<V>(map: &mut HashMap<Key, V>, _now_ms: u64, expires: impl Fn(&V) -> u64) {
    crate::registry::evict_oldest(map, expires);
}

impl State {
    /// Lookups check their own entry's expiry; this sweep only bounds memory.
    fn prune_if_due(&mut self, now_ms: u64) {
        if now_ms < self.next_prune_ms {
            return;
        }
        self.next_prune_ms = now_ms + PRUNE_INTERVAL_MS;
        self.policies.retain(|_, e| e.expires_ms > now_ms);
        self.hops.retain(|_, h| h.expires_ms > now_ms);
    }
}

impl PolicyRegistry {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn arm(&self, target: PeerAddr, source_port: u16, policy: Policy, now_ms: u64) {
        if source_port == 0 || policy.mode == Mode::None {
            return;
        }
        let key = (target, source_port);
        let mut state = self.lock();
        state.prune_if_due(now_ms);
        if state.policies.len() >= MAX_ENTRIES && !state.policies.contains_key(&key) {
            make_room(&mut state.policies, now_ms, |e| e.expires_ms);
        }
        state.policies.insert(
            key,
            Entry {
                policy,
                expires_ms: now_ms + POLICY_TTL_MS,
                taken: false,
                sequence: None,
                applied: false,
            },
        );
    }

    /// Records the path length inferred from a SYN-ACK's TTL.
    pub fn observe_hop(&self, target: PeerAddr, source_port: u16, received_ttl: u8, now_ms: u64) {
        if source_port == 0 || received_ttl == 0 {
            return;
        }
        let path_hops = infer_path_hops(received_ttl);
        if path_hops == 0 {
            return;
        }
        let key = (target, source_port);
        let mut state = self.lock();
        state.prune_if_due(now_ms);
        if state.hops.len() >= MAX_ENTRIES && !state.hops.contains_key(&key) {
            make_room(&mut state.hops, now_ms, |h| h.expires_ms);
        }
        state.hops.insert(
            key,
            Hop {
                path_hops,
                expires_ms: now_ms + POLICY_TTL_MS,
            },
        );
    }

    /// Packet-loop entry; `sequence` is the packet's TCP sequence number. The
    /// first call fixes the segment; later calls with the same sequence
    /// (retransmissions) get the same policy, anything else gets None.
    pub fn take(
        &self,
        target: PeerAddr,
        source_port: u16,
        sequence: Option<u32>,
        now_ms: u64,
    ) -> Option<Policy> {
        let key = (target, source_port);
        let mut state = self.lock();
        let entry = state.policies.get(&key)?;
        if entry.expires_ms <= now_ms {
            state.policies.remove(&key);
            return None;
        }
        if entry.taken {
            // A retransmitted ClientHello must get the same treatment as the
            // original; sending it clear would leak the SNI the profile hides.
            return match (sequence, entry.sequence) {
                (Some(seq), Some(fixed)) if seq == fixed => Some(entry.policy.clone()),
                _ => None,
            };
        }

        let hop = state.hops.get(&key).copied();
        let entry = state.policies.get_mut(&key)?;
        entry.taken = true;
        entry.sequence = sequence;
        if entry.policy.mode == Mode::FakeAutoTtl {
            match hop {
                Some(hop) if hop.expires_ms > now_ms && hop.path_hops >= 3 => {
                    entry.policy.fake_ttl = (hop.path_hops - 1).max(2);
                }
                _ => {
                    // Never let a missing SYN-ACK sample turn AutoTTL into an
                    // untouched hello that could be learned as a false winner.
                    entry.policy.mode = Mode::FakeBadSequence;
                    entry.policy.fake_sequence_delta = -10000;
                }
            }
        }
        Some(entry.policy.clone())
    }

    /// The packet loop really transformed the packet taken for this key.
    pub fn note_applied(&self, target: PeerAddr, source_port: u16, now_ms: u64) {
        if let Some(entry) = self.lock().policies.get_mut(&(target, source_port)) {
            entry.applied = true;
            // Outlive the probe: the prober asks only after the server answered.
            entry.expires_ms = entry.expires_ms.max(now_ms + APPLIED_TTL_MS);
        }
    }

    /// True exactly when `note_applied` ran for the policy armed on this key.
    /// Always forgets the key, so call it once after the probe finished.
    pub fn consume_applied(&self, target: PeerAddr, source_port: u16, now_ms: u64) -> bool {
        self.lock()
            .policies
            .remove(&(target, source_port))
            .is_some_and(|entry| entry.applied && entry.expires_ms > now_ms)
    }

    pub fn clear(&self) {
        let mut state = self.lock();
        state.policies.clear();
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

    fn policy(mode: Mode) -> Policy {
        Policy {
            mode,
            ..Policy::default()
        }
    }

    #[test]
    fn is_one_shot_and_infers_auto_ttl() {
        let registry = PolicyRegistry::default();
        let target = addr("203.0.113.8");
        registry.observe_hop(target, 52000, 120, 1000); // 128 - 120 = 8 hops
        registry.arm(target, 52000, policy(Mode::FakeAutoTtl), 1001);
        let taken = registry.take(target, 52000, None, 1002).expect("armed");
        assert_eq!(taken.fake_ttl, 7);
        assert!(registry.take(target, 52000, None, 1003).is_none());
    }

    #[test]
    fn expires_unused_policies() {
        let registry = PolicyRegistry::default();
        registry.arm(
            addr("2001:db8::8"),
            53000,
            policy(Mode::FakeBadSequence),
            1000,
        );
        assert!(
            registry
                .take(addr("2001:db8::8"), 53000, None, 16000)
                .is_none()
        );
    }

    #[test]
    fn auto_ttl_falls_back_to_bad_sequence_without_hop_sample() {
        let registry = PolicyRegistry::default();
        registry.arm(addr("203.0.113.9"), 52001, policy(Mode::FakeAutoTtl), 1000);
        let taken = registry
            .take(addr("203.0.113.9"), 52001, None, 1001)
            .expect("armed");
        assert_eq!(taken.mode, Mode::FakeBadSequence);
        assert_eq!(taken.fake_sequence_delta, -10000);
    }

    #[test]
    fn retransmit_of_the_same_segment_is_transformed_again() {
        let registry = PolicyRegistry::default();
        let target = addr("203.0.113.10");
        registry.observe_hop(target, 52002, 120, 1000);
        registry.arm(target, 52002, policy(Mode::FakeAutoTtl), 1001);

        assert_eq!(
            registry
                .take(target, 52002, Some(777), 1002)
                .unwrap()
                .fake_ttl,
            7
        );
        // The stack retransmits the ClientHello with the same sequence number.
        assert_eq!(
            registry
                .take(target, 52002, Some(777), 4000)
                .unwrap()
                .fake_ttl,
            7
        );
        // A different segment of the connection is real traffic, not the hello.
        assert!(registry.take(target, 52002, Some(778), 4001).is_none());
        // Without a sequence number the policy stays one-shot.
        assert!(registry.take(target, 52002, None, 4002).is_none());
    }

    #[test]
    fn addresses_compare_in_canonical_form() {
        let registry = PolicyRegistry::default();
        // The relay arms with the text it connected to; the packet loop looks up
        // with the bytes it read from the wire.
        registry.arm(
            addr("2001:DB8:0:0:0:0:0:8"),
            53001,
            policy(Mode::ReverseOrder),
            1000,
        );
        registry.arm(
            addr("::ffff:203.0.113.11"),
            53002,
            policy(Mode::ReverseOrder),
            1000,
        );
        let mut v6 = [0u8; 16];
        v6[..4].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
        v6[15] = 8;
        assert!(
            registry
                .take(PeerAddr::from_v6_bytes(v6), 53001, None, 1001)
                .is_some()
        );
        assert!(
            registry
                .take(
                    PeerAddr::from_v4_bytes([203, 0, 113, 11]),
                    53002,
                    None,
                    1001
                )
                .is_some()
        );
    }

    #[test]
    fn reports_only_transformations_that_really_happened() {
        let registry = PolicyRegistry::default();
        let target = addr("203.0.113.12");
        // Armed but the packet loop never touched the hello.
        registry.arm(target, 54000, policy(Mode::ReverseOrder), 1000);
        assert!(!registry.consume_applied(target, 54000, 1500));
        assert!(registry.take(target, 54000, None, 1501).is_none());

        registry.arm(target, 54001, policy(Mode::ReverseOrder), 1000);
        assert!(registry.take(target, 54001, Some(5), 1100).is_some());
        registry.note_applied(target, 54001, 1101);
        // The probe may wait for the server far longer than the policy TTL.
        assert!(registry.consume_applied(target, 54001, 30000));
        assert!(!registry.consume_applied(target, 54001, 30001));
    }

    #[test]
    fn evicts_oldest_instead_of_dropping_everything() {
        let registry = PolicyRegistry::default();
        let server = addr("203.0.113.13");
        for port in 1..=8193u16 {
            registry.arm(
                server,
                port,
                policy(Mode::ReverseOrder),
                1000 + u64::from(port),
            );
        }
        // Full: the 1/16 closest to expiry (ports 1..=512) made room at once.
        assert!(registry.take(server, 1, None, 9300).is_none());
        assert!(registry.take(server, 512, None, 9300).is_none());
        assert!(registry.take(server, 513, None, 9300).is_some());
        assert!(registry.take(server, 8193, None, 9300).is_some());
    }
}
