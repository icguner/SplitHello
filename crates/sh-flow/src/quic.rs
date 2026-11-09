//! Adaptive QUIC: prime the first Initial of a flow, keep QUIC when the peer
//! answers, and briefly drop an unresponsive server so the client falls back to
//! TCP (port of `AdaptiveRegistry`, `src/QuicStrategy.cpp`).

use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::PeerAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Pass,
    PrimeAndPass,
    Drop,
    /// Drop: this server just went unanswered and is blocked from now on
    /// (reported once, so callers can log the fallback without a log line
    /// per dropped datagram).
    Fallback,
}

#[derive(Debug, Clone, Copy)]
struct Flow {
    started_ms: u64,
    touched_ms: u64,
    answered: bool,
}

#[derive(Default)]
struct State {
    flows: HashMap<(PeerAddr, u16), Flow>,
    blocked_until: HashMap<PeerAddr, u64>,
    next_purge_ms: u64,
}

pub struct AdaptiveRegistry {
    response_timeout_ms: u64,
    fallback_ms: u64,
    state: Mutex<State>,
    unanswered_flows: AtomicUsize,
    blocked_servers: AtomicUsize,
}

impl Default for AdaptiveRegistry {
    fn default() -> Self {
        Self::new(900, 5 * 60 * 1000)
    }
}

impl AdaptiveRegistry {
    pub fn new(response_timeout_ms: u64, fallback_ms: u64) -> Self {
        let response_timeout_ms = response_timeout_ms.max(1);
        Self {
            response_timeout_ms,
            fallback_ms: fallback_ms.max(response_timeout_ms),
            state: Mutex::default(),
            unanswered_flows: AtomicUsize::new(0),
            blocked_servers: AtomicUsize::new(0),
        }
    }

    /// Lock-free pre-checks for the datagram hot path: only Initials create
    /// state, and only an unanswered flow or a blocked server can change what a
    /// datagram needs, so settled QUIC traffic skips the registry entirely.
    pub fn needs_outbound(&self, initial: bool) -> bool {
        initial || self.blocked_servers.load(Ordering::Relaxed) != 0
    }

    pub fn needs_inbound(&self) -> bool {
        self.unanswered_flows.load(Ordering::Relaxed) != 0
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn publish_blocked(&self, state: &State) {
        self.blocked_servers
            .store(state.blocked_until.len(), Ordering::Relaxed);
    }

    fn purge_if_due(&self, state: &mut State, now_ms: u64) {
        if now_ms < state.next_purge_ms {
            return;
        }
        state.next_purge_ms = now_ms + self.response_timeout_ms.min(1000);
        let fallback_ms = self.fallback_ms;
        let unanswered = &self.unanswered_flows;
        state.flows.retain(|_, flow| {
            let keep = now_ms - flow.touched_ms <= fallback_ms;
            if !keep && !flow.answered {
                unanswered.fetch_sub(1, Ordering::Relaxed);
            }
            keep
        });
        state.blocked_until.retain(|_, until| *until > now_ms);
        self.publish_blocked(state);
    }

    pub fn outbound(
        &self,
        server: PeerAddr,
        local_port: u16,
        initial: bool,
        now_ms: u64,
    ) -> Decision {
        let mut state = self.lock();
        self.purge_if_due(&mut state, now_ms);

        if let Some(&until) = state.blocked_until.get(&server) {
            if until > now_ms {
                return Decision::Drop;
            }
            state.blocked_until.remove(&server);
            self.publish_blocked(&state);
        }
        // Only Initials create learning state; other datagrams only consult
        // the blocked-server list above.
        if !initial {
            return Decision::Pass;
        }

        let flow = state.flows.entry((server, local_port)).or_insert(Flow {
            started_ms: now_ms,
            touched_ms: 0,
            answered: false,
        });
        let fresh = flow.touched_ms == 0;
        flow.touched_ms = now_ms.max(1);
        if fresh {
            self.unanswered_flows.fetch_add(1, Ordering::Relaxed);
            return Decision::PrimeAndPass;
        }
        if flow.answered {
            return Decision::Pass;
        }
        if now_ms - flow.started_ms >= self.response_timeout_ms {
            state
                .blocked_until
                .insert(server, now_ms + self.fallback_ms);
            self.publish_blocked(&state);
            return Decision::Fallback;
        }
        Decision::Pass
    }

    pub fn inbound(&self, server: PeerAddr, local_port: u16, now_ms: u64) {
        let mut state = self.lock();
        self.purge_if_due(&mut state, now_ms);
        let Some(flow) = state.flows.get_mut(&(server, local_port)) else {
            return;
        };
        if !flow.answered {
            self.unanswered_flows.fetch_sub(1, Ordering::Relaxed);
        }
        flow.answered = true;
        flow.touched_ms = now_ms.max(1);
        state.blocked_until.remove(&server);
        self.publish_blocked(&state);
    }

    pub fn clear(&self) {
        let mut state = self.lock();
        state.flows.clear();
        state.blocked_until.clear();
        state.next_purge_ms = 0;
        self.unanswered_flows.store(0, Ordering::Relaxed);
        self.publish_blocked(&state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> PeerAddr {
        PeerAddr::parse(text).unwrap()
    }

    #[test]
    fn primes_then_keeps_a_responsive_flow() {
        let registry = AdaptiveRegistry::new(900, 5000);
        let server = addr("203.0.113.1");
        assert_eq!(
            registry.outbound(server, 50000, true, 1000),
            Decision::PrimeAndPass
        );
        registry.inbound(server, 50000, 1100);
        assert_eq!(
            registry.outbound(server, 50000, false, 3000),
            Decision::Pass
        );
    }

    #[test]
    fn ignores_pre_initial_traffic_until_the_real_probe() {
        let registry = AdaptiveRegistry::new(900, 5000);
        let server = addr("203.0.113.3");
        assert_eq!(
            registry.outbound(server, 50000, false, 1000),
            Decision::Pass
        );
        assert_eq!(
            registry.outbound(server, 50000, true, 1100),
            Decision::PrimeAndPass
        );
    }

    #[test]
    fn falls_back_after_no_response() {
        let registry = AdaptiveRegistry::new(900, 5000);
        let server = addr("203.0.113.2");
        assert_eq!(
            registry.outbound(server, 50000, true, 1000),
            Decision::PrimeAndPass
        );
        assert_eq!(
            registry.outbound(server, 50000, true, 1900),
            Decision::Fallback
        );
        assert_eq!(registry.outbound(server, 50001, true, 2000), Decision::Drop);
        assert_eq!(
            registry.outbound(server, 50001, true, 7000),
            Decision::PrimeAndPass
        );
    }

    #[test]
    fn prechecks_let_settled_traffic_skip_the_registry() {
        let registry = AdaptiveRegistry::new(900, 5000);
        assert!(!registry.needs_inbound());
        assert!(!registry.needs_outbound(false));
        assert!(registry.needs_outbound(true));

        registry.outbound(addr("203.0.113.4"), 50000, true, 1000);
        assert!(registry.needs_inbound());
        registry.inbound(addr("203.0.113.4"), 50000, 1100);
        // Answered: the data datagrams that follow need neither direction.
        assert!(!registry.needs_inbound());
        assert!(!registry.needs_outbound(false));

        // An unanswered Initial gets blocked; non-Initial datagrams are then
        // checked against the block list until it expires.
        let blocked = addr("203.0.113.5");
        registry.outbound(blocked, 50001, true, 2000);
        assert_eq!(
            registry.outbound(blocked, 50001, true, 2900),
            Decision::Fallback
        );
        assert!(registry.needs_outbound(false));
        assert_eq!(
            registry.outbound(blocked, 50002, false, 3000),
            Decision::Drop
        );
        assert_eq!(
            registry.outbound(blocked, 50002, false, 8000),
            Decision::Pass
        );
        assert!(!registry.needs_outbound(false));
        assert!(!registry.needs_inbound());

        registry.outbound(addr("203.0.113.6"), 50003, true, 9000);
        assert!(registry.needs_inbound());
        registry.clear();
        assert!(!registry.needs_inbound());
    }
}
