//! Passive per-site learning for the packet engine.
//!
//! Connections belong to the applications, so nothing can be replayed. The
//! packet loop only reports what it sees: a ClientHello leaving, then either a
//! ServerHello or the connection being torn down first. A site whose untouched
//! hello is torn down is taken as blocked; its next connections get a packet
//! profile, and the first profile that is answered by a ServerHello is
//! remembered. Sites that are never torn down are never touched.
//!
//! Only proven profiles are written to disk. A silent drop (no reset, no
//! close) is not a verdict: it looks the same as a server that is down.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard};

use sh_flow::PeerAddr;
use sh_proto::packet::{Mode, PROFILES};

const FLOW_TTL_MS: u64 = 15_000;
const PRUNE_INTERVAL_MS: u64 = 1000;
const MAX_FLOWS: usize = 8192;
const MAX_HOSTS: usize = 1000;
const MAX_ADDRESSES: usize = 4096;
/// A site no profile opened is left alone this long, then tested afresh.
const GIVE_UP_MS: u64 = 30 * 60 * 1000;
const FILE_VERSION: u64 = 3;

/// Steps 1..=PROFILES.len() index `PROFILES`; 0 is the untouched hello.
fn mode_of(step: u8) -> Mode {
    match step {
        0 => Mode::None,
        step => PROFILES
            .get(usize::from(step) - 1)
            .map_or(Mode::None, |p| p.1),
    }
}

fn name_of(step: u8) -> &'static str {
    PROFILES
        .get(usize::from(step).wrapping_sub(1))
        .map_or("none", |p| p.0)
}

fn step_of(profile: &str) -> Option<u8> {
    PROFILES
        .iter()
        .position(|p| p.0 == profile)
        .map(|index| index as u8 + 1)
}

#[derive(Debug, Clone)]
struct Host {
    step: u8,
    /// Profiles that already failed for this site in this round.
    tried: u8,
    proven: bool,
    /// A proven profile survives one teardown: resets also just happen.
    struck: bool,
    /// Non-zero: every profile failed; untouched until this time.
    gave_up_until_ms: u64,
}

struct Flow {
    key: String,
    step: u8,
    expires_ms: u64,
}

#[derive(Default)]
struct State {
    hosts: HashMap<String, Host>,
    flows: HashMap<(PeerAddr, u16), Flow>,
    /// The profile that last proved itself on each network: new blocked
    /// sites start there, because the DPI box is the same for all of them.
    preferred: HashMap<String, u8>,
    /// The site last seen by name at each address. Browsers often push the
    /// name into the hello's second packet; such a hello is taken to be for
    /// the site that address was last used for.
    last_site: HashMap<PeerAddr, String>,
    next_prune_ms: u64,
}

pub struct Learner {
    path: Option<PathBuf>,
    state: Mutex<State>,
    dirty: AtomicBool,
}

fn key_for(network: &str, host: &str) -> String {
    format!(
        "{network}|{}",
        host.trim_end_matches('.').to_ascii_lowercase()
    )
}

fn network_of(key: &str) -> &str {
    key.split_once('|').map_or("", |(network, _)| network)
}

impl Learner {
    /// An empty path keeps everything in memory.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path: PathBuf = path.into();
        Self {
            path: (!path.as_os_str().is_empty()).then_some(path),
            state: Mutex::default(),
            dirty: AtomicBool::new(false),
        }
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Reads the file if present; a missing or unreadable one starts empty.
    /// Entries written by the relay builds name profiles that no longer
    /// exist: those sites are known to be blocked, so they start on a packet
    /// profile right away instead of failing once more first.
    pub fn load(&self) {
        let Some(bytes) = self.path.as_ref().and_then(sh_core::fsutil::read_all) else {
            return;
        };
        let Ok(serde_json::Value::Object(root)) = serde_json::from_slice(&bytes) else {
            return;
        };
        let Some(serde_json::Value::Object(domains)) = root.get("domains") else {
            return;
        };
        let mut state = self.lock();
        state.hosts.clear();
        state.preferred.clear();
        let mut legacy = Vec::new();
        for (key, value) in domains {
            let profile = value.as_str().unwrap_or("").split(';').next().unwrap_or("");
            if !key.contains('|') || state.hosts.len() + legacy.len() >= MAX_HOSTS {
                continue;
            }
            match step_of(profile) {
                Some(step) => {
                    state.preferred.insert(network_of(key).to_owned(), step);
                    state.hosts.insert(
                        key.clone(),
                        Host {
                            step,
                            tried: 0,
                            proven: true,
                            struck: false,
                            gave_up_until_ms: 0,
                        },
                    );
                }
                None if !profile.is_empty() && profile != "none" => legacy.push(key.clone()),
                None => {}
            }
        }
        for key in legacy {
            let step = state.preferred.get(network_of(&key)).copied().unwrap_or(1);
            state.hosts.insert(
                key,
                Host {
                    step,
                    tried: 0,
                    proven: false,
                    struck: false,
                    gave_up_until_ms: 0,
                },
            );
        }
    }

    /// A ClientHello is leaving for `server`. `host` is its server name when
    /// the packet shows it; otherwise the address stands in for the site.
    /// Returns what to do to the packet (`Mode::None`: leave it alone). A
    /// retransmission gets the answer the first copy got.
    pub fn on_hello(
        &self,
        network: &str,
        server: PeerAddr,
        client_port: u16,
        host: Option<&str>,
        now_ms: u64,
    ) -> Mode {
        let mut state = self.lock();
        if now_ms >= state.next_prune_ms {
            state.next_prune_ms = now_ms + PRUNE_INTERVAL_MS;
            state.flows.retain(|_, flow| flow.expires_ms > now_ms);
        }
        let flow_key = (server, client_port);
        if let Some(flow) = state.flows.get(&flow_key) {
            return mode_of(flow.step);
        }
        let key = match host {
            Some(host) => {
                let key = key_for(network, host);
                if state.last_site.len() >= MAX_ADDRESSES && !state.last_site.contains_key(&server)
                {
                    state.last_site.clear();
                }
                state.last_site.insert(server, key.clone());
                key
            }
            // Only a site this network already knows as blocked is worth the
            // guess; anything else is learned for the address itself.
            None => match state.last_site.get(&server) {
                Some(site) if network_of(site) == network && state.hosts.contains_key(site) => {
                    site.clone()
                }
                _ => key_for(network, &server.to_string()),
            },
        };
        let step = match state.hosts.get(&key) {
            Some(host) if host.gave_up_until_ms == 0 => host.step,
            Some(host) if host.gave_up_until_ms <= now_ms => {
                state.hosts.remove(&key);
                0
            }
            _ => 0,
        };
        // Full of live handshakes: this one simply goes unobserved.
        if state.flows.len() < MAX_FLOWS {
            state.flows.insert(
                flow_key,
                Flow {
                    key,
                    step,
                    expires_ms: now_ms + FLOW_TTL_MS,
                },
            );
        }
        mode_of(step)
    }

    /// The server answered the hello of this connection.
    pub fn on_server_hello(&self, server: PeerAddr, client_port: u16, now_ms: u64) {
        let mut state = self.lock();
        let Some(flow) = state.flows.remove(&(server, client_port)) else {
            return;
        };
        if flow.expires_ms <= now_ms {
            return;
        }
        let Some(host) = state.hosts.get_mut(&flow.key) else {
            return;
        };
        if flow.step == 0 {
            // Answered untouched after every profile had failed: it was not
            // the DPI box. Start over with a clean slate.
            if host.gave_up_until_ms != 0 {
                state.hosts.remove(&flow.key);
            }
            return;
        }
        if flow.step != host.step || host.gave_up_until_ms != 0 {
            return;
        }
        host.struck = false;
        if !host.proven {
            host.proven = true;
            host.tried = 0;
            self.dirty.store(true, Ordering::Relaxed);
            tracing::info!(
                "{}: '{}' ile acildi, kaydedildi",
                flow.key,
                name_of(flow.step)
            );
        }
        state
            .preferred
            .insert(network_of(&flow.key).to_owned(), flow.step);
    }

    /// The connection was reset or closed from the server side. Only counts
    /// while its hello is still unanswered.
    pub fn on_close(&self, server: PeerAddr, client_port: u16, now_ms: u64) {
        let mut state = self.lock();
        let Some(flow) = state.flows.remove(&(server, client_port)) else {
            return;
        };
        if flow.expires_ms <= now_ms {
            return;
        }
        let state = &mut *state;
        let Some(host) = state.hosts.get_mut(&flow.key) else {
            if flow.step != 0 {
                return; // forgotten meanwhile
            }
            if state.hosts.len() >= MAX_HOSTS {
                // Make room among sites that never proved anything.
                let Some(victim) = state
                    .hosts
                    .iter()
                    .find(|(_, host)| !host.proven)
                    .map(|(key, _)| key.clone())
                else {
                    return;
                };
                state.hosts.remove(&victim);
            }
            let step = state
                .preferred
                .get(network_of(&flow.key))
                .copied()
                .unwrap_or(1);
            tracing::info!(
                "{}: engel goruldu, sonraki baglantida '{}' denenecek",
                flow.key,
                name_of(step)
            );
            state.hosts.insert(
                flow.key,
                Host {
                    step,
                    tried: 0,
                    proven: false,
                    struck: false,
                    gave_up_until_ms: 0,
                },
            );
            return;
        };
        if flow.step != host.step || host.gave_up_until_ms != 0 {
            return;
        }
        if host.proven && !host.struck {
            host.struck = true;
            return;
        }
        if host.proven {
            host.proven = false;
            self.dirty.store(true, Ordering::Relaxed);
        }
        host.struck = false;
        host.tried += 1;
        if usize::from(host.tried) >= PROFILES.len() {
            host.gave_up_until_ms = now_ms + GIVE_UP_MS;
            tracing::info!(
                "{}: hicbir paket profili acmadi; 30 dk dokunulmayacak",
                flow.key
            );
            return;
        }
        host.step = host.step % PROFILES.len() as u8 + 1;
        tracing::info!(
            "{}: '{}' acmadi, sirada '{}'",
            flow.key,
            name_of(flow.step),
            name_of(host.step)
        );
    }

    /// (network|site, profile) for every remembered site.
    pub fn learned(&self) -> Vec<(String, &'static str)> {
        let mut learned: Vec<_> = self
            .lock()
            .hosts
            .iter()
            .filter(|(_, host)| host.proven)
            .map(|(key, host)| (key.clone(), name_of(host.step)))
            .collect();
        learned.sort();
        learned
    }

    pub fn len(&self) -> usize {
        self.lock().hosts.values().filter(|h| h.proven).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Forgets everything, on disk too.
    pub fn clear(&self) {
        {
            let mut state = self.lock();
            state.hosts.clear();
            state.preferred.clear();
            state.flows.clear();
            state.last_site.clear();
        }
        self.dirty.store(true, Ordering::Relaxed);
        self.save_if_dirty();
    }

    /// Writes the remembered sites when they changed. Called from outside the
    /// packet loop, so a slow disk never holds packets.
    pub fn save_if_dirty(&self) {
        let Some(path) = &self.path else { return };
        if !self.dirty.swap(false, Ordering::Relaxed) {
            return;
        }
        let domains: serde_json::Map<String, serde_json::Value> = self
            .learned()
            .into_iter()
            .map(|(key, profile)| (key, profile.into()))
            .collect();
        let text = serde_json::json!({ "version": FILE_VERSION, "domains": domains }).to_string();
        if let Err(error) = sh_core::fsutil::write_atomic(path, text.as_bytes()) {
            self.dirty.store(true, Ordering::Relaxed);
            tracing::warn!("Ogrenilen siteler kaydedilemedi: {error}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NET: &str = "home";

    fn server() -> PeerAddr {
        PeerAddr::parse("203.0.113.8").unwrap()
    }

    /// One connection to `host`: hello out, then the given ending.
    fn connect(learner: &Learner, port: u16, host: &str, answered: bool, now: u64) -> Mode {
        let mode = learner.on_hello(NET, server(), port, Some(host), now);
        if answered {
            learner.on_server_hello(server(), port, now + 20);
        } else {
            learner.on_close(server(), port, now + 20);
        }
        mode
    }

    #[test]
    fn untouched_sites_stay_untouched() {
        let learner = Learner::new("");
        for port in 1..=20 {
            assert_eq!(connect(&learner, port, "open.test", true, 1000), Mode::None);
        }
        assert!(learner.is_empty());
        // A hello nobody answers is not a verdict.
        learner.on_hello(NET, server(), 99, Some("slow.test"), 1000);
        assert_eq!(
            learner.on_hello(NET, server(), 100, Some("slow.test"), 60_000),
            Mode::None
        );
    }

    #[test]
    fn a_torn_down_hello_gets_a_profile_and_the_one_that_works_is_kept() {
        let learner = Learner::new("");
        assert_eq!(
            connect(&learner, 1, "blocked.test", false, 1000),
            Mode::None
        );
        // First profile is torn down too; the second gets through.
        assert_eq!(
            connect(&learner, 2, "Blocked.test.", false, 2000),
            Mode::FakeAutoTtl
        );
        assert!(learner.is_empty());
        assert_eq!(
            connect(&learner, 3, "blocked.test", true, 3000),
            Mode::SequenceOverlap
        );
        assert_eq!(
            learner.learned(),
            vec![("home|blocked.test".to_owned(), "packet-seqovl")]
        );
        // The next blocked site on this network starts with what worked.
        connect(&learner, 4, "other.test", false, 4000);
        assert_eq!(
            learner.on_hello(NET, server(), 5, Some("other.test"), 5000),
            Mode::SequenceOverlap
        );
        // Another network knows nothing of it.
        assert_eq!(
            learner.on_hello("cafe", server(), 6, Some("blocked.test"), 5000),
            Mode::None
        );
    }

    #[test]
    fn a_retransmitted_hello_gets_the_same_treatment_and_one_verdict() {
        let learner = Learner::new("");
        connect(&learner, 1, "blocked.test", false, 1000);
        assert_eq!(
            learner.on_hello(NET, server(), 2, Some("blocked.test"), 2000),
            Mode::FakeAutoTtl
        );
        // Torn down, and the stack retransmits nothing after that.
        learner.on_close(server(), 2, 2100);
        learner.on_close(server(), 2, 2200);
        assert_eq!(
            learner.on_hello(NET, server(), 3, Some("blocked.test"), 3000),
            Mode::SequenceOverlap
        );
        assert_eq!(
            learner.on_hello(NET, server(), 3, Some("blocked.test"), 4000),
            Mode::SequenceOverlap
        );
    }

    #[test]
    fn a_proven_profile_survives_one_reset_but_not_two() {
        let learner = Learner::new("");
        connect(&learner, 1, "blocked.test", false, 1000);
        connect(&learner, 2, "blocked.test", true, 2000);
        assert_eq!(learner.len(), 1);
        assert_eq!(
            connect(&learner, 3, "blocked.test", false, 3000),
            Mode::FakeAutoTtl
        );
        assert_eq!(learner.len(), 1);
        // An answer in between clears the strike.
        connect(&learner, 4, "blocked.test", true, 4000);
        connect(&learner, 5, "blocked.test", false, 5000);
        assert_eq!(learner.len(), 1);
        connect(&learner, 6, "blocked.test", false, 6000);
        assert!(learner.is_empty());
        assert_eq!(
            learner.on_hello(NET, server(), 7, Some("blocked.test"), 7000),
            Mode::SequenceOverlap
        );
    }

    #[test]
    fn a_site_nothing_opens_is_left_alone_for_a_while() {
        let learner = Learner::new("");
        let mut now = 1000;
        let mut port = 1;
        let mut seen = Vec::new();
        for _ in 0..=PROFILES.len() {
            seen.push(connect(&learner, port, "dead.test", false, now));
            port += 1;
            now += 1000;
        }
        // The untouched hello, then every profile once.
        assert_eq!(seen[0], Mode::None);
        let mut tried: Vec<_> = seen[1..].to_vec();
        tried.dedup();
        assert_eq!(tried.len(), PROFILES.len());
        assert_eq!(connect(&learner, port, "dead.test", false, now), Mode::None);
        // Answered untouched: it was never the DPI box.
        assert_eq!(
            connect(&learner, port + 1, "dead.test", true, now + 1000),
            Mode::None
        );
        assert_eq!(
            connect(&learner, port + 2, "dead.test", false, now + 2000),
            Mode::None
        );
        assert_eq!(
            learner.on_hello(NET, server(), port + 3, Some("dead.test"), now + 3000),
            Mode::FakeAutoTtl
        );
    }

    #[test]
    fn a_hello_without_a_visible_name_is_keyed_by_address() {
        let learner = Learner::new("");
        learner.on_hello(NET, server(), 1, None, 1000);
        learner.on_close(server(), 1, 1020);
        assert_eq!(
            learner.on_hello(NET, server(), 2, None, 2000),
            Mode::FakeAutoTtl
        );
        let elsewhere = PeerAddr::parse("203.0.113.9").unwrap();
        assert_eq!(learner.on_hello(NET, elsewhere, 3, None, 2000), Mode::None);
    }

    #[test]
    fn a_nameless_hello_follows_the_blocked_site_last_seen_at_that_address() {
        let learner = Learner::new("");
        connect(&learner, 1, "blocked.test", false, 1000);
        connect(&learner, 2, "blocked.test", true, 2000);
        // Same address, name in a later packet: treated as that site at once.
        assert_eq!(
            learner.on_hello(NET, server(), 3, None, 3000),
            Mode::FakeAutoTtl
        );
        learner.on_server_hello(server(), 3, 3020);
        assert_eq!(learner.len(), 1);
        // An address last used for an open site gives no such hint.
        let other = PeerAddr::parse("203.0.113.9").unwrap();
        learner.on_hello(NET, other, 4, Some("open.test"), 4000);
        learner.on_server_hello(other, 4, 4020);
        assert_eq!(learner.on_hello(NET, other, 5, None, 5000), Mode::None);
        // Nor does a site learned on another network.
        learner.on_hello("cafe", server(), 6, Some("blocked.test"), 6000);
        assert_eq!(
            learner.on_hello("cafe", server(), 7, None, 6000),
            Mode::None
        );
    }

    #[test]
    fn proven_sites_persist_and_relay_era_entries_skip_the_first_failure() {
        let dir = std::env::temp_dir().join(format!("sh-learn-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("strategies.json");
        std::fs::write(
            &path,
            r#"{"version":2,"domains":{"home|old.test":"record-1;sni-interference-likely;92;1;0;1","plain.test":"sni-mid"}}"#,
        )
        .unwrap();
        let learner = Learner::new(&path);
        learner.load();
        assert!(learner.is_empty());
        assert_eq!(
            connect(&learner, 1, "old.test", true, 1000),
            Mode::FakeAutoTtl
        );
        learner.save_if_dirty();

        let reloaded = Learner::new(&path);
        reloaded.load();
        assert_eq!(
            reloaded.learned(),
            vec![("home|old.test".to_owned(), "packet-autottl")]
        );
        reloaded.clear();
        let emptied = Learner::new(&path);
        emptied.load();
        assert!(emptied.is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
