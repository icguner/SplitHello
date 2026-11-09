//! Domain-level ad/tracker blocking (port of the pure half of
//! `src/AdBlock.cpp`). A host is blocked when it or any parent domain is in the
//! list (HaGeZi "onlydomains" lists block subdomains too). Readers only clone
//! an `Arc` snapshot under a brief read lock; the updater swaps whole snapshots.
//! The downloader/updater arrives with the network crates (stage 3).
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};

pub type DomainSet = HashSet<String>;

const MAX_TRACKED_HOSTS: usize = 2000;

fn lower_host(host: &str) -> String {
    host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase()
}

fn valid_hostname(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || name.starts_with('.') || name.ends_with('.') {
        return false;
    }
    let mut has_letter = false;
    for c in name.bytes() {
        has_letter |= c.is_ascii_alphabetic();
        if !(c.is_ascii_alphanumeric() || c == b'-' || c == b'.' || c == b'_') {
            return false;
        }
    }
    // Rejects IP literals ("0.0.0.0" in hosts files) and bare numbers.
    has_letter
}

/// Accepts plain domains, hosts lines (`0.0.0.0 domain`) and `||domain^` rules.
/// `#` and `!` lines are comments; anything that is not a hostname is skipped.
pub fn parse_domains(text: &str) -> DomainSet {
    let mut result = DomainSet::new();
    for line in text.lines() {
        let mut line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        if let Some(hash) = line.find('#') {
            line = line[..hash].trim();
        }
        if let Some(rule) = line.strip_prefix("||") {
            line = rule.split('^').next().unwrap_or(rule);
        } else if let Some(space) = line.rfind([' ', '\t']) {
            line = &line[space + 1..]; // hosts format: address, then name
        }
        let line = line.strip_prefix("*.").unwrap_or(line);
        let name = lower_host(line);
        if valid_hostname(&name) {
            result.insert(name);
        }
    }
    result
}

#[derive(Default)]
struct Sets {
    blocked: Arc<DomainSet>,
    allowed: DomainSet,
}

#[derive(Default)]
pub struct Blocklist {
    sets: RwLock<Arc<Sets>>,
}

impl Blocklist {
    fn snapshot(&self) -> Arc<Sets> {
        self.sets.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn store(&self, sets: Sets) {
        *self.sets.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(sets);
    }

    pub fn replace(&self, blocked: DomainSet) {
        let current = self.snapshot();
        self.store(Sets {
            blocked: Arc::new(blocked),
            allowed: current.allowed.clone(),
        });
    }

    pub fn set_allow<S: AsRef<str>>(&self, allowed: &[S]) {
        let current = self.snapshot();
        let allowed = allowed
            .iter()
            .map(|a| lower_host(a.as_ref()))
            .filter(|a| !a.is_empty())
            .collect();
        // The blocked set is shared, not copied.
        self.store(Sets {
            blocked: current.blocked.clone(),
            allowed,
        });
    }

    /// True when `host` (or a parent domain) is blocked and no parent of it is
    /// allow-listed. IP literals and empty names are never blocked.
    pub fn blocks(&self, host: &str) -> bool {
        let sets = self.snapshot();
        if sets.blocked.is_empty() || host.is_empty() {
            return false;
        }
        let name = lower_host(host);
        if name.is_empty() || name.starts_with('[') || name.contains(':') {
            return false;
        }
        // Walk "a.b.example.com" -> "b.example.com" -> "example.com" -> "com".
        let mut blocked = false;
        let mut part = name.as_str();
        loop {
            if sets.allowed.contains(part) {
                return false;
            }
            blocked |= sets.blocked.contains(part);
            match part.find('.') {
                Some(dot) => part = &part[dot + 1..],
                None => return blocked,
            }
        }
    }

    pub fn len(&self) -> usize {
        self.snapshot().blocked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Process-wide list shared by the relay and the DNS proxy.
pub fn global() -> &'static Blocklist {
    static LIST: OnceLock<Blocklist> = OnceLock::new();
    LIST.get_or_init(Blocklist::default)
}

static BLOCKED: AtomicU64 = AtomicU64::new(0);

fn tally() -> &'static Mutex<BTreeMap<String, u32>> {
    static TALLY: OnceLock<Mutex<BTreeMap<String, u32>>> = OnceLock::new();
    TALLY.get_or_init(Mutex::default)
}

/// Called for each block: bumps the total and keeps a bounded per-host tally
/// so the UI can offer "allow this" for false positives.
pub fn record_blocked(host: &str) {
    BLOCKED.fetch_add(1, Ordering::Relaxed);
    let name = lower_host(host);
    let mut tally = tally().lock().unwrap_or_else(|p| p.into_inner());
    if let Some(count) = tally.get_mut(&name) {
        *count += 1;
    } else if tally.len() < MAX_TRACKED_HOSTS {
        tally.insert(name, 1);
    } // else: counted in the total only, so memory stays bounded
}

pub fn blocked_count() -> u64 {
    BLOCKED.load(Ordering::Relaxed)
}

pub fn top_blocked(limit: usize) -> Vec<(String, u32)> {
    let mut all: Vec<_> = tally()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .iter()
        .map(|(host, count)| (host.clone(), *count))
        .collect();
    all.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    all.truncate(limit);
    all
}

/// HaGeZi list names accepted in config (`ad_block_lists`) and their path in the
/// dns-blocklists repository.
pub fn list_path(name: &str) -> Option<String> {
    let file = match name {
        "light" => "light-onlydomains.txt",    // fewest false positives
        "pro" => "pro-onlydomains.txt",        // recommended
        "tif" => "tif.medium-onlydomains.txt", // malware / phishing / scam feeds
        "doh" => "doh-onlydomains.txt",        // DoH servers: pushes apps onto our DNS
        _ => return None,
    };
    Some(format!("/hagezi/dns-blocklists/main/wildcard/{file}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_domain_formats() {
        let parsed = parse_domains(
            "# Title: demo\r\n\
             ads.example.com\r\n\
             0.0.0.0 Tracker.Example.NET\n\
             ||adserver.test^\n\
             *.wild.example.org\n\
             ! comment\n   \n\
             1.2.3.4\n\
             bad name.com\n\
             trailing.example.com # note\n",
        );
        for name in [
            "ads.example.com",
            "tracker.example.net",
            "adserver.test",
            "wild.example.org",
            "trailing.example.com",
        ] {
            assert!(parsed.contains(name), "{name}");
        }
        assert!(!parsed.contains("1.2.3.4"));
        assert!(!parsed.contains("0.0.0.0"));
    }

    #[test]
    fn blocks_subdomains_but_not_siblings() {
        let list = Blocklist::default();
        list.replace(parse_domains("doubleclick.net\nads.example.com\n"));
        assert!(list.blocks("doubleclick.net"));
        assert!(list.blocks("stats.g.DoubleClick.net.")); // case and trailing dot
        assert!(list.blocks("x.ads.example.com"));
        assert!(!list.blocks("example.com")); // parent of a blocked name
        assert!(!list.blocks("notdoubleclick.net")); // label boundary, not substring
        assert!(!list.blocks("twitch.tv"));
        assert!(!list.blocks("1.2.3.4"));
        assert!(!list.blocks("[2001:db8::1]"));
        assert!(!list.blocks(""));
    }

    #[test]
    fn allow_list_wins_over_blocklist() {
        let list = Blocklist::default();
        list.replace(parse_domains("tracker.com\n"));
        list.set_allow(&["Good.Tracker.com"]);
        assert!(list.blocks("tracker.com"));
        assert!(list.blocks("a.tracker.com"));
        assert!(!list.blocks("good.tracker.com"));
        assert!(!list.blocks("x.good.tracker.com"));
        // Replacing the list keeps the allow-list.
        list.replace(parse_domains("tracker.com\nother.com\n"));
        assert!(!list.blocks("good.tracker.com"));
        assert!(list.blocks("other.com"));
    }

    #[test]
    fn empty_list_blocks_nothing() {
        let list = Blocklist::default();
        assert!(!list.blocks("doubleclick.net"));
        assert_eq!(list.len(), 0);
    }

    #[test]
    fn tallies_blocked_hosts_lowercased() {
        let before = blocked_count();
        record_blocked("Tally-Test.Example.COM");
        record_blocked("tally-test.example.com");
        record_blocked("tally-other.example.com");
        assert_eq!(blocked_count(), before + 3);
        let count = top_blocked(2000)
            .into_iter()
            .find(|(h, _)| h == "tally-test.example.com")
            .map(|(_, c)| c);
        assert_eq!(count, Some(2));
    }

    #[test]
    fn list_names() {
        assert!(list_path("pro").is_some());
        assert!(list_path("tif").is_some());
        assert!(list_path("nope").is_none());
        assert!(list_path("pro").unwrap().ends_with("pro-onlydomains.txt"));
    }
}
