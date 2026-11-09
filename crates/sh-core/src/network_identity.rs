//! Opaque identity of the network the machine is on (port of
//! `src/NetworkIdentity.cpp`). Learned profiles are scoped to it, so the id
//! must be byte-identical to the C++ build's: `nla-` + FNV-1a-64 (16 lowercase
//! hex digits) over the sorted GUIDs of connected networks with Internet
//! connectivity, each as uppercase `StringFromGUID2` text without braces,
//! followed by `|`.

use std::sync::Mutex;
use std::time::{Duration, Instant};

pub const DEFAULT_ID: &str = "network-default";

fn fnv1a(text: &str) -> u64 {
    text.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

/// Builds the id from network GUID texts (order-independent).
pub fn id_from_guids(mut guids: Vec<String>) -> String {
    if guids.is_empty() {
        return DEFAULT_ID.into();
    }
    guids.sort();
    let joined: String = guids.iter().map(|g| format!("{g}|")).collect();
    format!("nla-{:016x}", fnv1a(&joined))
}

/// Asks Windows (NLA) for the current identity; `network-default` when it
/// cannot tell.
pub fn current() -> String {
    id_from_guids(platform::connected_internet_networks().unwrap_or_default())
}

#[cfg(windows)]
mod platform {
    use windows::Win32::Networking::NetworkListManager::{
        INetwork, INetworkListManager, NLM_CONNECTIVITY_IPV4_INTERNET,
        NLM_CONNECTIVITY_IPV6_INTERNET, NLM_ENUM_NETWORK_CONNECTED, NetworkListManager,
    };
    use windows::Win32::System::Com::{
        CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
        CoUninitialize,
    };
    use windows::core::GUID;

    /// `StringFromGUID2` form without braces: uppercase, dashed.
    fn guid_text(id: &GUID) -> String {
        let d4 = id.data4;
        format!(
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            id.data1, id.data2, id.data3, d4[0], d4[1], d4[2], d4[3], d4[4], d4[5], d4[6], d4[7]
        )
    }

    pub fn connected_internet_networks() -> Option<Vec<String>> {
        // SAFETY: plain COM initialization; balanced below when it succeeded.
        let init = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };
        // RPC_E_CHANGED_MODE: COM is already up in another mode, still usable.
        let uninitialize = init.is_ok();
        let result = (|| {
            // SAFETY: COM is initialized on this thread.
            let manager: INetworkListManager =
                unsafe { CoCreateInstance(&NetworkListManager, None, CLSCTX_INPROC_SERVER) }
                    .ok()?;
            // SAFETY: valid interface pointer.
            let networks = unsafe { manager.GetNetworks(NLM_ENUM_NETWORK_CONNECTED) }.ok()?;
            let mut ids = Vec::new();
            loop {
                let mut slot: [Option<INetwork>; 1] = [None];
                let mut fetched = 0u32;
                // SAFETY: one-element buffer and a valid counter pointer.
                if unsafe { networks.Next(&mut slot, Some(&mut fetched)) }.is_err() || fetched == 0
                {
                    break;
                }
                let Some(network) = slot[0].take() else { break };
                // SAFETY: valid interface pointer.
                let connectivity = unsafe { network.GetConnectivity() }.ok();
                let has_internet = connectivity.is_some_and(|c| {
                    c.0 & NLM_CONNECTIVITY_IPV4_INTERNET.0 != 0
                        || c.0 & NLM_CONNECTIVITY_IPV6_INTERNET.0 != 0
                });
                if has_internet {
                    // SAFETY: valid interface pointer.
                    if let Ok(id) = unsafe { network.GetNetworkId() } {
                        ids.push(guid_text(&id));
                    }
                }
            }
            Some(ids)
        })();
        if uninitialize {
            // SAFETY: balances the successful CoInitializeEx above.
            unsafe { CoUninitialize() };
        }
        result
    }
}

#[cfg(not(windows))]
mod platform {
    pub fn connected_internet_networks() -> Option<Vec<String>> {
        None
    }
}

struct CacheState {
    value: String,
    fetched_at: Option<Duration>,
    refreshing: bool,
}

/// Caches the identity for a while: the NLA COM call is too slow to make per
/// connection. Only one caller refreshes; the others get the stale value.
pub struct CachedIdentity<F> {
    fetch: F,
    ttl: Duration,
    state: Mutex<CacheState>,
}

impl<F: Fn() -> String> CachedIdentity<F> {
    pub fn new(fetch: F, ttl: Duration) -> Self {
        Self {
            fetch,
            ttl,
            state: Mutex::new(CacheState {
                value: String::new(),
                fetched_at: None,
                refreshing: false,
            }),
        }
    }

    /// `now` is time since an arbitrary fixed origin (monotonic).
    pub fn get(&self, now: Duration) -> String {
        {
            let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
            let fresh = !state.value.is_empty()
                && state
                    .fetched_at
                    .is_some_and(|at| now.saturating_sub(at) < self.ttl);
            // Someone else is already asking the OS: a slightly stale answer
            // beats stalling this connection behind their COM call.
            if fresh || (state.refreshing && !state.value.is_empty()) {
                return state.value.clone();
            }
            state.refreshing = true;
        }
        let fetched = (self.fetch)();
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        state.refreshing = false;
        state.fetched_at = Some(now);
        // The fallback id means "could not tell": keep a real identity we knew.
        if state.value.is_empty() || fetched != DEFAULT_ID {
            state.value = fetched;
        }
        state.value.clone()
    }
}

/// Process-wide 30 s cache over `current()`.
pub fn current_cached() -> String {
    use std::sync::OnceLock;
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    static CACHE: OnceLock<CachedIdentity<fn() -> String>> = OnceLock::new();
    let origin = *ORIGIN.get_or_init(Instant::now);
    CACHE
        .get_or_init(|| CachedIdentity::new(current as fn() -> String, Duration::from_secs(30)))
        .get(origin.elapsed())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

    #[test]
    fn id_matches_the_cpp_hash_shape() {
        assert_eq!(id_from_guids(Vec::new()), DEFAULT_ID);
        let one = id_from_guids(vec!["B".into(), "A".into()]);
        let two = id_from_guids(vec!["A".into(), "B".into()]);
        assert_eq!(one, two);
        assert!(one.starts_with("nla-") && one.len() == 20);
        // FNV-1a 64 of "A|B|": known value keeps the format byte-compatible.
        assert_eq!(one, format!("nla-{:016x}", fnv1a("A|B|")));
        assert_eq!(fnv1a(""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a("a"), 0xaf63_dc4c_8601_ec8c);
    }

    /// Compare by hand with the "Ag profili: nla-..." line the C++ engine logs
    /// on the same network. Run with `-- --ignored --nocapture`.
    #[test]
    #[ignore = "prints this machine's network id"]
    fn compat_print_current_id() {
        println!("network id: {}", current());
    }

    #[test]
    fn identity_is_stable_and_opaque() {
        let first = current();
        assert_eq!(first, current());
        assert!(first.starts_with("nla-") || first == DEFAULT_ID);
        let cached = current_cached();
        assert_eq!(cached, current_cached());
        assert!(cached.starts_with("nla-") || cached == DEFAULT_ID);
    }

    #[test]
    fn cached_identity_refreshes_only_after_the_ttl() {
        let calls = Cell::new(0);
        let next = RefCell::new("nla-a".to_string());
        let cache = CachedIdentity::new(
            || {
                calls.set(calls.get() + 1);
                next.borrow().clone()
            },
            Duration::from_secs(30),
        );
        let at = Duration::from_secs;
        assert_eq!(cache.get(at(0)), "nla-a");
        assert_eq!(calls.get(), 1);
        // Inside the window the OS is not asked again, even if the answer changed.
        *next.borrow_mut() = "nla-b".into();
        assert_eq!(cache.get(at(29)), "nla-a");
        assert_eq!(calls.get(), 1);
        assert_eq!(cache.get(at(30)), "nla-b");
        assert_eq!(calls.get(), 2);
        assert_eq!(cache.get(at(31)), "nla-b");
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn cached_identity_keeps_the_last_known_value_when_the_lookup_fails() {
        let calls = Cell::new(0);
        let answer = RefCell::new("nla-home".to_string());
        let cache = CachedIdentity::new(
            || {
                calls.set(calls.get() + 1);
                answer.borrow().clone()
            },
            Duration::from_secs(30),
        );
        let at = Duration::from_secs;
        assert_eq!(cache.get(at(0)), "nla-home");
        // COM failure / no connected network: current() yields the fallback id.
        *answer.borrow_mut() = DEFAULT_ID.into();
        assert_eq!(cache.get(at(40)), "nla-home");
        assert_eq!(calls.get(), 2);
        // The failed refresh still resets the window; no hammering of COM.
        assert_eq!(cache.get(at(50)), "nla-home");
        assert_eq!(calls.get(), 2);
    }
}
