//! Per-tuple process scope (port of `process_filter::Filter`,
//! `src/ProcessFilter.cpp`). The owner of a new outbound tuple is looked up
//! once in the TCP/UDP owner tables, its image matched against the rules, and
//! the decision cached; the packet loop never opens a process for known tuples.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::rules::Rules;

const MAXIMUM_CACHED: usize = 8192;
const TCP_TTL_MS: u64 = 10 * 60 * 1000;
const UDP_TTL_MS: u64 = 2 * 60 * 1000;
const UNKNOWN_TTL_MS: u64 = 1000;
const PROCESS_NAME_TTL_MS: u64 = 30 * 1000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub ipv6: bool,
    pub udp: bool,
    /// 4 or 16 meaningful bytes, network order.
    pub local_address: [u8; 16],
    pub remote_address: [u8; 16],
    pub local_port: u16,
    pub remote_port: u16,
}

#[derive(Clone, Copy)]
struct Decision {
    intercept: bool,
    expires_ms: u64,
    resolved: bool, // false: owner unknown, short negative cache
}

#[derive(Default)]
struct State {
    endpoints: HashMap<Endpoint, Decision>,
    process_names: HashMap<u32, (String, u64)>,
    next_sweep_ms: u64,
}

type OwnerLookup = Box<dyn Fn(&Endpoint) -> Option<u32> + Send + Sync>;

pub struct Filter {
    rules: Rules,
    owner: OwnerLookup,
    state: Mutex<State>,
}

impl Filter {
    pub fn new(rules: Rules) -> Self {
        Self::with_owner_lookup(rules, Box::new(owner))
    }

    /// Test seam: replaces the owner-table walk.
    pub fn with_owner_lookup(rules: Rules, owner: OwnerLookup) -> Self {
        Self {
            rules,
            owner,
            state: Mutex::default(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.rules.enabled()
    }

    pub fn rules(&self) -> &Rules {
        &self.rules
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn should_intercept(
        &self,
        endpoint: &Endpoint,
        outbound: bool,
        new_tcp_flow: bool,
        now_ms: u64,
    ) -> bool {
        if !self.rules.enabled() {
            return true;
        }
        if endpoint.local_port == 0 || endpoint.remote_port == 0 {
            return false;
        }
        let ttl = if endpoint.udp { UDP_TTL_MS } else { TCP_TTL_MS };
        if let Some(decision) = self.lock().endpoints.get_mut(endpoint)
            && decision.expires_ms > now_ms
        {
            // A resolved decision follows its connection: traffic keeps it
            // alive, so a long-lived intercepted flow is never turned into a
            // bypassed (and therefore reset) one by a fixed deadline.
            if decision.resolved {
                decision.expires_ms = decision.expires_ms.max(now_ms + ttl);
            }
            return decision.intercept;
        }

        // Never walk the owner tables for an inbound packet or for a TCP flow
        // that was already in progress when SplitHello started.
        if !outbound || (!endpoint.udp && !new_tcp_flow) {
            return false;
        }

        let image = (self.owner)(endpoint)
            .map(|pid| self.cached_image(pid, now_ms))
            .unwrap_or_default();
        // shortcut: an unresolved owner is left alone even with exclude-only
        // rules, because it might be the excluded process; the padded table
        // fetch keeps unresolved owners rare. Revisit if users report misses.
        let intercept = !image.is_empty() && self.rules.allows_image(&image);
        let resolved = !image.is_empty();
        let mut state = self.lock();
        if state.endpoints.len() >= MAXIMUM_CACHED && !state.endpoints.contains_key(endpoint) {
            make_room(&mut state, now_ms);
        }
        state.endpoints.insert(
            *endpoint,
            Decision {
                intercept,
                expires_ms: now_ms + if resolved { ttl } else { UNKNOWN_TTL_MS },
                resolved,
            },
        );
        intercept
    }

    pub fn forget(&self, endpoint: &Endpoint) {
        self.lock().endpoints.remove(endpoint);
    }

    pub fn clear(&self) {
        let mut state = self.lock();
        state.endpoints.clear();
        state.process_names.clear();
    }

    fn cached_image(&self, pid: u32, now_ms: u64) -> String {
        if let Some((image, expires)) = self.lock().process_names.get(&pid)
            && *expires > now_ms
        {
            return image.clone();
        }
        let image = process_image(pid);
        let mut state = self.lock();
        if state.process_names.len() >= MAXIMUM_CACHED {
            state
                .process_names
                .retain(|_, (_, expires)| *expires > now_ms);
            if state.process_names.len() >= MAXIMUM_CACHED {
                state.process_names.clear();
            }
        }
        state
            .process_names
            .insert(pid, (image.clone(), now_ms + PROCESS_NAME_TTL_MS));
        image
    }
}

/// Called with the cache full. Expired entries go first, scanned at most once
/// per second; if the cache is genuinely full of live tuples, the 1/16 closest
/// to expiry is evicted, bypassed tuples before intercepted ones.
fn make_room(state: &mut State, now_ms: u64) {
    if now_ms >= state.next_sweep_ms {
        state.next_sweep_ms = now_ms + 1000;
        state.endpoints.retain(|_, d| d.expires_ms > now_ms);
        if state.endpoints.len() < MAXIMUM_CACHED {
            return;
        }
    }
    let mut candidates: Vec<(bool, u64, Endpoint)> = state
        .endpoints
        .iter()
        .map(|(e, d)| (d.intercept, d.expires_ms, *e))
        .collect();
    let evict = (candidates.len() / 16).max(1);
    candidates.select_nth_unstable_by_key(evict - 1, |c| (c.0, c.1));
    for (_, _, endpoint) in &candidates[..evict] {
        state.endpoints.remove(endpoint);
    }
}

/// Lower-case image path with backslashes, "system" for PID 4, empty when unknown.
fn process_image(pid: u32) -> String {
    match pid {
        0 => String::new(),
        4 => "system".into(),
        _ => windows_image(pid),
    }
}

fn windows_image(pid: u32) -> String {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    use windows::core::PWSTR;

    // SAFETY: plain handle open; closed below.
    let Ok(process) = (unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) })
    else {
        return String::new();
    };
    let mut path = vec![0u16; 32768];
    let mut length = path.len() as u32;
    // SAFETY: `path` is valid for `length` UTF-16 units.
    let ok = unsafe {
        QueryFullProcessImageNameW(
            process,
            PROCESS_NAME_WIN32,
            PWSTR(path.as_mut_ptr()),
            &mut length,
        )
    }
    .is_ok();
    // SAFETY: opened above.
    let _ = unsafe { CloseHandle(process) };
    if !ok || length == 0 {
        return String::new();
    }
    String::from_utf16_lossy(&path[..length as usize])
        .trim()
        .to_ascii_lowercase()
        .replace('/', "\\")
}

/// The connection table can grow between the size query and the fetch (a
/// burst of new connections is exactly when this runs), so the buffer is
/// padded and the fetch retried instead of treating the race as "unknown".
fn fetch_table(fetch: impl Fn(*mut core::ffi::c_void, &mut u32) -> u32) -> Option<Vec<u8>> {
    const INSUFFICIENT_BUFFER: u32 = 122;
    let mut size = 0u32;
    let mut status = fetch(std::ptr::null_mut(), &mut size);
    for _ in 0..4 {
        if status != INSUFFICIENT_BUFFER || size == 0 {
            break;
        }
        size += size / 8 + 4096;
        // u32-aligned rows: allocate as u32 and view as bytes.
        let mut words = vec![0u32; size.div_ceil(4) as usize];
        let mut length = size;
        status = fetch(words.as_mut_ptr().cast(), &mut length);
        if status == 0 {
            let bytes = words.iter().flat_map(|w| w.to_ne_bytes()).collect();
            return Some(bytes);
        }
        size = length;
    }
    None
}

fn port(value: u32) -> u16 {
    u16::from_be(value as u16)
}

fn rows(bytes: &[u8], row_size: usize) -> impl Iterator<Item = &[u8]> {
    // Layout: DWORD count, then rows (each row u32-aligned).
    let count = bytes.get(..4).map_or(0, |b| {
        u32::from_ne_bytes(b.try_into().unwrap_or([0; 4])) as usize
    });
    bytes
        .get(4..)
        .unwrap_or_default()
        .chunks_exact(row_size)
        .take(count)
}

fn u32_at(row: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes(row[at..at + 4].try_into().unwrap_or([0; 4]))
}

/// Owner PID of the tuple from the system TCP/UDP tables.
fn owner(endpoint: &Endpoint) -> Option<u32> {
    use windows::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
    };
    use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

    let family = u32::from(if endpoint.ipv6 { AF_INET6.0 } else { AF_INET.0 });
    let length = if endpoint.ipv6 { 16 } else { 4 };
    let local = &endpoint.local_address[..length];
    let remote = &endpoint.remote_address[..length];

    if !endpoint.udp {
        // SAFETY: the buffer pointer/length pair comes from `fetch_table`.
        let bytes = fetch_table(|buffer, size| unsafe {
            GetExtendedTcpTable(
                Some(buffer),
                size,
                false,
                family,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        })?;
        // MIB_TCPROW_OWNER_PID: state, local addr, local port, remote addr,
        // remote port, pid. MIB_TCP6ROW_OWNER_PID: local addr[16], scope,
        // local port, remote addr[16], scope, remote port, state, pid.
        let (row_size, l_addr, l_port, r_addr, r_port, pid) = if endpoint.ipv6 {
            (56, 0, 20, 24, 44, 52)
        } else {
            (24, 4, 8, 12, 16, 20)
        };
        return rows(&bytes, row_size)
            .find(|row| {
                port(u32_at(row, l_port)) == endpoint.local_port
                    && port(u32_at(row, r_port)) == endpoint.remote_port
                    && &row[l_addr..l_addr + length] == local
                    && &row[r_addr..r_addr + length] == remote
            })
            .map(|row| u32_at(row, pid));
    }

    // SAFETY: as above.
    let bytes = fetch_table(|buffer, size| unsafe {
        GetExtendedUdpTable(Some(buffer), size, false, family, UDP_TABLE_OWNER_PID, 0)
    })?;
    // MIB_UDPROW_OWNER_PID: local addr, local port, pid.
    // MIB_UDP6ROW_OWNER_PID: local addr[16], scope, local port, pid.
    let (row_size, l_addr, l_port, pid) = if endpoint.ipv6 {
        (28, 0, 20, 24)
    } else {
        (12, 0, 4, 8)
    };
    let mut selected = None;
    for row in rows(&bytes, row_size) {
        let address = &row[l_addr..l_addr + length];
        if port(u32_at(row, l_port)) != endpoint.local_port
            || (address.iter().any(|b| *b != 0) && address != local)
        {
            continue;
        }
        let candidate = u32_at(row, pid);
        match selected {
            None => selected = Some(candidate),
            Some(existing) if existing != candidate => return None, // ambiguous
            Some(_) => {}
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, TcpListener, TcpStream};

    fn endpoint_of(stream: &TcpStream) -> Endpoint {
        let local = stream.local_addr().unwrap();
        let remote = stream.peer_addr().unwrap();
        let bytes = |ip: IpAddr| match ip {
            IpAddr::V4(v4) => {
                let mut out = [0u8; 16];
                out[..4].copy_from_slice(&v4.octets());
                out
            }
            IpAddr::V6(v6) => v6.octets(),
        };
        Endpoint {
            ipv6: local.is_ipv6(),
            udp: false,
            local_address: bytes(local.ip()),
            remote_address: bytes(remote.ip()),
            local_port: local.port(),
            remote_port: remote.port(),
        }
    }

    #[test]
    fn finds_this_process_as_the_owner_of_its_own_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        assert_eq!(owner(&endpoint_of(&stream)), Some(std::process::id()));
        let image = process_image(std::process::id());
        assert!(image.ends_with(".exe"), "{image}");
    }

    #[test]
    fn caches_decisions_and_only_resolves_new_outbound_flows() {
        let own_exe = std::env::current_exe().unwrap();
        let name = own_exe.file_name().unwrap().to_string_lossy().into_owned();
        let filter = Filter::with_owner_lookup(
            Rules::new(&[name.as_str()], &[] as &[&str]),
            Box::new(|_| Some(std::process::id())),
        );
        let endpoint = Endpoint {
            ipv6: false,
            udp: false,
            local_address: [10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            remote_address: [1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            local_port: 50000,
            remote_port: 443,
        };
        assert!(!filter.should_intercept(&endpoint, false, true, 1));
        assert!(!filter.should_intercept(&endpoint, true, false, 1));
        assert!(filter.should_intercept(&endpoint, true, true, 1));
        // Cached now: even an inbound packet of the tuple gets the decision.
        assert!(filter.should_intercept(&endpoint, false, false, 2));

        let other = Filter::with_owner_lookup(
            Rules::new(&["nothing.exe"], &[] as &[&str]),
            Box::new(|_| Some(std::process::id())),
        );
        assert!(!other.should_intercept(&endpoint, true, true, 1));
    }
}
