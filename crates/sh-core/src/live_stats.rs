//! Live engine counters in a small named memory mapping (port of
//! `src/LiveStats.cpp`). The layout is the C++ v2 layout byte for byte, so a
//! C++ tray can read a Rust engine and the other way round. Writers only do
//! fixed-size atomic updates: no allocation or I/O on the relay path.

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAGIC: i32 = 0x5348_4C53; // "SHLS"
const VERSION: i32 = 2;
pub const MAX_PROFILES: usize = 16;
/// The mapping the SYSTEM service publishes (fixed: the tray in the user's
/// session cannot hand it a per-run name).
pub const SERVICE_MAPPING: &str = "Global\\SplitHello-LiveStats";

/// 44 consecutive 32-bit integers (176 bytes), as in the C++ `SharedState`.
#[repr(C)]
struct SharedState {
    magic: AtomicI32,
    version: AtomicI32,
    /// sizeof of the writer: a layout mismatch reads as offline.
    size: AtomicI32,
    engine_pid: AtomicI32,
    started_at: AtomicI32,
    active_flows: AtomicI32,
    opened_flows: AtomicI32,
    decisions: AtomicI32,
    successful_decisions: AtomicI32,
    bypassed_decisions: AtomicI32,
    unresolved_decisions: AtomicI32,
    last_decision_at: AtomicI32,
    active_profiles: [AtomicI32; MAX_PROFILES],
    profile_decisions: [AtomicI32; MAX_PROFILES],
}

const STATE_SIZE: usize = std::mem::size_of::<SharedState>();
const _: () = assert!(STATE_SIZE == 176);

fn unix_seconds32() -> i32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs().min(0x7FFF_FFFF) as i32)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileSnapshot {
    pub name: String,
    pub active: u32,
    pub decisions: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub online: bool,
    pub engine_pid: u32,
    pub started_at: u32,
    pub active_flows: u32,
    /// Active flows not yet attributed to a profile.
    pub pending_flows: u32,
    pub opened_flows: u32,
    pub decisions: u32,
    pub successful_decisions: u32,
    pub bypassed_decisions: u32,
    pub unresolved_decisions: u32,
    pub last_decision_at: u32,
    pub profiles: Vec<ProfileSnapshot>,
}

/// Engine-side owner of the mapping.
pub struct Publisher {
    mapping: platform::Mapping,
}

impl Publisher {
    /// None when the mapping cannot be created (the engine runs without stats).
    pub fn new(name: &str) -> Option<Arc<Self>> {
        if name.is_empty() {
            return None;
        }
        let mapping = platform::Mapping::create(name, STATE_SIZE)?;
        let publisher = Self { mapping };
        // The tray reuses one name across engine restarts and never runs two
        // engines for it, so a new publisher owns and resets the block.
        let state = publisher.state();
        state.magic.store(0, Ordering::SeqCst);
        for field in publisher.all_fields() {
            field.store(0, Ordering::Relaxed);
        }
        state.version.store(VERSION, Ordering::Relaxed);
        state.size.store(STATE_SIZE as i32, Ordering::Relaxed);
        state
            .engine_pid
            .store(std::process::id() as i32, Ordering::Relaxed);
        state.started_at.store(unix_seconds32(), Ordering::Relaxed);
        state.magic.store(MAGIC, Ordering::SeqCst); // published last
        Some(Arc::new(publisher))
    }

    fn state(&self) -> &SharedState {
        // SAFETY: the view is STATE_SIZE bytes, page-aligned, lives as long as
        // `self`, and is only ever accessed through atomics.
        unsafe { &*self.mapping.ptr().cast::<SharedState>() }
    }

    fn all_fields(&self) -> impl Iterator<Item = &AtomicI32> {
        let s = self.state();
        [
            &s.version,
            &s.size,
            &s.engine_pid,
            &s.started_at,
            &s.active_flows,
            &s.opened_flows,
            &s.decisions,
            &s.successful_decisions,
            &s.bypassed_decisions,
            &s.unresolved_decisions,
            &s.last_decision_at,
        ]
        .into_iter()
        .chain(s.active_profiles.iter())
        .chain(s.profile_decisions.iter())
    }

    fn flow_opened(&self) {
        let s = self.state();
        s.active_flows.fetch_add(1, Ordering::SeqCst);
        s.opened_flows.fetch_add(1, Ordering::SeqCst);
    }

    fn profile_changed(&self, previous: Option<usize>, next: Option<usize>) {
        if previous == next {
            return;
        }
        let s = self.state();
        if let Some(slot) = previous.filter(|&slot| slot < MAX_PROFILES) {
            s.active_profiles[slot].fetch_sub(1, Ordering::SeqCst);
        }
        if let Some(slot) = next.filter(|&slot| slot < MAX_PROFILES) {
            s.active_profiles[slot].fetch_add(1, Ordering::SeqCst);
        }
    }

    fn decision(&self, slot: Option<usize>, success: bool, bypassed: bool) {
        let s = self.state();
        s.decisions.fetch_add(1, Ordering::SeqCst);
        if success {
            s.successful_decisions.fetch_add(1, Ordering::SeqCst);
            if let Some(slot) = slot.filter(|&slot| slot < MAX_PROFILES) {
                s.profile_decisions[slot].fetch_add(1, Ordering::SeqCst);
            }
        } else {
            s.unresolved_decisions.fetch_add(1, Ordering::SeqCst);
        }
        if bypassed {
            s.bypassed_decisions.fetch_add(1, Ordering::SeqCst);
        }
        s.last_decision_at.store(unix_seconds32(), Ordering::SeqCst);
    }

    fn flow_closed(&self, slot: Option<usize>) {
        let s = self.state();
        if let Some(slot) = slot.filter(|&slot| slot < MAX_PROFILES) {
            s.active_profiles[slot].fetch_sub(1, Ordering::SeqCst);
        }
        s.active_flows.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.state().magic.store(0, Ordering::SeqCst);
    }
}

/// One relay connection's lifetime. Dropping it returns the active counts to
/// zero on every early-return and fallback path.
#[derive(Default)]
pub struct Flow {
    publisher: Option<Arc<Publisher>>,
    slot: Option<usize>,
    decided: bool,
}

impl Flow {
    pub fn begin(&mut self, publisher: Option<Arc<Publisher>>) {
        self.finish();
        if let Some(publisher) = &publisher {
            publisher.flow_opened();
        }
        self.publisher = publisher;
    }

    /// `slot` is the profile's index in the profile table (None: unknown).
    pub fn set_profile(&mut self, slot: Option<usize>) {
        if let Some(publisher) = &self.publisher {
            publisher.profile_changed(self.slot, slot);
            self.slot = slot;
        }
    }

    pub fn decision(&mut self, success: bool, bypassed: bool) {
        if let (Some(publisher), false) = (&self.publisher, self.decided) {
            publisher.decision(self.slot, success, bypassed);
            self.decided = true;
        }
    }

    pub fn finish(&mut self) {
        if let Some(publisher) = self.publisher.take() {
            publisher.flow_closed(self.slot);
        }
        self.slot = None;
        self.decided = false;
    }
}

impl Drop for Flow {
    fn drop(&mut self) {
        self.finish();
    }
}

fn non_negative(value: i32) -> u32 {
    value.max(0) as u32
}

/// Reads the mapping; `profile_names` is the profile table (slot order).
pub fn read(name: &str, profile_names: &[&str]) -> Snapshot {
    let mut snapshot = Snapshot::default();
    if name.is_empty() {
        return snapshot;
    }
    let Some(mapping) = platform::Mapping::open_read(name, STATE_SIZE) else {
        return snapshot;
    };
    // SAFETY: the read-only view is STATE_SIZE bytes and outlives `state`.
    let state = unsafe { &*mapping.ptr().cast::<SharedState>() };
    let load = |field: &AtomicI32| field.load(Ordering::SeqCst);
    if load(&state.magic) != MAGIC
        || load(&state.version) != VERSION
        || load(&state.size) != STATE_SIZE as i32
    {
        return snapshot;
    }
    snapshot.online = true;
    snapshot.engine_pid = non_negative(load(&state.engine_pid));
    snapshot.started_at = non_negative(load(&state.started_at));
    snapshot.active_flows = non_negative(load(&state.active_flows));
    snapshot.opened_flows = load(&state.opened_flows) as u32;
    snapshot.decisions = load(&state.decisions) as u32;
    snapshot.successful_decisions = load(&state.successful_decisions) as u32;
    snapshot.bypassed_decisions = load(&state.bypassed_decisions) as u32;
    snapshot.unresolved_decisions = load(&state.unresolved_decisions) as u32;
    snapshot.last_decision_at = load(&state.last_decision_at) as u32;
    let mut classified = 0;
    for (index, name) in profile_names.iter().take(MAX_PROFILES).enumerate() {
        let active = non_negative(load(&state.active_profiles[index]));
        classified += active;
        snapshot.profiles.push(ProfileSnapshot {
            name: (*name).to_owned(),
            active,
            decisions: load(&state.profile_decisions[index]) as u32,
        });
    }
    snapshot.pending_flows = snapshot.active_flows.saturating_sub(classified);
    snapshot
}

#[cfg(windows)]
mod platform {
    use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
    use windows::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_ALL_ACCESS, FILE_MAP_READ, MEMORY_MAPPED_VIEW_ADDRESS,
        MapViewOfFile, OpenFileMappingW, PAGE_READWRITE, UnmapViewOfFile,
    };
    use windows::core::HSTRING;

    pub struct Mapping {
        handle: HANDLE,
        view: MEMORY_MAPPED_VIEW_ADDRESS,
    }

    // SAFETY: the handle and view are process-wide resources; access to the
    // memory goes through atomics only.
    unsafe impl Send for Mapping {}
    // SAFETY: as above.
    unsafe impl Sync for Mapping {}

    impl Mapping {
        /// A `Global\` name (the SYSTEM service) gets an explicit DACL:
        /// SYSTEM and Administrators full, interactive users read-only, so the
        /// user's tray and panel can read it and nothing else can write it.
        /// Other names keep the creator's default DACL.
        pub fn create(name: &str, size: usize) -> Option<Self> {
            use windows::Win32::Foundation::{HLOCAL, LocalFree};
            use windows::Win32::Security::Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            };
            use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};

            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            let shared = name.starts_with("Global\\")
                // SAFETY: converts a constant SDDL string; freed below.
                && unsafe {
                    ConvertStringSecurityDescriptorToSecurityDescriptorW(
                        windows::core::w!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GR;;;IU)"),
                        SDDL_REVISION_1,
                        &mut descriptor,
                        None,
                    )
                }
                .is_ok();
            let attributes = SECURITY_ATTRIBUTES {
                nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor.0,
                bInheritHandle: false.into(),
            };
            // SAFETY: pagefile-backed mapping with a valid name; the
            // descriptor outlives the call.
            let handle = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    shared.then_some(&attributes as *const _),
                    PAGE_READWRITE,
                    0,
                    size as u32,
                    &HSTRING::from(name),
                )
            };
            if shared {
                // SAFETY: allocated by the conversion above.
                let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
            }
            Self::map(handle.ok()?, FILE_MAP_ALL_ACCESS.0, size)
        }

        pub fn open_read(name: &str, size: usize) -> Option<Self> {
            // SAFETY: opening a named mapping read-only.
            let handle =
                unsafe { OpenFileMappingW(FILE_MAP_READ.0, false, &HSTRING::from(name)) }.ok()?;
            Self::map(handle, FILE_MAP_READ.0, size)
        }

        fn map(handle: HANDLE, access: u32, size: usize) -> Option<Self> {
            use windows::Win32::System::Memory::FILE_MAP;
            // SAFETY: `handle` is a valid mapping handle.
            let view = unsafe { MapViewOfFile(handle, FILE_MAP(access), 0, 0, size) };
            if view.Value.is_null() {
                // SAFETY: we own the handle.
                unsafe {
                    let _ = CloseHandle(handle);
                }
                return None;
            }
            Some(Self { handle, view })
        }

        pub fn ptr(&self) -> *mut u8 {
            self.view.Value.cast()
        }
    }

    impl Drop for Mapping {
        fn drop(&mut self) {
            // SAFETY: we own both the view and the handle.
            unsafe {
                let _ = UnmapViewOfFile(self.view);
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

#[cfg(not(windows))]
mod platform {
    pub struct Mapping;
    impl Mapping {
        pub fn create(_: &str, _: usize) -> Option<Self> {
            None
        }
        pub fn open_read(_: &str, _: usize) -> Option<Self> {
            None
        }
        pub fn ptr(&self) -> *mut u8 {
            std::ptr::null_mut()
        }
    }
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    const NAMES: [&str; 3] = ["none", "sni-mid", "record-1"];

    fn unique(name: &str) -> String {
        format!("Local\\SplitHello-test-{name}-{}", std::process::id())
    }

    #[test]
    fn publishes_counters_and_resets_on_drop() {
        let name = unique("counters");
        assert!(!read(&name, &NAMES).online);
        let publisher = Publisher::new(&name).expect("mapping");
        {
            let mut flow = Flow::default();
            flow.begin(Some(publisher.clone()));
            flow.set_profile(Some(1));
            let live = read(&name, &NAMES);
            assert!(live.online);
            assert_eq!(live.engine_pid, std::process::id());
            assert_eq!(live.active_flows, 1);
            assert_eq!(live.profiles[1].active, 1);
            assert_eq!(live.pending_flows, 0);
            flow.decision(true, true);
            flow.decision(true, true); // counted once
        }
        let after = read(&name, &NAMES);
        assert_eq!(after.active_flows, 0);
        assert_eq!(after.opened_flows, 1);
        assert_eq!(after.decisions, 1);
        assert_eq!(after.bypassed_decisions, 1);
        assert_eq!(after.profiles[1].decisions, 1);
        assert_eq!(after.profiles[1].active, 0);
        drop(publisher);
        assert!(!read(&name, &NAMES).online);
    }

    #[test]
    fn unattributed_flows_are_pending() {
        let name = unique("pending");
        let publisher = Publisher::new(&name).expect("mapping");
        let mut flow = Flow::default();
        flow.begin(Some(publisher.clone()));
        assert_eq!(read(&name, &NAMES).pending_flows, 1);
        flow.decision(false, false);
        assert_eq!(read(&name, &NAMES).unresolved_decisions, 1);
    }
}
