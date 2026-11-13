//! WinDivert 2.2.2 bindings, loaded at run time from `WinDivert.dll` next to
//! the executable. Dynamic loading keeps the tray, panel and one-shot commands
//! working when the driver files are missing; only the engine reports it.

use std::ffi::{CString, c_char, c_void};
use std::sync::OnceLock;

/// `WINDIVERT_ADDRESS` (80 bytes). Bitfield layout per MSVC, LSB first:
/// 0-7 Layer, 8-15 Event, 16 Sniffed, 17 Outbound, 18 Loopback, 19 Impostor,
/// 20 IPv6, 21 IPChecksum, 22 TCPChecksum, 23 UDPChecksum.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct Address {
    pub timestamp: i64,
    bits: u32,
    reserved: u32,
    union: [u64; 8],
}

const OUTBOUND: u32 = 1 << 17;
const CHECKSUMS: u32 = 0b111 << 21;

impl Address {
    pub fn outbound(&self) -> bool {
        self.bits & OUTBOUND != 0
    }

    pub fn set_outbound(&mut self, outbound: bool) {
        if outbound {
            self.bits |= OUTBOUND;
        } else {
            self.bits &= !OUTBOUND;
        }
    }

    /// What `WinDivertHelperCalcChecksums(.., pAddr, ..)` records after it
    /// recomputed the checksums: the driver then injects the bytes as they are.
    pub fn set_checksums_valid(&mut self) {
        self.bits |= CHECKSUMS;
    }
}

pub const LAYER_NETWORK: u32 = 0;
pub const FLAG_DROP: u64 = 0x0002;
pub const PARAM_QUEUE_LENGTH: u32 = 0;
pub const PARAM_QUEUE_TIME: u32 = 1;
pub const PARAM_QUEUE_SIZE: u32 = 2;
const SHUTDOWN_BOTH: u32 = 3;

type Handle = *mut c_void;
const INVALID_HANDLE: Handle = -1isize as Handle;

type OpenFn = unsafe extern "C" fn(*const c_char, u32, i16, u64) -> Handle;
type RecvExFn = unsafe extern "C" fn(
    Handle,
    *mut c_void,
    u32,
    *mut u32,
    u64,
    *mut Address,
    *mut u32,
    *mut c_void,
) -> i32;
type SendExFn = unsafe extern "C" fn(
    Handle,
    *const c_void,
    u32,
    *mut u32,
    u64,
    *const Address,
    u32,
    *mut c_void,
) -> i32;
type ShutdownFn = unsafe extern "C" fn(Handle, u32) -> i32;
type CloseFn = unsafe extern "C" fn(Handle) -> i32;
type SetParamFn = unsafe extern "C" fn(Handle, u32, u64) -> i32;
type CompileFn =
    unsafe extern "C" fn(*const c_char, u32, *mut c_char, u32, *mut *const c_char, *mut u32) -> i32;

struct Library {
    open: OpenFn,
    recv_ex: RecvExFn,
    send_ex: SendExFn,
    shutdown: ShutdownFn,
    close: CloseFn,
    set_param: SetParamFn,
    compile: CompileFn,
}

fn last_error() -> u32 {
    // SAFETY: reads the calling thread's last-error value.
    unsafe { windows::Win32::Foundation::GetLastError().0 }
}

fn load() -> Result<Library, String> {
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
        LoadLibraryExW,
    };
    use windows::core::{PCSTR, w};

    // Application directory only (plus System32 for its own imports): never
    // the current directory, so a planted DLL cannot be picked up.
    // SAFETY: plain library load with a static name.
    let module = unsafe {
        LoadLibraryExW(
            w!("WinDivert.dll"),
            None,
            LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }
    .map_err(|error| format!("WinDivert.dll yuklenemedi: {error}"))?;

    macro_rules! symbol {
        ($name:literal, $type:ty) => {{
            // SAFETY: the symbol's C signature is fixed by WinDivert 2.2 and
            // matches the function-pointer type it is transmuted into; the
            // module is never unloaded.
            let address = unsafe { GetProcAddress(module, PCSTR(concat!($name, "\0").as_ptr())) }
                .ok_or_else(|| format!("WinDivert.dll icinde {} yok", $name))?;
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $type>(address) }
        }};
    }
    Ok(Library {
        open: symbol!("WinDivertOpen", OpenFn),
        recv_ex: symbol!("WinDivertRecvEx", RecvExFn),
        send_ex: symbol!("WinDivertSendEx", SendExFn),
        shutdown: symbol!("WinDivertShutdown", ShutdownFn),
        close: symbol!("WinDivertClose", CloseFn),
        set_param: symbol!("WinDivertSetParam", SetParamFn),
        compile: symbol!("WinDivertHelperCompileFilter", CompileFn),
    })
}

fn library() -> Result<&'static Library, String> {
    static LIBRARY: OnceLock<Result<Library, String>> = OnceLock::new();
    LIBRARY.get_or_init(load).as_ref().map_err(Clone::clone)
}

/// Validates a filter string; Err carries the driver's message and position.
pub fn compile_filter(filter: &str) -> Result<(), String> {
    let library = library()?;
    let text = CString::new(filter).map_err(|_| "filtrede NUL".to_string())?;
    let mut object = vec![0 as c_char; 4096];
    let mut error: *const c_char = std::ptr::null();
    let mut position = 0u32;
    // SAFETY: all pointers are valid for the call; `object` has the stated length.
    let ok = unsafe {
        (library.compile)(
            text.as_ptr(),
            LAYER_NETWORK,
            object.as_mut_ptr(),
            object.len() as u32,
            &mut error,
            &mut position,
        )
    };
    if ok != 0 {
        return Ok(());
    }
    let message = if error.is_null() {
        "bilinmeyen hata".to_string()
    } else {
        // SAFETY: WinDivert returns a static NUL-terminated message.
        unsafe { std::ffi::CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    };
    Err(format!("({position}): {message}"))
}

/// An open WinDivert handle. `shutdown` may be called from another thread to
/// unblock a pending receive; the handle is closed on drop.
pub struct Divert {
    raw: Handle,
    library: &'static Library,
}

// SAFETY: WinDivert handles are kernel handles usable from any thread; the
// driver documents concurrent Recv/Send/Shutdown on one handle.
unsafe impl Send for Divert {}
unsafe impl Sync for Divert {}

/// Opening failed: the Win32 error code, or the DLL could not be loaded.
#[derive(Debug)]
pub enum OpenError {
    Library(String),
    Win32(u32),
}

impl Divert {
    pub fn open(filter: &str, priority: i16, flags: u64) -> Result<Self, OpenError> {
        let library = library().map_err(OpenError::Library)?;
        let text = CString::new(filter).map_err(|_| OpenError::Win32(87))?;
        // SAFETY: `text` is NUL-terminated and outlives the call.
        let raw = unsafe { (library.open)(text.as_ptr(), LAYER_NETWORK, priority, flags) };
        if raw == INVALID_HANDLE || raw.is_null() {
            return Err(OpenError::Win32(last_error()));
        }
        Ok(Self { raw, library })
    }

    pub fn set_param(&self, param: u32, value: u64) -> Result<(), u32> {
        // SAFETY: valid open handle.
        if unsafe { (self.library.set_param)(self.raw, param, value) } != 0 {
            Ok(())
        } else {
            Err(last_error())
        }
    }

    /// Blocks for a batch. Returns (bytes, addresses) filled.
    pub fn recv(
        &self,
        buffer: &mut [u8],
        addresses: &mut [Address],
    ) -> Result<(usize, usize), u32> {
        let mut received = 0u32;
        let mut address_bytes = std::mem::size_of_val(addresses) as u32;
        // SAFETY: both buffers are valid for the lengths passed.
        let ok = unsafe {
            (self.library.recv_ex)(
                self.raw,
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut received,
                0,
                addresses.as_mut_ptr(),
                &mut address_bytes,
                std::ptr::null_mut(),
            )
        };
        if ok == 0 {
            return Err(last_error());
        }
        Ok((
            received as usize,
            address_bytes as usize / std::mem::size_of::<Address>(),
        ))
    }

    /// Sends one or more packets back to back; Err carries (error, bytes sent).
    pub fn send(&self, packets: &[u8], addresses: &[Address]) -> Result<(), (u32, usize)> {
        let mut sent = 0u32;
        // SAFETY: both buffers are valid for the lengths passed.
        let ok = unsafe {
            (self.library.send_ex)(
                self.raw,
                packets.as_ptr().cast(),
                packets.len() as u32,
                &mut sent,
                0,
                addresses.as_ptr(),
                std::mem::size_of_val(addresses) as u32,
                std::ptr::null_mut(),
            )
        };
        if ok != 0 {
            Ok(())
        } else {
            Err((last_error(), sent as usize))
        }
    }

    pub fn shutdown(&self) {
        // SAFETY: valid open handle; shutdown is documented as thread-safe.
        unsafe { (self.library.shutdown)(self.raw, SHUTDOWN_BOTH) };
    }
}

impl Drop for Divert {
    fn drop(&mut self) {
        // SAFETY: the handle is open and closed exactly once.
        unsafe { (self.library.close)(self.raw) };
    }
}

/// Human text for `WinDivertOpen` failures (port of `openError`).
pub fn open_error_text(error: &OpenError) -> String {
    match error {
        OpenError::Library(text) => text.clone(),
        OpenError::Win32(5) => "yonetici yetkisi gerekli".into(),
        OpenError::Win32(2) => "WinDivert surucu dosyasi bulunamadi".into(),
        OpenError::Win32(577) => "WinDivert surucu imzasi Windows tarafindan reddedildi".into(),
        OpenError::Win32(1275) => {
            "WinDivert guvenlik yazilimi veya Windows tarafindan engellendi".into()
        }
        OpenError::Win32(code) => format!("Windows hata kodu {code}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Needs WinDivert.dll next to the test executable; run unelevated.
    #[test]
    #[ignore]
    fn driver_library_compiles_filters_and_refuses_unelevated_open() {
        let settings = crate::Settings {
            forced: None,
            dns_proxy_port: 1053,
            quic_mode: crate::QuicMode::Adaptive,
            capture_dns: true,
            filter_dns: false,
        };
        compile_filter(&settings.filter(None)).unwrap();
        assert!(compile_filter("tcp.DstPort == ").is_err());
        assert!(matches!(
            Divert::open("false", 0, 0),
            Err(OpenError::Win32(5))
        ));
    }

    #[test]
    fn address_matches_the_c_layout() {
        assert_eq!(std::mem::size_of::<Address>(), 80);
        let mut address = Address::default();
        address.set_outbound(true);
        assert_eq!(address.bits, 1 << 17);
        address.set_checksums_valid();
        address.set_outbound(false);
        assert_eq!(address.bits, 0x00E0_0000);
    }
}
