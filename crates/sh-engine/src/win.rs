//! Win32 process plumbing for the engine (ports from `src/main.cpp`):
//! elevation check and UAC relaunch, console control, the tray's shutdown
//! event / parent-process monitor and the ready event.

use std::sync::atomic::{AtomicBool, AtomicIsize, Ordering};
use std::thread::JoinHandle;

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    CreateEventW, EVENT_MODIFY_STATE, GetExitCodeProcess, INFINITE, OpenEventW, OpenProcess,
    PROCESS_SYNCHRONIZE, SYNCHRONIZATION_SYNCHRONIZE, SetEvent, WaitForMultipleObjects,
    WaitForSingleObject,
};
use windows::core::{HSTRING, PCWSTR};

static SHUTDOWN: AtomicBool = AtomicBool::new(false);
/// Set while waiting on an elevated child, so Ctrl+C reaches it.
static ELEVATION_EVENT: AtomicIsize = AtomicIsize::new(0);

pub fn shutdown_requested() -> bool {
    SHUTDOWN.load(Ordering::SeqCst)
}

pub fn request_shutdown() {
    SHUTDOWN.store(true, Ordering::SeqCst);
}

unsafe extern "system" fn console_handler(event: u32) -> windows::core::BOOL {
    use windows::Win32::System::Console::{
        CTRL_C_EVENT, CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT,
    };
    if [
        CTRL_C_EVENT,
        CTRL_CLOSE_EVENT,
        CTRL_LOGOFF_EVENT,
        CTRL_SHUTDOWN_EVENT,
    ]
    .contains(&event)
    {
        let elevated = ELEVATION_EVENT.load(Ordering::SeqCst);
        if elevated != 0 {
            // SAFETY: the event handle stays open while it is published here.
            let _ = unsafe { SetEvent(HANDLE(elevated as _)) };
        }
        request_shutdown();
        return true.into();
    }
    false.into()
}

/// Ctrl+C, console close, logoff and shutdown all request a clean stop.
pub fn install_console_handler() {
    // SAFETY: registers a static handler function.
    let _ = unsafe {
        windows::Win32::System::Console::SetConsoleCtrlHandler(Some(console_handler), true)
    };
}

pub fn is_elevated() -> bool {
    use windows::Win32::Security::{
        GetTokenInformation, TOKEN_ELEVATION, TOKEN_QUERY, TokenElevation,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    let mut token = HANDLE::default();
    // SAFETY: the token is closed below; the output struct has the queried size.
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// Relaunches this exe through UAC with the same arguments. With `wait`, a
/// shutdown event and our PID are passed so Ctrl+C here (or our death) stops
/// the elevated child, and its exit code is returned. None: refused/failed.
pub fn relaunch_elevated(wait: bool) -> Option<i32> {
    use windows::Win32::UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
    use windows::Win32::UI::WindowsAndMessaging::{SW_HIDE, SW_SHOWNORMAL};

    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let mut parameters = sh_core::cmdline::join(&arguments);
    let mut event = None;
    if wait {
        let name = format!(
            "Local\\SplitHello-shutdown-{}-{}",
            std::process::id(),
            sh_core::clock::now_ms()
        );
        // SAFETY: plain named-event creation, closed below.
        event = Some(unsafe { CreateEventW(None, true, false, &HSTRING::from(&name)) }.ok()?);
        parameters.push_str(&format!(
            " --shutdown-event {} --parent-pid {}",
            sh_core::cmdline::quote_argument(&name),
            std::process::id()
        ));
    }
    let close = |event: Option<HANDLE>| {
        if let Some(event) = event {
            // SAFETY: created above.
            let _ = unsafe { CloseHandle(event) };
        }
    };

    let Ok(executable) = std::env::current_exe() else {
        close(event);
        return None;
    };
    let executable = HSTRING::from(executable.as_os_str());
    let parameters = HSTRING::from(parameters);
    let mut launch = SHELLEXECUTEINFOW {
        cbSize: size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: windows::core::w!("runas"),
        lpFile: PCWSTR(executable.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: if wait { SW_SHOWNORMAL.0 } else { SW_HIDE.0 },
        ..Default::default()
    };
    // SAFETY: every string outlives the call.
    if let Err(error) = unsafe { ShellExecuteExW(&mut launch) } {
        tracing::error!("UAC baslatma hatasi: {error}");
        close(event);
        return None;
    }
    let process = launch.hProcess;
    if !wait {
        close(Some(process));
        return Some(0);
    }

    ELEVATION_EVENT.store(event.map_or(0, |e| e.0 as isize), Ordering::SeqCst);
    let mut code = 1u32;
    // SAFETY: the process handle was returned by ShellExecuteExW.
    unsafe {
        WaitForSingleObject(process, INFINITE);
        let _ = GetExitCodeProcess(process, &mut code);
    }
    ELEVATION_EVENT.store(0, Ordering::SeqCst);
    close(Some(process));
    close(event);
    Some(code as i32)
}

pub fn signal_ready_event(name: &str) {
    if name.is_empty() {
        return;
    }
    // SAFETY: open/set/close of a named event.
    unsafe {
        match OpenEventW(EVENT_MODIFY_STATE, false, &HSTRING::from(name)) {
            Ok(event) => {
                let _ = SetEvent(event);
                let _ = CloseHandle(event);
            }
            Err(error) => tracing::warn!("Tray hazir olayi acilamadi: {error}"),
        }
    }
}

/// Watches the tray's shutdown event and its process; either one firing
/// requests shutdown. Dropping it stops the watcher.
pub struct ShutdownMonitor {
    stop: isize,
    worker: Option<JoinHandle<()>>,
}

impl ShutdownMonitor {
    /// None when neither the event nor the parent could be opened.
    pub fn start(event_name: &str, parent_pid: u32) -> Option<Self> {
        // SAFETY: handle creation; the watcher closes `event`/`parent`, Drop `stop`.
        let (stop, event, parent) = unsafe {
            let stop = CreateEventW(None, true, false, PCWSTR::null()).ok()?;
            let event = (!event_name.is_empty())
                .then(|| {
                    OpenEventW(
                        SYNCHRONIZATION_SYNCHRONIZE | EVENT_MODIFY_STATE,
                        false,
                        &HSTRING::from(event_name),
                    )
                    .ok()
                })
                .flatten();
            let parent = (parent_pid != 0)
                .then(|| OpenProcess(PROCESS_SYNCHRONIZE, false, parent_pid).ok())
                .flatten();
            (stop, event, parent)
        };
        if event.is_none() && parent.is_none() {
            if !event_name.is_empty() || parent_pid != 0 {
                tracing::warn!("Ebeveyn kapanis olayi acilamadi");
            }
            // SAFETY: created above.
            let _ = unsafe { CloseHandle(stop) };
            return None;
        }
        let raw: Vec<isize> = event
            .into_iter()
            .chain(parent)
            .chain([stop])
            .map(|h| h.0 as isize)
            .collect();
        let worker = std::thread::spawn(move || {
            let handles: Vec<HANDLE> = raw.iter().map(|h| HANDLE(*h as _)).collect();
            // SAFETY: all handles are open until closed right after the wait.
            let result = unsafe { WaitForMultipleObjects(&handles, false, INFINITE) };
            let index = result.0.wrapping_sub(WAIT_OBJECT_0.0) as usize;
            if index < handles.len() - 1 {
                request_shutdown();
            }
            // `stop` (last) stays open: Drop signals it and closes it.
            for handle in &handles[..handles.len() - 1] {
                // SAFETY: closes each watched handle exactly once.
                let _ = unsafe { CloseHandle(*handle) };
            }
        });
        Some(Self {
            stop: stop.0 as isize,
            worker: Some(worker),
        })
    }
}

impl Drop for ShutdownMonitor {
    fn drop(&mut self) {
        let stop = HANDLE(self.stop as _);
        // SAFETY: `stop` is owned here and closed once, after the watcher ended.
        let _ = unsafe { SetEvent(stop) };
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = unsafe { CloseHandle(stop) };
    }
}
