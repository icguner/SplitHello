//! The engine as a Windows service (`--service`, started by the SCM as
//! LocalSystem). Elevation is granted once, at install time; the tray and
//! panel then run as the normal user and control the service through the SCM.
//!
//! The engine runs in-process. Transient exits (fail-open, port races) are
//! restarted within the same budget the tray used; exits that need the user
//! (bad config, missing Worker, WinDivert refused) stop the service with that
//! code as the service-specific exit code, which the tray explains. A stop or
//! start that hangs ends the process: the kernel then drops the WinDivert
//! filter, so traffic fails open.

use std::sync::atomic::{AtomicBool, AtomicIsize, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sh_core::clock::now_ms;
use sh_core::recovery::{self, RestartBudget};
use windows::Win32::System::Services::{
    RegisterServiceCtrlHandlerExW, SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP,
    SERVICE_CONTROL_INTERROGATE, SERVICE_CONTROL_SHUTDOWN, SERVICE_CONTROL_STOP, SERVICE_RUNNING,
    SERVICE_START_PENDING, SERVICE_STATUS, SERVICE_STATUS_CURRENT_STATE, SERVICE_STATUS_HANDLE,
    SERVICE_STOP_PENDING, SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
    SetServiceStatus, StartServiceCtrlDispatcherW,
};
use windows::core::{PWSTR, w};

use crate::options::{Action, Options};
use crate::win;

pub const SERVICE_NAME: &str = "SplitHello";
/// User-defined control: re-read the configuration (restart the engine).
pub const CONTROL_RELOAD: u32 = 128;

const START_LIMIT: Duration = Duration::from_secs(30);
const STOP_LIMIT: Duration = Duration::from_secs(10);
const ERROR_SERVICE_SPECIFIC: u32 = 1066;

static STATUS: AtomicIsize = AtomicIsize::new(0);
static CHECKPOINT: AtomicU32 = AtomicU32::new(0);
static STOP: AtomicBool = AtomicBool::new(false);
static STOP_AT_MS: AtomicU64 = AtomicU64::new(0);
static RELOAD: AtomicBool = AtomicBool::new(false);

/// Same rule as the tray: restarting cannot fix these.
fn needs_user_action(code: u32) -> bool {
    matches!(code, 12 | 13 | 16)
}

fn report(state: SERVICE_STATUS_CURRENT_STATE, exit_code: u32, wait_hint_ms: u32) {
    let handle = STATUS.load(Ordering::SeqCst);
    if handle == 0 {
        return;
    }
    let pending = state == SERVICE_START_PENDING || state == SERVICE_STOP_PENDING;
    let status = SERVICE_STATUS {
        dwServiceType: SERVICE_WIN32_OWN_PROCESS,
        dwCurrentState: state,
        dwControlsAccepted: if state == SERVICE_STOPPED || state == SERVICE_STOP_PENDING {
            0
        } else {
            SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
        },
        dwWin32ExitCode: if exit_code == 0 {
            0
        } else {
            ERROR_SERVICE_SPECIFIC
        },
        dwServiceSpecificExitCode: exit_code,
        dwCheckPoint: if pending {
            CHECKPOINT.fetch_add(1, Ordering::SeqCst) + 1
        } else {
            0
        },
        dwWaitHint: wait_hint_ms,
    };
    // SAFETY: the handle came from RegisterServiceCtrlHandlerExW.
    let _ = unsafe { SetServiceStatus(SERVICE_STATUS_HANDLE(handle as _), &status) };
}

unsafe extern "system" fn handler(
    control: u32,
    _event: u32,
    _data: *mut core::ffi::c_void,
    _context: *mut core::ffi::c_void,
) -> u32 {
    match control {
        SERVICE_CONTROL_STOP | SERVICE_CONTROL_SHUTDOWN => {
            STOP.store(true, Ordering::SeqCst);
            STOP_AT_MS.store(now_ms(), Ordering::SeqCst);
            report(SERVICE_STOP_PENDING, 0, STOP_LIMIT.as_millis() as u32);
            win::request_shutdown();
            0
        }
        CONTROL_RELOAD => {
            RELOAD.store(true, Ordering::SeqCst);
            win::request_shutdown();
            0
        }
        SERVICE_CONTROL_INTERROGATE => 0,
        _ => 120, // ERROR_CALL_NOT_IMPLEMENTED
    }
}

unsafe extern "system" fn service_main(_argc: u32, _argv: *mut PWSTR) {
    // SAFETY: registers our static handler for the service started by the SCM.
    let Ok(handle) =
        (unsafe { RegisterServiceCtrlHandlerExW(w!("SplitHello"), Some(handler), None) })
    else {
        return;
    };
    STATUS.store(handle.0 as isize, Ordering::SeqCst);
    report(SERVICE_START_PENDING, 0, START_LIMIT.as_millis() as u32);
    if let Some(dir) = crate::config_dir() {
        sh_core::logging::init(false, Some(&dir.join(sh_core::paths::LOG_FILE)));
    }
    let code = supervise();
    tracing::info!("SplitHello hizmeti durdu (kod {code})");
    report(SERVICE_STOPPED, code, 0);
}

/// Waits `delay`, returning early (true) when a stop was requested.
fn stop_during(delay: Duration) -> bool {
    let until = Instant::now() + delay;
    while Instant::now() < until {
        if STOP.load(Ordering::SeqCst) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    STOP.load(Ordering::SeqCst)
}

fn supervise() -> u32 {
    let mut budget = RestartBudget::default();
    loop {
        win::reset();
        RELOAD.store(false, Ordering::SeqCst);
        let options = Options {
            action: Action::Service,
            ..Options::default()
        };
        let engine = std::thread::spawn(move || crate::engine::run(&options));
        let started = Instant::now();
        let mut running = false;
        while !engine.is_finished() {
            if !running && win::engine_ready() {
                running = true;
                report(SERVICE_RUNNING, 0, 0);
            }
            let stopping = STOP.load(Ordering::SeqCst);
            let stuck_stopping = stopping
                && now_ms().saturating_sub(STOP_AT_MS.load(Ordering::SeqCst))
                    > STOP_LIMIT.as_millis() as u64;
            let stuck_starting = !running && !stopping && started.elapsed() > START_LIMIT;
            if stuck_stopping || stuck_starting {
                // Ending the process closes the WinDivert handle in the kernel.
                tracing::error!(
                    "Ag motoru {} takildi; surec sonlandiriliyor (fail-open)",
                    if stuck_stopping {
                        "durdurulurken"
                    } else {
                        "baslatilirken"
                    }
                );
                report(
                    SERVICE_STOPPED,
                    if stuck_stopping { 0 } else { 0xDEAD_0001 },
                    0,
                );
                std::process::exit(1);
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let code = engine.join().map_or(1, |code| code as u32);
        if STOP.load(Ordering::SeqCst) {
            return 0;
        }
        if RELOAD.swap(false, Ordering::SeqCst) {
            tracing::info!("Yapilandirma degisti; ag motoru yeniden baslatiliyor");
            report(SERVICE_START_PENDING, 0, START_LIMIT.as_millis() as u32);
            continue;
        }
        if code == 0 || needs_user_action(code) {
            return code;
        }
        let attempt = budget.consume(now_ms());
        if attempt == 0 {
            tracing::error!("Ag motoru cok sik durdu (son cikis={code}); hizmet durduruluyor");
            return code;
        }
        let delay = recovery::automatic_restart_delay_ms(attempt);
        tracing::warn!(
            "Ag motoru beklenmedik cikis={code}; yeniden baslatma {attempt}/{} ({delay} ms)",
            recovery::MAX_AUTOMATIC_RESTARTS
        );
        report(
            SERVICE_START_PENDING,
            0,
            delay + START_LIMIT.as_millis() as u32,
        );
        if stop_during(Duration::from_millis(u64::from(delay))) {
            return 0;
        }
    }
}

/// Entry point for `--service`; only the SCM can start it successfully.
pub fn run() -> i32 {
    let mut name: Vec<u16> = SERVICE_NAME.encode_utf16().chain([0]).collect();
    let table = [
        SERVICE_TABLE_ENTRYW {
            lpServiceName: PWSTR(name.as_mut_ptr()),
            lpServiceProc: Some(service_main),
        },
        SERVICE_TABLE_ENTRYW::default(),
    ];
    // SAFETY: the table and name outlive the dispatcher, which returns only
    // after the service stopped.
    match unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } {
        Ok(()) => 0,
        Err(error) => {
            eprintln!(
                "--service yalnizca Windows hizmeti olarak calisir (kurulum: --install-service): {error}"
            );
            1
        }
    }
}
