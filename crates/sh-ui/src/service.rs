//! Service install/uninstall (installer, elevated) and service control from
//! the unelevated tray.
//!
//! Install grants the interactive user only start, stop, status and the
//! reload control on the service: never "change config", which would let a
//! standard user point a SYSTEM service at another binary.

use std::path::Path;

use sh_engine::service::{CONTROL_RELOAD, SERVICE_NAME};
use windows::Win32::System::Services::{
    CloseServiceHandle, ControlService, OpenSCManagerW, OpenServiceW, QueryServiceStatus,
    SC_HANDLE, SC_MANAGER_CONNECT, SERVICE_CONTROL_STOP, SERVICE_QUERY_STATUS, SERVICE_START,
    SERVICE_STATUS, SERVICE_STOP, SERVICE_USER_DEFINED_CONTROL, StartServiceW,
};
use windows::core::w;

/// Default service DACL plus start/stop/status/user-control for interactive users.
const SERVICE_SDDL: &str = "D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)\
                            (A;;CCLCSWLOCRRC;;;AU)(A;;CCLCSWRPWPLOCRRC;;;IU)";
const STATE_FILES: [&str; 6] = [
    "config.json",
    "strategies.json",
    "telemetry.db",
    "telemetry.db-wal",
    "telemetry.db-shm",
    "adblock-allow.txt",
];

fn system_tool(name: &str) -> std::path::PathBuf {
    std::env::var_os("SystemRoot")
        .map(|root| Path::new(&root).join("System32").join(name))
        .unwrap_or_else(|| name.into())
}

fn run(tool: &str, arguments: &[&str]) -> Option<i32> {
    use std::os::windows::process::CommandExt;
    std::process::Command::new(system_tool(tool))
        .args(arguments)
        .creation_flags(0x0800_0000) // CREATE_NO_WINDOW
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .ok()?
        .code()
}

/// Copies the per-user state into the shared folder once, then rewrites the
/// config so the Worker secret is machine-scoped (readable by the service).
fn migrate(shared: &Path) {
    if shared.join("config.json").exists() {
        return;
    }
    let Some(user) = sh_core::paths::user_dir().filter(|d| d.is_dir()) else {
        return;
    };
    let lists = std::fs::read_dir(&user)
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with("adblock-") && name.ends_with(".txt"));
    for name in STATE_FILES.iter().map(|n| n.to_string()).chain(lists) {
        let source = user.join(&name);
        if source.is_file()
            && let Err(error) = std::fs::copy(&source, shared.join(&name))
        {
            eprintln!("{name} tasinamadi: {error}");
        }
    }
    let mut config = sh_core::config::Config::default();
    config.load_from(shared);
    if !config.load_failed {
        let _ = config.save_to(shared);
    }
    println!("Ayarlar {} klasorune tasindi.", shared.display());
}

pub fn install() -> i32 {
    let Ok(exe) = std::env::current_exe() else {
        return 1;
    };
    // The service runs this file as SYSTEM: a user-writable location would
    // be a privilege escalation.
    if !crate::startup::location_is_admin_only(&exe) {
        eprintln!("Hizmet yalnizca yonetici korumali bir klasorden (Program Files) kurulabilir.");
        return 1;
    }
    let Some(shared) = sh_core::paths::shared_dir() else {
        return 1;
    };
    if let Err(error) = std::fs::create_dir_all(&shared) {
        eprintln!("{} olusturulamadi: {error}", shared.display());
        return 1;
    }
    // Not inherited from ProgramData (where every user may create files):
    // SYSTEM and Administrators full, the installing user modify.
    let Some(user) = crate::startup::current_user() else {
        return 1;
    };
    let dir = shared.to_string_lossy().into_owned();
    let user_grant = format!("{user}:(OI)(CI)M");
    if run(
        "icacls.exe",
        &[
            &dir,
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(OI)(CI)F",
            "*S-1-5-32-544:(OI)(CI)F",
            &user_grant,
        ],
    ) != Some(0)
    {
        eprintln!("{dir} izinleri ayarlanamadi.");
        return 1;
    }
    migrate(&shared);

    let binary = format!("\"{}\" --service", exe.display());
    let exists = run("sc.exe", &["query", SERVICE_NAME]) == Some(0);
    let registered = if exists {
        run(
            "sc.exe",
            &[
                "config",
                SERVICE_NAME,
                "binPath=",
                &binary,
                "start=",
                "demand",
            ],
        )
    } else {
        run(
            "sc.exe",
            &[
                "create",
                SERVICE_NAME,
                "binPath=",
                &binary,
                "start=",
                "demand",
                "DisplayName=",
                "SplitHello",
            ],
        )
    };
    if registered != Some(0) {
        eprintln!("SplitHello hizmeti kaydedilemedi.");
        return 1;
    }
    let _ = run(
        "sc.exe",
        &[
            "description",
            SERVICE_NAME,
            "SplitHello ag motoru: DPI atlatma ve reklam engeli.",
        ],
    );
    // A crash is restarted by the SCM; the service restarts its own
    // transient engine exits.
    let _ = run(
        "sc.exe",
        &[
            "failure",
            SERVICE_NAME,
            "reset=",
            "86400",
            "actions=",
            "restart/5000/restart/15000//0",
        ],
    );
    if run("sc.exe", &["sdset", SERVICE_NAME, SERVICE_SDDL]) != Some(0) {
        eprintln!("Hizmet izinleri ayarlanamadi; tray hizmeti kontrol edemeyebilir.");
    }
    // The elevated logon task of pre-service installs is replaced by a
    // per-user Run entry (see `startup`).
    let _ = run("schtasks.exe", &["/Delete", "/TN", "\\SplitHello", "/F"]);
    println!("SplitHello hizmeti kuruldu.");
    0
}

pub fn uninstall() -> i32 {
    let _ = run("sc.exe", &["stop", SERVICE_NAME]);
    for _ in 0..30 {
        // `sc query` succeeds while it exists; stop is asynchronous.
        if Control::open()
            .and_then(|c| c.status())
            .is_none_or(|s| s.state == State::Stopped)
        {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    let _ = run("sc.exe", &["delete", SERVICE_NAME]);
    let _ = crate::startup::set_run_entry(false);
    0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Stopped,
    Starting,
    Running,
    Stopping,
}

#[derive(Debug, Clone, Copy)]
pub struct Status {
    pub state: State,
    /// The engine's exit code once stopped (0: clean stop).
    pub exit_code: u32,
}

pub struct Control {
    manager: SC_HANDLE,
    service: SC_HANDLE,
}

impl Control {
    /// None when the service is not installed (or not accessible).
    pub fn open() -> Option<Self> {
        // SAFETY: handles are closed on drop.
        unsafe {
            let manager = OpenSCManagerW(None, None, SC_MANAGER_CONNECT).ok()?;
            let access =
                SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL;
            let service = OpenServiceW(manager, w!("SplitHello"), access)
                .or_else(|_| OpenServiceW(manager, w!("SplitHello"), SERVICE_QUERY_STATUS));
            match service {
                Ok(service) => Some(Self { manager, service }),
                Err(_) => {
                    let _ = CloseServiceHandle(manager);
                    None
                }
            }
        }
    }

    pub fn status(&self) -> Option<Status> {
        use windows::Win32::System::Services::{
            SERVICE_CONTINUE_PENDING, SERVICE_PAUSED, SERVICE_RUNNING, SERVICE_START_PENDING,
            SERVICE_STOP_PENDING,
        };
        let mut status = SERVICE_STATUS::default();
        // SAFETY: valid handle and output struct.
        unsafe { QueryServiceStatus(self.service, &mut status) }.ok()?;
        let state = match status.dwCurrentState {
            SERVICE_RUNNING | SERVICE_PAUSED => State::Running,
            SERVICE_START_PENDING | SERVICE_CONTINUE_PENDING => State::Starting,
            SERVICE_STOP_PENDING => State::Stopping,
            _ => State::Stopped,
        };
        let exit_code = if status.dwWin32ExitCode == 1066 {
            status.dwServiceSpecificExitCode
        } else {
            status.dwWin32ExitCode
        };
        Some(Status { state, exit_code })
    }

    pub fn start(&self) -> bool {
        // SAFETY: valid handle, no arguments.
        unsafe { StartServiceW(self.service, None) }.is_ok()
    }

    fn control(&self, code: u32) -> bool {
        let mut status = SERVICE_STATUS::default();
        // SAFETY: valid handle and output struct.
        unsafe { ControlService(self.service, code, &mut status) }.is_ok()
    }

    pub fn stop(&self) -> bool {
        self.control(SERVICE_CONTROL_STOP)
    }

    /// Asks the running engine to re-read its configuration.
    pub fn reload(&self) -> bool {
        self.control(CONTROL_RELOAD)
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        // SAFETY: both handles are owned and closed once.
        unsafe {
            let _ = CloseServiceHandle(self.service);
            let _ = CloseServiceHandle(self.manager);
        }
    }
}

pub fn installed() -> bool {
    Control::open().is_some()
}
