//! Win32 tray and engine supervisor (port of `TrayApp`, `src/TrayApp.cpp`).
//!
//! The tray owns the engine child process: it starts it with a shutdown and a
//! ready event, kills it after 10 s stuck in a transition (the kernel then
//! drops its WinDivert filter: fail-open), restarts it within a budget, and
//! explains exit codes. The panel is a separate process (`--panel`).

use std::cell::RefCell;
use std::os::windows::process::CommandExt;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use sh_core::clock::now_ms;
use sh_core::config::{Config, DnsMode};
use sh_core::recovery::{self, RestartBudget};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HWND, LPARAM, LRESULT, WAIT_OBJECT_0,
    WPARAM,
};
use windows::Win32::System::Threading::{
    CreateEventW, CreateMutexW, SetEvent, WaitForSingleObject,
};
use windows::Win32::UI::Shell::{
    NIF_ICON, NIF_INFO, NIF_MESSAGE, NIF_TIP, NIIF_ERROR, NIIF_INFO, NIIF_NOSOUND, NIIF_WARNING,
    NIM_ADD, NIM_DELETE, NIM_MODIFY, NIM_SETVERSION, NOTIFY_ICON_INFOTIP_FLAGS,
    NOTIFYICON_VERSION_4, NOTIFYICONDATAW, Shell_NotifyIconW, ShellExecuteW,
};
use windows::Win32::UI::WindowsAndMessaging::*;
use windows::core::{HSTRING, PCWSTR, w};

pub const WINDOW_CLASS: PCWSTR = w!("SplitHello.TrayWindow");
/// Posted by the panel after it saved settings the engine reads at start.
pub const MESSAGE_RESTART_ENGINE: u32 = WM_APP + 4;

const TRAY_CALLBACK: u32 = WM_APP + 1;
const STARTUP_QUERIED: u32 = WM_APP + 2; // wParam: 1 enabled, 0 disabled
const STARTUP_CHANGED: u32 = WM_APP + 3; // wParam: result, lParam: target
const POLL_TIMER: usize = 1;

const COMMAND_START: u32 = 1001;
const COMMAND_STOP: u32 = 1002;
const COMMAND_STARTUP: u32 = 1003;
const COMMAND_OPEN_LOGS: u32 = 1004;
const COMMAND_EXIT: u32 = 1005;
const COMMAND_PANEL: u32 = 1006;
const COMMAND_ENCRYPTED_DNS: u32 = 1007;
const COMMAND_SETUP: u32 = 1009;
const COMMAND_ALLOW_BASE: u32 = 2000; // + index into the "recently blocked" submenu
const RECENT_BLOCKED_CHOICES: usize = 10;

/// An engine that stays in Starting/Stopping this long is hung. Terminating it
/// closes its WinDivert handle in the kernel, which removes the filter.
const TRANSITION_TIMEOUT_MS: u64 = 10_000;
pub const ENGINE_KILLED_EXIT_CODE: u32 = 0xDEAD_0001;
const DLL_NOT_FOUND: u32 = 0xC000_0135;
const ICON_RESOURCE: u16 = 101;

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineState {
    Stopped,
    Starting,
    Running,
    Stopping,
    Failed,
}

fn state_text(state: EngineState) -> &'static str {
    match state {
        EngineState::Starting => "Başlatılıyor",
        EngineState::Running => "Koruma aktif",
        EngineState::Stopping => "Durduruluyor",
        EngineState::Failed => "Başlatma başarısız",
        EngineState::Stopped => "Koruma kapalı",
    }
}

/// Turkish reason for an engine exit code, None when it says nothing extra.
pub fn failure_reason(code: u32) -> Option<&'static str> {
    Some(match code {
        11 => "DNS relay portu başka bir uygulama tarafından kullanılıyor.",
        12 => {
            "WinDivert açılamadı. WinDivert.dll ve WinDivert64.sys exe ile aynı klasörde olmalı; \
             antivirüs sürücüyü engelliyor olabilir."
        }
        13 => "Süreç filtresindeki include kuralları geçersiz. Panelden düzeltin veya boşaltın.",
        15 => "Tray kontrol kanalı açılamadı.",
        16 => "Yapılandırma dosyası okunamadı.",
        ENGINE_KILLED_EXIT_CODE => "Ağ motoru 10 saniye içinde yanıt vermedi ve sonlandırıldı.",
        DLL_NOT_FOUND => "WinDivert.dll bulunamadı; exe ile aynı klasörde olmalı.",
        _ => return None,
    })
}

/// Restarting cannot fix a missing driver or a bad configuration.
pub fn needs_user_action(code: u32) -> bool {
    matches!(code, 12 | 13 | 16 | DLL_NOT_FOUND)
}

fn wide<const N: usize>(text: &str) -> [u16; N] {
    let mut out = [0u16; N];
    for (slot, unit) in out.iter_mut().take(N - 1).zip(text.encode_utf16()) {
        *slot = unit;
    }
    out
}

fn unique_name(purpose: &str) -> String {
    format!(
        "Local\\SplitHello-{purpose}-{}-{}",
        std::process::id(),
        now_ms()
    )
}

fn config_dir() -> Option<PathBuf> {
    sh_core::paths::config_dir()
}

fn load_config() -> Config {
    let mut config = Config::default();
    if let Some(dir) = config_dir() {
        config.load_from(&dir);
    }
    config
}

struct NamedEvent(HANDLE);

impl NamedEvent {
    fn create(name: &str) -> Option<Self> {
        // SAFETY: plain event creation; closed on drop.
        unsafe { CreateEventW(None, true, false, &HSTRING::from(name)) }
            .ok()
            .map(Self)
    }

    fn signaled(&self) -> bool {
        // SAFETY: valid handle owned by self.
        unsafe { WaitForSingleObject(self.0, 0) == WAIT_OBJECT_0 }
    }

    fn set(&self) {
        // SAFETY: valid handle owned by self.
        let _ = unsafe { SetEvent(self.0) };
    }
}

impl Drop for NamedEvent {
    fn drop(&mut self) {
        // SAFETY: closed exactly once.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct Engine {
    child: Child,
    shutdown: NamedEvent,
    ready: NamedEvent,
    killed: bool,
}

struct Tray {
    window: HWND,
    icon: NOTIFYICONDATAW,
    taskbar_created: u32,
    engine_arguments: Vec<String>,
    recent_blocked: Vec<String>,
    startup_enabled: bool,
    startup_busy: Arc<AtomicBool>,
    exiting: bool,
    restart_pending: bool,
    configuration_restart_pending: bool,
    restart_at_ms: u64,
    state_since_ms: u64,
    budget: RestartBudget,
    state: EngineState,
    engine: Option<Engine>,
    setup: Option<Child>,
    panel: Option<Child>,
    /// Set when the engine is the SplitHello Windows service: the tray then
    /// runs unelevated and starts/stops it through the SCM.
    service: Option<crate::service::Control>,
}

thread_local! {
    static TRAY: RefCell<Option<Tray>> = const { RefCell::new(None) };
}

fn exe() -> Option<PathBuf> {
    std::env::current_exe().ok()
}

fn post(window: HWND, message: u32, wparam: usize, lparam: isize) {
    // SAFETY: posting to our own window.
    let _ = unsafe { PostMessageW(Some(window), message, WPARAM(wparam), LPARAM(lparam)) };
}

/// Runs the tray until exit. `engine_arguments`: the user's arguments minus
/// the internal ones.
pub fn run(engine_arguments: Vec<String>) -> i32 {
    // SAFETY: named mutex held for the tray's lifetime (released at exit).
    let mutex = unsafe { CreateMutexW(None, true, w!("Local\\SplitHello-Tray")) };
    let Ok(mutex) = mutex else {
        return 1;
    };
    // SAFETY: reads the last error of the call above.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        // SAFETY: close our handle to the existing mutex.
        let _ = unsafe { CloseHandle(mutex) };
        return 0;
    }
    let code = run_window(engine_arguments);
    // SAFETY: owned handle.
    let _ = unsafe { CloseHandle(mutex) };
    code
}

fn run_window(engine_arguments: Vec<String>) -> i32 {
    // SAFETY: standard window-class registration and window creation.
    let window = unsafe {
        let instance = windows::Win32::System::LibraryLoader::GetModuleHandleW(None).ok();
        let class = WNDCLASSEXW {
            cbSize: size_of::<WNDCLASSEXW>() as u32,
            lpfnWndProc: Some(window_proc),
            hInstance: instance.map(Into::into).unwrap_or_default(),
            hIcon: app_icon(false).unwrap_or_default(),
            lpszClassName: WINDOW_CLASS,
            ..Default::default()
        };
        if RegisterClassExW(&class) == 0 {
            tracing::error!("Tray pencere sinifi olusturulamadi");
            return 1;
        }
        match CreateWindowExW(
            WINDOW_EX_STYLE(0),
            WINDOW_CLASS,
            w!("SplitHello"),
            WS_OVERLAPPED,
            0,
            0,
            0,
            0,
            None,
            None,
            instance.map(Into::into),
            None,
        ) {
            Ok(window) => window,
            Err(error) => {
                tracing::error!("Tray penceresi olusturulamadi: {error}");
                return 1;
            }
        }
    };

    let mut tray = Tray {
        window,
        icon: NOTIFYICONDATAW::default(),
        // SAFETY: registers (or looks up) a system-wide message id.
        taskbar_created: unsafe { RegisterWindowMessageW(w!("TaskbarCreated")) },
        engine_arguments,
        recent_blocked: Vec::new(),
        startup_enabled: false,
        startup_busy: Arc::new(AtomicBool::new(false)),
        exiting: false,
        restart_pending: false,
        configuration_restart_pending: false,
        restart_at_ms: 0,
        state_since_ms: now_ms(),
        budget: RestartBudget::default(),
        state: EngineState::Stopped,
        engine: None,
        setup: None,
        panel: None,
        service: crate::service::Control::open(),
    };
    if !tray.add_icon() {
        // SAFETY: our window.
        let _ = unsafe { DestroyWindow(window) };
        return 1;
    }
    tray.refresh_startup_async();
    // SAFETY: timer on our window.
    unsafe { SetTimer(Some(window), POLL_TIMER, 250, None) };
    tray.start_engine(false);
    TRAY.with(|cell| *cell.borrow_mut() = Some(tray));

    let mut message = MSG::default();
    // SAFETY: standard message loop on this thread.
    unsafe {
        while GetMessageW(&mut message, None, 0, 0).as_bool() {
            let _ = TranslateMessage(&message);
            DispatchMessageW(&message);
        }
    }
    TRAY.with(|cell| cell.borrow_mut().take());
    message.wParam.0 as i32
}

unsafe extern "system" fn window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    if message == WM_DESTROY {
        // SAFETY: ends this thread's message loop.
        unsafe { PostQuitMessage(0) };
        return LRESULT(0);
    }
    // A re-entrant message (e.g. while the menu's modal loop runs) finds the
    // tray borrowed and gets default handling; the poll timer simply resumes.
    let handled = TRAY.with(|cell| {
        let mut slot = cell.try_borrow_mut().ok()?;
        let tray = slot.as_mut()?;
        tray.handle(message, wparam, lparam)
    });
    // SAFETY: default processing for our window.
    handled.unwrap_or_else(|| unsafe { DefWindowProcW(window, message, wparam, lparam) })
}

/// Small state icons: the app icon for Running/Stopped, system icons otherwise.
fn app_icon(small: bool) -> Option<HICON> {
    // SAFETY: shared resource icon; never destroyed.
    unsafe {
        let instance = windows::Win32::System::LibraryLoader::GetModuleHandleW(None).ok()?;
        let (cx, cy) = if small {
            (GetSystemMetrics(SM_CXSMICON), GetSystemMetrics(SM_CYSMICON))
        } else {
            (0, 0)
        };
        LoadImageW(
            Some(instance.into()),
            PCWSTR(ICON_RESOURCE as usize as *const u16),
            IMAGE_ICON,
            cx,
            cy,
            LR_SHARED,
        )
        .ok()
        .map(|handle| HICON(handle.0))
    }
}

fn state_icon(state: EngineState) -> HICON {
    let system = match state {
        EngineState::Running | EngineState::Stopped => {
            if let Some(icon) = app_icon(true) {
                return icon;
            }
            IDI_APPLICATION
        }
        EngineState::Starting => IDI_INFORMATION,
        EngineState::Stopping => IDI_WARNING,
        EngineState::Failed => IDI_ERROR,
    };
    // SAFETY: shared system icon.
    unsafe { LoadIconW(None, system) }.unwrap_or_default()
}

impl Tray {
    fn add_icon(&mut self) -> bool {
        self.icon = NOTIFYICONDATAW {
            cbSize: size_of::<NOTIFYICONDATAW>() as u32,
            hWnd: self.window,
            uID: 1,
            uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
            uCallbackMessage: TRAY_CALLBACK,
            hIcon: state_icon(self.state),
            szTip: wide(&format!("SplitHello — {}", state_text(self.state))),
            ..Default::default()
        };
        // SAFETY: the struct is fully initialised for NIM_ADD.
        if !unsafe { Shell_NotifyIconW(NIM_ADD, &self.icon) }.as_bool() {
            tracing::error!("Tray simgesi eklenemedi");
            return false;
        }
        self.icon.Anonymous.uVersion = NOTIFYICON_VERSION_4;
        // SAFETY: as above.
        let _ = unsafe { Shell_NotifyIconW(NIM_SETVERSION, &self.icon) };
        true
    }

    fn remove_icon(&mut self) {
        if !self.icon.hWnd.is_invalid() {
            // SAFETY: deletes the icon added by add_icon.
            let _ = unsafe { Shell_NotifyIconW(NIM_DELETE, &self.icon) };
            self.icon.hWnd = HWND::default();
        }
    }

    fn update_icon(&mut self) {
        if self.icon.hWnd.is_invalid() {
            return;
        }
        self.icon.uFlags = NIF_ICON | NIF_TIP;
        self.icon.hIcon = state_icon(self.state);
        self.icon.szTip = wide(&format!("SplitHello — {}", state_text(self.state)));
        // SAFETY: modifies our icon.
        let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &self.icon) };
    }

    fn balloon(&mut self, title: &str, text: &str, kind: NOTIFY_ICON_INFOTIP_FLAGS) {
        if self.icon.hWnd.is_invalid() {
            return;
        }
        self.icon.uFlags = NIF_INFO;
        self.icon.dwInfoFlags = kind | NIIF_NOSOUND;
        self.icon.szInfoTitle = wide(title);
        self.icon.szInfo = wide(text);
        // SAFETY: modifies our icon.
        let _ = unsafe { Shell_NotifyIconW(NIM_MODIFY, &self.icon) };
    }

    fn set_state(&mut self, state: EngineState) {
        if self.state != state {
            self.state_since_ms = now_ms();
        }
        self.state = state;
        self.update_icon();
    }

    fn destroy(&mut self) {
        // SAFETY: our window and timer.
        unsafe {
            let _ = KillTimer(Some(self.window), POLL_TIMER);
        }
        self.remove_icon();
        // SAFETY: WM_DESTROY is handled without borrowing the tray.
        let _ = unsafe { DestroyWindow(self.window) };
    }

    fn handle(&mut self, message: u32, wparam: WPARAM, lparam: LPARAM) -> Option<LRESULT> {
        if message == self.taskbar_created {
            self.add_icon();
            self.update_icon();
            return Some(LRESULT(0));
        }
        match message {
            TRAY_CALLBACK => {
                let notification = (lparam.0 & 0xFFFF) as u32;
                if notification == WM_CONTEXTMENU || notification == WM_RBUTTONUP {
                    self.show_menu();
                } else if notification == WM_LBUTTONDBLCLK {
                    self.open_panel();
                }
            }
            STARTUP_QUERIED => self.startup_enabled = wparam.0 != 0,
            STARTUP_CHANGED => self.startup_changed(wparam.0, lparam.0 != 0),
            MESSAGE_RESTART_ENGINE => self.restart_engine_for_configuration(),
            WM_COMMAND => self.command((wparam.0 & 0xFFFF) as u32),
            WM_TIMER if wparam.0 == POLL_TIMER => self.poll(),
            WM_QUERYENDSESSION => return Some(LRESULT(1)),
            WM_ENDSESSION => {
                if wparam.0 != 0 {
                    self.request_exit();
                }
            }
            WM_CLOSE => self.request_exit(),
            _ => return None,
        }
        Some(LRESULT(0))
    }

    fn command(&mut self, command: u32) {
        match command {
            COMMAND_START => self.start_engine(false),
            COMMAND_STOP => {
                self.configuration_restart_pending = false; // an explicit stop wins
                self.request_stop();
            }
            COMMAND_STARTUP => self.toggle_startup(),
            COMMAND_ENCRYPTED_DNS => self.toggle_encrypted_dns(),
            COMMAND_SETUP => self.launch_setup(),
            COMMAND_OPEN_LOGS => {
                if let Some(dir) = config_dir() {
                    // SAFETY: opens a folder in Explorer.
                    unsafe {
                        ShellExecuteW(
                            Some(self.window),
                            w!("open"),
                            &HSTRING::from(dir.as_os_str()),
                            None,
                            None,
                            SW_SHOWNORMAL,
                        )
                    };
                }
            }
            COMMAND_PANEL => self.open_panel(),
            COMMAND_EXIT => self.request_exit(),
            id if (COMMAND_ALLOW_BASE..COMMAND_ALLOW_BASE + RECENT_BLOCKED_CHOICES as u32)
                .contains(&id) =>
            {
                self.allow_blocked_host((id - COMMAND_ALLOW_BASE) as usize);
            }
            _ => {}
        }
    }

    fn show_menu(&mut self) {
        // Ask again for next time; this menu uses the cached value so a hung
        // Task Scheduler can never freeze the tray.
        self.refresh_startup_async();
        let config = load_config();
        let stopped = matches!(self.state, EngineState::Stopped | EngineState::Failed);
        let flag = |enabled: bool| {
            if enabled {
                MF_STRING
            } else {
                MF_STRING | MF_DISABLED
            }
        };
        let checked = |on: bool| {
            if on {
                MF_STRING | MF_CHECKED
            } else {
                MF_STRING
            }
        };

        // SAFETY: menu handles are created and destroyed here; strings outlive
        // each AppendMenuW call.
        unsafe {
            let Ok(menu) = CreatePopupMenu() else {
                return;
            };
            let append = |menu: HMENU, flags: MENU_ITEM_FLAGS, id: usize, text: &str| {
                let _ = AppendMenuW(menu, flags, id, &HSTRING::from(text));
            };
            let separator = |menu: HMENU| {
                let _ = AppendMenuW(menu, MF_SEPARATOR, 0, PCWSTR::null());
            };
            append(menu, MF_STRING | MF_DISABLED, 0, state_text(self.state));
            separator(menu);
            append(menu, MF_STRING, COMMAND_PANEL as usize, "Paneli aç");
            separator(menu);
            append(menu, flag(stopped), COMMAND_START as usize, "Başlat");
            append(menu, flag(!stopped), COMMAND_STOP as usize, "Durdur");
            separator(menu);
            append(
                menu,
                checked(config.dns_mode == DnsMode::Worker),
                COMMAND_ENCRYPTED_DNS as usize,
                "Şifreli DNS",
            );
            append(
                menu,
                flag(self.setup.is_none()),
                COMMAND_SETUP as usize,
                "Yedek Worker kur (isteğe bağlı)",
            );
            separator(menu);

            // Written by the engine: "#total<TAB>N", then "host<TAB>count".
            self.recent_blocked.clear();
            if config.ad_block
                && let Ok(submenu) = CreatePopupMenu()
            {
                let mut title = String::from("Reklam engeli");
                let recent = config_dir()
                    .and_then(|dir| std::fs::read_to_string(dir.join("adblock-recent.txt")).ok())
                    .unwrap_or_default();
                for line in recent.lines() {
                    let Some((host, count)) = line.split_once('\t') else {
                        continue;
                    };
                    if host == "#total" {
                        title = format!("Reklam engeli ({} engellendi)", count.trim());
                        continue;
                    }
                    if self.recent_blocked.len() == RECENT_BLOCKED_CHOICES {
                        continue;
                    }
                    let id = COMMAND_ALLOW_BASE as usize + self.recent_blocked.len();
                    append(
                        submenu,
                        MF_STRING,
                        id,
                        &format!("{host}  ×{count}  — serbest bırak"),
                    );
                    self.recent_blocked.push(host.to_string());
                }
                if self.recent_blocked.is_empty() {
                    append(submenu, MF_STRING | MF_DISABLED, 0, "Henüz engellenen yok");
                }
                append(menu, MF_POPUP, submenu.0 as usize, &title);
                separator(menu);
            }
            append(
                menu,
                checked(self.startup_enabled),
                COMMAND_STARTUP as usize,
                "Windows ile başlat",
            );
            append(
                menu,
                MF_STRING,
                COMMAND_OPEN_LOGS as usize,
                "Log klasörünü aç",
            );
            separator(menu);
            append(menu, MF_STRING, COMMAND_EXIT as usize, "Çıkış");

            let mut cursor = Default::default();
            let _ = GetCursorPos(&mut cursor);
            let _ = SetForegroundWindow(self.window);
            let command = TrackPopupMenu(
                menu,
                TPM_RETURNCMD | TPM_RIGHTBUTTON,
                cursor.x,
                cursor.y,
                None,
                self.window,
                None,
            );
            let _ = DestroyMenu(menu);
            if command.0 != 0 {
                post(self.window, WM_COMMAND, command.0 as usize, 0);
            }
        }
    }

    fn allow_blocked_host(&mut self, index: usize) {
        let Some(host) = self.recent_blocked.get(index).cloned() else {
            return;
        };
        use std::io::Write;
        let written = config_dir().is_some_and(|dir| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("adblock-allow.txt"))
                .and_then(|mut file| writeln!(file, "{host}"))
                .is_ok()
        });
        if written {
            self.balloon(
                "Reklam engeli",
                &format!("{host} serbest bırakıldı (birkaç saniye içinde geçerli olur)."),
                NIIF_INFO,
            );
        } else {
            self.balloon(
                "Serbest bırakılamadı",
                "Liste dosyasına yazılamadı.",
                NIIF_ERROR,
            );
        }
    }

    fn start_engine(&mut self, automatic: bool) {
        if self.engine.is_some() {
            return;
        }
        self.restart_pending = false;
        self.restart_at_ms = 0;
        if !automatic {
            self.budget.reset();
        }
        if let Some(service) = &self.service {
            if service.start() {
                self.set_state(EngineState::Starting);
            } else {
                self.set_state(EngineState::Failed);
                self.balloon(
                    "SplitHello başlatılamadı",
                    "SplitHello hizmeti başlatılamadı.",
                    NIIF_ERROR,
                );
            }
            return;
        }
        let Some(executable) = exe() else {
            self.set_state(EngineState::Failed);
            self.balloon(
                "SplitHello başlatılamadı",
                "Uygulama yolu bulunamadı.",
                NIIF_ERROR,
            );
            return;
        };
        let (shutdown_name, ready_name) = (unique_name("shutdown"), unique_name("ready"));
        let (Some(shutdown), Some(ready)) = (
            NamedEvent::create(&shutdown_name),
            NamedEvent::create(&ready_name),
        ) else {
            self.set_state(EngineState::Failed);
            self.balloon(
                "SplitHello başlatılamadı",
                "Kontrol kanalı oluşturulamadı.",
                NIIF_ERROR,
            );
            return;
        };
        let spawned = Command::new(executable)
            .args(&self.engine_arguments)
            .args([
                "--engine",
                "--shutdown-event",
                &shutdown_name,
                "--ready-event",
                &ready_name,
            ])
            .args(["--parent-pid", &std::process::id().to_string()])
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        match spawned {
            Ok(child) => {
                self.engine = Some(Engine {
                    child,
                    shutdown,
                    ready,
                    killed: false,
                });
                self.set_state(EngineState::Starting);
            }
            Err(error) => {
                tracing::error!("Ag motoru baslatilamadi: {error}");
                self.set_state(EngineState::Failed);
                self.balloon(
                    "SplitHello başlatılamadı",
                    "Ağ motoru açılamadı.",
                    NIIF_ERROR,
                );
            }
        }
    }

    fn request_stop(&mut self) {
        if self.restart_pending {
            self.restart_pending = false;
            self.restart_at_ms = 0;
            self.set_state(EngineState::Stopped);
            self.balloon(
                "SplitHello",
                "Otomatik yeniden başlatma iptal edildi.",
                NIIF_INFO,
            );
            return;
        }
        if let Some(service) = &self.service {
            if matches!(self.state, EngineState::Starting | EngineState::Running) {
                service.stop();
                self.set_state(EngineState::Stopping);
            }
            return;
        }
        let Some(engine) = &self.engine else {
            return;
        };
        // A second request re-signals; poll() terminates the process if it
        // still has not exited after the transition timeout.
        engine.shutdown.set();
        if self.state != EngineState::Stopping {
            self.set_state(EngineState::Stopping);
        }
    }

    fn request_exit(&mut self) {
        self.exiting = true;
        self.restart_pending = false;
        self.restart_at_ms = 0;
        self.configuration_restart_pending = false;
        let service_active = self.service.is_some()
            && matches!(
                self.state,
                EngineState::Starting | EngineState::Running | EngineState::Stopping
            );
        if self.engine.is_some() || service_active {
            // Quitting the tray ends protection, as before; poll() closes the
            // window once the engine or service has stopped.
            self.request_stop();
        } else {
            self.destroy();
        }
    }

    fn launch_setup(&mut self) {
        if self.setup.is_some() {
            self.balloon("SplitHello", "Kurulum zaten çalışıyor.", NIIF_INFO);
            return;
        }
        let Some(executable) = exe() else {
            self.balloon(
                "Kurulum başlatılamadı",
                "Uygulama yolu bulunamadı.",
                NIIF_ERROR,
            );
            return;
        };
        // The tray is already elevated, so the child is too: no UAC prompt.
        match Command::new(executable)
            .arg("--setup-only")
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
        {
            Ok(child) => self.setup = Some(child),
            Err(error) => {
                tracing::error!("Kurulum baslatilamadi: {error}");
                self.balloon(
                    "Kurulum başlatılamadı",
                    "Kurulum penceresi açılamadı.",
                    NIIF_ERROR,
                );
            }
        }
    }

    fn poll_setup(&mut self) {
        let Some(child) = &mut self.setup else {
            return;
        };
        let Ok(Some(status)) = child.try_wait() else {
            return;
        };
        self.setup = None;
        if self.exiting {
            return;
        }
        let config = load_config();
        if !status.success() || config.load_failed || config.worker_url.is_empty() {
            self.balloon(
                "Kurulum tamamlanamadı",
                "Ayrıntı için log klasörüne bakın; menüden kurulumu yeniden çalıştırabilirsiniz.",
                NIIF_WARNING,
            );
            return;
        }
        self.balloon("SplitHello", "Worker kurulumu tamamlandı.", NIIF_INFO);
        if self.engine.is_none() && matches!(self.state, EngineState::Stopped | EngineState::Failed)
        {
            self.start_engine(false);
        } else {
            self.restart_engine_for_configuration();
        }
    }

    fn poll(&mut self) {
        self.poll_setup();
        if let Some(panel) = &mut self.panel
            && !matches!(panel.try_wait(), Ok(None))
        {
            self.panel = None;
        }
        let now = now_ms();
        if self.service.is_some() {
            self.poll_service(now);
            return;
        }
        let Some(engine) = &mut self.engine else {
            if self.restart_pending && now >= self.restart_at_ms {
                self.start_engine(true);
            }
            return;
        };

        if self.state == EngineState::Starting && engine.ready.signaled() {
            self.set_state(EngineState::Running);
            self.balloon("SplitHello", "Koruma aktif.", NIIF_INFO);
        }
        let Some(engine) = &mut self.engine else {
            return;
        };
        let exited = engine.child.try_wait().ok().flatten();
        // Hung engine: terminating it closes its WinDivert handle in the
        // kernel, so traffic is no longer intercepted. Its exit is then
        // handled like any other.
        if exited.is_none()
            && !engine.killed
            && matches!(self.state, EngineState::Starting | EngineState::Stopping)
            && now - self.state_since_ms >= TRANSITION_TIMEOUT_MS
        {
            tracing::error!(
                "Ag motoru {TRANSITION_TIMEOUT_MS} ms icinde gecis tamamlamadi; sonlandiriliyor"
            );
            engine.killed = true;
            let _ = engine.child.kill();
            return;
        }
        let Some(status) = exited else {
            return;
        };
        let code = if engine.killed {
            ENGINE_KILLED_EXIT_CODE
        } else {
            status.code().map_or(1, |c| c as u32)
        };
        self.handle_engine_exit(code, now);
    }

    /// Service mode: follow the SCM state. The service restarts transient
    /// engine exits itself, so a stop seen here is final for this run.
    fn poll_service(&mut self, now: u64) {
        use crate::service::State;
        let Some(status) = self.service.as_ref().and_then(|s| s.status()) else {
            return;
        };
        match status.state {
            State::Running if self.state != EngineState::Running => {
                self.set_state(EngineState::Running);
                self.balloon("SplitHello", "Koruma aktif.", NIIF_INFO);
            }
            State::Starting
                if !matches!(self.state, EngineState::Starting | EngineState::Stopping) =>
            {
                self.set_state(EngineState::Starting); // started elsewhere, or restarting
            }
            State::Stopping if self.state != EngineState::Stopping => {
                self.set_state(EngineState::Stopping);
            }
            State::Stopped => {
                // StartService can report "stopped" for a moment before the
                // service process registers; do not read that as a failure.
                let just_started =
                    self.state == EngineState::Starting && now - self.state_since_ms < 2000;
                if matches!(
                    self.state,
                    EngineState::Starting | EngineState::Running | EngineState::Stopping
                ) && !just_started
                {
                    self.handle_engine_exit(status.exit_code, now);
                } else if self.exiting {
                    self.destroy();
                }
            }
            _ => {}
        }
    }

    fn handle_engine_exit(&mut self, code: u32, now: u64) {
        let expected = self.state == EngineState::Stopping || self.exiting;
        self.engine = None;
        if self.exiting {
            self.destroy();
            return;
        }
        let reason = failure_reason(code);
        if expected {
            if self.configuration_restart_pending {
                self.configuration_restart_pending = false;
                self.set_state(EngineState::Stopped);
                self.start_engine(false);
            } else {
                self.set_state(EngineState::Stopped);
                self.balloon("SplitHello", "Koruma durduruldu.", NIIF_INFO);
            }
        } else if needs_user_action(code) {
            self.restart_pending = false;
            self.restart_at_ms = 0;
            self.set_state(EngineState::Failed);
            tracing::error!(
                "Ag motoru baslatilamadi (cikis={code}); otomatik yeniden baslatma yok"
            );
            self.balloon(
                "SplitHello başlatılamadı",
                &format!(
                    "{} Düzelttikten sonra Başlat seçin.",
                    reason.unwrap_or("Ağ motoru başlatılamadı.")
                ),
                NIIF_ERROR,
            );
        } else if self.service.is_some() {
            // The service already spent its restart budget (or was stopped
            // from outside): report, do not restart from here.
            self.set_state(EngineState::Failed);
            self.balloon(
                "SplitHello koruması durdu",
                &format!(
                    "Normal internet yolu açık; yeniden denemek için Başlat seçin.{}",
                    reason.map(|r| format!(" {r}")).unwrap_or_default()
                ),
                NIIF_ERROR,
            );
        } else {
            self.schedule_restart(code, now, reason);
        }
    }

    fn schedule_restart(&mut self, code: u32, now: u64, reason: Option<&str>) {
        self.set_state(EngineState::Failed);
        let detail = reason.map(|r| format!(" {r}")).unwrap_or_default();
        let attempt = self.budget.consume(now);
        if attempt == 0 {
            tracing::error!(
                "Ag motoru cok sik durdu (son cikis={code}); otomatik yeniden baslatma durduruldu"
            );
            self.balloon(
                "SplitHello koruması durdu",
                &format!(
                    "Normal internet yolu açık. Yeniden başlatma sınırına ulaşıldı; tray'den Başlat seçin.{detail}"
                ),
                NIIF_ERROR,
            );
            return;
        }
        let delay = recovery::automatic_restart_delay_ms(attempt);
        self.restart_pending = true;
        self.restart_at_ms = now + u64::from(delay);
        tracing::warn!(
            "Ag motoru beklenmedik cikis={code} verdi; otomatik yeniden baslatma {attempt}/{} ({delay} ms)",
            recovery::MAX_AUTOMATIC_RESTARTS
        );
        self.balloon(
            "SplitHello kendini toparlıyor",
            &format!(
                "Filtre kapatıldı; normal internet yolu açık. Ağ motoru kısa süre içinde yeniden başlayacak.{detail}"
            ),
            NIIF_WARNING,
        );
    }

    fn refresh_startup_async(&mut self) {
        if self.startup_busy.swap(true, Ordering::SeqCst) {
            return;
        }
        let (busy, window) = (self.startup_busy.clone(), self.window.0 as isize);
        std::thread::spawn(move || {
            let exists = crate::startup::task_exists();
            busy.store(false, Ordering::SeqCst);
            if let Some(exists) = exists {
                post(HWND(window as _), STARTUP_QUERIED, usize::from(exists), 0);
            }
        });
    }

    fn toggle_startup(&mut self) {
        if self.startup_busy.swap(true, Ordering::SeqCst) {
            self.balloon(
                "SplitHello",
                "Görev Zamanlayıcı işlemi sürüyor; birazdan tekrar deneyin.",
                NIIF_INFO,
            );
            return;
        }
        let target = !self.startup_enabled;
        let (busy, window) = (self.startup_busy.clone(), self.window.0 as isize);
        std::thread::spawn(move || {
            let result = crate::startup::set_enabled(target);
            busy.store(false, Ordering::SeqCst);
            post(
                HWND(window as _),
                STARTUP_CHANGED,
                result as usize,
                isize::from(target),
            );
        });
    }

    fn startup_changed(&mut self, result: usize, target: bool) {
        use crate::startup::StartupResult;
        if result == StartupResult::Ok as usize {
            self.startup_enabled = target;
            let text = if target {
                "Windows ile otomatik başlangıç açıldı."
            } else {
                "Windows ile otomatik başlangıç kapatıldı."
            };
            self.balloon("SplitHello", text, NIIF_INFO);
        } else if result == StartupResult::UnsafeLocation as usize {
            self.balloon(
                "Otomatik başlangıç açılamadı",
                "SplitHello yönetici yetkisiyle her oturumda çalışacağı için yalnızca standart \
                 kullanıcıların değiştiremeyeceği bir klasörden (örn. C:\\Program Files\\SplitHello) \
                 etkinleştirilebilir. Uygulamayı oraya taşıyıp tekrar deneyin.",
                NIIF_WARNING,
            );
        } else {
            self.balloon(
                "Otomatik başlangıç değiştirilemedi",
                "Windows Görev Zamanlayıcı ayarı kaydedilemedi.",
                NIIF_ERROR,
            );
        }
    }

    fn open_panel(&mut self) {
        if self.panel.is_some() {
            return; // already open; the panel keeps itself in front when focused
        }
        let Some(executable) = exe() else {
            return;
        };
        match Command::new(executable)
            .arg("--panel")
            .creation_flags(CREATE_NO_WINDOW)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        {
            Ok(child) => self.panel = Some(child),
            Err(error) => {
                tracing::error!("Panel acilamadi: {error}");
                self.balloon("SplitHello", "Panel açılamadı.", NIIF_ERROR);
            }
        }
    }

    fn restart_engine_for_configuration(&mut self) {
        if self.exiting {
            return;
        }
        match self.state {
            // The user stopped protection; new settings apply on the next
            // manual Başlat instead of silently turning protection back on.
            EngineState::Stopped | EngineState::Stopping => {}
            EngineState::Starting | EngineState::Running => {
                self.restart_pending = false;
                self.restart_at_ms = 0;
                // The service restarts its engine in place on this control.
                if let Some(service) = &self.service
                    && service.reload()
                {
                    self.set_state(EngineState::Starting);
                    return;
                }
                self.configuration_restart_pending = true;
                self.request_stop();
            }
            EngineState::Failed => {
                // Failed on its own: the changed configuration may fix it.
                self.restart_pending = false;
                self.restart_at_ms = 0;
                if self.engine.is_none() {
                    self.start_engine(false);
                }
            }
        }
    }

    fn toggle_encrypted_dns(&mut self) {
        let mut config = load_config();
        if config.load_failed {
            // Saving would replace the unreadable file with defaults.
            self.balloon(
                "DNS modu değişmedi",
                "Yapılandırma dosyası okunamadı.",
                NIIF_ERROR,
            );
            return;
        }
        // DnsMode::Worker means "encrypted DNS on"; the Worker is only a fallback now.
        let on = config.dns_mode != DnsMode::Worker;
        config.dns_mode = if on { DnsMode::Worker } else { DnsMode::System };
        if config_dir().is_none_or(|dir| config.save_to(&dir).is_err()) {
            self.balloon(
                "DNS modu değişmedi",
                "Yapılandırma kaydedilemedi.",
                NIIF_ERROR,
            );
            return;
        }
        tracing::info!("Sifreli DNS {}", if on { "acildi" } else { "kapatildi" });
        self.restart_engine_for_configuration();
    }
}

impl Drop for Tray {
    fn drop(&mut self) {
        self.remove_icon();
        if let Some(mut panel) = self.panel.take() {
            let _ = panel.kill();
        }
    }
}

/// True when a tray already holds the instance mutex. An elevated tray's
/// mutex has an admin-only DACL, so access-denied also means "exists".
pub fn instance_running() -> bool {
    use windows::Win32::Foundation::ERROR_ACCESS_DENIED;
    use windows::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
    // SAFETY: open/close of a named mutex.
    unsafe {
        match OpenMutexW(
            SYNCHRONIZATION_SYNCHRONIZE,
            false,
            w!("Local\\SplitHello-Tray"),
        ) {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => GetLastError() == ERROR_ACCESS_DENIED,
        }
    }
}

/// Lets the tray restart the engine after the panel saved settings.
pub fn notify_tray_restart() -> bool {
    // SAFETY: finds and posts to the tray's message-only window.
    unsafe {
        match FindWindowW(WINDOW_CLASS, None) {
            Ok(window) => {
                post(window, MESSAGE_RESTART_ENGINE, 0, 0);
                true
            }
            Err(_) => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_map_like_the_cpp_tray() {
        for code in [12, 13, 16, DLL_NOT_FOUND] {
            assert!(needs_user_action(code), "{code}");
            assert!(failure_reason(code).is_some());
        }
        for code in [0, 1, 2, 3, 11, 14, 15, ENGINE_KILLED_EXIT_CODE] {
            assert!(!needs_user_action(code), "{code}");
        }
        assert!(failure_reason(2).is_none());
        assert!(failure_reason(ENGINE_KILLED_EXIT_CODE).is_some());
    }

    #[test]
    fn wide_strings_are_truncated_and_terminated() {
        let text: [u16; 4] = wide("abcdef");
        assert_eq!(text, [97, 98, 99, 0]);
    }
}
