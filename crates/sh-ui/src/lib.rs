//! The user-facing side (port of `TrayApp` and `DashboardPanel`): the Win32
//! tray with its engine supervisor, the "Windows ile başlat" task, and the
//! egui panel, which runs as its own process (`--panel`).

pub mod panel;
pub mod startup;
mod theme;
pub mod tray;

use sh_engine::options::Options;

/// Arguments the tray passes on to its engine: the user's, minus the
/// internal ones the tray adds itself.
fn engine_arguments(args: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut iter = args.iter();
    while let Some(argument) = iter.next() {
        match argument.as_str() {
            "--shutdown-event" | "--ready-event" | "--parent-pid" | "--live-stats" => {
                iter.next();
            }
            "--engine" => {}
            _ => result.push(argument.clone()),
        }
    }
    result
}

/// A console-subsystem exe launched from Explorer gets its own console;
/// detaching closes it without hiding a terminal the user launched us from.
pub fn detach_console() {
    // SAFETY: detaching from the console has no preconditions.
    let _ = unsafe { windows::Win32::System::Console::FreeConsole() };
}

/// Tray launch (port of the tray branch of `main`): elevate once, refuse a
/// second instance, then supervise the engine.
pub fn run_tray(options: &Options, args: &[String]) -> i32 {
    detach_console();
    sh_core::logging::init(false, None);
    if !sh_engine::win::is_elevated() {
        // Decide "already running" before the UAC prompt; otherwise a second
        // launch asks for elevation and then exits without a word.
        if tray::instance_running() {
            tracing::info!("SplitHello tray zaten calisiyor");
            return 0;
        }
        tracing::info!("WinDivert icin yonetici izni isteniyor");
        return sh_engine::win::relaunch_elevated(false).unwrap_or_else(|| {
            use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
            // SAFETY: modal message box with static strings.
            unsafe {
                MessageBoxW(
                    None,
                    windows::core::w!("SplitHello ağ koruması için yönetici izni gerekiyor."),
                    windows::core::w!("SplitHello"),
                    MB_OK | MB_ICONERROR,
                )
            };
            1
        });
    }
    let mut config = sh_core::config::Config::default();
    if let Some(dir) = sh_core::paths::config_dir() {
        config.load_from(&dir);
    }
    // An unreadable config is not "setup missing": let the engine start and
    // report the precise reason (exit 16) instead of asking for setup.
    let configured = !options.worker_url.is_empty() || config.is_valid() || config.load_failed;
    tray::run(engine_arguments(args), configured)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_arguments_drop_internal_flags() {
        let args: Vec<String> = [
            "--port",
            "1081",
            "--engine",
            "--live-stats",
            "x",
            "--parent-pid",
            "4",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        assert_eq!(engine_arguments(&args), ["--port", "1081"]);
    }
}
