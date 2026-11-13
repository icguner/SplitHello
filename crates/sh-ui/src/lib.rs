//! The user-facing side (port of `TrayApp` and `DashboardPanel`): the Win32
//! tray with its engine supervisor, the "Windows ile başlat" task, and the
//! egui panel, which runs as its own process (`--panel`).

pub mod panel;
pub mod service;
pub mod startup;
mod theme;
pub mod tray;

/// Arguments the tray passes on to its engine: the user's, minus the
/// internal ones the tray adds itself.
fn engine_arguments(args: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    let mut iter = args.iter();
    while let Some(argument) = iter.next() {
        match argument.as_str() {
            "--shutdown-event" | "--ready-event" | "--parent-pid" => {
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
pub fn run_tray(args: &[String]) -> i32 {
    detach_console();
    sh_core::logging::init(false, None);
    // With the service installed the engine already has its rights: the
    // tray runs as the normal user and never asks for elevation.
    if !service::installed() && !sh_engine::win::is_elevated() {
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
    tray::run(engine_arguments(args))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_arguments_drop_internal_flags() {
        let args: Vec<String> = [
            "--quic-mode",
            "block",
            "--engine",
            "--ready-event",
            "x",
            "--parent-pid",
            "4",
        ]
        .iter()
        .map(|s| (*s).to_string())
        .collect();
        assert_eq!(engine_arguments(&args), ["--quic-mode", "block"]);
    }
}
