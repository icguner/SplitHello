//! SplitHello (Rust): tray, engine, panel and one-shot commands in one exe,
//! dispatched like the C++ `main`.

use sh_engine::options::{self, Action};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let options = match options::parse(&args) {
        Ok(options) => options,
        Err(code) => std::process::exit(code),
    };
    let code = match options.action {
        Action::Panel => {
            sh_ui::detach_console();
            sh_ui::panel::run()
        }
        Action::EnableStartup => sh_ui::startup::enable_from_command_line(),
        Action::InstallService => sh_ui::service::install(),
        Action::UninstallService => sh_ui::service::uninstall(),
        Action::Run if options.tray_mode() => sh_ui::run_tray(&args),
        _ => {
            let reconfigured = matches!(options.action, Action::SetupOnly | Action::Redeploy);
            let code = sh_engine::run(options);
            if code == 0 && reconfigured {
                reload_running_engine();
            }
            code
        }
    };
    std::process::exit(code);
}

/// Setup and redeploy rotate the Worker secret: an engine still holding the
/// old one would be refused until it gave up. The tray restarts the engine it
/// supervises; without a tray the service is asked directly. A launcher that
/// reloads again afterwards (tray, panel) only costs one more quick restart.
fn reload_running_engine() {
    if !sh_ui::tray::notify_tray_restart()
        && let Some(service) = sh_ui::service::Control::open()
    {
        service.reload();
    }
}
