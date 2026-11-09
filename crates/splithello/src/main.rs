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
            sh_ui::panel::run(&options.live_stats)
        }
        Action::EnableStartup => sh_ui::startup::enable_from_command_line(),
        Action::Run if options.tray_mode() => sh_ui::run_tray(&options, &args),
        _ => sh_engine::run(options),
    };
    std::process::exit(code);
}
