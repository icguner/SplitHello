//! Engine composition (port of `src/main.cpp`): command line, the WinDivert
//! engine and one-shot commands.

pub mod adblock_updater;
pub mod engine;
pub mod options;
pub mod service;
pub mod win;

use options::Action;

pub use sh_core::paths::config_dir;

/// Engine runs and one-shot commands; returns the process exit code. The
/// binary sends tray, panel and startup-task launches to `sh-ui` instead.
pub fn run(options: options::Options) -> i32 {
    match options.action {
        Action::Help => {
            options::print_usage();
            0
        }
        Action::ListStrategies => {
            list_strategies();
            0
        }
        Action::ForgetStrategies => forget_strategies(),
        Action::ForgetToken => forget_token(),
        Action::Run | Action::Setup => engine::run(&options),
        Action::Service => service::run(),
        Action::SetupOnly | Action::Redeploy => setup_only(options.action),
        _ => {
            eprintln!(
                "--restore-proxy Rust surumunde yok (yalniz WinDivert oncesi eski surumlerin \
                 kalintisi); C++ splithello.exe ile calistirin."
            );
            1
        }
    }
}

fn list_strategies() {
    println!("Paket profilleri (--strategy <ad>; ilki varsayilan):\n");
    for (name, _) in sh_proto::packet::PROFILES {
        println!("  {name}");
    }
}

/// `--setup-only` (tray-launched console) and `--redeploy`: no engine after.
fn setup_only(action: Action) -> i32 {
    let Some(dir) = config_dir() else {
        eprintln!("APPDATA yolu belirlenemedi");
        return 1;
    };
    sh_core::logging::init(false, Some(&dir.join(sh_core::paths::LOG_FILE)));
    let mut config = sh_core::config::Config::default();
    config.load_from(&dir);
    if config.load_failed {
        eprintln!(
            "Yapilandirma okunamadi: {}",
            sh_core::config::Config::path_in(&dir).display()
        );
        return engine::EXIT_CONFIG_UNREADABLE;
    }
    let done = if action == Action::Redeploy {
        if config.worker_name.is_empty() {
            eprintln!("Once --setup calistirin.");
            return 1;
        }
        sh_setup::redeploy(&mut config, &dir)
    } else {
        let done = sh_setup::run_setup(&mut config, &dir);
        // The console belongs to the tray-launched child and closes on exit.
        sh_setup::wait_for_enter();
        done
    };
    if done { 0 } else { 1 }
}

fn forget_token() -> i32 {
    let Some(dir) = config_dir() else {
        eprintln!("APPDATA yolu belirlenemedi");
        return 1;
    };
    let mut config = sh_core::config::Config::default();
    config.load_from(&dir);
    if config.load_failed {
        eprintln!("Token silinemedi.");
        return 1;
    }
    // accountId stays: it is not a secret and selects the same account.
    config.api_token.clear();
    match config.save_to(&dir) {
        Ok(()) => {
            println!(
                "Eski Cloudflare API token alani silindi.\nWrangler OAuth oturumu etkilenmedi."
            );
            0
        }
        Err(_) => {
            eprintln!("Token silinemedi.");
            1
        }
    }
}

fn forget_strategies() -> i32 {
    let Some(dir) = config_dir() else {
        eprintln!("APPDATA yolu belirlenemedi");
        return 1;
    };
    let learner = sh_strategy::Learner::new(dir.join(sh_core::paths::STRATEGY_FILE));
    learner.load();
    let count = learner.len();
    learner.clear();
    println!("{count} site icin ogrenilen profil silindi.");
    0
}
