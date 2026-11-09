//! Engine composition (port of `src/main.cpp`): command line, the
//! transparent (WinDivert) and manual-proxy engines and one-shot commands.

pub mod adblock_updater;
pub mod engine;
pub mod options;
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
        Action::Run
            if options.manual_proxy || options.engine || options.console || options.verbose =>
        {
            engine::run(&options)
        }
        _ => {
            eprintln!(
                "Bu islem Rust surumunde henuz yok (kurulum, --restore-proxy). Simdilik C++ \
                 splithello.exe ile calistirin."
            );
            1
        }
    }
}

fn list_strategies() {
    println!("Parcalama profilleri (deneme sirasiyla):\n");
    for profile in sh_strategy::PROFILES {
        let note = if profile.requires_sni {
            " (SNI gerektirir)"
        } else {
            ""
        };
        println!("  {:<22}{}{note}", profile.name, profile.description);
    }
    if let Some(dir) = config_dir() {
        println!(
            "\nCalisan profil ag + alan adi bazinda ogrenilir ve {} dosyasinda saklanir.",
            dir.join(sh_core::paths::STRATEGY_FILE).display()
        );
    }
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
    let store = sh_strategy::Store::new(dir.join(sh_core::paths::STRATEGY_FILE));
    store.load();
    let count = store.len();
    store.clear();
    println!("{count} alan adi icin ogrenilen strateji silindi.");
    0
}
