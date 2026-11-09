//! Engine composition (port of `src/main.cpp`): command line, the
//! transparent (WinDivert) and manual-proxy engines and one-shot commands. The
//! tray, panel and setup arrive in stage 5.

pub mod adblock_updater;
pub mod engine;
pub mod options;
mod win;

use options::Action;

/// `%APPDATA%\splithello`, or `SPLITHELLO_CONFIG_DIR` when set. The override is
/// a development aid: it lets a Rust build run beside the C++ engine against a
/// copy of the state instead of both rewriting the same strategies.json.
pub fn config_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("SPLITHELLO_CONFIG_DIR")
        .filter(|value| !value.is_empty())
        .map(std::path::PathBuf::from)
        .or_else(sh_core::paths::config_dir)
}

/// Entry point for the `splithello` binary; returns the process exit code.
pub fn run(args: Vec<String>) -> i32 {
    let options = match options::parse(&args) {
        Ok(options) => options,
        Err(code) => return code,
    };
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
                "Bu islem Rust surumunde henuz yok (asama 5: tray, kurulum). Motoru calistirmak icin \
                 --console veya --manual-proxy kullanin."
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
