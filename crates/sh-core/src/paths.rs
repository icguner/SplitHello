//! Where SplitHello keeps its state: `%APPDATA%\splithello` (port of the path
//! helpers in `src/Config.cpp`). Paths stay `OsString`-based so a profile path
//! with non-ANSI characters is never mangled.

use std::path::PathBuf;

/// `%APPDATA%\splithello`, or None when APPDATA is unset.
/// `SPLITHELLO_CONFIG_DIR` overrides it: a development aid that lets a Rust
/// build run beside the C++ engine against a copy of the state.
pub fn config_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("SPLITHELLO_CONFIG_DIR").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    std::env::var_os("APPDATA")
        .filter(|value| !value.is_empty())
        .map(|appdata| PathBuf::from(appdata).join("splithello"))
}

pub fn in_config_dir(name: &str) -> Option<PathBuf> {
    config_dir().map(|dir| dir.join(name))
}

pub const CONFIG_FILE: &str = "config.json";
pub const STRATEGY_FILE: &str = "strategies.json";
pub const TELEMETRY_FILE: &str = "telemetry.db";
pub const LOG_FILE: &str = "splithello.log";
pub const PROXY_BACKUP_FILE: &str = "proxy-backup.json";
