//! Where SplitHello keeps its state: `%APPDATA%\splithello` (port of the path
//! helpers in `src/Config.cpp`). Paths stay `OsString`-based so a profile path
//! with non-ANSI characters is never mangled.

use std::path::PathBuf;

/// `%APPDATA%\splithello`, or None when APPDATA is unset.
pub fn config_dir() -> Option<PathBuf> {
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
