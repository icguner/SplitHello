//! Persistent configuration in `%APPDATA%\splithello\config.json` (port of
//! `src/Config.cpp`). Keys, defaults and the write order are unchanged, so the
//! C++ and Rust builds read each other's files.
//!
//! One deliberate difference: a file that exists but is not valid JSON sets
//! `load_failed` (the C++ reader silently fell back to defaults, which a later
//! save would have written over the user's file).

use std::path::{Path, PathBuf};

use serde_json::{Map, Value};

use crate::{fsutil, secure};

const MAXIMUM_PROCESS_RULES: usize = 128;
const MAXIMUM_RULE_LENGTH: usize = 1024;
pub const DEFAULT_WORKER_NAME: &str = "splithello-relay";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DnsMode {
    #[default]
    Worker,
    /// Leaves DNS/53 untouched.
    System,
}

/// A public DoH resolver reached by IP literal, so no DNS lookup precedes it.
pub struct DnsProvider {
    pub id: &'static str,
    pub name: &'static str,
    pub host: &'static str,
    pub json_path: &'static str,
}

/// Encrypted-DNS providers: the chosen one is asked first, the rest in this order.
pub const DNS_PROVIDERS: [DnsProvider; 4] = [
    DnsProvider {
        id: "cloudflare",
        name: "Cloudflare",
        host: "1.1.1.1",
        json_path: "/dns-query",
    },
    DnsProvider {
        id: "google",
        name: "Google",
        host: "8.8.8.8",
        json_path: "/resolve",
    },
    DnsProvider {
        id: "adguard",
        name: "AdGuard",
        host: "94.140.14.14",
        json_path: "/resolve",
    },
    DnsProvider {
        id: "dnssb",
        name: "DNS.SB",
        host: "185.222.222.222",
        json_path: "/dns-query",
    },
];

/// Index of a provider id in `DNS_PROVIDERS`; unknown ids map to the first.
pub fn dns_provider_index(id: &str) -> usize {
    DNS_PROVIDERS.iter().position(|p| p.id == id).unwrap_or(0)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Legacy migration buffer only; never written back.
    pub api_token: String,
    pub account_id: String,
    pub worker_name: String,
    /// `wss://name.subdomain.workers.dev`
    pub worker_url: String,
    /// Bearer secret the Worker requires (DPAPI-encrypted on disk).
    pub shared_secret: String,
    pub dns_mode: DnsMode,
    /// Id from `DNS_PROVIDERS`; always a known one after load.
    pub dns_provider: String,
    pub process_include: Vec<String>,
    pub process_exclude: Vec<String>,
    pub ad_block: bool,
    pub ad_block_allow: Vec<String>,
    /// HaGeZi lists to merge: light, pro, tif, doh.
    pub ad_block_lists: Vec<String>,

    /// load() found a plaintext secret; callers re-save to encrypt it.
    pub migrated_from_plaintext: bool,
    pub legacy_api_token_present: bool,
    /// The stored DPAPI blob could not be decrypted. It is kept verbatim and
    /// written back unless `shared_secret` is set, so a transient failure never
    /// destroys the secret.
    pub shared_secret_blob: String,
    /// A config file exists but could not be read: never save() such a config,
    /// it holds defaults and would overwrite the real file.
    pub load_failed: bool,
    /// `process_include` was non-empty on disk but every entry was unusable; the
    /// engine refuses to start rather than widen the scope to every process.
    pub process_include_invalid: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            api_token: String::new(),
            account_id: String::new(),
            worker_name: DEFAULT_WORKER_NAME.into(),
            worker_url: String::new(),
            shared_secret: String::new(),
            dns_mode: DnsMode::Worker,
            dns_provider: DNS_PROVIDERS[0].id.into(),
            process_include: Vec::new(),
            process_exclude: Vec::new(),
            ad_block: true,
            ad_block_allow: Vec::new(),
            ad_block_lists: vec!["pro".into()],
            migrated_from_plaintext: false,
            legacy_api_token_present: false,
            shared_secret_blob: String::new(),
            load_failed: false,
            process_include_invalid: false,
        }
    }
}

fn get_string(json: &Map<String, Value>, key: &str) -> String {
    json.get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

fn get_bool(json: &Map<String, Value>, key: &str) -> bool {
    json.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// String elements of an array value, stopping at the first non-string one.
fn get_string_array(json: &Map<String, Value>, key: &str) -> Vec<String> {
    let Some(Value::Array(items)) = json.get(key) else {
        return Vec::new();
    };
    items
        .iter()
        .map_while(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn read_process_rules(json: &Map<String, Value>, key: &str) -> Vec<String> {
    get_string_array(json, key)
        .into_iter()
        .filter(|rule| !rule.is_empty() && rule.len() <= MAXIMUM_RULE_LENGTH)
        .take(MAXIMUM_PROCESS_RULES)
        .collect()
}

/// Reads the DPAPI-protected key or, for configs from older builds, its
/// plaintext counterpart. An undecryptable blob is returned as `kept_blob`.
fn read_secret(
    json: &Map<String, Value>,
    protected_key: &str,
    legacy_key: &str,
    migrated: &mut bool,
) -> (String, String) {
    let blob = get_string(json, protected_key);
    if !blob.is_empty() {
        let plaintext = secure::unprotect(&blob);
        if plaintext.is_empty() {
            tracing::warn!(
                "Config: '{protected_key}' cozulemedi; alan bos ama diskteki sifreli deger korunuyor \
                 (baska Windows kullanicisi veya bozuk dosya olabilir)"
            );
            return (String::new(), blob);
        }
        return (plaintext, String::new());
    }
    let legacy = get_string(json, legacy_key);
    if !legacy.is_empty() {
        *migrated = true;
    }
    (legacy, String::new())
}

fn quote(text: &str) -> String {
    serde_json::to_string(text).unwrap_or_else(|_| "\"\"".into())
}

fn string_array(values: &[String]) -> String {
    format!(
        "[{}]",
        values
            .iter()
            .map(|v| quote(v))
            .collect::<Vec<_>>()
            .join(", ")
    )
}

impl Config {
    pub fn path_in(dir: &Path) -> PathBuf {
        dir.join(crate::paths::CONFIG_FILE)
    }

    /// Loads `config.json` from `dir`. False when there is no readable file;
    /// check `load_failed` to tell a fresh install from a broken file.
    pub fn load_from(&mut self, dir: &Path) -> bool {
        self.load_failed = false;
        let path = Self::path_in(dir);
        let Some(bytes) = fsutil::read_all(&path) else {
            // A missing file is a fresh install; an existing unreadable one must
            // not be overwritten by defaults.
            self.load_failed = path.exists();
            if self.load_failed {
                tracing::error!("Config okunamadi (dosya var): {}", path.display());
            }
            return false;
        };
        let json = match serde_json::from_slice::<Value>(&bytes) {
            Ok(Value::Object(map)) => map,
            _ => {
                self.load_failed = true;
                tracing::error!("Config gecerli JSON degil: {}", path.display());
                return false;
            }
        };

        self.legacy_api_token_present = !get_string(&json, "api_token_dpapi").is_empty()
            || !get_string(&json, "api_token").is_empty();
        let mut migrated = false;
        (self.api_token, _) = read_secret(&json, "api_token_dpapi", "api_token", &mut migrated);
        (self.shared_secret, self.shared_secret_blob) =
            read_secret(&json, "shared_secret_dpapi", "shared_secret", &mut migrated);
        self.migrated_from_plaintext = migrated;
        self.account_id = get_string(&json, "account_id");
        self.worker_name = get_string(&json, "worker_name");
        if self.worker_name.is_empty() {
            self.worker_name = DEFAULT_WORKER_NAME.into();
        }
        self.worker_url = get_string(&json, "worker_url");
        self.dns_mode = if get_string(&json, "dns_mode") == "system" {
            DnsMode::System
        } else {
            DnsMode::Worker
        };
        self.dns_provider = DNS_PROVIDERS[dns_provider_index(&get_string(&json, "dns_provider"))]
            .id
            .into();

        self.process_include = read_process_rules(&json, "process_include");
        self.process_exclude = read_process_rules(&json, "process_exclude");
        // On unless the file says otherwise, so configs from older releases get it.
        self.ad_block = !json.contains_key("ad_block") || get_bool(&json, "ad_block");
        self.ad_block_allow = get_string_array(&json, "ad_block_allow");
        if json.contains_key("ad_block_lists") {
            self.ad_block_lists = get_string_array(&json, "ad_block_lists");
        }

        // An include list that normalizes to nothing would read as "no include
        // rules" = every process: flag it so the engine fails closed instead.
        self.process_include_invalid = self.process_include.is_empty()
            && !get_string_array(&json, "process_include").is_empty();
        if self.process_include_invalid {
            tracing::warn!(
                "Config: process_include dolu ama hicbir girdi gecerli degil; kapsam genisletilmeyecek, \
                 ag motoru baslatilmayacak"
            );
        }
        if self.migrated_from_plaintext {
            tracing::warn!("Config: duz metin sirlar bulundu, DPAPI ile yeniden sifreleniyor");
        }
        true
    }

    /// Writes `config.json` into `dir` (created if needed). If encryption fails
    /// the secret is dropped rather than written in the clear; an undecryptable
    /// blob from load() is written back untouched until a new secret is set.
    pub fn save_to(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let protected_secret = if self.shared_secret.is_empty() {
            self.shared_secret_blob.clone()
        } else {
            let protected = secure::protect(&self.shared_secret);
            if protected.is_empty() {
                tracing::error!("Worker gizli anahtari sifrelenemedi, kaydedilmiyor.");
            }
            protected
        };

        let dns_mode = match self.dns_mode {
            DnsMode::System => "system",
            DnsMode::Worker => "worker",
        };
        let content = format!(
            "{{\n  \"shared_secret_dpapi\": {},\n  \"account_id\": {},\n  \"worker_name\": {},\n  \
             \"worker_url\": {},\n  \"dns_mode\": \"{dns_mode}\",\n  \"dns_provider\": {},\n  \
             \"process_include\": {},\n  \
             \"process_exclude\": {},\n  \"ad_block\": {},\n  \"ad_block_allow\": {},\n  \
             \"ad_block_lists\": {}\n}}\n",
            quote(&protected_secret),
            quote(&self.account_id),
            quote(&self.worker_name),
            quote(&self.worker_url),
            quote(&self.dns_provider),
            string_array(&self.process_include),
            string_array(&self.process_exclude),
            self.ad_block,
            string_array(&self.ad_block_allow),
            string_array(&self.ad_block_lists),
        );
        let path = Self::path_in(dir);
        fsutil::write_atomic(&path, content.as_bytes())?;
        tracing::info!("Config kaydedildi: {}", path.display());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("sh-core-config-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write(dir: &Path, json: &str) {
        fs::write(Config::path_in(dir), json).unwrap();
    }

    fn load(dir: &Path) -> Config {
        let mut config = Config::default();
        assert!(config.load_from(dir));
        config
    }

    #[cfg(windows)]
    #[test]
    fn keeps_undecryptable_secret_blob_across_save() {
        let dir = scratch("blob");
        // Valid base64 that DPAPI cannot decrypt, like a blob from another user.
        let foreign = "bm90LWEtZHBhcGktYmxvYi1ub3QtYS1kcGFwaS1ibG9i";
        write(
            &dir,
            &format!(
                r#"{{"shared_secret_dpapi": "{foreign}", "dns_mode": "worker", "worker_url": "wss://x"}}"#
            ),
        );
        let mut config = load(&dir);
        assert!(config.shared_secret.is_empty());
        assert_eq!(config.shared_secret_blob, foreign);

        // An unrelated change (e.g. the panel saving rules) keeps the blob.
        config.ad_block = false;
        config.save_to(&dir).unwrap();
        assert!(
            fs::read_to_string(Config::path_in(&dir))
                .unwrap()
                .contains(foreign)
        );

        // Setting a secret explicitly replaces it.
        config.shared_secret = "fresh-secret".into();
        config.save_to(&dir).unwrap();
        assert!(
            !fs::read_to_string(Config::path_in(&dir))
                .unwrap()
                .contains(foreign)
        );
        let reloaded = load(&dir);
        assert_eq!(reloaded.shared_secret, "fresh-secret");
        assert!(reloaded.shared_secret_blob.is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn flags_process_include_that_normalizes_to_nothing() {
        let dir = scratch("include");
        write(
            &dir,
            r#"{"process_include": ["", ""], "process_exclude": ["a.exe"]}"#,
        );
        let invalid = load(&dir);
        assert!(invalid.process_include.is_empty());
        assert!(invalid.process_include_invalid);
        assert_eq!(invalid.process_exclude.len(), 1);

        write(&dir, r#"{"process_include": []}"#);
        assert!(!load(&dir).process_include_invalid);

        write(&dir, r#"{"process_include": ["chrome.exe"]}"#);
        let valid = load(&dir);
        assert!(!valid.process_include_invalid);
        assert_eq!(valid.process_include.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Compatibility check against the real file the C++ build wrote on this
    /// machine (read-only). Run with `cargo test -p sh-core -- --ignored`.
    #[cfg(windows)]
    #[test]
    #[ignore = "reads the developer's real %APPDATA%\\splithello\\config.json"]
    fn compat_reads_the_live_cpp_config() {
        let dir = crate::paths::config_dir().expect("APPDATA");
        let mut config = Config::default();
        assert!(config.load_from(&dir), "no readable config.json");
        assert!(
            config.shared_secret_blob.is_empty(),
            "C++ DPAPI blob did not decrypt"
        );
        if !config.worker_url.is_empty() {
            assert!(
                config.shared_secret.len() == 64
                    && config.shared_secret.bytes().all(|b| b.is_ascii_hexdigit())
            );
        }
        println!(
            "dns_mode={:?} lists={:?} include={}",
            config.dns_mode,
            config.ad_block_lists,
            config.process_include.len()
        );
    }

    #[test]
    fn missing_file_is_not_a_load_failure() {
        let dir = scratch("missing");
        let mut config = Config::default();
        assert!(!config.load_from(&dir));
        assert!(!config.load_failed);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn invalid_json_is_a_load_failure() {
        let dir = scratch("invalid");
        write(&dir, "{ not json");
        let mut config = Config::default();
        assert!(!config.load_from(&dir));
        assert!(config.load_failed);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn reads_values_and_defaults_like_the_cpp_build() {
        let dir = scratch("values");
        write(
            &dir,
            r#"{"account_id": "acc", "worker_name": "", "worker_url": "wss://w.example.workers.dev",
                "dns_mode": "system", "split_delay_ms": 5000, "probe_timeout_ms": 900,
                "tunnel_fallback": true, "ad_block_allow": ["a.com", 7, "b.com"]}"#,
        );
        let config = load(&dir);
        assert_eq!(config.account_id, "acc");
        assert_eq!(config.worker_name, DEFAULT_WORKER_NAME);
        assert_eq!(config.dns_mode, DnsMode::System);
        assert_eq!(config.dns_provider, "cloudflare"); // missing: the first provider
        // Keys of the relay builds (split delay, probe timeout, tunnel) are ignored.
        assert!(config.ad_block); // absent means on
        assert_eq!(config.ad_block_allow, ["a.com"]); // stops at a non-string
        assert_eq!(config.ad_block_lists, ["pro"]);

        write(&dir, r#"{"ad_block": false, "ad_block_lists": []}"#);
        let off = load(&dir);
        assert!(!off.ad_block);
        assert!(off.ad_block_lists.is_empty());

        write(&dir, r#"{"dns_provider": "adguard"}"#);
        assert_eq!(load(&dir).dns_provider, "adguard");
        write(&dir, r#"{"dns_provider": "quad9"}"#);
        assert_eq!(load(&dir).dns_provider, "cloudflare");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn save_writes_the_cpp_key_order() {
        let dir = scratch("order");
        let config = Config {
            process_include: vec!["chrome.exe".into()],
            dns_provider: "dnssb".into(),
            ..Config::default()
        };
        config.save_to(&dir).unwrap();
        let saved = fs::read_to_string(Config::path_in(&dir)).unwrap();
        let keys: Vec<usize> = [
            "shared_secret_dpapi",
            "account_id",
            "worker_name",
            "worker_url",
            "dns_mode",
            "dns_provider",
            "process_include",
            "process_exclude",
            "ad_block\"",
            "ad_block_allow",
            "ad_block_lists",
        ]
        .iter()
        .map(|key| saved.find(key).unwrap_or_else(|| panic!("{key} missing")))
        .collect();
        assert!(keys.windows(2).all(|w| w[0] < w[1]));
        assert!(saved.contains("\"process_include\": [\"chrome.exe\"]"));
        assert_eq!(load(&dir), config);
        fs::remove_dir_all(&dir).unwrap();
    }
}
