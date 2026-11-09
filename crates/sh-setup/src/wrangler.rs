//! Wrangler driver (port of `src/Wrangler.cpp`): runs a pinned
//! `npx --yes wrangler@<version>` with an environment stripped of API-token
//! variables, so only the OS-keyring OAuth session can be used.

use std::io::{Read, Write};
use std::os::windows::io::AsRawHandle;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// The single place the Wrangler release is chosen: an exact x.y.z, so a
/// broken or compromised new release never runs unreviewed. To bump, change
/// it and run --setup / --redeploy once against a scratch account.
const WRANGLER_VERSION: &str = "4.149.0";
/// Wrangler stores OAuth in the keyring only with this native binding, and
/// installs it itself only on a terminal stdin; ours is piped. Same version
/// Wrangler pins; update both together.
const KEYRING_VERSION: &str = "1.3.0";
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);
const LOGIN_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const DEPLOY_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_CAPTURED_OUTPUT: usize = 2 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    pub email: String,
    pub accounts: Vec<Account>,
}

struct Output {
    launched: bool,
    timed_out: bool,
    code: i32,
    text: String,
}

impl Output {
    fn ok(&self) -> bool {
        self.launched && !self.timed_out && self.code == 0
    }
}

/// Runs `node <arguments>` with piped stdio (stdout and stderr captured
/// together), `input` written to stdin, inside a kill-on-close job so the
/// npx -> node -> wrangler chain dies together on timeout.
fn run(
    node: &Path,
    arguments: &[&str],
    directory: Option<&Path>,
    input: &str,
    timeout: Duration,
) -> Output {
    let mut command = Command::new(node);
    command
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Wrangler prefers these over OAuth: strip every spelling.
    for key in [
        "CLOUDFLARE_API_TOKEN",
        "CLOUDFLARE_API_KEY",
        "CLOUDFLARE_EMAIL",
        "CF_API_TOKEN",
        "CF_API_KEY",
        "CF_EMAIL",
    ] {
        command.env_remove(key);
    }
    command
        .env("CLOUDFLARE_AUTH_USE_KEYRING", "true")
        .env("NO_COLOR", "1")
        .env("WRANGLER_SEND_METRICS", "false");
    if let Some(directory) = directory {
        command.current_dir(directory);
    }
    let failed = Output {
        launched: false,
        timed_out: false,
        code: -1,
        text: String::new(),
    };
    let Ok(mut child) = command.spawn() else {
        return failed;
    };
    // shortcut: the job is assigned right after spawn, not on a suspended
    // child; npx needs far longer than that to start its own children.
    let job = Job::around(child.as_raw_handle());

    let text = Arc::new(Mutex::new(Vec::new()));
    let readers: Vec<_> = [
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    ]
    .into_iter()
    .flatten()
    .map(|mut stream| {
        let text = text.clone();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 4096];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                let mut text = text.lock().unwrap_or_else(|p| p.into_inner());
                let room = MAX_CAPTURED_OUTPUT.saturating_sub(text.len());
                text.extend_from_slice(&buffer[..read.min(room)]);
            }
        })
    })
    .collect();
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input.as_bytes());
    }

    let deadline = Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        if let Ok(Some(status)) = child.try_wait() {
            break Some(status);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            drop(job); // kill-on-close takes the whole chain down
            let _ = child.kill();
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    for reader in readers {
        let _ = reader.join();
    }
    let text =
        String::from_utf8_lossy(&text.lock().unwrap_or_else(|p| p.into_inner())).into_owned();
    Output {
        launched: true,
        timed_out,
        code: status.and_then(|s| s.code()).unwrap_or(-1),
        text,
    }
}

struct Job(windows::Win32::Foundation::HANDLE);

impl Job {
    fn around(process: std::os::windows::io::RawHandle) -> Option<Self> {
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };
        // SAFETY: the job handle is owned by the returned value; the process
        // handle stays owned by its Child.
        unsafe {
            let job = CreateJobObjectW(None, None).ok()?;
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            let _ = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::from_ref(&limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if AssignProcessToJobObject(job, HANDLE(process)).is_err() {
                let _ = windows::Win32::Foundation::CloseHandle(job);
                tracing::debug!(
                    "Wrangler job nesnesine atanamadi; yalnizca ana surec sonlandirilabilir"
                );
                return None;
            }
            Some(Self(job))
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        // SAFETY: owned handle; closing it kills the job's processes.
        let _ = unsafe { windows::Win32::Foundation::CloseHandle(self.0) };
    }
}

fn search_path(name: &str) -> Option<PathBuf> {
    std::env::split_paths(&std::env::var_os("PATH")?)
        .map(|dir| dir.join(name))
        .find(|path| path.is_file())
}

/// node.exe and npm's npx-cli.js (npx.cmd is a batch file; running it through
/// cmd would re-parse our arguments).
fn find_npx_runtime() -> Option<(PathBuf, PathBuf)> {
    let node = search_path("node.exe")?;
    let mut roots = vec![node.parent()?.to_path_buf()];
    if let Some(npx_dir) = search_path("npx.cmd").and_then(|p| p.parent().map(Path::to_path_buf)) {
        if npx_dir.file_name().is_some_and(|n| n == "bin")
            && let Some(root) = npx_dir.ancestors().nth(3)
        {
            roots.push(root.to_path_buf());
        }
        roots.insert(1, npx_dir);
    }
    roots
        .into_iter()
        .map(|root| {
            root.join("node_modules")
                .join("npm")
                .join("bin")
                .join("npx-cli.js")
        })
        .find(|cli| cli.is_file())
        .map(|cli| (node, cli))
}

/// The reason Wrangler printed last ("[ERROR] ..."), without ANSI escapes.
pub fn last_error_line(output: &str) -> String {
    let mut plain = String::with_capacity(output.len());
    let mut chars = output.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.peek() == Some(&'[') {
            chars.next();
            for c in chars.by_ref() {
                if ('@'..='~').contains(&c) {
                    break;
                }
            }
            continue;
        }
        plain.push(c);
    }
    let mut found = String::new();
    for line in plain.lines() {
        if let Some(at) = line.find("[ERROR]") {
            let reason = line[at + 7..].trim();
            found = reason.strip_prefix("Error: ").unwrap_or(reason).to_string();
        }
    }
    found
}

fn is_hex_account_id(id: &str) -> bool {
    id.len() == 32 && id.chars().all(|c| c.is_ascii_hexdigit())
}

pub fn is_valid_worker_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 63
        && !name.starts_with('-')
        && !name.ends_with('-')
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// `wrangler whoami --json`; banner lines before the JSON are skipped.
pub fn parse_identity(output: &str) -> Option<Identity> {
    let value = output.match_indices('{').find_map(|(at, _)| {
        serde_json::Deserializer::from_str(&output[at..])
            .into_iter::<serde_json::Value>()
            .next()?
            .ok()
            .filter(|v| v.get("accounts").is_some())
    })?;
    let text = |v: &serde_json::Value, key: &str| {
        v.get(key)
            .and_then(|s| s.as_str())
            .unwrap_or_default()
            .to_string()
    };
    let accounts: Vec<Account> = value["accounts"]
        .as_array()?
        .iter()
        .map(|a| Account {
            id: text(a, "id"),
            name: text(a, "name"),
        })
        .filter(|a| is_hex_account_id(&a.id))
        .collect();
    (!accounts.is_empty()).then(|| Identity {
        email: text(&value, "email"),
        accounts,
    })
}

/// "wss://<worker>.<subdomain>.workers.dev" from deploy output. Requiring the
/// worker name rules out other workers.dev links (docs, templates).
pub fn parse_workers_dev_url(output: &str, worker_name: &str) -> String {
    let prefix = if worker_name.is_empty() {
        String::new()
    } else {
        format!("{worker_name}.")
    };
    const SUFFIX: &str = ".workers.dev";
    for (at, _) in output.match_indices("https://") {
        let host: String = output[at + 8..]
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
            .collect::<String>()
            .to_ascii_lowercase();
        if host.ends_with(SUFFIX)
            && host.starts_with(&prefix)
            && host.len() > prefix.len() + SUFFIX.len()
        {
            return format!("wss://{host}");
        }
    }
    String::new()
}

fn wrangler_config(account_id: &str, worker_name: &str, rate_limiter: bool) -> String {
    let mut config = format!(
        "name = \"{worker_name}\"\nmain = \"index.js\"\naccount_id = \"{account_id}\"\n\
         compatibility_date = \"2024-09-23\"\ncompatibility_flags = [\"nodejs_compat\"]\n\
         workers_dev = true\npreview_urls = false\nsend_metrics = false\n"
    );
    if rate_limiter {
        config.push_str(
            "\n[[unsafe.bindings]]\nname = \"RATE_LIMITER\"\ntype = \"ratelimit\"\n\
             namespace_id = \"1001\"\nsimple = { limit = 600, period = 60 }\n",
        );
    }
    config
}

pub struct Client {
    runtime: Option<(PathBuf, PathBuf)>,
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl Client {
    pub fn new() -> Self {
        Self {
            runtime: find_npx_runtime(),
        }
    }

    fn npx(
        &self,
        arguments: &[&str],
        directory: Option<&Path>,
        input: &str,
        timeout: Duration,
    ) -> Output {
        let Some((node, cli)) = &self.runtime else {
            return Output {
                launched: false,
                timed_out: false,
                code: -1,
                text: String::new(),
            };
        };
        let cli = cli.to_string_lossy();
        let package = format!("wrangler@{WRANGLER_VERSION}");
        let mut all = vec![cli.as_ref(), "--yes", package.as_str()];
        all.extend_from_slice(arguments);
        run(node, &all, directory, input, timeout)
    }

    pub fn available(&self) -> Result<(), String> {
        if self.runtime.is_none() {
            return Err("Node.js/npm bulunamadi. Node.js 20+ LTS kurup tekrar deneyin.".into());
        }
        let result = self.npx(&["--version"], None, "", PROBE_TIMEOUT);
        match result {
            r if r.ok() => Ok(()),
            r if r.timed_out => Err("Wrangler surum kontrolu zaman asimina ugradi.".into()),
            r => Err(format!("Wrangler calistirilamadi: {}", r.text)),
        }
    }

    fn ensure_keyring_binding(&self) -> bool {
        let Some((node, cli)) = &self.runtime else {
            return false;
        };
        let npm = cli.with_file_name("npm-cli.js");
        if !npm.is_file() {
            return true; // let Wrangler report it
        }
        let npm_text = npm.to_string_lossy();
        let root = run(node, &[&npm_text, "root", "-g"], None, "", PROBE_TIMEOUT);
        if root.ok()
            && Path::new(root.text.trim())
                .join("@napi-rs")
                .join("keyring")
                .join("index.js")
                .is_file()
        {
            return true;
        }
        println!("  Windows anahtar zinciri modulu kuruluyor (bir kerelik)...");
        let package = format!("@napi-rs/keyring@{KEYRING_VERSION}");
        let install = run(
            node,
            &[
                &npm_text,
                "install",
                "-g",
                &package,
                "--no-audit",
                "--no-fund",
                "--loglevel=error",
            ],
            None,
            "",
            PROBE_TIMEOUT,
        );
        tracing::debug!(
            "npm install keyring (exit={}): {}",
            install.code,
            install.text
        );
        if !install.ok() {
            eprintln!("Anahtar zinciri modulu kurulamadi. Elle: npm install -g {package}");
        }
        install.ok()
    }

    pub fn login_with_keyring(&self) -> bool {
        if !self.ensure_keyring_binding() {
            return false;
        }
        // Wrangler's own output is noise here; only the reason is shown.
        let result = self.npx(&["login", "--use-keyring"], None, "", LOGIN_TIMEOUT);
        tracing::debug!("wrangler login (exit={}): {}", result.code, result.text);
        if result.ok() {
            return true;
        }
        if result.timed_out {
            eprintln!("Cloudflare girisi zaman asimina ugradi.");
        } else {
            let mut reason = last_error_line(&result.text);
            if reason.starts_with("Consent denied") {
                reason = "Cloudflare'de izin verilmedi.".into();
            }
            eprintln!(
                "{}",
                if reason.is_empty() {
                    "Cloudflare girisi tamamlanamadi."
                } else {
                    &reason
                }
            );
        }
        false
    }

    pub fn whoami(&self) -> Option<Identity> {
        let result = self.npx(&["whoami", "--json"], None, "", PROBE_TIMEOUT);
        if !result.ok() {
            tracing::debug!(
                "wrangler whoami basarisiz (exit={}): {}",
                result.code,
                result.text
            );
            return None;
        }
        parse_identity(&result.text)
    }

    /// Deploys the Worker and stores the secret; the workers.dev URL on success.
    pub fn deploy(
        &self,
        account_id: &str,
        worker_name: &str,
        source: &str,
        secret: &str,
        previous_url: &str,
    ) -> Option<String> {
        if !is_hex_account_id(account_id)
            || !is_valid_worker_name(worker_name)
            || source.is_empty()
            || secret.is_empty()
        {
            eprintln!("Wrangler deploy parametreleri gecersiz.");
            return None;
        }
        let directory = TempDir::new()?;
        let config_path = directory.0.join("wrangler.toml");
        let config_text = config_path.to_string_lossy().into_owned();
        let write = |rate_limiter: bool| {
            sh_core::fsutil::write_atomic(directory.0.join("index.js"), source.as_bytes()).is_ok()
                && sh_core::fsutil::write_atomic(
                    &config_path,
                    wrangler_config(account_id, worker_name, rate_limiter).as_bytes(),
                )
                .is_ok()
        };
        if !write(true) {
            eprintln!("Gecici Worker dosyalari yazilamadi.");
            return None;
        }
        let deploy = || {
            self.npx(
                &["deploy", "--config", &config_text, "--no-autoconfig"],
                Some(&directory.0),
                "",
                DEPLOY_TIMEOUT,
            )
        };
        let mut result = deploy();
        let mut without_rate_limiter = false;
        if !result.ok() {
            // Any failure lands here, not only a rejected binding: say plainly
            // what the retry gives up.
            tracing::debug!("wrangler deploy (exit={}): {}", result.code, result.text);
            eprintln!(
                "Deploy basarisiz; hesap duzeyindeki hiz siniri olmadan bir kez daha deneniyor."
            );
            if !write(false) {
                return None;
            }
            result = deploy();
            without_rate_limiter = result.ok();
        }
        if !result.ok() {
            tracing::debug!("wrangler deploy (exit={}): {}", result.code, result.text);
            let reason = last_error_line(&result.text);
            eprintln!(
                "{}",
                if result.timed_out {
                    "Deploy zaman asimina ugradi.".to_string()
                } else if reason.is_empty() {
                    "Deploy basarisiz.".to_string()
                } else {
                    reason
                }
            );
            return None;
        }

        let secret_result = self.npx(
            &["secret", "put", "SHARED_SECRET", "--config", &config_text],
            Some(&directory.0),
            &format!("{secret}\n"),
            DEPLOY_TIMEOUT,
        );
        if !secret_result.ok() {
            let reason = last_error_line(&secret_result.text);
            eprintln!(
                "{}",
                if secret_result.timed_out {
                    "Gizli anahtar yukleme zaman asimina ugradi.".to_string()
                } else if reason.is_empty() {
                    "Gizli anahtar yuklenemedi.".to_string()
                } else {
                    reason
                }
            );
            return None;
        }
        if without_rate_limiter {
            eprintln!(
                "Hesap duzeyinde hiz siniri olmadan deploy edildi; yalnizca yedek sayac aktif. \
                 Hesabiniz destekliyorsa --redeploy ile tekrar deneyin."
            );
            tracing::warn!("Worker rate limit binding'i olmadan deploy edildi");
        }

        let mut url = parse_workers_dev_url(&result.text, worker_name);
        if url.is_empty()
            && previous_url.starts_with(&format!("wss://{worker_name}."))
            && previous_url.ends_with(".workers.dev")
        {
            url = previous_url.to_string();
        }
        if url.is_empty() {
            eprintln!("Wrangler deploy basarili, ancak workers.dev URL'si okunamadi.");
            return None;
        }
        Some(url)
    }
}

/// Removed (with the Worker source and wrangler.toml) on drop.
struct TempDir(PathBuf);

impl TempDir {
    fn new() -> Option<Self> {
        let base = std::env::temp_dir();
        for attempt in 0..16 {
            let path = base.join(format!(
                "shw{}-{}-{attempt}",
                std::process::id(),
                sh_core::clock::now_ms()
            ));
            if std::fs::create_dir(&path).is_ok() {
                return Some(Self(path));
            }
        }
        eprintln!("Gecici Wrangler klasoru olusturulamadi.");
        None
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Read-only against the real toolchain and Cloudflare session (no deploy).
    #[test]
    #[ignore]
    fn real_wrangler_runs_and_reads_the_session() {
        let client = Client::new();
        client.available().unwrap();
        let identity = client.whoami();
        println!("whoami: {:?}", identity.map(|i| i.accounts.len()));
    }

    #[test]
    fn identity_skips_banners_and_bad_ids() {
        let output = "⛅️ wrangler 4.149.0\n{\"email\":\"a@b.c\",\"accounts\":[\
                      {\"id\":\"0123456789abcdef0123456789abcdef\",\"name\":\"Main\"},\
                      {\"id\":\"nope\",\"name\":\"Bad\"}]}\n";
        let identity = parse_identity(output).unwrap();
        assert_eq!(identity.email, "a@b.c");
        assert_eq!(identity.accounts.len(), 1);
        assert_eq!(identity.accounts[0].name, "Main");
        assert!(parse_identity("no json").is_none());
    }

    #[test]
    fn workers_dev_url_must_name_our_worker() {
        let output = "see https://developers.cloudflare.com/workers.dev\n\
                      Deployed https://other.me.workers.dev\n\
                      Deployed https://SplitHello-Relay.me.workers.dev (1 sec)";
        assert_eq!(
            parse_workers_dev_url(output, "splithello-relay"),
            "wss://splithello-relay.me.workers.dev"
        );
        assert_eq!(
            parse_workers_dev_url("https://x.workers.dev", "splithello-relay"),
            ""
        );
    }

    #[test]
    fn worker_names_and_error_lines() {
        assert!(is_valid_worker_name("splithello-relay"));
        assert!(!is_valid_worker_name("-bad"));
        assert!(!is_valid_worker_name("Upper"));
        assert_eq!(
            last_error_line("ok\n\x1b[31m✘ [ERROR]\x1b[0m Error: Consent denied\nmore"),
            "Consent denied"
        );
    }
}
