//! Interactive Cloudflare setup (port of `src/Setup.cpp`): Wrangler OAuth
//! with OS-keyring storage, Worker deploy, a fresh shared secret, and an
//! end-to-end check against the deployed Worker.

pub mod wrangler;

use std::io::{BufRead, Write};
use std::path::Path;
use std::time::Duration;

use sh_core::config::Config;
use wrangler::{Client, Identity};

/// Embedded so `splithello --setup` always ships the Worker it was built with.
const WORKER_SOURCE: &str = include_str!("../../../worker/src/index.js");
const SHARED_SECRET_BYTES: usize = 32; // 256 bits, hex-encoded

fn step(number: u32, text: &str) {
    print!("[{number}/6] {text}");
    let _ = std::io::stdout().flush();
}

fn step_ok(detail: &str) {
    println!(" OK {detail}");
}

fn step_failed() {
    println!(" HATA");
}

fn read_line() -> Option<String> {
    let mut line = String::new();
    match std::io::stdin().lock().read_line(&mut line) {
        Ok(0) | Err(_) => None,
        Ok(_) => Some(line.trim().to_string()),
    }
}

/// Default answer is yes; end of input (no console) counts as no.
fn ask_retry(question: &str) -> bool {
    print!("\n{question} [E/h] ");
    let _ = std::io::stdout().flush();
    read_line().is_some_and(|a| a.is_empty() || a.starts_with(['e', 'E', 'y', 'Y']))
}

fn select_account(identity: &Identity, preferred: &str) -> Option<String> {
    if !preferred.is_empty() && identity.accounts.iter().any(|a| a.id == preferred) {
        return Some(preferred.to_string());
    }
    match identity.accounts.as_slice() {
        [] => return None,
        [only] => return Some(only.id.clone()),
        _ => {}
    }
    println!("\nBirden fazla Cloudflare hesabi var:");
    for (index, account) in identity.accounts.iter().enumerate() {
        let name = if account.name.is_empty() {
            &account.id
        } else {
            &account.name
        };
        println!("  {}  {name} ({}...)", index + 1, &account.id[..8]);
    }
    print!("Kullanilacak hesap [1-{}]: ", identity.accounts.len());
    let _ = std::io::stdout().flush();
    let chosen = read_line()
        .and_then(|a| a.parse::<usize>().ok())
        .filter(|n| (1..=identity.accounts.len()).contains(n));
    if chosen.is_none() {
        eprintln!("Gecersiz hesap secimi.");
    }
    chosen.map(|n| identity.accounts[n - 1].id.clone())
}

/// End-to-end: the deployment works *and* accepts our secret. A fresh secret
/// takes a few seconds to reach every edge, so early 401s are expected.
fn verify(worker_url: &str, secret: &str) -> (bool, i32) {
    let host = sh_net::http::host_from_url(worker_url);
    if host.is_empty() {
        return (false, 0);
    }
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return (false, 0);
    };
    let client = sh_net::http::HttpClient::default();
    let mut request = sh_net::http::Request::get(host, "/resolve?host=cloudflare.com")
        .header("Authorization", &format!("Bearer {secret}"));
    request.timeout = Duration::from_secs(15);
    let response = runtime.block_on(client.perform(request));
    let ok = response.status == 200
        && serde_json::from_slice::<serde_json::Value>(&response.body)
            .ok()
            .and_then(|v| v.get("a")?.as_array().map(|a| !a.is_empty()))
            .unwrap_or(false);
    (ok, response.status)
}

fn deploy_and_verify(config: &mut Config, dir: &Path, client: &Client) -> bool {
    if config.shared_secret.is_empty() {
        config.shared_secret = sh_core::secure::random_hex(SHARED_SECRET_BYTES);
        if config.shared_secret.is_empty() {
            eprintln!("Rastgele anahtar uretilemedi.");
            return false;
        }
    }
    step(4, &format!("Worker yukleniyor ({})...", config.worker_name));
    let Some(url) = client.deploy(
        &config.account_id,
        &config.worker_name,
        WORKER_SOURCE,
        &config.shared_secret,
        &config.worker_url,
    ) else {
        step_failed();
        eprintln!("Ayrinti icin --verbose ile calistirin.");
        return false;
    };
    step_ok("");
    config.worker_url = url;
    step(5, "Adres kaydediliyor...");
    step_ok(&config.worker_url);

    // Persist the rotated secret before the network check: a transient outage
    // must not strand an updated remote Worker with a lost secret.
    if config.save_to(dir).is_err() {
        eprintln!(
            "Worker yuklendi ama yeni gizli anahtar config'e kaydedilemedi.\n\
             Dosya izinlerini duzeltip --redeploy calistirin."
        );
        return false;
    }

    step(6, "Uctan uca dogrulaniyor...");
    let mut status = 0;
    for _ in 0..10 {
        let (ok, last) = verify(&config.worker_url, &config.shared_secret);
        if ok {
            step_ok("");
            return true;
        }
        status = last;
        std::thread::sleep(Duration::from_secs(2));
    }
    step_failed();
    if status == 401 || status == 403 {
        eprintln!("Worker gizli anahtari kabul etmedi (HTTP {status}).");
    }
    eprintln!(
        "Worker yuklendi ama henuz yanit vermiyor.\n\
         Yeni anahtar kaydedildi; biraz sonra tekrar deneyin veya --redeploy calistirin."
    );
    false
}

fn prepare_client() -> Option<Client> {
    step(1, "Wrangler kontrol ediliyor...");
    let client = Client::new();
    match client.available() {
        Ok(()) => {
            step_ok("");
            Some(client)
        }
        Err(error) => {
            step_failed();
            eprintln!("{error}");
            None
        }
    }
}

fn login_and_read_identity(client: &Client, always_login: bool) -> Option<Identity> {
    if !always_login && let Some(identity) = client.whoami() {
        return Some(identity);
    }
    // A closed tab or a denied consent is common: offer another go.
    loop {
        step(
            2,
            "Cloudflare girisi: tarayicida acilan sayfada izin verin.\n",
        );
        if client.login_with_keyring() {
            break;
        }
        if !ask_retry("Tekrar denensin mi?") {
            return None;
        }
    }
    let identity = client.whoami();
    if identity.is_none() {
        eprintln!("Giris tamamlandi ama hesap bilgisi okunamadi.");
    }
    identity
}

pub fn run_setup(config: &mut Config, dir: &Path) -> bool {
    println!("\nSplitHello kurulumu\n");
    let Some(client) = prepare_client() else {
        return false;
    };
    let Some(identity) = login_and_read_identity(&client, true) else {
        return false;
    };
    step(3, "Cloudflare hesabi seciliyor...");
    let Some(account) = select_account(&identity, &config.account_id) else {
        step_failed();
        return false;
    };
    config.account_id = account;
    step_ok(&format!("{}...", &config.account_id[..8]));

    if config.worker_name.is_empty() {
        config.worker_name = "splithello-relay".into();
    }
    if !wrangler::is_valid_worker_name(&config.worker_name) {
        eprintln!("Gecersiz Worker adi: {}", config.worker_name);
        return false;
    }
    // Pre-OAuth API tokens are migration-only: never passed on or written back.
    config.api_token.clear();
    config.shared_secret = sh_core::secure::random_hex(SHARED_SECRET_BYTES);
    if !deploy_and_verify(config, dir, &client) {
        return false;
    }
    println!(
        "\nKurulum tamamlandi.\n  Worker  {}\n  Ayarlar {}\n",
        config.worker_url,
        Config::path_in(dir).display()
    );
    true
}

pub fn redeploy(config: &mut Config, dir: &Path) -> bool {
    let Some(client) = prepare_client() else {
        return false;
    };
    let Some(identity) = login_and_read_identity(&client, false) else {
        return false;
    };
    let Some(account) = select_account(&identity, &config.account_id) else {
        return false;
    };
    config.account_id = account;
    if !wrangler::is_valid_worker_name(&config.worker_name) {
        eprintln!("Gecersiz Worker adi: {}", config.worker_name);
        return false;
    }
    config.api_token.clear();
    config.shared_secret = sh_core::secure::random_hex(SHARED_SECRET_BYTES);
    if config.shared_secret.is_empty() {
        eprintln!("Rastgele anahtar uretilemedi.");
        return false;
    }
    if !deploy_and_verify(config, dir, &client) {
        return false;
    }
    println!("\nYeniden yukleme tamamlandi. Yeni gizli anahtar kaydedildi.");
    true
}

/// Waits for Enter (the tray-launched setup console closes on exit).
pub fn wait_for_enter() {
    print!("\nKapatmak icin Enter'a basin...");
    let _ = std::io::stdout().flush();
    let _ = read_line();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embeds_the_worker_and_prefers_the_saved_account() {
        assert!(WORKER_SOURCE.contains("SHARED_SECRET"));
        let identity = Identity {
            email: String::new(),
            accounts: vec![
                wrangler::Account {
                    id: "a".repeat(32),
                    name: "A".into(),
                },
                wrangler::Account {
                    id: "b".repeat(32),
                    name: "B".into(),
                },
            ],
        };
        assert_eq!(
            select_account(&identity, &"b".repeat(32)),
            Some("b".repeat(32))
        );
    }
}
