//! Manual-proxy engine: SOCKS5 / HTTP CONNECT on 127.0.0.1, no WinDivert, no
//! elevation. Runs until Ctrl+C. Packet-level profiles are skipped (there is
//! no packet loop to apply them), exactly as in the C++ manual mode.

use std::sync::Arc;
use std::time::Duration;

use sh_core::config::{Config, DnsMode};
use sh_net::http::HttpClient;
use sh_relay::{Listener, ListenerMode, RelayContext};
use tokio::sync::watch;

use crate::adblock_updater::{self, Route, UpdaterFiles};
use crate::options::Options;

pub fn run(options: &Options) -> i32 {
    let Some(dir) = crate::config_dir() else {
        eprintln!("APPDATA yolu belirlenemedi");
        return 1;
    };
    sh_core::logging::init(options.verbose, Some(&dir.join(sh_core::paths::LOG_FILE)));

    let mut config = Config::default();
    config.load_from(&dir);
    if config.load_failed {
        tracing::error!(
            "Yapilandirma dosyasi var ama okunamadi: {}",
            Config::path_in(&dir).display()
        );
        return 16;
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            tracing::error!("Calisma ortami kurulamadi: {error}");
            return 1;
        }
    };
    runtime.block_on(serve(options, config, dir))
}

async fn serve(options: &Options, config: Config, dir: std::path::PathBuf) -> i32 {
    let worker_url = if options.worker_url.is_empty() {
        config.worker_url.clone()
    } else {
        options.worker_url.clone()
    };
    let use_worker_dns = config.dns_mode == DnsMode::Worker && !worker_url.is_empty();
    let http = Arc::new(HttpClient::default());
    // Manual mode: no packet loop, so the engine's own HTTPS dials 443 directly.
    let resolver = use_worker_dns.then(|| {
        Arc::new(sh_dns::Resolver::new(
            &worker_url,
            config.shared_secret.clone(),
            0,
            http.clone(),
            None,
        ))
    });

    let strategies = Arc::new(sh_strategy::Store::new(
        dir.join(sh_core::paths::STRATEGY_FILE),
    ));
    strategies.load();
    let telemetry = Arc::new(sh_telemetry::Store::new(
        dir.join(sh_core::paths::TELEMETRY_FILE),
    ));
    if !telemetry.start() {
        tracing::warn!("Yerel telemetri baslatilamadi; ag motoru istatistiksiz devam ediyor");
    }

    let tunnel =
        (use_worker_dns && (config.tunnel_fallback || options.tunnel_fallback)).then(|| {
            sh_relay::TunnelSettings {
                worker_host: sh_net::http::host_from_url(&worker_url),
                shared_secret: config.shared_secret.clone(),
                connect_port: 443,
            }
        });
    let context = Arc::new(RelayContext {
        resolver: resolver.clone(),
        strategies: strategies.clone(),
        packet_policies: None,
        telemetry: Some(telemetry.clone()),
        live_stats: None,
        network_id: Arc::new(sh_core::network_identity::current_cached),
        split_delay_ms: options.split_delay_ms.unwrap_or(config.split_delay_ms),
        probe_timeout: Duration::from_millis(u64::from(config.probe_timeout_ms)),
        tunnel,
        idle_timeout: Duration::from_secs(10 * 60),
        handshake_timeout: Duration::from_secs(10),
        forced_profile: options.forced_strategy.clone(),
    });

    let listener = match Listener::bind(options.port, ListenerMode::Manual, context) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("Port {} bind hatasi: {error}", options.port);
            return 10;
        }
    };
    tracing::info!(
        "SplitHello (Rust) manuel proxy modunda: 127.0.0.1:{} (SOCKS5 + HTTP CONNECT)",
        listener.local_port()
    );
    tracing::info!(
        "DNS modu: {}",
        if use_worker_dns {
            "Worker"
        } else {
            "sistem (Worker yok)"
        }
    );
    tracing::warn!("Manuel proxy modu: yalniz SOCKS5/HTTP CONNECT kullanan uygulamalar yakalanir");

    let (stop, shutdown) = watch::channel(false);
    let updater = config.ad_block.then(|| {
        tokio::spawn(adblock_updater::run(
            UpdaterFiles {
                cache_dir: dir.clone(),
                allow_file: dir.join("adblock-allow.txt"),
                recent_file: dir.join("adblock-recent.txt"),
            },
            config.ad_block_lists.clone(),
            config.ad_block_allow.clone(),
            Route {
                http: http.clone(),
                resolver: resolver.clone(),
                connect_port: 0,
            },
            shutdown.clone(),
        ))
    });
    let server = tokio::spawn(listener.clone().run(shutdown));

    let _ = tokio::signal::ctrl_c().await;
    tracing::info!("Durduruluyor...");
    let _ = stop.send(true);
    let _ = server.await;
    if let Some(updater) = updater {
        let _ = updater.await;
    }
    telemetry.stop();
    0
}
