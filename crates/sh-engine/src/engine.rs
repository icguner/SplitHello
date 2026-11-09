//! Engine run (port of the run path of `main`, `src/main.cpp`).
//!
//! Transparent mode (default): relay listener, then the DNS proxy, then
//! WinDivert; the ready event is set only after all three are up. Stopping
//! closes interception first, so a failing piece always fails open. Manual
//! mode: SOCKS5 / HTTP CONNECT on 127.0.0.1, no WinDivert, no elevation.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use sh_core::config::{Config, DnsMode};
use sh_divert::{Interceptor, Registries, Settings};
use sh_flow::{DatagramRegistry, FlowRegistry, PolicyRegistry};
use sh_net::http::HttpClient;
use sh_relay::{Listener, ListenerMode, RelayContext};
use tokio::sync::watch;

use crate::adblock_updater::{self, Route, UpdaterFiles};
use crate::options::{Options, QuicMode};
use crate::win;

pub const EXIT_FAIL_OPEN: i32 = 2;
pub const EXIT_RELAY_PORT_IN_USE: i32 = 10;
pub const EXIT_DNS_PORT_IN_USE: i32 = 11;
pub const EXIT_WINDIVERT_OPEN_FAILED: i32 = 12;
pub const EXIT_INVALID_PROCESS_RULES: i32 = 13;
pub const EXIT_SETUP_REQUIRED: i32 = 14;
pub const EXIT_MONITOR_UNAVAILABLE: i32 = 15;
pub const EXIT_CONFIG_UNREADABLE: i32 = 16;

const PREFERRED_CONNECT_PORT: u16 = 65534;
const ALTERNATE_CONNECT_PORT: u16 = 65533;

pub fn run(options: &Options) -> i32 {
    let Some(dir) = crate::config_dir() else {
        eprintln!("APPDATA yolu belirlenemedi");
        return 1;
    };
    win::install_console_handler();
    sh_core::logging::init(options.verbose, Some(&dir.join(sh_core::paths::LOG_FILE)));

    let transparent = !options.manual_proxy;
    if transparent && !win::is_elevated() {
        tracing::info!("WinDivert icin yonetici izni isteniyor");
        return win::relaunch_elevated(true).unwrap_or_else(|| {
            tracing::error!("Yonetici olarak yeniden baslatma reddedildi veya basarisiz oldu");
            1
        });
    }

    // The hidden engine must always be stoppable by its tray. If neither the
    // shutdown event nor the parent process could be opened, running on would
    // leave interception nobody can turn off: exit (fail-open).
    let monitor = win::ShutdownMonitor::start(&options.shutdown_event, options.parent_pid);
    let monitor_requested =
        options.engine || !options.shutdown_event.is_empty() || options.parent_pid != 0;
    if monitor_requested && monitor.is_none() {
        tracing::error!("Tray kapatma kanali acilamadi; denetimsiz calismamak icin cikiliyor");
        return EXIT_MONITOR_UNAVAILABLE;
    }

    let mut config = Config::default();
    config.load_from(&dir);
    if config.load_failed {
        // Defaults would be saved over the real file later.
        tracing::error!(
            "Yapilandirma dosyasi var ama okunamadi: {}",
            Config::path_in(&dir).display()
        );
        eprintln!(
            "Yapilandirma okunamadi: {}",
            Config::path_in(&dir).display()
        );
        return EXIT_CONFIG_UNREADABLE;
    }
    // Cloudflare OAuth lives in Wrangler's keyring now: rewrite old configs
    // once to drop legacy API-token fields while keeping the Worker secret.
    if config.migrated_from_plaintext || config.legacy_api_token_present {
        config.api_token.clear();
        if let Err(error) = config.save_to(&dir) {
            tracing::warn!("Yapilandirma tasinamadi: {error}");
        }
    }

    if options.action == crate::options::Action::Setup && !sh_setup::run_setup(&mut config, &dir) {
        return 1;
    }
    if options.worker_url.is_empty()
        && config.worker_url.is_empty()
        && config.dns_mode == DnsMode::Worker
    {
        if options.engine {
            // The hidden engine has no console; never block it on setup.
            tracing::error!("Worker yapilandirmasi yok; once splithello.exe --setup calistirin");
            return EXIT_SETUP_REQUIRED;
        }
        println!("Yapilandirma bulunamadi. Setup baslatiliyor...");
        if !sh_setup::run_setup(&mut config, &dir) {
            return 1;
        }
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
    let code = runtime.block_on(serve(options, config, dir));
    drop(monitor);
    tracing::info!("SplitHello durduruldu");
    code
}

/// Binds the first usable candidate. Windows reserves port ranges (Hyper-V,
/// WSL, Docker) that change between boots; binding inside one fails with
/// WSAEACCES, so internal ports step aside instead of failing.
fn first_bound<T>(
    candidates: &[u16],
    mut bind: impl FnMut(u16) -> std::io::Result<T>,
) -> Option<(u16, T)> {
    candidates
        .iter()
        .find_map(|&port| bind(port).ok().map(|bound| (port, bound)))
}

async fn wait_until(mut ready: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if ready() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    ready()
}

async fn serve(options: &Options, mut config: Config, dir: PathBuf) -> i32 {
    let transparent = !options.manual_proxy;
    let worker_url = if options.worker_url.is_empty() {
        config.worker_url.clone()
    } else {
        options.worker_url.clone()
    };
    let use_worker_dns = config.dns_mode == DnsMode::Worker;
    if worker_url.is_empty() && use_worker_dns {
        tracing::error!("Worker yapilandirmasi yok; once splithello.exe --setup calistirin");
        return EXIT_SETUP_REQUIRED;
    }
    if use_worker_dns && config.shared_secret.is_empty() {
        tracing::warn!(
            "Worker gizli anahtari yok. Worker istekleri guvenli bicimde reddeder; kullanmak icin '--redeploy' calistirin."
        );
    }
    if let Some(delay) = options.split_delay_ms {
        config.split_delay_ms = delay;
    }
    config.tunnel_fallback |= options.tunnel_fallback;

    // An include list that is present but entirely unusable must not turn into
    // "no include rules" (= intercept every process).
    if config.process_include_invalid {
        tracing::error!(
            "process_include dolu ama tum girdiler gecersiz; kapsam genisletilmeyecek, ag motoru baslatilmiyor"
        );
        eprintln!(
            "process_include gecersiz: duzeltin veya bosaltin ({})",
            Config::path_in(&dir).display()
        );
        return EXIT_INVALID_PROCESS_RULES;
    }
    // shortcut: CLI rules are merged for this run only and not shown in the panel.
    config
        .process_include
        .extend(options.process_include.iter().cloned());
    config
        .process_exclude
        .extend(options.process_exclude.iter().cloned());

    // shortcut: proxy settings left in Internet Options by pre-WinDivert
    // builds are not restored here; the C++ build's --restore-proxy does it.
    if dir.join("proxy-backup.json").exists() {
        tracing::warn!(
            "Eski surumden proxy yedegi var; geri yuklemek icin C++ surumuyle --restore-proxy calistirin"
        );
    }

    let flows = Arc::new(FlowRegistry::default());
    let datagrams = Arc::new(DatagramRegistry::default());
    let policies = Arc::new(PolicyRegistry::default());
    let rules = sh_divert::rules::Rules::new(&config.process_include, &config.process_exclude);
    let process_filter = Arc::new(sh_divert::process::Filter::new(rules));

    let candidates: Vec<u16> = if transparent && !options.port_explicit {
        vec![options.port, 18080, 28080, 38080, 48080]
    } else {
        vec![options.port]
    };
    // The listener needs the context, and the context the connect port, which
    // depends on the relay port: pick the connect port per candidate.
    let connect_port_for = |port: u16| {
        if port == PREFERRED_CONNECT_PORT {
            ALTERNATE_CONNECT_PORT
        } else {
            PREFERRED_CONNECT_PORT
        }
    };

    let http = Arc::new(HttpClient::default());
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
    let live_stats = (!options.live_stats.is_empty())
        .then(|| sh_core::live_stats::Publisher::new(&options.live_stats))
        .flatten();
    if !options.live_stats.is_empty() && live_stats.is_none() {
        tracing::warn!("Canli tray istatistik kanali acilamadi");
    }
    if !options.forced_strategy.is_empty() {
        tracing::info!(
            "Profil zorlandi: '{}' (otomatik secim devre disi)",
            options.forced_strategy
        );
    }

    let mut resolver = None;
    let bound = first_bound(&candidates, |port| {
        let connect_port = if transparent {
            connect_port_for(port)
        } else {
            0
        };
        let port_resolver = use_worker_dns.then(|| {
            Arc::new(sh_dns::Resolver::new(
                &worker_url,
                config.shared_secret.clone(),
                connect_port,
                http.clone(),
                None,
            ))
        });
        let context = Arc::new(RelayContext {
            resolver: port_resolver.clone(),
            strategies: strategies.clone(),
            packet_policies: transparent.then(|| policies.clone()),
            telemetry: Some(telemetry.clone()),
            live_stats: live_stats.clone(),
            // The network can change while the engine runs (Wi-Fi roaming,
            // VPN): the relay asks per decision instead of using the start value.
            network_id: Arc::new(sh_core::network_identity::current_cached),
            split_delay_ms: config.split_delay_ms,
            probe_timeout: Duration::from_millis(u64::from(config.probe_timeout_ms)),
            tunnel: (use_worker_dns && config.tunnel_fallback).then(|| sh_relay::TunnelSettings {
                worker_host: sh_net::http::host_from_url(&worker_url),
                shared_secret: config.shared_secret.clone(),
                connect_port: if transparent { connect_port } else { 443 },
            }),
            idle_timeout: Duration::from_secs(10 * 60),
            handshake_timeout: Duration::from_secs(10),
            forced_profile: options.forced_strategy.clone(),
        });
        let mode = if transparent {
            ListenerMode::Transparent(flows.clone())
        } else {
            ListenerMode::Manual
        };
        let listener = Listener::bind(port, mode, context)?;
        resolver = port_resolver;
        Ok(listener)
    });
    let Some((port, listener)) = bound else {
        tracing::error!(
            "Relay portu acilamadi (port {} kullanimda olabilir)",
            options.port
        );
        telemetry.stop();
        return EXIT_RELAY_PORT_IN_USE;
    };
    if port != options.port {
        tracing::warn!(
            "Port {} kullanilamiyor (Windows ayirmis olabilir); {port} kullaniliyor",
            options.port
        );
    }
    let connect_port = connect_port_for(port);

    tracing::info!("SplitHello baslatiliyor");
    tracing::info!(
        "DNS modu: {}",
        if use_worker_dns {
            "Worker"
        } else {
            "sistem (Worker yok)"
        }
    );
    if use_worker_dns {
        tracing::info!("Worker: {worker_url}");
    }
    tracing::info!(
        "Ag profili: {}",
        sh_core::network_identity::current_cached()
    );
    tracing::info!(
        "Relay portu: {port} | split-delay: {} ms | ogrenilen alan adi: {}",
        config.split_delay_ms,
        strategies.len()
    );
    if process_filter.enabled() {
        tracing::info!(
            "Surec filtresi: {} include, {} exclude kurali",
            process_filter.rules().include_count(),
            process_filter.rules().exclude_count()
        );
    }

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
            // The updater's own HTTPS dials the connect port, so the packet
            // loop does not reflect it back into this engine.
            Route {
                http: http.clone(),
                resolver: resolver.clone(),
                connect_port: if transparent { connect_port } else { 0 },
            },
            shutdown.clone(),
        ))
    });
    let relay = tokio::spawn(listener.clone().run(shutdown.clone()));
    let running = Running {
        stop,
        relay,
        updater,
        telemetry,
    };

    if !transparent {
        tracing::info!(
            "SplitHello (Rust) manuel proxy modunda: 127.0.0.1:{port} (SOCKS5 + HTTP CONNECT)"
        );
        tracing::warn!(
            "Manuel proxy modu: yalniz SOCKS5/HTTP CONNECT kullanan uygulamalar yakalanir"
        );
        while !win::shutdown_requested() && !running.relay.is_finished() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        tracing::info!("Durduruluyor...");
        return running.finish(0).await;
    }

    // WinDivert must never reflect into a listener that has not started.
    if !wait_until(|| listener.running() || running.relay.is_finished()).await
        || !listener.running()
    {
        tracing::error!("Transparent relay baslatilamadi (port {port} kullanimda olabilir)");
        return running.finish(EXIT_RELAY_PORT_IN_USE).await;
    }

    let mut dns_proxy = None;
    let mut dns_port = 1053;
    if let Some(resolver) = resolver.as_ref().filter(|_| use_worker_dns) {
        let dns_candidates: Vec<u16> = [1053, 1054, 15353, 25353, 35353]
            .into_iter()
            .filter(|&candidate| candidate != port)
            .collect();
        let Some((bound_port, socket)) = first_bound(&dns_candidates, sh_dns::DnsProxy::bind)
        else {
            tracing::error!("Transparent DNS relay baslatilamadi (port 1053 kullanimda olabilir)");
            return running.finish(EXIT_DNS_PORT_IN_USE).await;
        };
        dns_port = bound_port;
        let proxy = sh_dns::DnsProxy::new(resolver.clone(), datagrams.clone());
        let task = tokio::spawn(proxy.clone().run(socket, shutdown.clone()));
        if !wait_until(|| proxy.running()).await {
            tracing::error!("Transparent DNS relay baslatilamadi (port {dns_port})");
            return running.finish(EXIT_DNS_PORT_IN_USE).await;
        }
        dns_proxy = Some((proxy, task));
    }

    let settings = Settings {
        proxy_port: port,
        dns_proxy_port: dns_port,
        connect_port,
        quic_mode: match options.quic_mode {
            QuicMode::Allow => sh_divert::QuicMode::Allow,
            QuicMode::Adaptive => sh_divert::QuicMode::Adaptive,
            QuicMode::Block => sh_divert::QuicMode::Block,
        },
        capture_dns: use_worker_dns,
    };
    let registries = Registries {
        flows: flows.clone(),
        datagrams: datagrams.clone(),
        policies: policies.clone(),
        process_filter: Some(process_filter.clone()),
    };
    let interceptor = match Interceptor::start(settings, registries) {
        Ok(interceptor) => interceptor,
        Err(error) => {
            tracing::error!("{error}");
            return running.finish(EXIT_WINDIVERT_OPEN_FAILED).await;
        }
    };
    win::signal_ready_event(&options.ready_event);

    // Observe the packet loop, the relay and the DNS reader: any failure
    // releases interception.
    let dns_healthy = || {
        dns_proxy.as_ref().is_none_or(|(proxy, _)| proxy.running())
            && resolver.as_ref().is_none_or(|r| !r.worker_unavailable())
    };
    while !win::shutdown_requested()
        && !running.relay.is_finished()
        && interceptor.running()
        && dns_healthy()
    {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let requested = win::shutdown_requested();
    let fatal = interceptor.fatal_error_code();
    let code = if !requested && resolver.as_ref().is_some_and(|r| r.worker_unavailable()) {
        tracing::error!(
            "Worker erisilemiyor; trafik yakalama kapatiliyor. Tray otomatik yeniden baslatmayacak"
        );
        sh_core::recovery::WORKER_UNAVAILABLE_EXIT_CODE
    } else if !requested && !dns_healthy() {
        tracing::error!("DNS alicisi durdu; trafik yakalama kapatiliyor");
        EXIT_FAIL_OPEN
    } else if fatal != 0 {
        tracing::error!(
            "Ag motoru fail-open ile kapandi: WinDivert hata={fatal}; tray yeniden baslatabilir"
        );
        EXIT_FAIL_OPEN
    } else if running.relay.is_finished() && interceptor.running() {
        tracing::error!(
            "Transparent relay beklenmedik sekilde durdu; WinDivert fail-open kapatiliyor"
        );
        EXIT_FAIL_OPEN
    } else {
        0
    };

    // Interception goes first, so nothing is reflected into a closing listener.
    tokio::task::block_in_place(|| interceptor.stop());
    drop(interceptor);
    let code = running.finish(code).await;
    if let Some((_, task)) = dns_proxy {
        let _ = task.await;
    }
    code
}

/// What every exit path must stop and await.
struct Running {
    stop: watch::Sender<bool>,
    relay: tokio::task::JoinHandle<()>,
    updater: Option<tokio::task::JoinHandle<()>>,
    telemetry: Arc<sh_telemetry::Store>,
}

impl Running {
    async fn finish(self, code: i32) -> i32 {
        let _ = self.stop.send(true);
        let _ = self.relay.await;
        if let Some(updater) = self.updater {
            let _ = updater.await;
        }
        self.telemetry.stop();
        code
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_bound_skips_unusable_ports() {
        let taken = std::net::TcpListener::bind("0.0.0.0:0").unwrap();
        let busy = taken.local_addr().unwrap().port();
        let (port, _listener) = first_bound(&[busy, 0], |p| {
            let socket = std::net::TcpListener::bind(("0.0.0.0", p))?;
            Ok(socket)
        })
        .unwrap();
        assert_eq!(port, 0);
    }
}
