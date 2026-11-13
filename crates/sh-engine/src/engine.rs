//! Engine run (port of the run path of `main`, `src/main.cpp`).
//!
//! The DNS proxy (encrypted DNS mode) starts first, then WinDivert; the ready
//! event is set only after both are up. Stopping closes interception first,
//! so a failing piece always fails open.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sh_core::config::{Config, DnsMode};
use sh_divert::{Interceptor, Registries, Settings};
use sh_flow::{DatagramRegistry, HopRegistry};
use sh_net::http::HttpClient;
use tokio::sync::watch;

use crate::adblock_updater::{self, Route, UpdaterFiles};
use crate::options::{Options, QuicMode};
use crate::win;

pub const EXIT_FAIL_OPEN: i32 = 2;
pub const EXIT_DNS_PORT_IN_USE: i32 = 11;
pub const EXIT_WINDIVERT_OPEN_FAILED: i32 = 12;
pub const EXIT_INVALID_PROCESS_RULES: i32 = 13;
pub const EXIT_MONITOR_UNAVAILABLE: i32 = 15;
pub const EXIT_CONFIG_UNREADABLE: i32 = 16;
const HEALTH_REPORT_INTERVAL: Duration = Duration::from_secs(60);
const PROBE_FIRST: Duration = Duration::from_secs(15);
const PROBE_MAX: Duration = Duration::from_secs(300);
const HTTPS_PORT: u16 = 443;

pub fn run(options: &Options) -> i32 {
    let Some(dir) = crate::config_dir() else {
        eprintln!("APPDATA yolu belirlenemedi");
        return 1;
    };
    win::install_console_handler();
    sh_core::logging::init(options.verbose, Some(&dir.join(sh_core::paths::LOG_FILE)));

    if !win::is_elevated() {
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

    // A desktop relay is I/O-bound: a few workers carry a thousand
    // connections, and a bounded blocking pool keeps a burst of system DNS
    // lookups (Worker down) from spawning hundreds of threads.
    let workers = std::thread::available_parallelism().map_or(2, |n| n.get().clamp(2, 4));
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(workers)
        .max_blocking_threads(32)
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
    let worker_url = if options.worker_url.is_empty() {
        config.worker_url.clone()
    } else {
        options.worker_url.clone()
    };
    // Encrypted DNS: public DoH resolvers first, the Worker (optional) last.
    let use_worker_dns = config.dns_mode == DnsMode::Worker;
    if use_worker_dns && !worker_url.is_empty() && config.shared_secret.is_empty() {
        tracing::warn!(
            "Worker gizli anahtari yok. Worker istekleri guvenli bicimde reddeder; kullanmak icin '--redeploy' calistirin."
        );
    }

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

    // `--strategy` fixes one profile for every site and turns learning off.
    let forced = if options.forced_strategy.is_empty() {
        None
    } else {
        let Some(mode) = sh_proto::packet::mode_for_profile(&options.forced_strategy) else {
            tracing::error!("Bilinmeyen paket profili: {}", options.forced_strategy);
            return 1;
        };
        Some(mode)
    };
    let learner = Arc::new(sh_strategy::Learner::new(
        dir.join(sh_core::paths::STRATEGY_FILE),
    ));
    learner.load();

    let datagrams = Arc::new(DatagramRegistry::default());
    let rules = sh_divert::rules::Rules::new(&config.process_include, &config.process_exclude);
    let process_filter = Arc::new(sh_divert::process::Filter::new(rules));
    let http = Arc::new(HttpClient::default());
    // The engine's own HTTPS (Worker, list updates) dials addresses it
    // resolved itself: asking the system resolver would loop back into the
    // DNS proxy. Its ClientHello leaves through the packet loop like any other.
    let resolver = use_worker_dns.then(|| {
        Arc::new(sh_dns::Resolver::new(
            &worker_url,
            config.shared_secret.clone(),
            HTTPS_PORT,
            http.clone(),
            sh_core::config::dns_provider_index(&config.dns_provider),
            None,
        ))
    });

    tracing::info!("SplitHello baslatiliyor");
    tracing::info!(
        "DNS modu: {}",
        resolver.as_ref().map_or("sistem".into(), |r| format!(
            "sifreli ({})",
            r.upstream_names().join(", ")
        ))
    );
    if use_worker_dns && !worker_url.is_empty() {
        tracing::info!("Worker: {worker_url}");
    }
    tracing::info!(
        "Ag profili: {} | {}",
        sh_core::network_identity::current_cached(),
        if forced.is_some() {
            format!("sabit profil: {}", options.forced_strategy)
        } else {
            format!("ogrenilen site: {}", learner.len())
        }
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
            Route {
                http: http.clone(),
                resolver: resolver.clone(),
                connect_port: HTTPS_PORT,
            },
            shutdown.clone(),
        ))
    });
    let running = Running { stop, updater };

    let mut dns_proxy = None;
    let mut dns_port = 1053;
    if let Some(resolver) = &resolver {
        let Some((bound_port, socket)) =
            first_bound(&[1053, 1054, 15353, 25353, 35353], sh_dns::DnsProxy::bind)
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
        forced,
        dns_proxy_port: dns_port,
        quic_mode: match options.quic_mode {
            QuicMode::Allow => sh_divert::QuicMode::Allow,
            QuicMode::Adaptive => sh_divert::QuicMode::Adaptive,
            QuicMode::Block => sh_divert::QuicMode::Block,
        },
        capture_dns: use_worker_dns,
        filter_dns: config.ad_block && !use_worker_dns,
    };
    let registries = Registries {
        datagrams,
        hops: Arc::new(HopRegistry::default()),
        learner: learner.clone(),
        // The network can change while the engine runs (Wi-Fi roaming, VPN).
        network: Arc::new(sh_core::network_identity::current_cached),
        process_filter: Some(process_filter),
    };
    let interceptor = match Interceptor::start(settings, registries) {
        Ok(interceptor) => interceptor,
        Err(error) => {
            tracing::error!("{error}");
            return running.finish(EXIT_WINDIVERT_OPEN_FAILED).await;
        }
    };
    win::signal_ready_event(&options.ready_event);

    // Observe the packet loop and the DNS reader: any failure releases
    // interception.
    let dns_healthy = || dns_proxy.as_ref().is_none_or(|(proxy, _)| proxy.running());
    let mut reported = interceptor.hello_counts();
    let mut next_report = Instant::now() + HEALTH_REPORT_INTERVAL;
    // While encrypted DNS is out: (next probe, the wait that led to it).
    let mut probe: Option<(Instant, Duration)> = None;
    while !win::shutdown_requested() && interceptor.running() && dns_healthy() {
        tokio::time::sleep(Duration::from_millis(50)).await;
        learner.save_if_dirty();
        // An outage of every encrypted upstream must not take name resolution
        // down with it, and must not end protection for good either: queries
        // go to the system's resolver until one answers a probe.
        if let Some(resolver) = &resolver {
            match probe {
                None if resolver.worker_unavailable() => {
                    tracing::error!(
                        "Sifreli DNS sunuculari erisilemiyor; DNS sistem cozucusune birakildi, yanit verince geri alinacak"
                    );
                    interceptor.set_dns_bypass(true);
                    probe = Some((Instant::now() + PROBE_FIRST, PROBE_FIRST));
                }
                Some((at, wait)) if Instant::now() >= at => {
                    if resolver.probe().await {
                        tracing::info!(
                            "Sifreli DNS sunuculari yeniden erisilebilir; DNS korumasi geri acildi"
                        );
                        interceptor.set_dns_bypass(false);
                        probe = None;
                    } else {
                        let wait = (wait * 2).min(PROBE_MAX);
                        probe = Some((Instant::now() + wait, wait));
                    }
                }
                _ => {}
            }
        }
        if Instant::now() >= next_report {
            next_report = Instant::now() + HEALTH_REPORT_INTERVAL;
            let current = interceptor.hello_counts();
            let (seen, transformed) = (current.0 - reported.0, current.1 - reported.1);
            reported = current;
            // Quiet minutes stay out of the log.
            if seen != 0 {
                tracing::info!(
                    "Saglik (60 sn): ClientHello gorulen={seen} degistirilen={transformed}"
                );
            }
        }
    }

    let requested = win::shutdown_requested();
    let fatal = interceptor.fatal_error_code();
    let code = if !requested && !dns_healthy() {
        tracing::error!("DNS alicisi durdu; trafik yakalama kapatiliyor");
        EXIT_FAIL_OPEN
    } else if fatal != 0 {
        tracing::error!(
            "Ag motoru fail-open ile kapandi: WinDivert hata={fatal}; tray yeniden baslatabilir"
        );
        EXIT_FAIL_OPEN
    } else {
        0
    };

    tokio::task::block_in_place(|| interceptor.stop());
    drop(interceptor);
    learner.save_if_dirty();
    let code = running.finish(code).await;
    if let Some((_, task)) = dns_proxy {
        let _ = task.await;
    }
    code
}

/// What every exit path must stop and await.
struct Running {
    stop: watch::Sender<bool>,
    updater: Option<tokio::task::JoinHandle<()>>,
}

impl Running {
    async fn finish(self, code: i32) -> i32 {
        let _ = self.stop.send(true);
        if let Some(updater) = self.updater {
            let _ = updater.await;
        }
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
