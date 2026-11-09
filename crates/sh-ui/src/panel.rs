//! The panel (successor of `DashboardPanel`): an egui window in its own
//! process, opened by the tray with `--panel --live-stats <name>`. It reads
//! the engine's live-stats mapping, the telemetry database and the files in
//! the config folder; settings it saves are applied by asking the tray to
//! restart the engine. The look lives in `theme`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use sh_core::config::{Config, DnsMode};
use sh_core::live_stats::Snapshot;
use sh_telemetry::DashboardData;

use crate::theme::{self, icon, palette};

/// Ad-blocking strengths, weakest first: HaGeZi list names in
/// `ad_block_lists` (see `sh_adblock::list_path`) and what the panel shows.
const STRENGTHS: [(&str, &str, &str); 4] = [
    (
        "light",
        "Hafif",
        "89 bin alan adı; neredeyse hiç yanlış engel yok.",
    ),
    (
        "multi",
        "Normal",
        "207 bin alan adı; günlük kullanım için dengeli.",
    ),
    ("pro", "Pro", "224 bin alan adı; önerilen."),
    (
        "pro.plus",
        "Pro++",
        "241 bin alan adı; en sıkı, nadiren bir siteyi bozabilir.",
    ),
];
const TRACKING: &str = "native.winoffice";
const ANNOYANCES: &str = "popupads";
const DOH: &str = "doh";
const SECURITY: [&str; 2] = ["tif", "fake"];
const GAMBLING: &str = "gambling";
const ADULT: &str = "nsfw";
const TELEMETRY_DAYS: u32 = 7;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

pub fn run(live_stats_name: &str) -> i32 {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SplitHello")
            .with_inner_size(theme::WINDOW_SIZE)
            .with_min_inner_size([900.0, 600.0]),
        ..Default::default()
    };
    let name = live_stats_name.to_string();
    let result = eframe::run_native(
        "SplitHello",
        options,
        Box::new(move |cc| {
            theme::install(&cc.egui_ctx);
            Ok(Box::new(Panel::new(name)))
        }),
    );
    match result {
        Ok(()) => 0,
        Err(error) => {
            tracing::error!("Panel acilamadi: {error}");
            1
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Status,
    Protection,
    Connection,
    Processes,
    Diagnostics,
    Log,
}

/// What the panel edits in config.json; compared with the saved copy to show
/// the save bar only when something changed. Protection features map onto
/// `ad_block_lists` names; names the panel does not know are kept as they are.
#[derive(Clone, PartialEq, Eq, Default)]
struct Settings {
    ads: bool,
    strength: usize, // index into STRENGTHS
    tracking: bool,
    annoyances: bool,
    doh: bool,
    security: bool,
    gambling: bool,
    adult: bool,
    other_lists: Vec<String>,
    dns_worker: bool,
    tunnel_fallback: bool,
    allow: Vec<String>,
    include: Vec<String>,
    exclude: Vec<String>,
}

impl Settings {
    fn from_config(config: &Config) -> Self {
        // With blocking off every feature shows off, whatever the lists say.
        let has = |name: &str| config.ad_block && config.ad_block_lists.iter().any(|l| l == name);
        let strongest = STRENGTHS.iter().rposition(|(name, _, _)| has(name));
        let managed: Vec<&str> = STRENGTHS
            .iter()
            .map(|(name, _, _)| *name)
            .chain([TRACKING, ANNOYANCES, DOH, GAMBLING, ADULT])
            .chain(SECURITY)
            .collect();
        Self {
            ads: strongest.is_some(),
            strength: strongest.unwrap_or(2),
            tracking: has(TRACKING),
            annoyances: has(ANNOYANCES),
            doh: has(DOH),
            security: SECURITY.iter().any(|name| has(name)),
            gambling: has(GAMBLING),
            adult: has(ADULT),
            other_lists: config
                .ad_block_lists
                .iter()
                .filter(|l| !managed.contains(&l.as_str()))
                .cloned()
                .collect(),
            dns_worker: config.dns_mode == DnsMode::Worker,
            tunnel_fallback: config.tunnel_fallback,
            allow: config.ad_block_allow.clone(),
            include: config.process_include.clone(),
            exclude: config.process_exclude.clone(),
        }
    }

    fn lists(&self) -> Vec<String> {
        let mut lists: Vec<&str> = Vec::new();
        if self.ads {
            lists.push(STRENGTHS[self.strength].0);
        }
        for (on, names) in [
            (self.tracking, &[TRACKING][..]),
            (self.annoyances, &[ANNOYANCES][..]),
            (self.doh, &[DOH][..]),
            (self.security, &SECURITY[..]),
            (self.gambling, &[GAMBLING][..]),
            (self.adult, &[ADULT][..]),
        ] {
            if on {
                lists.extend(names);
            }
        }
        lists
            .into_iter()
            .map(String::from)
            .chain(self.other_lists.iter().cloned())
            .collect()
    }

    fn apply(&self, config: &mut Config) {
        let lists = self.lists();
        config.ad_block = lists.len() > self.other_lists.len();
        if config.ad_block {
            config.ad_block_lists = lists;
        }
        config.dns_mode = if self.dns_worker {
            DnsMode::Worker
        } else {
            DnsMode::System
        };
        config.tunnel_fallback = self.tunnel_fallback;
        config.ad_block_allow = self.allow.clone();
        config.process_include = self.include.clone();
        config.process_exclude = self.exclude.clone();
    }
}

struct Panel {
    /// The setup console this panel started, and whether to switch DNS to
    /// the Worker once it succeeds.
    setup: Option<(std::process::Child, bool)>,
    worker_url: String,
    worker_name: String,
    learned_sites: Option<usize>,
    page: Page,
    dir: Option<PathBuf>,
    live_name: String,
    profile_names: Vec<&'static str>,
    live: Snapshot,
    live_at: Option<Instant>,
    settings: Settings,
    saved: Settings,
    // Add-field contents, kept out of Settings so typing is not "unsaved".
    allow_draft: String,
    include_draft: String,
    exclude_draft: String,
    status: Option<(String, bool)>, // (message, success)
    recent: Vec<(String, String)>,
    total_blocked: String,
    files_at: Option<Instant>,
    telemetry: Arc<Mutex<Option<DashboardData>>>,
    telemetry_loading: Arc<Mutex<bool>>,
    search: String,
    log: String,
}

impl Panel {
    fn new(live_name: String) -> Self {
        let mut panel = Self {
            setup: None,
            worker_url: String::new(),
            worker_name: String::new(),
            learned_sites: None,
            page: Page::Status,
            dir: sh_core::paths::config_dir(),
            live_name,
            profile_names: sh_strategy::PROFILES.iter().map(|p| p.name).collect(),
            live: Snapshot::default(),
            live_at: None,
            settings: Settings::default(),
            saved: Settings::default(),
            allow_draft: String::new(),
            include_draft: String::new(),
            exclude_draft: String::new(),
            status: None,
            recent: Vec::new(),
            total_blocked: "0".into(),
            files_at: None,
            telemetry: Arc::default(),
            telemetry_loading: Arc::default(),
            search: String::new(),
            log: String::new(),
        };
        panel.load_settings();
        panel
    }

    fn load_config(&self) -> Option<Config> {
        let mut config = Config::default();
        config.load_from(self.dir.as_ref()?);
        (!config.load_failed).then_some(config)
    }

    fn load_settings(&mut self) {
        let Some(config) = self.load_config() else {
            self.status = Some(("Yapılandırma okunamadı.".into(), false));
            return;
        };
        self.saved = Settings::from_config(&config);
        self.settings = self.saved.clone();
        self.worker_url = config.worker_url;
        self.worker_name = config.worker_name;
    }

    /// Opens `splithello.exe --setup-only` (or `--redeploy`) in its own console.
    fn launch_setup(&mut self, redeploy: bool, enable_worker: bool) {
        use std::os::windows::process::CommandExt;
        if self.setup.is_some() {
            return;
        }
        let spawned = std::env::current_exe().and_then(|exe| {
            std::process::Command::new(exe)
                .arg(if redeploy {
                    "--redeploy"
                } else {
                    "--setup-only"
                })
                .creation_flags(CREATE_NEW_CONSOLE)
                .spawn()
        });
        match spawned {
            Ok(child) => self.setup = Some((child, enable_worker)),
            Err(error) => self.status = Some((format!("Kurulum açılamadı: {error}"), false)),
        }
    }

    fn poll_setup(&mut self) {
        let Some((child, enable_worker)) = &mut self.setup else {
            return;
        };
        let Ok(Some(status)) = child.try_wait() else {
            return;
        };
        let enable_worker = *enable_worker;
        self.setup = None;
        let Some(mut config) = self.load_config() else {
            return;
        };
        self.worker_url = config.worker_url.clone();
        self.worker_name = config.worker_name.clone();
        if !status.success() || config.worker_url.is_empty() {
            self.status = Some((
                "Kurulum tamamlanamadı; ayrıntı için kurulum penceresine veya kayıtlara bakın."
                    .into(),
                false,
            ));
            return;
        }
        if enable_worker {
            config.dns_mode = DnsMode::Worker;
            if let Some(dir) = &self.dir {
                let _ = config.save_to(dir);
            }
            self.saved.dns_worker = true;
            self.settings.dns_worker = true;
        }
        crate::tray::notify_tray_restart();
        self.status = Some(("Worker hazır; ağ motoru yeniden başlıyor.".into(), true));
    }

    /// Re-reads config.json and changes only what this panel edits, so a
    /// concurrent change (tray DNS toggle, setup) is not overwritten.
    fn save_settings(&mut self) {
        let (Some(dir), Some(mut config)) = (self.dir.clone(), self.load_config()) else {
            self.status = Some(("Yapılandırma okunamadı; kaydedilmedi.".into(), false));
            return;
        };
        if self.settings.dns_worker && config.worker_url.is_empty() {
            // Worker DNS without a Worker would stop the engine (exit 14).
            self.status = Some((
                "Şifreli DNS için önce Worker kurulumu gerekli.".into(),
                false,
            ));
            return;
        }
        self.settings.apply(&mut config);
        if let Err(error) = config.save_to(&dir) {
            self.status = Some((format!("Kaydedilemedi: {error}"), false));
            return;
        }
        self.status = Some(if crate::tray::notify_tray_restart() {
            (
                "Kaydedildi. Ağ motoru yeni ayarlarla yeniden başlıyor.".into(),
                true,
            )
        } else {
            (
                "Kaydedildi. Tray kapalı; ayarlar bir sonraki başlatmada geçerli.".into(),
                true,
            )
        });
        self.load_settings();
    }

    fn refresh_live(&mut self) {
        if self
            .live_at
            .is_none_or(|at| at.elapsed() >= Duration::from_secs(1))
        {
            self.live = sh_core::live_stats::read(&self.live_name, &self.profile_names);
            self.live_at = Some(Instant::now());
        }
    }

    fn refresh_files(&mut self, force: bool) {
        if !force
            && self
                .files_at
                .is_some_and(|at| at.elapsed() < Duration::from_secs(3))
        {
            return;
        }
        self.files_at = Some(Instant::now());
        let Some(dir) = &self.dir else {
            return;
        };
        // Written by the engine: "#total<TAB>N", then "host<TAB>count".
        let recent = std::fs::read_to_string(dir.join("adblock-recent.txt")).unwrap_or_default();
        self.recent.clear();
        for line in recent.lines() {
            if let Some((host, count)) = line.split_once('\t') {
                if host == "#total" {
                    self.total_blocked = count.trim().to_string();
                } else {
                    self.recent
                        .push((host.to_string(), count.trim().to_string()));
                }
            }
        }
        if self.page == Page::Log {
            self.log = tail(&dir.join(sh_core::paths::LOG_FILE), 96 * 1024);
        }
    }

    fn refresh_telemetry(&self, ctx: &egui::Context) {
        let Some(dir) = &self.dir else {
            return;
        };
        {
            let mut loading = self
                .telemetry_loading
                .lock()
                .unwrap_or_else(|p| p.into_inner());
            if *loading {
                return;
            }
            *loading = true;
        }
        let path = dir.join(sh_core::paths::TELEMETRY_FILE);
        let (slot, loading, ctx) = (
            self.telemetry.clone(),
            self.telemetry_loading.clone(),
            ctx.clone(),
        );
        // The query can take a moment on a large database; keep the UI live.
        std::thread::spawn(move || {
            let data = sh_telemetry::snapshot(&path, TELEMETRY_DAYS);
            *slot.lock().unwrap_or_else(|p| p.into_inner()) = Some(data);
            *loading.lock().unwrap_or_else(|p| p.into_inner()) = false;
            ctx.request_repaint();
        });
    }

    fn allow_host(&mut self, host: &str) {
        use std::io::Write;
        let written = self.dir.as_ref().is_some_and(|dir| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(dir.join("adblock-allow.txt"))
                .and_then(|mut file| writeln!(file, "{host}"))
                .is_ok()
        });
        self.status = Some(if written {
            (
                format!("{host} serbest bırakıldı; birkaç saniye içinde geçerli olur."),
                true,
            )
        } else {
            ("İzin listesine yazılamadı.".into(), false)
        });
    }
}

/// The last `limit` bytes of a text file, starting at a line boundary.
fn tail(path: &std::path::Path, limit: usize) -> String {
    use std::io::{Read, Seek, SeekFrom};
    // Reads only the tail, not the whole (up to 512 KiB) file.
    let Ok(mut file) = std::fs::File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map_or(0, |m| m.len());
    let start = length.saturating_sub(limit as u64);
    let mut bytes = Vec::with_capacity(limit);
    if file.seek(SeekFrom::Start(start)).is_err() || file.read_to_end(&mut bytes).is_err() {
        return String::new();
    }
    let text = String::from_utf8_lossy(&bytes);
    match (start, text.find('\n')) {
        (0, _) | (_, None) => text.into_owned(),
        (_, Some(newline)) => text[newline + 1..].to_string(),
    }
}

fn refresh_button(ui: &mut egui::Ui) -> bool {
    ui.button(RichText::new(icon::REFRESH).font(theme::icons(15.0)))
        .on_hover_text("Yenile")
        .clicked()
}

impl eframe::App for Panel {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.refresh_live();
        self.refresh_files(false);
        self.poll_setup();
        ui.ctx().request_repaint_after(Duration::from_secs(1));
        let p = palette(ui);

        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(theme::SIDEBAR_WIDTH)
            .show_separator_line(false)
            .frame(
                egui::Frame::new()
                    .fill(p.sidebar)
                    .inner_margin(egui::Margin::symmetric(14, 18)),
            )
            .show(ui, |ui| self.sidebar(ui));

        let dirty = self.settings != self.saved;
        if dirty
            && matches!(
                self.page,
                Page::Protection | Page::Connection | Page::Processes
            )
        {
            egui::Panel::bottom("save")
                .show_separator_line(false)
                .frame(
                    egui::Frame::new()
                        .fill(p.card)
                        .stroke(egui::Stroke::new(1.0, p.stroke))
                        .inner_margin(egui::Margin::symmetric(28, 14)),
                )
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.label(RichText::new("Kaydedilmemiş değişiklikler var").size(15.0));
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if theme::primary_button(ui, "Kaydet ve uygula").clicked() {
                                self.save_settings();
                            }
                            if ui.button("Geri al").clicked() {
                                self.settings = self.saved.clone();
                            }
                        });
                    });
                });
        }

        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(p.background))
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        egui::Frame::new()
                            .inner_margin(egui::Margin {
                                left: 36,
                                right: 36,
                                top: 28,
                                bottom: 36,
                            })
                            .show(ui, |ui| {
                                // set_max_width can also widen; never past the window.
                                let width = ui.available_width().min(theme::CONTENT_MAX_WIDTH);
                                ui.set_max_width(width);
                                self.status_banner(ui);
                                match self.page {
                                    Page::Status => self.status_page(ui),
                                    Page::Protection => self.protection_page(ui),
                                    Page::Connection => self.connection_page(ui),
                                    Page::Processes => self.process_page(ui),
                                    Page::Diagnostics => self.diagnostics_page(ui),
                                    Page::Log => self.log_page(ui),
                                }
                            });
                    });
            });
    }
}

impl Panel {
    fn sidebar(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        ui.horizontal(|ui| {
            ui.add_space(6.0);
            ui.label(
                RichText::new(icon::SHIELD)
                    .font(theme::icons(22.0))
                    .color(p.blue),
            );
            ui.label(RichText::new("SplitHello").font(theme::semibold(21.0)));
        });
        ui.add_space(22.0);
        ui.spacing_mut().item_spacing.y = 4.0;
        for (page, glyph, label) in [
            (Page::Status, icon::STATUS, "Durum"),
            (Page::Protection, icon::SHIELD, "Koruma"),
            (Page::Connection, icon::LINK, "Bağlantı"),
            (Page::Processes, icon::APPS, "Uygulamalar"),
            (Page::Diagnostics, icon::CHART, "Teşhis"),
            (Page::Log, icon::DOCUMENT, "Kayıtlar"),
        ] {
            if theme::nav_item(ui, glyph, label, self.page == page).clicked() && self.page != page {
                self.page = page;
                self.status = None;
                if page == Page::Log {
                    self.refresh_files(true);
                }
                if page == Page::Diagnostics {
                    self.refresh_telemetry(ui.ctx());
                }
                if page == Page::Connection {
                    self.learned_sites = self.dir.as_ref().map(|dir| {
                        let store =
                            sh_strategy::Store::new(dir.join(sh_core::paths::STRATEGY_FILE));
                        store.load();
                        store.len()
                    });
                }
            }
        }
        ui.with_layout(egui::Layout::bottom_up(egui::Align::Min), |ui| {
            let (dot, text) = if self.live.online {
                (p.green, "Koruma aktif")
            } else {
                (p.secondary, "Motor kapalı")
            };
            ui.horizontal(|ui| {
                ui.add_space(8.0);
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 5.0, dot);
                ui.label(RichText::new(text).size(13.5).color(p.secondary));
            });
        });
    }

    fn status_banner(&mut self, ui: &mut egui::Ui) {
        let Some((text, success)) = self.status.clone() else {
            return;
        };
        let p = palette(ui);
        let color = if success { p.green } else { p.red };
        egui::Frame::new()
            .fill(color.gamma_multiply(0.14))
            .corner_radius(egui::CornerRadius::same(10))
            .inner_margin(egui::Margin::symmetric(16, 10))
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.horizontal(|ui| {
                    ui.label(RichText::new(text).color(color));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::quiet_button(ui, "Kapat").clicked() {
                            self.status = None;
                        }
                    });
                });
            });
        ui.add_space(12.0);
    }

    fn status_page(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        let live = self.live.clone();
        theme::page_title(
            ui,
            "Durum",
            "Ağ motorunun şu anki durumu ve bu oturumdaki kararlar.",
        );

        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                let color = if live.online { p.green } else { p.secondary };
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
                ui.painter()
                    .circle_filled(rect.center(), 28.0, color.gamma_multiply(0.16));
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    icon::SHIELD,
                    theme::icons(26.0),
                    color,
                );
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.add_space(4.0);
                    let title = if live.online {
                        "Koruma aktif"
                    } else {
                        "Koruma kapalı"
                    };
                    ui.label(RichText::new(title).font(theme::semibold(24.0)));
                    theme::secondary(
                        ui,
                        if live.online {
                            "HTTPS trafiği izleniyor; DPI müdahalesi otomatik olarak aşılıyor."
                        } else {
                            "Canlı veri yok. Motoru tray menüsünden başlatın."
                        },
                    );
                });
            });
        });
        ui.add_space(14.0);
        theme::metrics(
            ui,
            &[
                ("Aktif bağlantı", live.active_flows.to_string(), None),
                ("Karar bekleyen", live.pending_flows.to_string(), None),
                ("Oturum kararı", live.decisions.to_string(), None),
                (
                    "Engellenen reklam",
                    self.total_blocked.clone(),
                    Some(p.orange),
                ),
            ],
        );
        ui.add_space(4.0);
        theme::metrics(
            ui,
            &[
                (
                    "Doğrudan geçti",
                    live.successful_decisions.to_string(),
                    None,
                ),
                (
                    "DPI aşıldı",
                    live.bypassed_decisions.to_string(),
                    Some(p.green),
                ),
                (
                    "Çözülemedi",
                    live.unresolved_decisions.to_string(),
                    Some(p.red),
                ),
            ],
        );
        ui.add_space(14.0);

        theme::card(ui, |ui| {
            theme::card_title(ui, "Profiller");
            theme::secondary(ui, "Bu oturumda kullanılan atlatma profilleri.");
            ui.add_space(8.0);
            let used: Vec<_> = live
                .profiles
                .iter()
                .filter(|pr| pr.active > 0 || pr.decisions > 0)
                .collect();
            if used.is_empty() {
                theme::secondary(ui, "Henüz profil kullanılmadı.");
                return;
            }
            let most = used.iter().map(|pr| pr.decisions).max().unwrap_or(1).max(1);
            for profile in used {
                ui.horizontal(|ui| {
                    ui.add_sized(
                        egui::vec2(170.0, 22.0),
                        egui::Label::new(RichText::new(&profile.name)).halign(egui::Align::LEFT),
                    );
                    let width = (ui.available_width() - 150.0).max(40.0);
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(width, 8.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 4.0, p.field);
                    let mut filled = rect;
                    filled.set_width(rect.width() * profile.decisions as f32 / most as f32);
                    ui.painter().rect_filled(filled, 4.0, p.blue);
                    ui.label(
                        RichText::new(format!(
                            "{} karar · {} aktif",
                            profile.decisions, profile.active
                        ))
                        .size(13.0)
                        .color(p.secondary),
                    );
                });
            }
        });
    }

    fn protection_page(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        theme::page_title(
            ui,
            "Koruma",
            "Tüm uygulamalarda DNS ve TLS düzeyinde çalışır; tarayıcı eklentisi gerekmez.",
        );
        let mut want_worker = false;
        theme::card(ui, |ui| {
            let s = &mut self.settings;
            theme::feature_row(
                ui,
                icon::BLOCKED,
                &mut s.ads,
                "Reklam engelleme",
                "Banner, video, açılır pencere ve uygulama içi reklamları engeller.",
            );
            if s.ads {
                ui.horizontal(|ui| {
                    ui.add_space(42.0);
                    ui.vertical(|ui| {
                        let labels: Vec<&str> =
                            STRENGTHS.iter().map(|(_, label, _)| *label).collect();
                        theme::segmented(ui, &mut s.strength, &labels);
                        theme::secondary(ui, STRENGTHS[s.strength].2);
                    });
                });
            }
            ui.separator();
            theme::feature_row(
                ui,
                icon::HIDE,
                &mut s.tracking,
                "İzleyici koruması",
                "Windows ve Office telemetrisini keser; web izleyicileri reklam listesiyle engellenir.",
            );
            ui.separator();
            theme::feature_row(
                ui,
                icon::MESSAGE,
                &mut s.annoyances,
                "Rahatsız edici öğeler",
                "Açılır pencere reklam ağlarını engeller. Sayfa içi çerez bildirimleri DNS düzeyinde engellenemez.",
            );
            ui.separator();
            let was_worker = s.dns_worker;
            theme::feature_row(
                ui,
                icon::CLOUD,
                &mut s.dns_worker,
                "DNS koruması",
                "Sorgular şifreli olarak kendi Cloudflare Worker'ınızda çözülür; ISS'nin DNS engelleri aşılır.",
            );
            if s.dns_worker && !was_worker && self.worker_url.is_empty() {
                s.dns_worker = false;
                want_worker = true;
            }
            if s.dns_worker {
                ui.horizontal(|ui| {
                    ui.add_space(42.0);
                    ui.vertical(|ui| {
                        theme::switch_row(
                            ui,
                            &mut s.doh,
                            "Uygulamaların kendi DNS'ini kapat",
                            "Tarayıcıların gizli DoH sunucularını engeller; tüm sorgular korumadan geçer.",
                        );
                    });
                });
            }
            ui.separator();
            theme::feature_row(
                ui,
                icon::GLOBE,
                &mut s.security,
                "Gezinme güvenliği",
                "Kötü amaçlı, oltalama ve sahte alışveriş sitelerine bağlantıyı keser.",
            );
        });
        if want_worker {
            self.status = Some((
                "DNS koruması için Cloudflare Worker kuruluyor; açılan pencerede tarayıcıdan izin verin.".into(),
                true,
            ));
            self.launch_setup(false, true);
        }
        ui.add_space(14.0);
        theme::card(ui, |ui| {
            theme::card_title(ui, "Ebeveyn denetimi");
            theme::secondary(
                ui,
                "Bu kategorilerdeki siteler tüm cihaz trafiğinde engellenir.",
            );
            ui.add_space(6.0);
            let s = &mut self.settings;
            theme::feature_row(
                ui,
                icon::GAME,
                &mut s.gambling,
                "Kumar ve bahis",
                "Bahis, casino ve kumar siteleri (yaklaşık 640 bin alan adı).",
            );
            ui.separator();
            theme::feature_row(
                ui,
                icon::LOCK,
                &mut s.adult,
                "Yetişkin içerik",
                "Yetişkinlere yönelik siteler.",
            );
        });
        ui.add_space(14.0);
        theme::card(ui, |ui| {
            theme::card_title(ui, "Her zaman izin verilenler");
            theme::secondary(ui, "Bu alan adları ve alt alan adları hiç engellenmez.");
            ui.add_space(6.0);
            theme::editable_list(
                ui,
                &mut self.settings.allow,
                &mut self.allow_draft,
                "ornek.com",
                "Liste boş.",
            );
        });
        ui.add_space(14.0);

        let mut allow = None;
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                theme::card_title(ui, "Son engellenenler");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new(format!("Toplam {}", self.total_blocked))
                            .font(theme::semibold(15.0))
                            .color(p.orange),
                    );
                });
            });
            if self.recent.is_empty() {
                theme::secondary(ui, "Henüz engellenen alan adı yok.");
            }
            for (index, (host, count)) in self.recent.iter().enumerate() {
                if index > 0 {
                    ui.separator();
                }
                ui.horizontal(|ui| {
                    ui.label(RichText::new(host).size(15.0));
                    ui.label(
                        RichText::new(format!("×{count}"))
                            .size(13.0)
                            .color(p.secondary),
                    );
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if theme::quiet_button(ui, "Serbest bırak").clicked() {
                            allow = Some(host.clone());
                        }
                    });
                });
            }
        });
        if let Some(host) = allow {
            self.allow_host(&host);
        }
    }

    fn connection_page(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        theme::page_title(
            ui,
            "Bağlantı",
            "Sansürlü sitelere erişim: otomatik DPI atlatma ve kendi Cloudflare Worker'ınız.",
        );
        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                let (rect, _) = ui.allocate_exact_size(egui::vec2(56.0, 56.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 28.0, p.blue.gamma_multiply(0.16));
                ui.painter().text(
                    rect.center(),
                    egui::Align2::CENTER_CENTER,
                    icon::LINK,
                    theme::icons(24.0),
                    p.blue,
                );
                ui.add_space(8.0);
                ui.vertical(|ui| {
                    ui.add_space(4.0);
                    ui.label(RichText::new("DPI atlatma her zaman açık").font(theme::semibold(22.0)));
                    theme::secondary(
                        ui,
                        "Engellenen bir siteye bağlanırken TLS el sıkışması parçalanır; çalışan yöntem \
                         ağ ve site başına öğrenilir, sonraki bağlantılar ilk denemede açılır.",
                    );
                });
            });
        });
        ui.add_space(14.0);
        theme::metrics(
            ui,
            &[
                (
                    "Öğrenilmiş site",
                    self.learned_sites.map_or("—".into(), |n| n.to_string()),
                    None,
                ),
                (
                    "Bu oturumda aşılan",
                    self.live.bypassed_decisions.to_string(),
                    Some(p.green),
                ),
                (
                    "Çözülemeyen",
                    self.live.unresolved_decisions.to_string(),
                    Some(p.red),
                ),
            ],
        );
        ui.add_space(14.0);

        let mut action = None;
        theme::card(ui, |ui| {
            theme::card_title(ui, "Cloudflare Worker");
            theme::secondary(
                ui,
                "Ücretsiz Cloudflare hesabınızda çalışan kişisel sunucu. Türkiye'de ISS DNS'i engelli \
                 sitelere sahte yanıt verdiği için şifreli DNS bunun üzerinden çözülür; hiçbir profil \
                 işe yaramazsa trafik onun üzerinden tünellenebilir.",
            );
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let installed = !self.worker_url.is_empty();
                let (dot, text) = if installed {
                    (
                        p.green,
                        format!("Kurulu: {}", sh_net::http::host_from_url(&self.worker_url)),
                    )
                } else {
                    (p.orange, "Kurulu değil".to_string())
                };
                let (rect, _) =
                    ui.allocate_exact_size(egui::vec2(10.0, 10.0), egui::Sense::hover());
                ui.painter().circle_filled(rect.center(), 5.0, dot);
                ui.label(text);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if self.setup.is_some() {
                        ui.spinner();
                        theme::secondary(ui, "Kurulum penceresi açık…");
                        return;
                    }
                    let label = if installed {
                        "Yeniden kur"
                    } else {
                        "Kurulumu başlat"
                    };
                    if theme::primary_button(ui, label).clicked() {
                        action = Some(false);
                    }
                    if !self.worker_name.is_empty() && ui.button("Worker'ı güncelle").clicked() {
                        action = Some(true);
                    }
                });
            });
            ui.add_space(6.0);
            ui.separator();
            ui.add_enabled_ui(!self.worker_url.is_empty(), |ui| {
                theme::switch_row(
                    ui,
                    &mut self.settings.dns_worker,
                    "Şifreli DNS",
                    "Tüm DNS sorguları Worker üzerinden şifreli çözülür (Koruma › DNS koruması ile aynı).",
                );
                ui.separator();
                theme::switch_row(
                    ui,
                    &mut self.settings.tunnel_fallback,
                    "Tünel yedeği",
                    "Hiçbir atlatma yöntemi işe yaramazsa bağlantı Worker üzerinden tünellenir.",
                );
            });
        });
        if let Some(redeploy) = action {
            self.launch_setup(redeploy, !redeploy && self.worker_url.is_empty());
        }
    }

    fn process_page(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        theme::page_title(
            ui,
            "Uygulamalar",
            "SplitHello'nun hangi uygulamaların trafiğine dokunacağını seçin.",
        );
        theme::card(ui, |ui| {
            theme::card_title(ui, "Yalnızca bunlar");
            theme::secondary(ui, "Boş bırakırsanız tüm uygulamalar korunur.");
            ui.add_space(6.0);
            theme::editable_list(
                ui,
                &mut self.settings.include,
                &mut self.include_draft,
                "chrome.exe",
                "Liste boş: tüm uygulamalar korunuyor.",
            );
        });
        ui.add_space(14.0);
        theme::card(ui, |ui| {
            theme::card_title(ui, "Bunlar hariç");
            theme::secondary(ui, "Hariç tutma her zaman kazanır.");
            ui.add_space(6.0);
            theme::editable_list(
                ui,
                &mut self.settings.exclude,
                &mut self.exclude_draft,
                "C:\\Games\\*",
                "Hariç tutulan uygulama yok.",
            );
        });
        ui.add_space(10.0);
        theme::secondary(
            ui,
            "Desenler büyük/küçük harf duyarsızdır; * ve ? kullanılabilir. Ters bölü içeren desen \
             tam yolu, diğerleri yalnızca exe adını eşler.",
        );
        // The engine's own parser, for the "invalid include" warning.
        let rules = sh_divert::rules::Rules::new(&self.settings.include, &self.settings.exclude);
        if rules.include_list_invalid() {
            ui.label(RichText::new("Bu liste geçersiz: motor başlamaz.").color(p.red));
        }
    }

    fn diagnostics_page(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 60.0);
                theme::page_title(
                    ui,
                    "Teşhis",
                    &format!("Son {TELEMETRY_DAYS} günde verilen kararlar ve müdahale kanıtları."),
                );
            });
            if *self
                .telemetry_loading
                .lock()
                .unwrap_or_else(|e| e.into_inner())
            {
                ui.spinner();
            } else if refresh_button(ui) {
                self.refresh_telemetry(ui.ctx());
            }
        });
        let snapshot = self
            .telemetry
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let Some(data) = snapshot else {
            theme::card(ui, |ui| theme::secondary(ui, "Veriler yükleniyor…"));
            return;
        };
        if !data.ready {
            theme::card(ui, |ui| {
                ui.label(
                    RichText::new(format!("Telemetri okunamadı: {}", data.error)).color(p.red),
                );
            });
            return;
        }
        theme::metrics(
            ui,
            &[
                ("Toplam karar", data.total.to_string(), None),
                ("Dokunulmadı", data.normal.to_string(), None),
                ("DPI aşıldı", data.bypassed.to_string(), Some(p.green)),
                ("Çözülemedi", data.unresolved.to_string(), Some(p.red)),
            ],
        );
        ui.add_space(4.0);
        theme::metrics(
            ui,
            &[
                ("Medyan süre", format!("{} ms", data.latency.p50), None),
                (
                    "Yavaş (p90)",
                    format!("{} ms", data.latency.p90),
                    Some(p.orange),
                ),
                (
                    "Kuyruk (p99)",
                    format!("{} ms", data.latency.p99),
                    Some(p.red),
                ),
            ],
        );
        ui.add_space(14.0);

        theme::card(ui, |ui| {
            theme::card_title(ui, "Müdahale görülen alan adları");
            ui.add_space(6.0);
            let widths = [0.55, 0.15, 0.15, 0.15];
            let header =
                ["Alan adı", "Toplam", "Aşıldı", "Çözülemedi"].map(|h| (h.to_string(), None));
            theme::table_row(ui, &header, &widths, true);
            if data.top_hosts.is_empty() {
                theme::secondary(ui, "Kayıt yok.");
            }
            for host in &data.top_hosts {
                theme::table_row(
                    ui,
                    &[
                        (host.host.clone(), None),
                        (host.total.to_string(), None),
                        (host.bypassed.to_string(), Some(p.green)),
                        (
                            host.unresolved.to_string(),
                            (host.unresolved > 0).then_some(p.red),
                        ),
                    ],
                    &widths,
                    false,
                );
            }
        });
        ui.add_space(14.0);

        ui.columns(2, |columns| {
            theme::card(&mut columns[0], |ui| {
                theme::card_title(ui, "Profiller");
                ui.add_space(6.0);
                let widths = [0.46, 0.18, 0.18, 0.18];
                let header = ["Profil", "Karar", "ms", "Deneme"].map(|h| (h.to_string(), None));
                theme::table_row(ui, &header, &widths, true);
                for profile in &data.profiles {
                    theme::table_row(
                        ui,
                        &[
                            (profile.name.clone(), None),
                            (profile.count.to_string(), None),
                            (format!("{:.0}", profile.average_latency_ms), None),
                            (format!("{:.1}", profile.average_attempts), None),
                        ],
                        &widths,
                        false,
                    );
                }
            });
            theme::card(&mut columns[1], |ui| {
                theme::card_title(ui, "Teşhis dağılımı");
                ui.add_space(6.0);
                let total: i64 = data.diagnoses.iter().map(|d| d.count).sum::<i64>().max(1);
                for item in &data.diagnoses {
                    ui.horizontal(|ui| {
                        ui.label(&item.key);
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            ui.label(
                                RichText::new(format!(
                                    "{}  ·  %{}",
                                    item.count,
                                    item.count * 100 / total
                                ))
                                .color(p.secondary),
                            );
                        });
                    });
                }
            });
        });
        ui.add_space(14.0);

        theme::card(ui, |ui| {
            ui.horizontal(|ui| {
                theme::card_title(ui, "Son kararlar");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.search)
                            .hint_text("Alan adı ara")
                            .desired_width(240.0)
                            .margin(egui::Margin::symmetric(10, 6)),
                    );
                });
            });
            ui.add_space(6.0);
            let needle = self.search.to_ascii_lowercase();
            let widths = [0.4, 0.25, 0.15, 0.1, 0.1];
            let header =
                ["Alan adı", "Teşhis", "Profil", "Deneme", "ms"].map(|h| (h.to_string(), None));
            theme::table_row(ui, &header, &widths, true);
            for event in data
                .recent
                .iter()
                .filter(|e| e.host.contains(&needle))
                .take(150)
            {
                theme::table_row(
                    ui,
                    &[
                        (event.host.clone(), None),
                        (event.diagnosis.clone(), (!event.success).then_some(p.red)),
                        (event.winner.clone(), None),
                        (event.attempt_count.to_string(), None),
                        (event.total_elapsed_ms.to_string(), None),
                    ],
                    &widths,
                    false,
                );
            }
        });
    }

    fn log_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.set_width(ui.available_width() - 60.0);
                theme::page_title(ui, "Kayıtlar", "splithello.log dosyasının son 96 KB'ı.");
            });
            if refresh_button(ui) {
                self.refresh_files(true);
            }
        });
        theme::card(ui, |ui| {
            egui::ScrollArea::vertical()
                .max_height(560.0)
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.log.as_str())
                            .font(egui::TextStyle::Monospace)
                            .frame(egui::Frame::NONE)
                            .desired_width(f32::INFINITY),
                    );
                });
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_round_trip_through_config_lists() {
        let mut config = Config {
            ad_block: true,
            ad_block_lists: vec![
                "light".into(),
                "pro".into(),
                "tif".into(),
                "future-list".into(),
            ],
            ..Config::default()
        };
        let mut settings = Settings::from_config(&config);
        assert!(settings.ads && settings.security && !settings.tracking);
        assert_eq!(STRENGTHS[settings.strength].0, "pro"); // strongest wins
        assert_eq!(settings.other_lists, ["future-list"]);

        settings.strength = 0;
        settings.tracking = true;
        settings.apply(&mut config);
        assert_eq!(
            config.ad_block_lists,
            ["light", "native.winoffice", "tif", "fake", "future-list"]
        );
        assert!(config.ad_block);

        // Everything off: blocking off, list names left for next time.
        let mut off = Settings::from_config(&config);
        off.ads = false;
        off.tracking = false;
        off.security = false;
        off.apply(&mut config);
        assert!(!config.ad_block);
        assert!(!Settings::from_config(&config).ads);
    }

    #[test]
    fn tail_starts_at_a_line_boundary() {
        let path = std::env::temp_dir().join(format!("sh-ui-tail-{}.txt", std::process::id()));
        std::fs::write(&path, "first line\nsecond line\nthird\n").unwrap();
        assert_eq!(tail(&path, 15), "third\n");
        assert_eq!(tail(&path, 1000), "first line\nsecond line\nthird\n");
        std::fs::remove_file(&path).unwrap();
    }
}
