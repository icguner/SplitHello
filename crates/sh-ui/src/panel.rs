//! The panel (successor of `DashboardPanel`): an egui window in its own
//! process, opened by the tray with `--panel --live-stats <name>`. It reads
//! the engine's live-stats mapping, the telemetry database and the files in
//! the config folder; settings it saves are applied by asking the tray to
//! restart the engine. The look lives in `theme`.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText};
use sh_core::config::Config;
use sh_core::live_stats::Snapshot;
use sh_telemetry::DashboardData;

use crate::theme::{self, icon, palette};

/// HaGeZi lists the updater knows (see `sh_adblock::list_path`).
const LISTS: [(&str, &str, &str); 4] = [
    (
        "light",
        "Light",
        "En az yanlış pozitif; temel reklam ve izleyiciler.",
    ),
    ("pro", "Pro", "Önerilen denge: reklam, izleyici, telemetri."),
    (
        "tif",
        "Tehdit istihbaratı",
        "Kötü amaçlı yazılım, oltalama ve dolandırıcılık alanları.",
    ),
    (
        "doh",
        "DoH sunucuları",
        "Uygulamaların kendi DNS'ini kapatır, DNS'imize yönlendirir.",
    ),
];
const TELEMETRY_DAYS: u32 = 7;

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
    AdBlock,
    Processes,
    Diagnostics,
    Log,
}

/// What the panel edits in config.json; compared with the saved copy to show
/// the save bar only when something changed.
#[derive(Clone, PartialEq, Eq, Default)]
struct Settings {
    ad_block: bool,
    lists: Vec<bool>,
    allow: Vec<String>,
    include: Vec<String>,
    exclude: Vec<String>,
}

struct Panel {
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
        self.saved = Settings {
            ad_block: config.ad_block,
            lists: LISTS
                .iter()
                .map(|(name, _, _)| config.ad_block_lists.iter().any(|l| l == name))
                .collect(),
            allow: config.ad_block_allow.clone(),
            include: config.process_include.clone(),
            exclude: config.process_exclude.clone(),
        };
        self.settings = self.saved.clone();
    }

    /// Re-reads config.json and changes only what this panel edits, so a
    /// concurrent change (tray DNS toggle, setup) is not overwritten.
    fn save_settings(&mut self) {
        let (Some(dir), Some(mut config)) = (self.dir.clone(), self.load_config()) else {
            self.status = Some(("Yapılandırma okunamadı; kaydedilmedi.".into(), false));
            return;
        };
        let s = &self.settings;
        config.ad_block = s.ad_block;
        config.ad_block_lists = LISTS
            .iter()
            .zip(&s.lists)
            .filter(|(_, on)| **on)
            .map(|((name, _, _), _)| (*name).to_string())
            .collect();
        config.ad_block_allow = s.allow.clone();
        config.process_include = s.include.clone();
        config.process_exclude = s.exclude.clone();
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
        self.log = tail(&dir.join(sh_core::paths::LOG_FILE), 96 * 1024);
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
    let Ok(bytes) = std::fs::read(path) else {
        return String::new();
    };
    let start = bytes.len().saturating_sub(limit);
    let text = String::from_utf8_lossy(&bytes[start..]);
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
        if dirty && matches!(self.page, Page::AdBlock | Page::Processes) {
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
                                    Page::AdBlock => self.ad_block_page(ui),
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
            (Page::AdBlock, icon::SHIELD, "Reklam engeli"),
            (Page::Processes, icon::APPS, "Uygulamalar"),
            (Page::Diagnostics, icon::CHART, "Teşhis"),
            (Page::Log, icon::DOCUMENT, "Kayıtlar"),
        ] {
            if theme::nav_item(ui, glyph, label, self.page == page).clicked() && self.page != page {
                self.page = page;
                self.status = None;
                if page == Page::Diagnostics {
                    self.refresh_telemetry(ui.ctx());
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

    fn ad_block_page(&mut self, ui: &mut egui::Ui) {
        let p = palette(ui);
        theme::page_title(
            ui,
            "Reklam engeli",
            "Reklamları ve izleyicileri tüm uygulamalarda, DNS ve TLS düzeyinde engeller.",
        );
        theme::card(ui, |ui| {
            theme::switch_row(
                ui,
                &mut self.settings.ad_block,
                "Reklam ve izleyicileri engelle",
                "Engellenen alan adlarına hiç bağlanılmaz; sayfalar daha hızlı açılır.",
            );
        });
        ui.add_space(14.0);
        theme::card(ui, |ui| {
            theme::card_title(ui, "Engel listeleri");
            theme::secondary(ui, "HaGeZi listeleri; her gün otomatik güncellenir.");
            ui.add_space(6.0);
            let enabled = self.settings.ad_block;
            for (index, ((_, title, description), on)) in
                LISTS.iter().zip(self.settings.lists.iter_mut()).enumerate()
            {
                if index > 0 {
                    ui.separator();
                }
                ui.add_enabled_ui(enabled, |ui| {
                    theme::switch_row(ui, on, title, description);
                });
            }
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
    fn tail_starts_at_a_line_boundary() {
        let path = std::env::temp_dir().join(format!("sh-ui-tail-{}.txt", std::process::id()));
        std::fs::write(&path, "first line\nsecond line\nthird\n").unwrap();
        assert_eq!(tail(&path, 15), "third\n");
        assert_eq!(tail(&path, 1000), "first line\nsecond line\nthird\n");
        std::fs::remove_file(&path).unwrap();
    }
}
