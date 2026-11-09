//! The panel (successor of `DashboardPanel`): an egui window in its own
//! process, opened by the tray with `--panel --live-stats <name>`. It reads
//! the engine's live-stats mapping, the telemetry database and the files in
//! the config folder; settings it saves are applied by asking the tray to
//! restart the engine.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use eframe::egui::{self, Color32, RichText};
use sh_core::config::Config;
use sh_core::live_stats::Snapshot;
use sh_telemetry::DashboardData;

const ACCENT: Color32 = Color32::from_rgb(0x2E, 0x9C, 0x6A);
const WARN: Color32 = Color32::from_rgb(0xD9, 0x8E, 0x04);
const BAD: Color32 = Color32::from_rgb(0xD1, 0x43, 0x43);
/// HaGeZi lists the updater knows (see `sh_adblock::list_path`).
const LISTS: [(&str, &str); 4] = [
    ("light", "Light — en az yanlış pozitif"),
    ("pro", "Pro — önerilen"),
    ("tif", "TIF — kötü amaçlı / oltalama"),
    ("doh", "DoH sunucuları — uygulamaları DNS'imize yönlendirir"),
];
const TELEMETRY_DAYS: u32 = 7;

pub fn run(live_stats_name: &str) -> i32 {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("SplitHello")
            .with_inner_size([1000.0, 700.0])
            .with_min_inner_size([680.0, 440.0]),
        ..Default::default()
    };
    let name = live_stats_name.to_string();
    let result = eframe::run_native(
        "SplitHello",
        options,
        Box::new(move |_| Ok(Box::new(Panel::new(name)))),
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

struct Panel {
    page: Page,
    dir: Option<PathBuf>,
    live_name: String,
    profile_names: Vec<&'static str>,
    live: Snapshot,
    live_at: Option<Instant>,
    // Settings being edited (loaded from config.json on open / after save).
    ad_block: bool,
    lists: Vec<bool>,
    allow_text: String,
    include_text: String,
    exclude_text: String,
    status: Option<(String, Color32)>,
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
            ad_block: false,
            lists: vec![false; LISTS.len()],
            allow_text: String::new(),
            include_text: String::new(),
            exclude_text: String::new(),
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
            self.status = Some(("Yapılandırma okunamadı.".into(), BAD));
            return;
        };
        self.ad_block = config.ad_block;
        self.lists = LISTS
            .iter()
            .map(|(name, _)| config.ad_block_lists.iter().any(|l| l == name))
            .collect();
        self.allow_text = config.ad_block_allow.join("\n");
        self.include_text = config.process_include.join("\n");
        self.exclude_text = config.process_exclude.join("\n");
    }

    /// Re-reads config.json and changes only what this panel edits, so a
    /// concurrent change (tray DNS toggle, setup) is not overwritten.
    fn save_settings(&mut self) {
        let lines = |text: &str| -> Vec<String> {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        };
        let (Some(dir), Some(mut config)) = (self.dir.clone(), self.load_config()) else {
            self.status = Some(("Yapılandırma okunamadı; kaydedilmedi.".into(), BAD));
            return;
        };
        config.ad_block = self.ad_block;
        config.ad_block_lists = LISTS
            .iter()
            .zip(&self.lists)
            .filter(|(_, on)| **on)
            .map(|((name, _), _)| (*name).to_string())
            .collect();
        config.ad_block_allow = lines(&self.allow_text);
        config.process_include = lines(&self.include_text);
        config.process_exclude = lines(&self.exclude_text);
        if let Err(error) = config.save_to(&dir) {
            self.status = Some((format!("Kaydedilemedi: {error}"), BAD));
            return;
        }
        self.status = Some(if crate::tray::notify_tray_restart() {
            (
                "Kaydedildi; ağ motoru yeni ayarlarla yeniden başlıyor.".into(),
                ACCENT,
            )
        } else {
            (
                "Kaydedildi; tray kapalı, ayarlar bir sonraki başlatmada geçerli.".into(),
                WARN,
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
                format!("{host} serbest bırakıldı (birkaç saniye içinde geçerli olur)."),
                ACCENT,
            )
        } else {
            ("Liste dosyasına yazılamadı.".into(), BAD)
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

fn stat(ui: &mut egui::Ui, label: &str, value: impl ToString, color: Color32) {
    ui.vertical(|ui| {
        ui.label(RichText::new(label).small().weak());
        ui.label(
            RichText::new(value.to_string())
                .size(22.0)
                .strong()
                .color(color),
        );
    });
}

fn section(ui: &mut egui::Ui, title: &str) {
    ui.add_space(10.0);
    ui.label(RichText::new(title).strong().size(15.0));
    ui.separator();
}

impl eframe::App for Panel {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.refresh_live();
        self.refresh_files(false);
        ui.ctx().request_repaint_after(Duration::from_secs(1));

        egui::Panel::left("nav")
            .resizable(false)
            .exact_size(170.0)
            .show(ui, |ui| {
                ui.add_space(12.0);
                ui.label(
                    RichText::new("SplitHello")
                        .size(20.0)
                        .strong()
                        .color(ACCENT),
                );
                ui.add_space(12.0);
                for (page, label) in [
                    (Page::Status, "Durum"),
                    (Page::AdBlock, "Reklam engeli"),
                    (Page::Processes, "Süreç kuralları"),
                    (Page::Diagnostics, "Teşhis"),
                    (Page::Log, "Log"),
                ] {
                    let selected = self.page == page;
                    if ui
                        .selectable_label(selected, RichText::new(label).size(15.0))
                        .clicked()
                    {
                        self.page = page;
                        self.status = None;
                        if page == Page::Diagnostics {
                            self.refresh_telemetry(ui.ctx());
                        }
                    }
                }
            });

        egui::CentralPanel::default().show(ui, |ui| {
            if let Some((text, color)) = &self.status {
                ui.label(RichText::new(text).color(*color));
            }
            egui::ScrollArea::vertical().show(ui, |ui| match self.page {
                Page::Status => self.status_page(ui),
                Page::AdBlock => self.ad_block_page(ui),
                Page::Processes => self.process_page(ui),
                Page::Diagnostics => self.diagnostics_page(ui),
                Page::Log => self.log_page(ui),
            });
        });
    }
}

impl Panel {
    fn status_page(&mut self, ui: &mut egui::Ui) {
        let live = &self.live;
        section(ui, "Ağ motoru");
        ui.horizontal(|ui| {
            let (text, color) = if live.online {
                ("Koruma aktif", ACCENT)
            } else {
                ("Çevrimdışı", BAD)
            };
            stat(ui, "DURUM", text, color);
            ui.add_space(24.0);
            stat(ui, "AKTİF AKIŞ", live.active_flows, Color32::PLACEHOLDER);
            ui.add_space(24.0);
            stat(
                ui,
                "KARAR BEKLEYEN",
                live.pending_flows,
                Color32::PLACEHOLDER,
            );
            ui.add_space(24.0);
            stat(ui, "OTURUM KARARI", live.decisions, Color32::PLACEHOLDER);
        });
        ui.horizontal(|ui| {
            stat(ui, "BAŞARILI", live.successful_decisions, ACCENT);
            ui.add_space(24.0);
            stat(ui, "ATLATILDI", live.bypassed_decisions, ACCENT);
            ui.add_space(24.0);
            stat(ui, "ÇÖZÜLEMEDİ", live.unresolved_decisions, BAD);
            ui.add_space(24.0);
            stat(ui, "ENGELLENEN REKLAM", &self.total_blocked, WARN);
        });
        if !live.online {
            ui.label(
                RichText::new("Canlı veri yok: motor kapalı ya da panel tray dışından açıldı.")
                    .weak(),
            );
        }
        section(ui, "Profiller");
        egui::Grid::new("profiles")
            .striped(true)
            .num_columns(3)
            .show(ui, |ui| {
                ui.label(RichText::new("PROFİL").weak());
                ui.label(RichText::new("AKTİF").weak());
                ui.label(RichText::new("KARAR").weak());
                ui.end_row();
                for profile in live
                    .profiles
                    .iter()
                    .filter(|p| p.active > 0 || p.decisions > 0)
                {
                    ui.label(&profile.name);
                    ui.label(profile.active.to_string());
                    ui.label(profile.decisions.to_string());
                    ui.end_row();
                }
            });
    }

    fn ad_block_page(&mut self, ui: &mut egui::Ui) {
        section(ui, "Reklam ve izleyici engeli");
        ui.checkbox(&mut self.ad_block, "Reklam engelini aç (DNS + SNI)");
        ui.add_space(6.0);
        ui.label(RichText::new("Listeler (HaGeZi, günlük güncellenir)").weak());
        for ((_, label), on) in LISTS.iter().zip(self.lists.iter_mut()) {
            ui.checkbox(on, *label);
        }
        section(ui, "Her zaman izinli alan adları");
        ui.label(RichText::new("Satır başına bir alan adı; alt alan adlarını da kapsar.").weak());
        ui.add(
            egui::TextEdit::multiline(&mut self.allow_text)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .hint_text("ornek.com"),
        );
        if ui.button("Kaydet ve motoru yenile").clicked() {
            self.save_settings();
        }

        section(
            ui,
            &format!("Son engellenenler (toplam {})", self.total_blocked),
        );
        if self.recent.is_empty() {
            ui.label(RichText::new("Henüz engellenen yok.").weak());
        }
        let mut allow = None;
        egui::Grid::new("recent")
            .striped(true)
            .num_columns(3)
            .show(ui, |ui| {
                for (host, count) in &self.recent {
                    ui.label(host);
                    ui.label(format!("×{count}"));
                    if ui.small_button("Serbest bırak").clicked() {
                        allow = Some(host.clone());
                    }
                    ui.end_row();
                }
            });
        if let Some(host) = allow {
            self.allow_host(&host);
        }
    }

    fn process_page(&mut self, ui: &mut egui::Ui) {
        section(ui, "Süreç kuralları");
        ui.label(
            RichText::new(
                "Desenler büyük/küçük harf duyarsızdır, * ve ? destekler. Ters bölü içeren desen \
                 tam yolu, diğerleri exe adını eşler. Hariç tutma her zaman kazanır.",
            )
            .weak(),
        );
        ui.add_space(6.0);
        ui.label("Yalnız bunları işle (boş: tüm uygulamalar)");
        ui.add(
            egui::TextEdit::multiline(&mut self.include_text)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .hint_text("chrome.exe"),
        );
        ui.label("Bunları hiç işleme");
        ui.add(
            egui::TextEdit::multiline(&mut self.exclude_text)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .hint_text("C:\\Games\\*"),
        );
        let rules = process_rules(&self.include_text, &self.exclude_text);
        if rules.include_list_invalid() {
            ui.label(RichText::new("Include listesi geçersiz: motor başlamaz.").color(BAD));
        }
        if ui.button("Kaydet ve motoru yenile").clicked() {
            self.save_settings();
        }
    }

    fn diagnostics_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Yenile").clicked() {
                self.refresh_telemetry(ui.ctx());
            }
            if *self
                .telemetry_loading
                .lock()
                .unwrap_or_else(|p| p.into_inner())
            {
                ui.spinner();
            }
        });
        let guard = self.telemetry.lock().unwrap_or_else(|p| p.into_inner());
        let Some(data) = guard.as_ref() else {
            ui.label(RichText::new("Veri bekleniyor…").weak());
            return;
        };
        if !data.ready {
            ui.label(RichText::new(format!("Telemetri okunamadı: {}", data.error)).color(BAD));
            return;
        }
        section(ui, &format!("Özet (son {} gün)", data.window_days));
        ui.horizontal(|ui| {
            stat(ui, "TOPLAM KARAR", data.total, Color32::PLACEHOLDER);
            ui.add_space(20.0);
            stat(ui, "DOKUNULMADI", data.normal, Color32::PLACEHOLDER);
            ui.add_space(20.0);
            stat(ui, "ATLATILDI", data.bypassed, ACCENT);
            ui.add_space(20.0);
            stat(ui, "ÇÖZÜLEMEDİ", data.unresolved, BAD);
            ui.add_space(20.0);
            stat(
                ui,
                "p50 / p90 / p99 ms",
                format!(
                    "{} / {} / {}",
                    data.latency.p50, data.latency.p90, data.latency.p99
                ),
                Color32::PLACEHOLDER,
            );
        });

        section(ui, "Müdahale gerektiren alanlar");
        egui::Grid::new("hosts")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for title in ["ALAN ADI", "TOPLAM", "ATLATILDI", "ÇÖZÜLEMEDİ"] {
                    ui.label(RichText::new(title).weak());
                }
                ui.end_row();
                for host in &data.top_hosts {
                    ui.label(&host.host);
                    ui.label(host.total.to_string());
                    ui.label(host.bypassed.to_string());
                    ui.label(RichText::new(host.unresolved.to_string()).color(
                        if host.unresolved > 0 {
                            BAD
                        } else {
                            Color32::PLACEHOLDER
                        },
                    ));
                    ui.end_row();
                }
            });

        section(ui, "Profiller");
        egui::Grid::new("profile-stats")
            .striped(true)
            .num_columns(4)
            .show(ui, |ui| {
                for title in ["PROFİL", "KARAR", "ORT. ms", "ORT. DENEME"] {
                    ui.label(RichText::new(title).weak());
                }
                ui.end_row();
                for profile in &data.profiles {
                    ui.label(&profile.name);
                    ui.label(profile.count.to_string());
                    ui.label(format!("{:.0}", profile.average_latency_ms));
                    ui.label(format!("{:.1}", profile.average_attempts));
                    ui.end_row();
                }
            });

        section(ui, "Teşhis dağılımı");
        for item in data.diagnoses.iter().chain(&data.signals) {
            ui.label(format!("{}: {}", item.key, item.count));
        }

        section(ui, "Son kararlar");
        ui.add(egui::TextEdit::singleline(&mut self.search).hint_text("Alan adı ara…"));
        let needle = self.search.to_ascii_lowercase();
        egui::Grid::new("events")
            .striped(true)
            .num_columns(5)
            .show(ui, |ui| {
                for title in ["ALAN ADI", "TEŞHİS", "PROFİL", "DENEME", "ms"] {
                    ui.label(RichText::new(title).weak());
                }
                ui.end_row();
                for event in data
                    .recent
                    .iter()
                    .filter(|e| e.host.contains(&needle))
                    .take(200)
                {
                    ui.label(&event.host);
                    ui.label(RichText::new(&event.diagnosis).color(if event.success {
                        Color32::PLACEHOLDER
                    } else {
                        BAD
                    }));
                    ui.label(&event.winner);
                    ui.label(event.attempt_count.to_string());
                    ui.label(event.total_elapsed_ms.to_string());
                    ui.end_row();
                }
            });
    }

    fn log_page(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            if ui.button("Yenile").clicked() {
                self.refresh_files(true);
            }
            ui.label(RichText::new("splithello.log (son 96 KB)").weak());
        });
        ui.add(
            egui::TextEdit::multiline(&mut self.log.as_str())
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY),
        );
    }
}

/// The same rule parser the engine uses, for the "invalid include" warning.
fn process_rules(include: &str, exclude: &str) -> sh_divert::rules::Rules {
    fn lines(text: &str) -> Vec<&str> {
        text.lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect()
    }
    sh_divert::rules::Rules::new(&lines(include), &lines(exclude))
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
