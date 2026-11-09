//! The panel's look: macOS-style palette for light and dark (following the
//! system), Windows' own Segoe UI Variable / Fluent icons, and the few custom
//! widgets the pages share (cards, iOS-style switches, sidebar items).

use std::path::PathBuf;
use std::sync::Arc;

use eframe::egui::{
    self, Color32, CornerRadius, FontData, FontDefinitions, FontFamily, FontId, Margin, Response,
    RichText, Sense, Shadow, Stroke, TextStyle, Theme, ThemePreference, Ui, Vec2, vec2,
};

#[derive(Clone, Copy)]
pub struct Palette {
    pub background: Color32,
    pub sidebar: Color32,
    pub card: Color32,
    pub field: Color32,
    pub stroke: Color32,
    pub text: Color32,
    pub secondary: Color32,
    pub blue: Color32,
    pub green: Color32,
    pub orange: Color32,
    pub red: Color32,
    pub dark: bool,
}

pub const LIGHT: Palette = Palette {
    background: Color32::from_rgb(0xF5, 0xF5, 0xF7),
    sidebar: Color32::from_rgb(0xEB, 0xEB, 0xEF),
    card: Color32::WHITE,
    field: Color32::from_rgb(0xF2, 0xF2, 0xF7),
    stroke: Color32::from_rgb(0xE3, 0xE3, 0xE8),
    text: Color32::from_rgb(0x1D, 0x1D, 0x1F),
    secondary: Color32::from_rgb(0x6E, 0x6E, 0x73),
    blue: Color32::from_rgb(0x00, 0x7A, 0xFF),
    green: Color32::from_rgb(0x34, 0xC7, 0x59),
    orange: Color32::from_rgb(0xFF, 0x95, 0x00),
    red: Color32::from_rgb(0xFF, 0x3B, 0x30),
    dark: false,
};

pub const DARK: Palette = Palette {
    background: Color32::from_rgb(0x1C, 0x1C, 0x1E),
    sidebar: Color32::from_rgb(0x24, 0x24, 0x27),
    card: Color32::from_rgb(0x2C, 0x2C, 0x2E),
    field: Color32::from_rgb(0x1C, 0x1C, 0x1E),
    stroke: Color32::from_rgb(0x3A, 0x3A, 0x3C),
    text: Color32::from_rgb(0xF5, 0xF5, 0xF7),
    secondary: Color32::from_rgb(0x98, 0x98, 0x9D),
    blue: Color32::from_rgb(0x0A, 0x84, 0xFF),
    green: Color32::from_rgb(0x30, 0xD1, 0x58),
    orange: Color32::from_rgb(0xFF, 0x9F, 0x0A),
    red: Color32::from_rgb(0xFF, 0x45, 0x3A),
    dark: true,
};

pub fn palette(ui: &Ui) -> Palette {
    if ui.visuals().dark_mode { DARK } else { LIGHT }
}

/// Segoe Fluent Icons code points (Windows 11; empty when the font is absent).
pub mod icon {
    pub const STATUS: &str = "\u{E80F}"; // Home
    pub const SHIELD: &str = "\u{EA18}";
    pub const APPS: &str = "\u{E71D}";
    pub const CHART: &str = "\u{E9D9}"; // Diagnostic
    pub const DOCUMENT: &str = "\u{E8A5}";
    pub const REFRESH: &str = "\u{E72C}";
    pub const REMOVE: &str = "\u{E711}"; // Cancel
}

pub fn semibold(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("semibold".into()))
}

pub fn icons(size: f32) -> FontId {
    FontId::new(size, FontFamily::Name("icons".into()))
}

/// Loads Windows' UI fonts (falling back to egui's) and the light/dark styles.
pub fn install(ctx: &egui::Context) {
    let fonts_dir = std::env::var_os("SystemRoot")
        .map(|root| PathBuf::from(root).join("Fonts"))
        .unwrap_or_else(|| PathBuf::from("C:\\Windows\\Fonts"));
    let mut fonts = FontDefinitions::default();
    let defaults = fonts
        .families
        .get(&FontFamily::Proportional)
        .cloned()
        .unwrap_or_default();
    let mut load = |name: &str, files: &[&str]| -> bool {
        for file in files {
            if let Ok(bytes) = std::fs::read(fonts_dir.join(file)) {
                fonts
                    .font_data
                    .insert(name.into(), Arc::new(FontData::from_owned(bytes)));
                return true;
            }
        }
        false
    };
    let regular = load("ui", &["SegUIVar.ttf", "segoeui.ttf"]);
    let bold = load("ui-semibold", &["seguisb.ttf", "segoeuib.ttf"]);
    let mono = load("mono", &["CascadiaMono.ttf", "consola.ttf"]);
    let glyphs = load("fluent", &["SegoeIcons.ttf", "segmdl2.ttf"]);

    let with = |first: Option<&str>| -> Vec<String> {
        first
            .map(String::from)
            .into_iter()
            .chain(defaults.iter().cloned())
            .collect()
    };
    fonts
        .families
        .insert(FontFamily::Proportional, with(regular.then_some("ui")));
    fonts.families.insert(
        FontFamily::Name("semibold".into()),
        with(bold.then_some("ui-semibold").or(regular.then_some("ui"))),
    );
    fonts.families.insert(
        FontFamily::Name("icons".into()),
        with(glyphs.then_some("fluent")),
    );
    if mono {
        fonts
            .families
            .entry(FontFamily::Monospace)
            .or_default()
            .insert(0, "mono".into());
    }
    ctx.set_fonts(fonts);

    ctx.set_theme(ThemePreference::System);
    ctx.set_style_of(Theme::Light, style(&LIGHT));
    ctx.set_style_of(Theme::Dark, style(&DARK));
}

fn style(p: &Palette) -> egui::Style {
    let mut style = egui::Style {
        text_styles: [
            (TextStyle::Small, FontId::proportional(12.5)),
            (TextStyle::Body, FontId::proportional(15.0)),
            (TextStyle::Button, FontId::proportional(15.0)),
            (TextStyle::Heading, semibold(28.0)),
            (TextStyle::Monospace, FontId::monospace(13.0)),
        ]
        .into(),
        ..Default::default()
    };
    style.spacing.item_spacing = vec2(10.0, 10.0);
    style.spacing.button_padding = vec2(14.0, 7.0);
    style.spacing.interact_size.y = 32.0;

    let mut visuals = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };
    visuals.panel_fill = p.background;
    visuals.window_fill = p.card;
    visuals.extreme_bg_color = p.field;
    visuals.faint_bg_color = p.field;
    visuals.override_text_color = Some(p.text);
    visuals.weak_text_color = Some(p.secondary);
    visuals.hyperlink_color = p.blue;
    visuals.selection.bg_fill = p.blue.gamma_multiply(0.35);
    visuals.selection.stroke = Stroke::new(1.0, p.blue);
    let radius = CornerRadius::same(8);
    let (idle, hover, press) = if p.dark {
        (
            Color32::from_rgb(0x3A, 0x3A, 0x3C),
            Color32::from_rgb(0x48, 0x48, 0x4A),
            Color32::from_rgb(0x55, 0x55, 0x58),
        )
    } else {
        (
            Color32::from_rgb(0xE8, 0xE8, 0xED),
            Color32::from_rgb(0xDD, 0xDD, 0xE3),
            Color32::from_rgb(0xD1, 0xD1, 0xD6),
        )
    };
    for (widget, fill) in [
        (&mut visuals.widgets.inactive, idle),
        (&mut visuals.widgets.hovered, hover),
        (&mut visuals.widgets.active, press),
        (&mut visuals.widgets.open, hover),
    ] {
        widget.corner_radius = radius;
        widget.bg_fill = fill;
        widget.weak_bg_fill = fill;
        widget.bg_stroke = Stroke::NONE;
        widget.fg_stroke = Stroke::new(1.0, p.text);
        widget.expansion = 0.0;
    }
    visuals.widgets.noninteractive.corner_radius = radius;
    visuals.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.stroke);
    visuals.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text);
    // Text fields: a quiet outline that turns blue on focus.
    visuals.widgets.inactive.bg_stroke = Stroke::new(1.0, p.stroke);
    visuals.widgets.hovered.bg_stroke = Stroke::new(1.0, p.stroke);
    visuals.widgets.active.bg_stroke = Stroke::new(1.5, p.blue);
    visuals.window_corner_radius = CornerRadius::same(14);
    style.visuals = visuals;
    style
}

/// A white (dark: graphite) rounded card with a soft shadow.
pub fn card<R>(ui: &mut Ui, add: impl FnOnce(&mut Ui) -> R) -> R {
    let p = palette(ui);
    egui::Frame::new()
        .fill(p.card)
        .stroke(Stroke::new(1.0, p.stroke))
        .corner_radius(CornerRadius::same(14))
        .inner_margin(Margin::same(20))
        .shadow(Shadow {
            offset: [0, 2],
            blur: 14,
            spread: 0,
            color: Color32::from_black_alpha(if p.dark { 70 } else { 14 }),
        })
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            add(ui)
        })
        .inner
}

pub fn page_title(ui: &mut Ui, title: &str, subtitle: &str) {
    ui.add_space(6.0);
    ui.label(RichText::new(title).font(semibold(30.0)));
    ui.label(
        RichText::new(subtitle)
            .size(15.0)
            .color(palette(ui).secondary),
    );
    ui.add_space(14.0);
}

pub fn card_title(ui: &mut Ui, title: &str) {
    ui.label(RichText::new(title).font(semibold(17.0)));
    ui.add_space(2.0);
}

pub fn secondary(ui: &mut Ui, text: impl Into<String>) {
    let color = palette(ui).secondary;
    ui.label(RichText::new(text.into()).color(color));
}

fn mix(a: Color32, b: Color32, t: f32) -> Color32 {
    let channel = |x: u8, y: u8| (f32::from(x) + (f32::from(y) - f32::from(x)) * t).round() as u8;
    Color32::from_rgb(
        channel(a.r(), b.r()),
        channel(a.g(), b.g()),
        channel(a.b(), b.b()),
    )
}

/// iOS-style switch; announced to screen readers as a labelled switch.
pub fn switch(ui: &mut Ui, on: &mut bool, label: &str) -> Response {
    let p = palette(ui);
    let (rect, mut response) = ui.allocate_exact_size(vec2(46.0, 28.0), Sense::click());
    if response.clicked() {
        *on = !*on;
        response.mark_changed();
    }
    let enabled = ui.is_enabled();
    let state = *on;
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Switch, enabled, state, label));
    let t = ui.ctx().animate_bool_responsive(response.id, *on);
    if ui.is_rect_visible(rect) {
        let off = if p.dark {
            Color32::from_rgb(0x48, 0x48, 0x4A)
        } else {
            Color32::from_rgb(0xE5, 0xE5, 0xEA)
        };
        let radius = rect.height() / 2.0;
        ui.painter().rect_filled(rect, radius, mix(off, p.green, t));
        let x = egui::lerp((rect.left() + radius)..=(rect.right() - radius), t);
        let center = egui::pos2(x, rect.center().y);
        ui.painter().circle_filled(
            center + vec2(0.0, 1.0),
            radius - 2.0,
            Color32::from_black_alpha(40),
        );
        ui.painter()
            .circle_filled(center, radius - 2.5, Color32::WHITE);
        if response.has_focus() {
            ui.painter().rect_stroke(
                rect.expand(2.0),
                radius + 2.0,
                Stroke::new(2.0, p.blue),
                egui::StrokeKind::Outside,
            );
        }
    }
    response
}

/// A settings row: title and description on the left, a switch on the right.
pub fn switch_row(ui: &mut Ui, on: &mut bool, title: &str, description: &str) -> bool {
    let mut changed = false;
    ui.horizontal(|ui| {
        ui.vertical(|ui| {
            ui.set_width((ui.available_width() - 70.0).max(120.0));
            ui.label(RichText::new(title).size(15.5));
            if !description.is_empty() {
                secondary(ui, description);
            }
        });
        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
            changed = switch(ui, on, title).changed();
        });
    });
    changed
}

pub fn primary_button(ui: &mut Ui, text: &str) -> Response {
    let p = palette(ui);
    ui.add(
        egui::Button::new(
            RichText::new(text)
                .color(Color32::WHITE)
                .font(semibold(15.0)),
        )
        .fill(p.blue)
        .corner_radius(CornerRadius::same(10))
        .min_size(vec2(0.0, 36.0)),
    )
}

pub fn quiet_button(ui: &mut Ui, text: &str) -> Response {
    let p = palette(ui);
    ui.add(
        egui::Button::new(RichText::new(text).color(p.blue))
            .frame(false)
            .min_size(vec2(0.0, 28.0)),
    )
}

/// A sidebar entry: icon + label, filled when selected.
pub fn nav_item(ui: &mut Ui, glyph: &str, label: &str, selected: bool) -> Response {
    let p = palette(ui);
    let (rect, response) = ui.allocate_exact_size(vec2(ui.available_width(), 38.0), Sense::click());
    response.widget_info(|| egui::WidgetInfo::selected(egui::Role::Tab, true, selected, label));
    if ui.is_rect_visible(rect) {
        let fill = if selected {
            p.blue
        } else if response.hovered() {
            p.stroke
        } else {
            Color32::TRANSPARENT
        };
        ui.painter().rect_filled(rect, 9.0, fill);
        let color = if selected { Color32::WHITE } else { p.text };
        let glyph_color = if selected { Color32::WHITE } else { p.blue };
        ui.painter().text(
            rect.left_center() + vec2(14.0, 0.0),
            egui::Align2::LEFT_CENTER,
            glyph,
            icons(16.0),
            glyph_color,
        );
        ui.painter().text(
            rect.left_center() + vec2(42.0, 0.0),
            egui::Align2::LEFT_CENTER,
            label,
            FontId::proportional(15.0),
            color,
        );
    }
    response
}

/// One number on a card: small caption above a large figure.
pub fn metric(ui: &mut Ui, caption: &str, value: impl ToString, color: Option<Color32>) {
    let p = palette(ui);
    card(ui, |ui| {
        ui.label(RichText::new(caption).size(13.0).color(p.secondary));
        ui.label(
            RichText::new(value.to_string())
                .font(semibold(30.0))
                .color(color.unwrap_or(p.text)),
        );
    });
}

/// A row of equally wide metric cards.
pub fn metrics(ui: &mut Ui, items: &[(&str, String, Option<Color32>)]) {
    ui.columns(items.len(), |columns| {
        for (column, (caption, value, color)) in columns.iter_mut().zip(items) {
            metric(column, caption, value, *color);
        }
    });
}

/// A table row inside a card: cells at fixed fractions of the width.
pub fn table_row(ui: &mut Ui, cells: &[(String, Option<Color32>)], widths: &[f32], header: bool) {
    let p = palette(ui);
    let total = ui.available_width();
    ui.horizontal(|ui| {
        for ((text, color), width) in cells.iter().zip(widths) {
            let mut rich = RichText::new(text);
            rich = if header {
                rich.size(12.5).color(p.secondary)
            } else {
                rich.color(color.unwrap_or(p.text))
            };
            ui.allocate_ui_with_layout(
                vec2(total * width - 10.0, 24.0),
                egui::Layout::left_to_right(egui::Align::Center),
                |ui| {
                    ui.set_min_width(total * width - 10.0);
                    ui.add(egui::Label::new(rich).truncate());
                },
            );
        }
    });
    if header {
        ui.separator();
    }
}

/// A macOS-style list: one row per entry with a remove button and an add
/// field underneath (Enter or "Ekle"). Returns true when the list changed.
pub fn editable_list(
    ui: &mut Ui,
    items: &mut Vec<String>,
    draft: &mut String,
    hint: &str,
    empty: &str,
) -> bool {
    let p = palette(ui);
    let mut changed = false;
    let mut remove = None;
    egui::Frame::new()
        .fill(p.field)
        .corner_radius(CornerRadius::same(10))
        .inner_margin(Margin::symmetric(14, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            if items.is_empty() {
                ui.add_space(4.0);
                secondary(ui, empty);
                ui.add_space(4.0);
            }
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    ui.separator();
                }
                ui.horizontal(|ui| {
                    ui.label(RichText::new(item).size(15.0));
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let button = ui
                            .add(
                                egui::Button::new(
                                    RichText::new(icon::REMOVE).font(icons(13.0)).color(p.red),
                                )
                                .frame(false)
                                .min_size(vec2(28.0, 28.0)),
                            )
                            .on_hover_text("Kaldır");
                        let label = format!("{item} kaldır");
                        button.widget_info(|| {
                            egui::WidgetInfo::labeled(egui::Role::Button, true, &label)
                        });
                        if button.clicked() {
                            remove = Some(index);
                        }
                    });
                });
            }
        });
    if let Some(index) = remove {
        items.remove(index);
        changed = true;
    }
    ui.add_space(4.0);
    ui.horizontal(|ui| {
        let field = ui.add(
            egui::TextEdit::singleline(draft)
                .hint_text(hint)
                .desired_width((ui.available_width() - 90.0).max(120.0))
                .margin(Margin::symmetric(12, 7)),
        );
        let entered = field.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        let ready = !draft.trim().is_empty();
        let clicked = ui
            .add_enabled(ready, egui::Button::new("Ekle").min_size(vec2(72.0, 32.0)))
            .clicked();
        if ready && (clicked || entered) {
            let value = draft.trim().to_string();
            if !items.contains(&value) {
                items.push(value);
                changed = true;
            }
            draft.clear();
            if entered {
                field.request_focus();
            }
        }
    });
    changed
}

pub const SIDEBAR_WIDTH: f32 = 236.0;
pub const CONTENT_MAX_WIDTH: f32 = 980.0;
pub const WINDOW_SIZE: Vec2 = vec2(1180.0, 800.0);
