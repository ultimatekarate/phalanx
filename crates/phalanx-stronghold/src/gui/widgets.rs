// crates/phalanx-stronghold/src/gui/widgets.rs
//
// Shared rendering widgets: gauge bars, hex labels, status badges.
// Pure geometric — no textures, no images.
//
// Hands layer — presentation only.

use eframe::egui;

/// Horizontal gauge bar with label and color coding.
///
/// `value` is a scaler in [0.0, 1.0] where 1.0 = healthy, 0.0 = saturated.
/// Green > 0.5, yellow 0.2–0.5, red < 0.2.
#[allow(
    clippy::cast_possible_truncation, // f64→f32 for scaler values in [0, 1]
    clippy::arithmetic_side_effects   // available_width * fill bounded by widget size
)]
pub fn gauge_bar(ui: &mut egui::Ui, label: &str, value: f64) {
    let value_f32 = value as f32;
    let fill = value_f32.clamp(0.0, 1.0);

    let color = if fill > 0.5 {
        egui::Color32::from_rgb(80, 180, 80) // green
    } else if fill > 0.2 {
        egui::Color32::from_rgb(220, 180, 40) // yellow
    } else {
        egui::Color32::from_rgb(200, 60, 60) // red
    };

    ui.horizontal(|ui| {
        ui.label(format!("{label}:"));
        let available = ui.available_width().min(300.0);
        let (rect, _response) =
            ui.allocate_exact_size(egui::vec2(available, 18.0), egui::Sense::hover());

        // Background
        ui.painter()
            .rect_filled(rect, 3.0, egui::Color32::from_gray(40));

        // Fill
        let fill_width = rect.width() * fill;
        let fill_rect = egui::Rect::from_min_size(rect.min, egui::vec2(fill_width, rect.height()));
        ui.painter().rect_filled(fill_rect, 3.0, color);

        // Percentage text
        let pct = format!("{:.0}%", fill * 100.0);
        ui.painter().text(
            rect.center(),
            egui::Align2::CENTER_CENTER,
            pct,
            egui::FontId::proportional(12.0),
            egui::Color32::WHITE,
        );
    });
}

/// Format a 32-byte hash as a hex string.
#[allow(clippy::arithmetic_side_effects)] // Capacity: 32 * 2 = 64, always fits.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Display a hex hash truncated to the first 16 characters.
pub fn short_hex(bytes: &[u8; 32]) -> String {
    let full = hex_encode(bytes);
    full.get(..16).map(|s| format!("{s}...")).unwrap_or(full)
}
