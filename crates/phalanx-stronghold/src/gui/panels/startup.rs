// crates/phalanx-stronghold/src/gui/panels/startup.rs
//
// Startup screen: passphrase entry, config path, launch button.
// Pre-fills passphrase from PHALANX_IDENTITY_PASSPHRASE env var.

use eframe::egui;
use zeroize::Zeroizing;

use crate::gui::bridge::DaemonBridge;
use crate::gui::state::{AppPhase, PanelId, PanelStates};

/// Render the startup screen. If launch succeeds, writes the new phase
/// to `next_phase` for the caller to apply (avoids borrow conflicts).
pub fn render(
    ctx: &egui::Context,
    passphrase_buf: &mut Zeroizing<String>,
    config_path: &mut String,
    error: &mut Option<String>,
    next_phase: &mut Option<AppPhase>,
) {
    egui::CentralPanel::default().show(ctx, |ui| {
        ui.add_space(40.0);
        ui.vertical_centered(|ui| {
            ui.heading("PHALANX STRONGHOLD");
            ui.add_space(8.0);
            ui.label("Corroboration Server");
        });

        ui.add_space(30.0);

        // Passphrase input
        ui.horizontal(|ui| {
            ui.label("Passphrase:");
            let text: &mut String = passphrase_buf;
            ui.add(
                egui::TextEdit::singleline(text)
                    .password(true)
                    .desired_width(300.0),
            );
        });

        ui.add_space(8.0);

        // Config file path
        ui.horizontal(|ui| {
            ui.label("Config file:");
            ui.add(egui::TextEdit::singleline(config_path).desired_width(300.0));
        });

        ui.add_space(20.0);

        // Launch button
        if ui.button("Launch Stronghold").clicked() {
            match DaemonBridge::launch(passphrase_buf, config_path) {
                Ok(bridge) => {
                    *next_phase = Some(AppPhase::Running {
                        bridge,
                        active_panel: PanelId::Dashboard,
                        panels: PanelStates::default(),
                    });
                }
                Err(msg) => {
                    *error = Some(msg);
                }
            }
        }

        // Error display
        if let Some(err) = error {
            ui.add_space(12.0);
            ui.colored_label(egui::Color32::RED, err.as_str());
        }
    });
}
