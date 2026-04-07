// crates/phalanx-stronghold/src/gui/mod.rs
//
// StrongholdApp: eframe application. Dispatches rendering to panels
// based on AppPhase. Handles phase transitions (Startup → Running).
//
// Hands layer — presentation and wiring only.

pub mod bridge;
pub mod panels;
pub mod state;
pub mod widgets;

use eframe::egui;
use zeroize::Zeroizing;

use state::{AppPhase, PanelId};

// ── StrongholdApp ──────────────────────────────────────────────────────

pub struct StrongholdApp {
    phase: AppPhase,
}

impl StrongholdApp {
    pub fn new() -> Self {
        // Pre-fill passphrase from env var if available
        let passphrase = std::env::var("PHALANX_IDENTITY_PASSPHRASE").unwrap_or_default();

        Self {
            phase: AppPhase::Startup {
                passphrase_buf: Zeroizing::new(passphrase),
                config_path: "stronghold.toml".into(),
                error: None,
            },
        }
    }
}

impl eframe::App for StrongholdApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // Phase transition target — set by startup panel on successful launch
        let mut next_phase = None;

        match &mut self.phase {
            AppPhase::Startup {
                passphrase_buf,
                config_path,
                error,
            } => {
                panels::startup::render(ctx, passphrase_buf, config_path, error, &mut next_phase);
            }

            AppPhase::Running {
                bridge,
                active_panel,
                panels,
            } => {
                // Poll all pending async replies (non-blocking)
                panels.poll_all();

                // Top navigation bar
                egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
                    ui.horizontal(|ui| {
                        ui.heading("PHALANX STRONGHOLD");
                        ui.separator();

                        // Truncated DID display
                        let did = bridge.identity.did.to_string();
                        let short_did = did.get(..24).unwrap_or(&did);
                        ui.monospace(short_did);
                        ui.separator();

                        // Panel tabs
                        let tab_defs = [
                            (PanelId::Dashboard, "Dashboard"),
                            (PanelId::Communities, "Communities"),
                            (PanelId::Recordings, "Recordings"),
                            (PanelId::Corroborate, "Corroborate"),
                            (PanelId::Export, "Export"),
                        ];

                        for (id, label) in &tab_defs {
                            if ui.selectable_label(*active_panel == *id, *label).clicked() {
                                *active_panel = *id;
                            }
                        }
                    });
                });

                // Main content panel
                egui::CentralPanel::default().show(ctx, |ui| {
                    match active_panel {
                        PanelId::Dashboard => {
                            panels::dashboard::render(ui, ctx, bridge);
                        }
                        PanelId::Communities => {
                            panels::communities::render(ui, ctx, bridge, &mut panels.communities);
                        }
                        PanelId::Recordings => {
                            // Borrow communities state immutably while recordings state
                            // is borrowed mutably — safe because they are separate fields.
                            let communities_state = &panels.communities;
                            panels::recordings::render(
                                ui,
                                ctx,
                                bridge,
                                &mut panels.recordings,
                                communities_state,
                            );
                        }
                        PanelId::Corroborate => {
                            panels::corroborate::render(ui, ctx, bridge, &mut panels.corroborate);
                        }
                        PanelId::Export => {
                            panels::export::render(ui, ctx, bridge, &mut panels.export);
                        }
                    }
                });
            }

            AppPhase::Failed { message } => {
                egui::CentralPanel::default().show(ctx, |ui| {
                    ui.add_space(40.0);
                    ui.colored_label(egui::Color32::RED, format!("Fatal: {message}"));
                });
            }
        }

        // Apply phase transition outside the match to avoid borrow conflicts.
        // The old Startup phase is dropped here — Zeroizing<String> wipes the passphrase.
        if let Some(phase) = next_phase {
            self.phase = phase;
        }
    }
}
