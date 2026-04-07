// crates/phalanx-stronghold/src/gui/panels/dashboard.rs
//
// Live Volterra gauge dashboard. Reads directly from Arc<StrongholdGovernor>
// via RwLock::read() — zero channel overhead, zero allocation.
// Repaints at 2 Hz via request_repaint_after.

use std::time::Duration;

use eframe::egui;
use phalanx_forensics::policy::Homeostasis;

use crate::gui::bridge::DaemonBridge;
use crate::gui::widgets::gauge_bar;

pub fn render(ui: &mut egui::Ui, ctx: &egui::Context, bridge: &DaemonBridge) {
    ui.heading("System Dashboard");
    ui.add_space(12.0);

    ui.horizontal(|ui| {
        ui.label("DID:");
        ui.monospace(bridge.identity.did.to_string());
    });

    ui.add_space(8.0);
    ui.label("Daemon status: Online");

    ui.add_space(20.0);
    ui.separator();
    ui.add_space(8.0);

    ui.heading("Volterra Homeostasis");
    ui.add_space(8.0);

    let gov = &bridge.governor;

    // Composite stress is 0.0 (idle) to 1.0+ (saturated).
    // Invert for gauge display: 1.0 = healthy, 0.0 = saturated.
    let stress = gov.composite_stress();
    let stress_health = (1.0 - stress).max(0.0);
    gauge_bar(ui, "Composite Health", stress_health);

    ui.add_space(4.0);

    // Scalers are already 0.0–1.0 where 1.0 = healthy
    gauge_bar(ui, "Ingestion      ", gov.ingestion_scaler().0);
    ui.add_space(2.0);
    gauge_bar(ui, "Storage        ", gov.storage_scaler().0);
    ui.add_space(2.0);
    gauge_bar(ui, "Bandwidth      ", gov.bandwidth_scaler().0);
    ui.add_space(2.0);
    gauge_bar(ui, "Memory         ", gov.memory_scaler().0);
    ui.add_space(2.0);
    gauge_bar(ui, "Connections    ", gov.connection_scaler().0);

    ui.add_space(16.0);
    ui.separator();
    ui.add_space(8.0);

    // Configuration summary
    ui.heading("Configuration");
    ui.add_space(4.0);
    ui.monospace(format!("Vault: {}", bridge.vault_path.display()));
    ui.monospace(format!(
        "Listen: {:?}",
        bridge.config.network.listen_addresses
    ));

    // Request repaint at 2 Hz for live gauge updates
    ctx.request_repaint_after(Duration::from_millis(500));
}
