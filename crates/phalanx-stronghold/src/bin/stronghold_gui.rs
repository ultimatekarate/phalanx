// crates/phalanx-stronghold/src/bin/stronghold_gui.rs
//
// Desktop GUI entry point. eframe owns the main thread event loop.
// Tokio runtime is created inside DaemonBridge on "Launch" click.
// No #[tokio::main] — eframe and tokio coexist without contention.

use eframe::egui;
use tracing_subscriber::EnvFilter;

fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1024.0, 768.0])
            .with_title("Phalanx Stronghold"),
        ..Default::default()
    };

    eframe::run_native(
        "Phalanx Stronghold",
        options,
        Box::new(|_cc| Ok(Box::new(phalanx_stronghold::gui::StrongholdApp::new()))),
    )
}
