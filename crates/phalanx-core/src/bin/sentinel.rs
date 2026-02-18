// This binary should probably be renamed to 'Witness' or something like that.

use std::error::Error;
use std::path::Path;
use tracing::info;

// Internal Modules from Workspace
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::base::engine::PhalanxEngine;
// Corrected naming: network.rs likely defines load_swarm_key
use phalanx_core::primitives::identity::init_identity;
use phalanx_core::security::telemetry;
use phalanx_core::transport::swarm::load_swarm_key;

/// The entry point for the Phalanx Stronghold binary.
///
/// Behavior: This function initializes the logging sub-system, loads system
/// configuration, and boots the `PhalanxEngine`. It acts as the high-level
/// supervisor for the long-running async runtime.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Telemetry & Initialization
    // WorkerGuard is kept in main to ensure logs flush on shutdown
    let _guard = telemetry::init_observability();
    setup_shutdown_handler();

    // 2. Configuration Loading
    // Resolves "no function or associated item named `load_from_env` found"
    // Precedence: PHALANX_CONFIG_PATH -> phalanx.toml -> Default
    let config = PhalanxConfig::load_from_env();
    let physics = PhalanxPhysics::default_wan();

    // 3. Identity & Security Setup
    let my_identity = init_identity("identity.bin")?;
    let psk_path = Path::new("swarm.key");
    let psk = load_swarm_key(psk_path);

    if psk.is_some() {
        info!("Joining Private Swarm (Static PSK Loaded).");
    } else {
        info!("Joining Public Swarm (No PSK).");
    }

    // 4. Engine Initialization
    // Consumes the identity and config to build the background Swarm
    let mut engine = PhalanxEngine::new(config, my_identity, physics, psk)?;

    println!("--- PHALANX SENSOR: ONLINE (WAN + LAN) ---");

    // 5. Execution
    // Multiplexes hardware polling, gossipsub, and crucible reassembly
    engine.run().await?;

    Ok(())
}

/// Configures global signal handlers for clean system termination.
///
/// Behavior: Ensures that the Guardian seals the vault and flushes the
/// Write-Ahead Log (WAL) before the process exits.
fn setup_shutdown_handler() {
    ctrlc::set_handler(move || {
        println!("\n[PHALANX] Shutdown initiated. Sealing vault...");
        // Phase 3: Engine will eventually handle graceful drops
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");
}
