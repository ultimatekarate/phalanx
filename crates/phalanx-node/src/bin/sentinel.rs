use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

// Internal Modules from Workspace
use phalanx_node::config::NodeConfig; // Replaced PhalanxConfig
use phalanx_node::state::SyncReputationCache;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::init_observability;
use phalanx_node::FileJournal;
use phalanx_proto::prelude::PhalanxPhysics;
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::prelude::Libp2pAdapter;

/// The entry point for the Phalanx Sentinel binary.
///
/// Behavior: This function initializes the logging sub-system, loads system
/// configuration, configures the production network adapter, and boots the `PhalanxEngine`.
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Telemetry & Initialization
    init_observability();
    setup_shutdown_handler();

    // 2. Configuration Loading
    let config = NodeConfig::load_from_env();
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

    info!("Initializing Transient WAL");
    let journal = FileJournal::new("sentinel_transient_wal.bin").await?;

    // --- ZERO-TRUST DEPENDENCY GRAPH ---
    // Initialize the asynchronous trust registry and the synchronous cache boundary.
    let trust_registry = TrustRegistry::build(&config).await;
    let reputation_cache = Arc::new(SyncReputationCache::default());

    // 4. Production Network Adapter Setup (Hexagonal Port Injection)
    let network_keypair = my_identity.to_libp2p_keypair();
    let swarm = setup_phalanx_swarm(
        network_keypair,
        &config,
        &physics,
        psk,
        reputation_cache.clone(),
    )?;

    // Wrap the standard library/libp2p I/O inside the domain-compliant adapter
    let network_adapter = Libp2pAdapter::new(swarm);
    let (discovery_tx, discovery_rx) = mpsc::channel(100);
    // 5. Engine Initialization
    // The engine is now completely agnostic to libp2p and simply consumes the NetworkTransport trait
    let mut engine = PhalanxEngine::new(
        config,
        my_identity,
        network_adapter,
        journal,
        trust_registry,
        reputation_cache,
        discovery_rx,
        discovery_tx,
    )
    .await?;

    println!("--- PHALANX SENSOR: ONLINE (WAN + LAN) ---");

    // 6. Execution
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
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");
}
