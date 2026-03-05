use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::info;

// Internal Modules from Workspace
use phalanx_node::actors::meshsentinel::SentinelDependencies;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::network::bridge::Libp2pBridge;
use phalanx_node::network::orchestrator::setup_phalanx_swarm;
use phalanx_node::psk::load_swarm_key;
use phalanx_node::state::SyncReputationCache;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::init_observability;
use phalanx_node::FileJournal;
use phalanx_node::MeshSentinel;
use phalanx_proto::prelude::{PhalanxIdentity, PhalanxPhysics};
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::prelude::Libp2pAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // 1. Telemetry & Initialization
    init_observability();
    setup_shutdown_handler();

    // 2. Configuration Loading
    let config = NodeConfig::load_from_env();
    let physics = PhalanxPhysics::default_wan();

    // 3. Identity & Security Setup
    let my_identity = PhalanxIdentity::init("identity.bin")?;
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

    let adapter = Libp2pAdapter::new(swarm);
    let network = Libp2pBridge::new(adapter);

    let (discovery_tx, discovery_rx) = mpsc::channel(100);

    // 5. Engine Initialization via Parameter Object
    let deps = SentinelDependencies {
        config,
        identity: my_identity,
        network,
        journal,
        trust_registry,
        reputation_cache,
        discovery_rx,
        discovery_tx,
    };

    let mut engine: MeshSentinel<Libp2pBridge, FileJournal> = MeshSentinel::new(deps).await?;

    println!("--- PHALANX SENSOR: ONLINE (WAN + LAN) ---");

    // 6. Execution
    engine.run().await?;

    Ok(())
}

fn setup_shutdown_handler() {
    ctrlc::set_handler(move || {
        println!("\n[PHALANX] Shutdown initiated. Sealing vault...");
        std::process::exit(0);
    })
    .expect("Error setting Ctrl-C handler");
}
