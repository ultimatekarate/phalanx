use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use tracing::info;

// Internal Modules from Workspace
use phalanx_forensics::PeerEvaluator;
use phalanx_node::actors::meshsentinel::SentinelDependencies;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::network::bridge::Libp2pBridge;
use phalanx_node::network::orchestrator::setup_phalanx_swarm;
use phalanx_node::persistence::vault::{derive_vault_key, load_or_create_vault_salt};
use phalanx_node::psk::load_swarm_key;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::init_observability;
use phalanx_node::FileJournal;
use phalanx_node::MeshSentinel;
use phalanx_proto::prelude::{PhalanxIdentity, PhalanxPhysics};
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::prelude::Libp2pAdapter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Telemetry & Initialization
    init_observability();
    setup_shutdown_handler();

    // Configuration Loading
    let config = NodeConfig::load_from_env();
    let physics = PhalanxPhysics::default_wan();

    // TODO: Hard coded for now, this will come from the UI once it is built.
    let identity_passphrase = std::env::var("PHALANX_IDENTITY_PASSPHRASE")
        .map_err(|_| "Security Violation: PHALANX_IDENTITY_PASSPHRASE not set")?;

    // Identity & Security Setup
    let my_identity = PhalanxIdentity::init("identity.bin", &identity_passphrase)?;
    let psk_path = Path::new("swarm.key");
    let psk = load_swarm_key(psk_path);

    if psk.is_some() {
        info!("Joining Private Swarm (Static PSK Loaded).");
    } else {
        info!("Joining Public Swarm (No PSK).");
    }

    info!("Initializing Transient WAL");
    let vault_salt = load_or_create_vault_salt("vault")?;
    let vault_key = derive_vault_key(&my_identity, &vault_salt);
    let journal = FileJournal::new("sentinel_transient_wal.bin", vault_key.clone()).await?;

    // --- ZERO-TRUST DEPENDENCY GRAPH ---
    // External registry for swarm's gossipsub validator.
    // MeshSentinel::new() builds its own internal registry for actor operations.
    let trust_registry = TrustRegistry::build(&config).await;
    let reputation_projection = trust_registry.projection_handle();

    // Production Network Adapter Setup (Hexagonal Port Injection)
    let network_keypair = my_identity.to_libp2p_keypair();
    let swarm = setup_phalanx_swarm(
        network_keypair,
        &config,
        &physics,
        psk,
        Arc::new(reputation_projection) as Arc<dyn PeerEvaluator>,
    )?;

    let adapter = Libp2pAdapter::new(swarm);
    let bridge = Libp2pBridge::new(adapter);
    let (ingress, egress) = bridge.split();

    // Engine Initialization via Parameter Object
    let deps = SentinelDependencies {
        config,
        identity: my_identity,
        ingress,
        egress,
        journal,
        trust_registry,
        system_governor: Arc::new(phalanx_node::vitals::SystemGovernor::new()),
        vault_key,
        local_mesh: None, // NoOp — BLE/WiFi Direct injected during mobile integration
    };

    let mut engine = MeshSentinel::new(deps).await?;

    println!("--- PHALANX SENSOR: ONLINE (WAN + LAN) ---");

    // Execution
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
