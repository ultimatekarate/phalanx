use std::env;
use std::error::Error;
use std::path::PathBuf;
use tokio::fs;

use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::primitives::identity::PhalanxIdentity;
use phalanx_core::security::telemetry;
use phalanx_core::storage::journal::FileJournal;
use phalanx_core::storage::stronghold::StrongholdEngine;
use phalanx_core::transport::libp2p_adapter::Libp2pAdapter;
use phalanx_core::transport::swarm::{get_storage_key, setup_phalanx_swarm};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    telemetry::init_subscriber();
    tracing::info!("Initializing Phalanx Stronghold Composition Root...");

    // 1. Resolve Environment Paths
    let root_dir = env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));

    let config_path = root_dir.join("phalanx.toml");
    let psk_path = root_dir.join("swarm.key");

    // 2. Load Configuration and Identity
    let config = PhalanxConfig::load_from_file(&config_path)?;
    let physics = PhalanxPhysics::default_wan();
    let identity = PhalanxIdentity::load_or_generate(&config.identity_path)?;
    let local_peer_id = identity.to_network_id();

    tracing::info!(peer_id = %local_peer_id, "Identity verified.");

    // 3. Network Infrastructure Provisioning
    let psk_bytes = fs::read(&psk_path).await.map_err(|e| {
        tracing::error!(error = %e, path = ?psk_path, "Failed to load pre-shared swarm key.");
        e
    })?;

    // Convert identity to libp2p cryptographic types
    let libp2p_key = identity.to_libp2p_keypair();

    // Initialize the raw swarm
    let mut swarm = setup_phalanx_swarm(libp2p_key, &config, &physics, Some(psk_bytes))?;

    // Announce storage capabilities to the Kademlia DHT
    let storage_key = get_storage_key();
    if let Err(kad_err) = swarm.behaviour_mut().kademlia.start_providing(storage_key) {
        tracing::warn!(error = %kad_err, "Failed to announce storage capability to Kademlia DHT.");
    }

    // Bind to the specified network interface
    let listen_port = config.network.listen_port.unwrap_or(4001);
    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", listen_port).parse()?;
    swarm.listen_on(listen_addr)?;

    // Wrap the raw swarm in the abstraction layer
    let network_adapter = Libp2pAdapter::new(swarm);

    // 4. Storage Infrastructure Provisioning
    let journal_path = root_dir.join(&config.storage.journal_dir);
    let transient_journal = FileJournal::new(journal_path).await?;

    // 5. Engine Ignition
    let mut engine = StrongholdEngine::new(
        config,
        identity,
        physics,
        network_adapter,
        transient_journal,
    )?;

    tracing::info!("Stronghold Engine provisioned. Commencing run loop.");

    // Relinquish control to the engine
    engine.run().await?;

    Ok(())
}
