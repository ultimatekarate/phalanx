use phalanx_node::state::SyncReputationCache;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::init_observability;
use phalanx_node::FileJournal;
use phalanx_node::NodeConfig;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::prelude::PhalanxPhysics;
use phalanx_transport::prelude::Libp2pAdapter;
use std::sync::Arc;
use tokio::sync::mpsc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_observability();

    let config = NodeConfig::load("phalanx.toml")?;
    let identity = PhalanxIdentity::new_ephemeral();
    let physics = PhalanxPhysics::default_wan();

    // --- ZERO-TRUST DEPENDENCY GRAPH ---
    // Initialize the asynchronous trust registry and the synchronous cache boundary.
    let trust_registry = TrustRegistry::build(&config).await;
    let reputation_cache = Arc::new(SyncReputationCache::default());

    let mut swarm = setup_phalanx_swarm(
        identity.to_libp2p_keypair(),
        &config,
        &physics,
        None,
        reputation_cache.clone(),
    )?;

    // Subscription and DHT logic remains here to keep Engine transport-agnostic
    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;

    let network = Libp2pAdapter::new(swarm);
    let journal = FileJournal::new("crucible_wal.bin").await?;
    let (discovery_tx, discovery_rx) = mpsc::channel(100);
    // Instantiate the unified engine
    let mut engine = PhalanxEngine::new(
        config,
        identity,
        network,
        journal,
        trust_registry,
        reputation_cache,
        discovery_rx,
        discovery_tx,
    )
    .await?;

    engine.run().await
}
