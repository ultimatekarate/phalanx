use phalanx_node::actors::meshsentinel::SentinelDependencies;
use phalanx_node::network::bridge::Libp2pBridge;
use phalanx_node::network::orchestrator::setup_phalanx_swarm;
use phalanx_node::state::SyncReputationCache;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::init_observability;
use phalanx_node::FileJournal;
use phalanx_node::MeshSentinel;
use phalanx_node::NodeConfig;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::prelude::PhalanxPhysics;
use phalanx_transport::identity_ext::Libp2pExt;
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
    let trust_registry = TrustRegistry::build(&config).await;
    let reputation_cache = Arc::new(SyncReputationCache::default());

    let mut swarm = setup_phalanx_swarm(
        identity.to_libp2p_keypair(),
        &config,
        &physics,
        None,
        reputation_cache.clone(),
    )?;

    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;

    let adapter = Libp2pAdapter::new(swarm);
    let network = Libp2pBridge::new(adapter);

    let journal = FileJournal::new("crucible_wal.bin").await?;
    let (discovery_tx, discovery_rx) = mpsc::channel(100);

    // 5. Engine Initialization via Parameter Object
    let deps = SentinelDependencies {
        config,
        identity,
        network,
        journal,
        trust_registry,
        reputation_cache,
        discovery_rx,
        discovery_tx,
    };

    let mut engine: MeshSentinel<Libp2pBridge, FileJournal> = MeshSentinel::new(deps).await?;

    engine.run().await
}
