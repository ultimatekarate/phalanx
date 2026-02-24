use phalanx_core::base::engine::{PhalanxEngine, SyncReputationCache};
use phalanx_core::security::trust::TrustRegistry;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    phalanx_core::security::telemetry::init_observability();

    let config = phalanx_core::base::config::PhalanxConfig::load("phalanx.toml")?;
    let (identity, _) = phalanx_core::primitives::identity::PhalanxIdentity::generate()?;
    let physics = phalanx_core::base::config::PhalanxPhysics::default_wan();

    // --- ZERO-TRUST DEPENDENCY GRAPH ---
    // Initialize the asynchronous trust registry and the synchronous cache boundary.
    let trust_registry = TrustRegistry::build(&config).await;
    let reputation_cache = Arc::new(SyncReputationCache::default());

    let mut swarm = phalanx_core::transport::swarm::setup_phalanx_swarm(
        identity.to_libp2p_keypair(),
        &config,
        &physics,
        None,
        reputation_cache.clone(),
    )?;

    // Subscription and DHT logic remains here to keep Engine transport-agnostic
    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;

    let network = phalanx_core::transport::libp2p_adapter::Libp2pAdapter::new(swarm);
    let journal = phalanx_core::storage::journal::FileJournal::new("crucible_wal.bin").await?;

    // Instantiate the unified engine
    let mut engine = PhalanxEngine::new(
        config,
        identity,
        network,
        journal,
        trust_registry,
        reputation_cache,
    )
    .await?;

    engine.run().await
}
