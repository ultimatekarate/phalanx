#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    phalanx_core::security::telemetry::init_observability();
    let config = phalanx_core::base::config::PhalanxConfig::load("phalanx.toml")?;
    let (identity, _) = phalanx_core::primitives::identity::PhalanxIdentity::generate()?;
    let physics = phalanx_core::base::config::PhalanxPhysics::default_wan();

    let mut swarm = phalanx_core::transport::swarm::setup_phalanx_swarm(
        identity.to_libp2p_keypair(),
        &config,
        &physics,
        None,
    )?;

    // Subscription and DHT logic remains here to keep Engine transport-agnostic
    swarm.listen_on("/ip4/0.0.0.0/tcp/4001".parse()?)?;

    let network = phalanx_core::transport::libp2p_adapter::Libp2pAdapter::new(swarm);
    let journal = phalanx_core::storage::journal::FileJournal::new("crucible_wal.bin").await?;

    let mut engine =
        phalanx_core::base::engine::PhalanxEngine::new(config, identity, physics, network, journal)
            .await?;

    engine.run().await
}
