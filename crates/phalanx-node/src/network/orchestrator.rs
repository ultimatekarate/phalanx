use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libp2p::{
    core::upgrade::Version, identity::Keypair, kad, noise, pnet::PreSharedKey, relay, swarm::SwarmBuilder,
    yamux, Swarm, StreamProtocol
};
use libp2p::request_response::{self, ProtocolSupport};

use phalanx_proto::constants::RETRIEVAL_PROTOCOL_ID;
use crate::config::PhalanxConfig;
// Note: PhalanxPhysics and PeerEvaluator must be imported from the appropriate crates

pub fn setup_phalanx_swarm(
    local_key: Keypair,
    config: &PhalanxConfig,
    physics: &PhalanxPhysics,
    psk: Option<PreSharedKey>,
    evaluator: Arc<dyn PeerEvaluator>,
) -> Result<Swarm<phalanx_transport::PhalanxBehaviour<phalanx_node::RedbStore>>, Box<dyn Error>> {
    let local_peer_id = local_key.public().to_peer_id();
    tracing::info!(target: "phalanx_node::orchestrator", peer_id = %local_peer_id, "Initializing Network Stack");

    // 1. Persistent Kademlia Store Construction
    let dht_db_path = Path::new(&config.storage.vault_path).join("dht_store.redb");
    let local_network_id = phalanx_proto::NetworkId::from(local_peer_id);
    let persistent_store = phalanx_node::RedbStore::new(&dht_db_path, local_network_id, evaluator)?;

    // 2. Kademlia Protocol Validation
    let protocol_str = format!("/phalanx/kad/{}", config.network.protocol_version);
    let kad_protocol = StreamProtocol::try_from_owned(protocol_str)?;
    let kad_config = kad::Config::new(kad_protocol);
    let kademlia_behaviour = kad::Behaviour::with_config(local_peer_id, persistent_store, kad_config);

    // 3. Relay Initialization
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);

    // 4. Transport and Behaviour Composition via phalanx-transport
    let base_transport = phalanx_transport::build_base_transport(&local_key, psk)?;
    let composite_behaviour = phalanx_transport::build_behaviour(
        &local_key, 
        config, 
        physics, 
        relay_client, 
        kademlia_behaviour
    )?;

    // 5. Swarm Assembly
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|_key| base_transport)?
        .with_other_transport(|key| {
            let noise_config = noise::Config::new(key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let yamux_config = yamux::Config::default();

            Ok(relay_transport
                .upgrade(Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux_config))
        })?
        .with_behaviour(|_| composite_behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}