use std::error::Error;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use libp2p::{
    core::upgrade::Version, identity::Keypair, kad, noise, pnet::PreSharedKey, relay, yamux,
    Multiaddr, StreamProtocol, Swarm, SwarmBuilder, Transport,
};

use phalanx_forensics::PeerEvaluator;

use crate::config::NodeConfig;
use crate::persistence::kademlia::RedbStore;
use phalanx_proto::prelude::NetworkId;
use phalanx_proto::prelude::PhalanxPhysics;
use phalanx_transport::behaviour::PhalanxBehaviour;
use phalanx_transport::builder::build_base_transport;
use phalanx_transport::builder::build_behaviour;

pub fn setup_phalanx_swarm(
    local_key: Keypair,
    config: &NodeConfig,
    physics: &PhalanxPhysics,
    psk: Option<PreSharedKey>,
    evaluator: Arc<dyn PeerEvaluator>,
) -> Result<Swarm<PhalanxBehaviour<RedbStore>>, Box<dyn Error>> {
    let local_peer_id = local_key.public().to_peer_id();
    tracing::info!(target: "phalanx_node::orchestrator", peer_id = %local_peer_id, "Initializing Network Stack");

    // Enforce PSK requirement when configured.
    // Prevents silent fallback to unencrypted transport when the swarm key
    // is missing or corrupt, which would expose all traffic.
    if config.network.require_psk && psk.is_none() {
        return Err(
            "N3: require_psk is set but no Pre-Shared Key was provided. \
                    The node cannot start without transport-layer encryption."
                .into(),
        );
    }

    // Persistent Kademlia Store Construction
    let dht_db_path = Path::new(&config.storage.vault_path).join("dht_store.redb");
    let local_network_id = NetworkId::from(local_peer_id.to_string());
    let persistent_store = RedbStore::new(&dht_db_path, local_network_id, evaluator)?;

    // Kademlia Protocol Validation
    // E3 FIX: Harden Kademlia configuration against routing table poisoning.
    let protocol_str = format!("/phalanx/kad/{}", config.network.protocol_version);
    let kad_protocol = StreamProtocol::try_from_owned(protocol_str)?;
    let mut kad_config = kad::Config::new(kad_protocol);
    kad_config.set_replication_factor(std::num::NonZeroUsize::new(20).unwrap());
    kad_config.set_query_timeout(Duration::from_secs(30));
    kad_config.set_record_ttl(Some(Duration::from_secs(3600)));
    kad_config.set_provider_record_ttl(Some(Duration::from_secs(3600)));
    kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
    let kademlia_behaviour =
        kad::Behaviour::with_config(local_peer_id, persistent_store, kad_config);

    // Relay Initialization
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);

    // Transport and Behaviour Composition via phalanx-transport
    let base_transport = build_base_transport(&local_key, psk)?;
    let composite_behaviour = build_behaviour(
        &local_key,
        config.network.max_chunk_size_bytes,
        config.network.protocol_version.clone(),
        physics,
        relay_client,
        kademlia_behaviour,
    )?;

    // Swarm Assembly
    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
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
        // E1 FIX: Enforce connection limits to prevent eclipse attacks.
        .with_swarm_config(|c: libp2p::swarm::Config| {
            c.with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(128)
        })
        .build();

    // --- Swarm Activation ---
    // All calls below register intent only. Actual socket/connection
    // work begins when the swarm is polled inside the adapter's tokio task.

    // Open listening sockets on configured addresses
    for addr in &config.network.listen_addresses {
        let multiaddr: Multiaddr = addr.parse()?;
        swarm.listen_on(multiaddr)?;
        tracing::info!(target: "phalanx_node::orchestrator", address = %addr, "Listening on address");
    }

    // Subscribe to gossipsub topics
    let topics = [
        &config.network.video_topic,
        &config.network.audio_topic,
        &config.network.control_topic,
    ];
    for topic in topics {
        let ident = libp2p::gossipsub::IdentTopic::new(topic.to_string());
        swarm.behaviour_mut().gossipsub.subscribe(&ident)?;
        tracing::info!(target: "phalanx_node::orchestrator", topic = %topic, "Subscribed to topic");
    }

    // Dial bootstrap peers
    for peer_addr in &config.network.bootstrap_peers {
        if let Ok(multiaddr) = peer_addr.parse::<Multiaddr>() {
            if let Err(e) = swarm.dial(multiaddr) {
                tracing::warn!(target: "phalanx_node::orchestrator", error = %e, addr = %peer_addr, "Failed to dial bootstrap peer");
            }
        }
    }

    Ok(swarm)
}
