// crates/phalanx-stronghold/src/swarm.rs
//
// Swarm setup for the Stronghold daemon. Uses the transport factory
// with an ephemeral in-memory DHT store (no redb dependency).
//
// Hands layer — owns transport initialization.

use async_trait::async_trait;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::network::{IngressPort, TransportError};
use phalanx_transport::prelude::*;
use tokio::sync::mpsc;

use crate::config::NetworkConfig;

/// Gossipsub topics the Stronghold subscribes to: both media topics (passive
/// gossip collection) and the revocation topic — `StrongholdSentinel` honors
/// inbound `RevocationToken`s against held custody copies. All three are
/// profile-projected, so they cannot drift from the node's published topics.
#[must_use]
pub fn subscribe_topics(network_config: &NetworkConfig) -> Vec<String> {
    vec![
        network_config.video_topic.to_string(),
        network_config.audio_topic.to_string(),
        network_config.revocation_topic.to_string(),
    ]
}

/// Set up a mesh transport for the Stronghold using an ephemeral DHT store.
pub fn setup_stronghold_swarm(
    identity: &PhalanxIdentity,
    network_config: &NetworkConfig,
) -> Result<(Libp2pIngress, Libp2pEgress), TransportError> {
    let transport_config = MeshTransportConfig {
        listen_addresses: network_config.listen_addresses.clone(),
        bootstrap_peers: network_config.bootstrap_peers.clone(),
        subscribe_topics: subscribe_topics(network_config),
        // Profile-pinned: the same protocol version the node projects, so the
        // node and the Stronghold share one Kademlia DHT (the divergent
        // 1.0.0/1.1.0 default was the silent partition this refactor closes).
        protocol_version: network_config.protocol_version.clone(),
        require_psk: network_config.require_psk,
        kademlia_filter_both: false,
        ..MeshTransportConfig::default()
    };

    build_mesh_transport(identity, &transport_config)
}

/// Thin ingress wrapper around `mpsc::Receiver<NetworkEvent>`.
/// Bridges the factory's ingress receiver to the `IngressPort` trait
/// consumed by `StrongholdSentinel`.
pub struct StrongholdIngress {
    rx: mpsc::Receiver<NetworkEvent>,
}

impl StrongholdIngress {
    pub fn new(rx: mpsc::Receiver<NetworkEvent>) -> Self {
        Self { rx }
    }
}

#[async_trait]
impl IngressPort for StrongholdIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.rx.recv().await
    }
}
