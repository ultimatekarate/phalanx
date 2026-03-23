// crates/phalanx-stronghold/src/swarm.rs
//
// Swarm setup for the Stronghold daemon. Uses the transport factory
// with an ephemeral in-memory DHT store (no redb dependency).
//
// Hands layer — owns transport initialization.

use async_trait::async_trait;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::network::NetworkEvent;
use phalanx_transport::prelude::*;
use tokio::sync::mpsc;

use crate::config::NetworkConfig;

/// Set up a mesh transport for the Stronghold using an ephemeral DHT store.
pub fn setup_stronghold_swarm(
    identity: &PhalanxIdentity,
    network_config: &NetworkConfig,
) -> Result<(Libp2pAdapter, mpsc::Receiver<NetworkEvent>), TransportError> {
    let transport_config = MeshTransportConfig {
        listen_addresses: network_config.listen_addresses.clone(),
        bootstrap_peers: network_config.bootstrap_peers.clone(),
        subscribe_topics: vec![
            network_config.video_topic.to_string(),
            network_config.audio_topic.to_string(),
        ],
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
