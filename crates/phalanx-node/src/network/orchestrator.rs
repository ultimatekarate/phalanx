use std::path::Path;
use std::sync::Arc;

use phalanx_forensics::PeerEvaluator;
use phalanx_proto::network::TransportError;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_transport::prelude::*;

use crate::config::{NetworkConfig, NodeConfig};
use crate::persistence::kademlia::RedbStore;

/// Gossipsub topics the node subscribes to at startup — one per message class
/// the node handles inbound: media → `IngestionActor`, control (heartbeats) →
/// `VitalsActor`, revocation (Cryptographic Forgetting) → `RevocationActor`.
///
/// Deliberately absent: the generic mesh topic (`MeshTopic::mesh()`) that
/// canary alerts are published on. No inbound alert handler exists yet, and
/// `MeshSentinel::handle_data_received` routes unrecognized topics into
/// evidence ingestion — subscribing before the handler exists would misroute
/// encrypted alerts. Add the topic here together with its handler.
#[must_use]
pub fn subscribe_topics(network: &NetworkConfig) -> Vec<String> {
    vec![
        network.video_topic.to_string(),
        network.audio_topic.to_string(),
        network.control_topic.to_string(),
        network.revocation_topic.to_string(),
    ]
}

/// Build the complete transport stack for a Phalanx node.
///
/// All libp2p internals are encapsulated by the transport factory.
/// Returns a ready-to-use `(Libp2pIngress, Libp2pEgress)` pair.
pub fn setup_transport(
    identity: &PhalanxIdentity,
    config: &NodeConfig,
    psk: Option<[u8; 32]>,
    evaluator: Arc<dyn PeerEvaluator>,
) -> Result<(Libp2pIngress, Libp2pEgress), TransportError> {
    // Persistent Kademlia Store Construction
    let dht_db_path = Path::new(&config.storage.vault_path).join("dht_store.redb");
    let local_network_id = identity.to_mesh_address();
    let persistent_store = RedbStore::new(&dht_db_path, local_network_id, evaluator)
        .map_err(|e| TransportError::Internal(format!("DHT store: {e}")))?;

    let transport_config = MeshTransportConfig {
        listen_addresses: config.network.listen_addresses.clone(),
        // Dial bootstrap peers AND the configured archival Strongholds, so a
        // directed archive push has a live connection to its custody target
        // (the transport rejects pushes to unconnected peers). This is what
        // makes the single-Stronghold deployment turnkey from one config block.
        bootstrap_peers: config.network.dial_peers(),
        subscribe_topics: subscribe_topics(&config.network),
        protocol_version: config.network.protocol_version.clone(),
        max_chunk_size_bytes: config.network.max_chunk_size_bytes,
        psk,
        require_psk: config.network.require_psk,
        kademlia_filter_both: true,
        ..MeshTransportConfig::default()
    };

    build_mesh_transport_with_store(identity, persistent_store, &transport_config)
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;
    use phalanx_proto::prelude::MeshTopic;

    #[test]
    fn subscribe_list_covers_every_inbound_message_class() {
        // Regression: the revocation topic was once published-to but absent
        // from every default subscribe list, so broadcast revocation tokens
        // ("deletion propagates across the mesh") went nowhere.
        let topics = subscribe_topics(&NetworkConfig::default());
        for class in [
            MeshTopic::video(),
            MeshTopic::audio(),
            MeshTopic::control(),
            MeshTopic::revocation(),
        ] {
            assert!(
                topics.contains(&class.to_string()),
                "subscribe list missing {class}"
            );
        }
    }
}
