use std::path::Path;
use std::sync::Arc;

use phalanx_forensics::PeerEvaluator;
use phalanx_proto::network::TransportError;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_transport::prelude::*;

use crate::config::NodeConfig;
use crate::persistence::kademlia::RedbStore;

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
        bootstrap_peers: config.network.bootstrap_peers.clone(),
        subscribe_topics: vec![
            config.network.video_topic.to_string(),
            config.network.audio_topic.to_string(),
            config.network.control_topic.to_string(),
        ],
        protocol_version: config.network.protocol_version.clone(),
        max_chunk_size_bytes: config.network.max_chunk_size_bytes,
        psk,
        require_psk: config.network.require_psk,
        kademlia_filter_both: true,
        ..MeshTransportConfig::default()
    };

    build_mesh_transport_with_store(identity, persistent_store, &transport_config)
}
