#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
use std::sync::Arc;

use phalanx_forensics::trust::PeerEvaluator;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::kademlia::RedbStore;
use phalanx_proto::identity::NetworkId;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_transport::prelude::{build_mesh_transport_with_store, MeshTransportConfig};
use tempfile::tempdir;

/// A minimal PeerEvaluator for testing that trusts all peers.
struct MockEvaluator;

impl PeerEvaluator for MockEvaluator {
    fn evaluate_reputation(&self, _peer_id: &NetworkId) -> f32 {
        1.0
    }
}

#[tokio::test]
async fn test_node_behaviour_initialization() {
    let (identity, _mnemonic) = PhalanxIdentity::generate().unwrap();
    let _config = NodeConfig::default();

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_dht.redb");

    let local_network_id = identity.did.to_network_id();
    let store = RedbStore::new(
        &db_path,
        NetworkId::from(local_network_id),
        Arc::new(MockEvaluator),
    )
    .unwrap();

    let transport_config = MeshTransportConfig::default();
    let result = build_mesh_transport_with_store(&identity, store, &transport_config);

    assert!(
        result.is_ok(),
        "Integration: Node storage failed to bind to Transport behaviour: {:?}",
        result.err()
    );
}
