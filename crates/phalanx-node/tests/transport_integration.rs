use std::sync::Arc;

use libp2p::identity::Keypair;
use libp2p::{kad, relay};
use phalanx_forensics::trust::PeerEvaluator;
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::kademlia::RedbStore;
use phalanx_proto::identity::NetworkId;
use phalanx_proto::types::PhalanxPhysics;
use phalanx_transport::builder::build_behaviour;
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
    let keypair = Keypair::generate_ed25519();
    let config = NodeConfig::default();
    let physics = PhalanxPhysics::default_wan();
    let local_peer_id = keypair.public().to_peer_id();

    let dir = tempdir().unwrap();
    let db_path = dir.path().join("test_dht.redb");

    let store = RedbStore::new(
        &db_path,
        NetworkId::from(local_peer_id.to_string()),
        Arc::new(MockEvaluator),
    )
    .unwrap();
    let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad::Config::default());
    let (_, relay_client_behaviour) = relay::client::new(local_peer_id);

    let result = build_behaviour(
        &keypair,
        config.network.max_chunk_size_bytes,
        config.network.protocol_version.clone(),
        &physics,
        relay_client_behaviour,
        kademlia,
    );
    assert!(
        result.is_ok(),
        "Integration: Node storage failed to bind to Transport behaviour"
    );
}
