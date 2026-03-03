#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::storage::kademlia::RedbStore;
    use phalanx_transport::builder::{build_behaviour, TransportConfig};
    use tempfile::tempdir; // Replaced deprecated tempdir crate

    #[tokio::test]
    async fn test_node_behaviour_initialization() {
        let keypair = Keypair::generate_ed25519();
        let transport_config = TransportConfig::default();
        let physics = PhalanxPhysics::default_wan();
        let local_peer_id = keypair.public().to_peer_id();

        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_dht.redb");

        // Node-layer component
        let store = RedbStore::new(
            &db_path,
            NetworkId::from(local_peer_id),
            Arc::new(MockEvaluator),
        )
        .unwrap();
        let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad::Config::default());
        let (_, relay_client_behaviour) = relay::client::new(local_peer_id);

        let result = build_behaviour(
            &keypair,
            &transport_config,
            &physics,
            relay_client_behaviour,
            kademlia,
        );
        assert!(
            result.is_ok(),
            "Integration: Node storage failed to bind to Transport behaviour"
        );
    }
}
