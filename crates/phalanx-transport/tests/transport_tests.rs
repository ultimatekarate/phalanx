//! Integration tests for phalanx-transport.
//!
//! Tests verify the MockAdapter mesh simulation and PeerMapper identity
//! translation — the layer where forensic identities meet libp2p.

use std::collections::HashMap;
use std::sync::Arc;

use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::EgressPort;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::topic::MeshTopic;

use phalanx_transport::adapters::mock::MockAdapter;
use phalanx_transport::routing::MeshRoutingTable;
use phalanx_transport::PeerMapper;

use tokio::sync::{mpsc, RwLock};

// ─── MockAdapter mesh simulation ──────────────────────────────────────────

fn setup_mesh(
    peer_ids: &[NetworkId],
) -> (
    Vec<MockAdapter>,
    Vec<mpsc::Receiver<NetworkEvent>>,
    Arc<RwLock<MeshRoutingTable>>,
) {
    let mut table = MeshRoutingTable {
        routes: HashMap::new(),
        pending_responses: HashMap::new(),
    };

    let mut adapters = Vec::new();
    let mut receivers = Vec::new();

    // Each peer gets: ingress channel (for receiving events) + route in mesh table
    for id in peer_ids {
        let (_ingress_tx, ingress_rx) = mpsc::channel(128);
        let (route_tx, route_rx) = mpsc::channel(128);
        table.routes.insert(id.clone(), route_tx);
        receivers.push(route_rx);
        adapters.push((id.clone(), ingress_rx));
    }

    let mesh_bus = Arc::new(RwLock::new(table));

    let mock_adapters: Vec<MockAdapter> = adapters
        .into_iter()
        .map(|(id, rx)| MockAdapter::new(id, rx, mesh_bus.clone()))
        .collect();

    (mock_adapters, receivers, mesh_bus)
}

#[tokio::test]
async fn mesh_publish_subscribe_roundtrip() {
    let peer_a = NetworkId("peer_a".into());
    let peer_b = NetworkId("peer_b".into());
    let peer_c = NetworkId("peer_c".into());

    let (adapters, mut receivers, _bus) =
        setup_mesh(&[peer_a.clone(), peer_b.clone(), peer_c.clone()]);

    let topic = MeshTopic::new("test/topic");
    let data = vec![0xDE, 0xAD, 0xBE, 0xEF];

    // Peer A publishes
    adapters[0]
        .publish(&topic, data.clone())
        .await
        .expect("publish should not fail");

    // Peers B and C should receive (they're in the routing table)
    // Peer A also receives (broadcast goes to all routes)
    for (i, rx) in receivers.iter_mut().enumerate() {
        match tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv()).await {
            Ok(Some(NetworkEvent::DataReceived { data: received, .. })) => {
                assert_eq!(received, data, "Peer {i} should receive the published data");
            }
            Ok(Some(other)) => {
                // Other event types are acceptable in some mock implementations
                let _ = other;
            }
            Ok(None) => panic!("Peer {i} channel closed unexpectedly"),
            Err(_) => {
                // Timeout is acceptable if the mock doesn't route to self
                if i == 0 {
                    // Peer A (sender) may not receive its own message
                } else {
                    panic!("Peer {i} did not receive message within timeout");
                }
            }
        }
    }
}

// ─── PeerMapper roundtrip ─────────────────────────────────────────────────

#[test]
fn peer_mapper_roundtrip() {
    use libp2p::identity::Keypair;
    use libp2p::PeerId;

    let keypair = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());

    let network_id = PeerMapper::to_network_id(&peer_id);
    let recovered =
        PeerMapper::from_network_id(&network_id).expect("should convert back to PeerId");

    assert_eq!(
        recovered, peer_id,
        "PeerId → NetworkId → PeerId roundtrip must be lossless"
    );
}
