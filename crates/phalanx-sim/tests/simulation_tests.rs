// crates/phalanx-sim/tests/simulation_tests.rs
//
// Integration tests for the SimulationHarness, SimulationWorld,
// TelemetryCollector, and chaos injection.

use phalanx_node::config::NodeConfig;
use phalanx_proto::identity::NodeRole;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::telemetry::{ChaosMode, SimEvent};
use phalanx_sim::physics::PhalanxPhysics;
use phalanx_sim::SimulationHarness;

use std::time::Duration;

// ============================================================================
// Smoke Tests
// ============================================================================

#[tokio::test]
async fn test_spawn_and_shutdown() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config, physics);

    // Spawn two nodes
    let node_a = harness
        .spawn_node("Guardian-A", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Guardian-A");

    let node_b = harness
        .spawn_node("Stronghold-B", NodeRole::Stronghold)
        .await
        .expect("Failed to spawn Stronghold-B");

    // Allow background tasks to process
    tokio::task::yield_now().await;

    // Verify PeerDiscovered telemetry events were emitted
    let events = collector.events().await;
    let peer_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, SimEvent::PeerDiscovered { .. }))
        .collect();
    assert_eq!(
        peer_events.len(),
        2,
        "Expected 2 PeerDiscovered events, got {}",
        peer_events.len()
    );

    // Shut down both nodes via their ingress channels
    harness
        .inject_event(&node_a, NetworkEvent::Shutdown)
        .await
        .expect("Failed to send shutdown to node A");
    harness
        .inject_event(&node_b, NetworkEvent::Shutdown)
        .await
        .expect("Failed to send shutdown to node B");

    // Allow shutdown processing
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_resolve_did() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config, physics);

    let node_did = harness
        .spawn_node("Resolver", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    // Resolve should succeed
    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // NetworkId should be non-empty
    assert!(!network_id.0.is_empty(), "NetworkId should not be empty");

    // Resolve unknown DID should fail
    let unknown = phalanx_proto::prelude::Did::from("did:key:unknown");
    assert!(
        harness.resolve_did(&unknown).await.is_err(),
        "Should fail for unknown DID"
    );

    // Clean up
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .unwrap();
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Chaos Tests
// ============================================================================

#[tokio::test]
async fn test_inject_chaos_emits_telemetry() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config, physics);

    let node_did = harness
        .spawn_node("Chaos-Target", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    // Inject chaos
    harness
        .inject_chaos(&node_did, ChaosMode::PacketLoss(0.5))
        .await;

    // Allow telemetry to propagate
    tokio::task::yield_now().await;

    // Verify ChaosUpdate event
    let events = collector.events().await;
    let chaos_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, SimEvent::ChaosUpdate { .. }))
        .collect();
    assert_eq!(
        chaos_events.len(),
        1,
        "Expected 1 ChaosUpdate event, got {}",
        chaos_events.len()
    );

    // Clean up
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .unwrap();
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_inject_transport_failure() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config, physics);

    let node_did = harness
        .spawn_node("Byzantine-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    // inject_transport_failure should set Byzantine chaos mode
    harness.inject_transport_failure(&node_did).await;

    tokio::task::yield_now().await;

    let events = collector.events().await;
    let chaos_event = events.iter().find(|e| {
        matches!(
            e,
            SimEvent::ChaosUpdate {
                mode: ChaosMode::Byzantine,
                ..
            }
        )
    });
    assert!(
        chaos_event.is_some(),
        "Expected ChaosUpdate with Byzantine mode"
    );

    // Clean up
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .unwrap();
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Telemetry Collector Tests
// ============================================================================

#[tokio::test]
async fn test_telemetry_summary() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config, physics);

    // Spawn 3 nodes to generate PeerDiscovered events
    let node_a = harness
        .spawn_node("Node-A", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-A");
    let node_b = harness
        .spawn_node("Node-B", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-B");
    let node_c = harness
        .spawn_node("Node-C", NodeRole::Stronghold)
        .await
        .expect("Failed to spawn Node-C");

    // Inject chaos on one node
    harness
        .inject_chaos(&node_a, ChaosMode::HighLatency(100))
        .await;

    tokio::task::yield_now().await;

    // Generate summary
    let summary = collector.summary().await;

    // Verify summary contains expected information
    assert!(
        summary.contains("Simulation Telemetry Summary"),
        "Summary should have header"
    );
    assert!(
        summary.contains("PeerDiscovered: 3"),
        "Should have 3 PeerDiscovered events, got:\n{}",
        summary
    );
    assert!(
        summary.contains("ChaosUpdate: 1"),
        "Should have 1 ChaosUpdate event, got:\n{}",
        summary
    );

    // Clean up all nodes
    for did in [&node_a, &node_b, &node_c] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .unwrap();
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_telemetry_wait_for() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config, physics);

    let _node = harness
        .spawn_node("WaitFor-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    // wait_for should find a PeerDiscovered event
    let found = collector
        .wait_for(
            |e| matches!(e, SimEvent::PeerDiscovered { .. }),
            Duration::from_secs(1),
        )
        .await;

    assert!(found.is_some(), "Should find PeerDiscovered event");

    // wait_for should timeout for a non-existent event
    let not_found = collector
        .wait_for(
            |e| matches!(e, SimEvent::Shutdown),
            Duration::from_millis(50),
        )
        .await;

    assert!(not_found.is_none(), "Should not find Shutdown event");
}
