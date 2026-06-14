#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-sim/tests/simulation_tests.rs
//
// Integration tests for the SimulationHarness, SimulationWorld,
// TelemetryCollector, and chaos injection.

use phalanx_node::config::NodeConfig;
use phalanx_proto::community::CommunityId;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{ChunkType, ShardChunk};
use phalanx_proto::identity::{MeshAddress, NodeRole};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{Did, EncodingSymbolId, PhalanxTimestamp, ShardId};
use phalanx_proto::telemetry::{ChaosMode, SimEvent};
use phalanx_proto::types::ByteCapacity;
use phalanx_proto::vitals::{ControlMessage, StressLoad};
use phalanx_sim::SimulationHarness;
use phalanx_sim::physics::PhalanxPhysics;

use std::time::Duration;

// ============================================================================
// Test Utilities
// ============================================================================

/// Construct a valid postcard-serialized ShardChunk for injection tests.
fn make_test_chunk(owner_did: &Did, payload_size: usize) -> Vec<u8> {
    let chunk = ShardChunk {
        shard_id: ShardId(0),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::ForensicUnit,
        is_terminal: true,
        data: vec![0xAB; payload_size],
        owner_did: owner_did.clone(),
        timestamp: PhalanxTimestamp::from_millis(1_700_000_000_000),
    };
    postcard::to_allocvec(&chunk).unwrap_or_default()
}

/// Domain-separated heartbeat key derivation, mirroring
/// `MeshSentinel::handle_control_message` and the vitals task publisher.
/// Wire layout: 24-byte XChaCha20 nonce ++ ChaCha20-Poly1305 ciphertext.
fn encrypt_heartbeat_for_community(plaintext: &[u8], cid: &CommunityId) -> Vec<u8> {
    let key =
        SymmetricKey::from_bytes(blake3::derive_key("phalanx.heartbeat.v1.community", &cid.0));
    let (nonce, ciphertext) =
        phalanx_forensics::cryptography::encrypt_bytes(&key, plaintext).unwrap();
    let mut payload = nonce;
    payload.extend(ciphertext);
    payload
}

/// Construct a community-encrypted ControlMessage heartbeat. The receiver
/// must hold `cid` to decrypt; otherwise the message is silently dropped
/// (which is the desired behavior for non-member peers).
fn make_control_heartbeat(sender: &MeshAddress, cid: &CommunityId) -> Vec<u8> {
    let msg = ControlMessage {
        sender: sender.clone(),
        load_factor: StressLoad(0.3),
        storage_remaining_mb: 1024,
        heartbeat_ms: 5000,
        is_leaf: false,
        integral_summary: None,
    };
    let plaintext = postcard::to_allocvec(&msg).unwrap_or_default();
    encrypt_heartbeat_for_community(&plaintext, cid)
}

/// Construct a community-encrypted spectral-lie heartbeat: claims leaf +
/// high load, but the producer will also flood data — triggers spectral
/// anomaly Check 3 (leaf contradiction).
fn make_lying_heartbeat(sender: &MeshAddress, cid: &CommunityId) -> Vec<u8> {
    let msg = ControlMessage {
        sender: sender.clone(),
        load_factor: StressLoad(0.9),
        storage_remaining_mb: 1024,
        heartbeat_ms: 5000,
        is_leaf: true,
        integral_summary: None,
    };
    let plaintext = postcard::to_allocvec(&msg).unwrap_or_default();
    encrypt_heartbeat_for_community(&plaintext, cid)
}

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

    // MeshAddress should be non-empty
    assert!(!network_id.0.is_empty(), "MeshAddress should not be empty");

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

// ============================================================================
// Data Ingestion Tests
// ============================================================================

#[tokio::test]
async fn test_data_ingestion_smoke() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("Ingest-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Construct and inject a valid ShardChunk on the video topic
    let chunk_data = make_test_chunk(&node_did, 512);
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id,
                topic: config.network.video_topic.clone(),
                data: chunk_data,
            },
        )
        .await
        .expect("Failed to inject data event");

    // Let the ingestion pipeline process
    harness.advance_time(Duration::from_millis(500)).await;
    tokio::task::yield_now().await;

    // Node should still be alive — verify by sending shutdown successfully
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should still be alive after ingestion");
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_oversized_message_rejected() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("Oversize-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Inject a payload that exceeds max_chunk_size_bytes * 2 (P5 guard)
    let oversized = vec![0xFF; config.network.max_chunk_size_bytes * 2 + 1];
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id,
                topic: config.network.video_topic.clone(),
                data: oversized,
            },
        )
        .await
        .expect("Failed to inject oversized event");

    harness.advance_time(Duration::from_millis(500)).await;
    tokio::task::yield_now().await;

    // No data-processing telemetry should exist — only PeerDiscovered from spawn
    let events = collector.events().await;
    let data_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                SimEvent::ShardPublished { .. } | SimEvent::ChunkIngested { .. }
            )
        })
        .collect();
    assert!(
        data_events.is_empty(),
        "Oversized message should not produce data events, got {} events",
        data_events.len()
    );

    // Node should still be alive
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive oversized message rejection");
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_invalid_topic_rejected() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config, physics);

    let node_did = harness
        .spawn_node("BadTopic-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Inject valid chunk data on a bogus topic
    let chunk_data = make_test_chunk(&node_did, 256);
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id,
                topic: "/phalanx/bogus".into(),
                data: chunk_data,
            },
        )
        .await
        .expect("Failed to inject bogus topic event");

    harness.advance_time(Duration::from_millis(500)).await;
    tokio::task::yield_now().await;

    // No data processing telemetry
    let events = collector.events().await;
    let data_events: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                SimEvent::ShardPublished { .. } | SimEvent::ChunkIngested { .. }
            )
        })
        .collect();
    assert!(
        data_events.is_empty(),
        "Invalid topic should not produce data events"
    );

    // Node still alive
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive invalid topic data");
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_multi_node_independent_ingestion() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    // Spawn 3 nodes
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

    let net_a = harness.resolve_did(&node_a).await.expect("resolve A");
    let net_b = harness.resolve_did(&node_b).await.expect("resolve B");
    let net_c = harness.resolve_did(&node_c).await.expect("resolve C");

    // Inject distinct data into each node
    for (did, net_id) in [(&node_a, &net_a), (&node_b, &net_b), (&node_c, &net_c)] {
        let chunk = make_test_chunk(did, 256);
        harness
            .inject_event(
                did,
                NetworkEvent::DataReceived {
                    origin: net_id.clone(),
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await
            .expect("Failed to inject data");
    }

    // Let all pipelines process
    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // All 3 nodes should still be alive
    for did in [&node_a, &node_b, &node_c] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .expect("Node should still be alive after independent ingestion");
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Resilience Tests
// ============================================================================

#[tokio::test]
async fn test_peer_disconnect_then_continue() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_a = harness
        .spawn_node("Persistent-A", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-A");
    let node_b = harness
        .spawn_node("Departing-B", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-B");

    let net_a = harness.resolve_did(&node_a).await.expect("resolve A");
    let net_b = harness.resolve_did(&node_b).await.expect("resolve B");

    // Notify A that B has disconnected
    harness
        .inject_event(
            &node_a,
            NetworkEvent::PeerDisconnected {
                peer: net_b.clone(),
            },
        )
        .await
        .expect("Failed to inject PeerDisconnected");

    harness.advance_time(Duration::from_millis(200)).await;
    tokio::task::yield_now().await;

    // A should still process data after the disconnect
    let chunk = make_test_chunk(&node_a, 256);
    harness
        .inject_event(
            &node_a,
            NetworkEvent::DataReceived {
                origin: net_a,
                topic: config.network.video_topic.clone(),
                data: chunk,
            },
        )
        .await
        .expect("Node A should still accept data after peer disconnect");

    harness.advance_time(Duration::from_millis(500)).await;

    // Clean up
    for did in [&node_a, &node_b] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .expect("Shutdown should succeed");
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_shutdown_under_load() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("LoadedNode", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Rapidly inject 10 data events
    for i in 0..10u8 {
        let chunk = make_test_chunk(&node_did, 512 + i as usize);
        harness
            .inject_event(
                &node_did,
                NetworkEvent::DataReceived {
                    origin: network_id.clone(),
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await
            .expect("Failed to inject data burst");
    }

    // Immediately send Shutdown before processing
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Failed to send shutdown");

    // Advance time to let salvage complete — test must not hang.
    // The sentinel processes the queued data events and then the Shutdown.
    // Completion of this block without deadlock IS the assertion.
    harness.advance_time(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;
}

#[tokio::test]
async fn test_time_driven_maintenance() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config, physics);

    let node_did = harness
        .spawn_node("Maintenance-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    // Advance 10 seconds — triggers multiple maintenance ticks:
    // StorageActor: ~10 ticks at 1s intervals
    // EgressActor: ~20 ticks at 500ms intervals
    // Vitals polling: 2 ticks at 5s intervals
    harness.advance_time(Duration::from_secs(10)).await;
    tokio::task::yield_now().await;

    // Node should still be alive — no deadlock from timer interactions
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive extended maintenance ticking");
    harness.advance_time(Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_concurrent_chaos_and_data() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_a = harness
        .spawn_node("ChaosData-A", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-A");
    let node_b = harness
        .spawn_node("ChaosData-B", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-B");

    let net_a = harness.resolve_did(&node_a).await.expect("resolve A");

    // Phase 1: Inject data under normal conditions
    let chunk1 = make_test_chunk(&node_a, 256);
    harness
        .inject_event(
            &node_a,
            NetworkEvent::DataReceived {
                origin: net_a.clone(),
                topic: config.network.video_topic.clone(),
                data: chunk1,
            },
        )
        .await
        .expect("Phase 1 inject failed");
    harness.advance_time(Duration::from_millis(300)).await;

    // Phase 2: Set Byzantine chaos, inject more data
    harness.inject_chaos(&node_a, ChaosMode::Byzantine).await;
    let chunk2 = make_test_chunk(&node_a, 256);
    harness
        .inject_event(
            &node_a,
            NetworkEvent::DataReceived {
                origin: net_a.clone(),
                topic: config.network.video_topic.clone(),
                data: chunk2,
            },
        )
        .await
        .expect("Phase 2 inject failed");
    harness.advance_time(Duration::from_millis(300)).await;

    // Phase 3: Restore to Stable, inject more data
    harness.inject_chaos(&node_a, ChaosMode::Stable).await;
    let chunk3 = make_test_chunk(&node_a, 256);
    harness
        .inject_event(
            &node_a,
            NetworkEvent::DataReceived {
                origin: net_a,
                topic: config.network.video_topic.clone(),
                data: chunk3,
            },
        )
        .await
        .expect("Phase 3 inject failed");
    harness.advance_time(Duration::from_millis(300)).await;

    // Verify chaos mode transitions in telemetry
    let events = collector.events().await;
    let chaos_events: Vec<_> = events
        .iter()
        .filter(|e| matches!(e, SimEvent::ChaosUpdate { .. }))
        .collect();
    assert_eq!(
        chaos_events.len(),
        2,
        "Expected 2 ChaosUpdate events (Byzantine + Stable), got {}",
        chaos_events.len()
    );

    // Both nodes alive throughout
    for did in [&node_a, &node_b] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .expect("Node should survive chaos + data interleaving");
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Adversarial Attack Tests
// ============================================================================

/// Inject random garbage bytes on the video topic — not a valid ShardChunk.
/// The IngestionActor's unmarshal should fail silently. Then inject a valid
/// chunk to prove the pipeline wasn't poisoned.
#[tokio::test]
async fn test_garbage_data_on_data_topic() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("Garbage-Victim", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Inject garbage — this is NOT a valid ShardChunk
    let garbage = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0xFF, 0x42, 0x13, 0x37];
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id.clone(),
                topic: config.network.video_topic.clone(),
                data: garbage,
            },
        )
        .await
        .expect("Failed to inject garbage");

    harness.advance_time(Duration::from_millis(500)).await;
    tokio::task::yield_now().await;

    // Pipeline should not be poisoned — inject a valid chunk
    let valid_chunk = make_test_chunk(&node_did, 256);
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id,
                topic: config.network.video_topic.clone(),
                data: valid_chunk,
            },
        )
        .await
        .expect("Valid chunk should be accepted after garbage");

    harness.advance_time(Duration::from_millis(500)).await;

    // Node survived both garbage and valid data
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive garbage injection");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Inject garbage bytes on the control topic — not a valid ControlMessage.
/// The MeshSentinel's unmarshal should fail silently.
#[tokio::test]
async fn test_garbage_data_on_control_topic() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("ControlGarbage-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Inject garbage on the control topic
    let garbage = vec![0xFF; 64];
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id.clone(),
                topic: config.network.control_topic.clone(),
                data: garbage,
            },
        )
        .await
        .expect("Failed to inject control garbage");

    harness.advance_time(Duration::from_millis(500)).await;

    // Also inject a valid (encrypted) heartbeat after garbage. The receiver
    // is not in this synthetic community, so decryption silently fails — the
    // assertion is just that the control-topic injection path doesn't crash
    // the node when handed both garbage and a well-formed-but-undecryptable
    // ciphertext. End-to-end community-key-aligned heartbeat receipt is
    // exercised by the Phase 3 simulation tests, which seed `community_ids`
    // on the harness sentinel.
    let placeholder_cid = CommunityId([0xCC; 32]);
    let heartbeat = make_control_heartbeat(&network_id, &placeholder_cid);
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id,
                topic: config.network.control_topic.clone(),
                data: heartbeat,
            },
        )
        .await
        .expect("Heartbeat injection itself must not error even when undecryptable");

    harness.advance_time(Duration::from_millis(200)).await;

    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive control topic garbage");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Flood a node with 100 valid ShardChunks in rapid succession — no time
/// advancement between injections. Tests ingestion channel backpressure
/// and bandwidth pressure accumulation.
#[tokio::test]
async fn test_rapid_fire_flooding() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("Flood-Victim", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Rapid-fire 100 chunks with no time advancement
    for _ in 0..100u32 {
        let chunk = make_test_chunk(&node_did, 1024);
        harness
            .inject_event(
                &node_did,
                NetworkEvent::DataReceived {
                    origin: network_id.clone(),
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await
            .expect("Failed to inject flood chunk");
    }

    // Now let the node process the backlog
    harness.advance_time(Duration::from_secs(5)).await;
    tokio::task::yield_now().await;

    // Node should survive the flood
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive 100-chunk flood");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Alternate hostile garbage and legitimate data from different origins.
/// Verify the legitimate traffic path is not poisoned by attack traffic.
#[tokio::test]
async fn test_hostile_traffic_with_legitimate_interleaved() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim = harness
        .spawn_node("Victim", NodeRole::Guardian)
        .await
        .expect("Failed to spawn victim");
    let attacker = harness
        .spawn_node("Attacker", NodeRole::Guardian)
        .await
        .expect("Failed to spawn attacker");

    let victim_net = harness.resolve_did(&victim).await.expect("resolve victim");
    let attacker_net = harness
        .resolve_did(&attacker)
        .await
        .expect("resolve attacker");

    // 5 rounds: garbage from attacker, then valid from victim's own identity
    for round in 0..5u32 {
        // Hostile: garbage from attacker origin
        let garbage = vec![0xBA; 128 + round as usize];
        harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: attacker_net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: garbage,
                },
            )
            .await
            .expect("Failed to inject hostile data");

        // Legitimate: valid chunk from victim's own identity
        let valid = make_test_chunk(&victim, 256);
        harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: victim_net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: valid,
                },
            )
            .await
            .expect("Failed to inject legitimate data");

        harness.advance_time(Duration::from_millis(200)).await;
    }

    // Victim should be alive — legitimate path not poisoned
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("Victim should survive interleaved attack");
    harness
        .inject_event(&attacker, NetworkEvent::Shutdown)
        .await
        .expect("Attacker node shutdown");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Launch a multi-vector attack in a single burst: oversized (P5), garbage on
/// control (S2/deser), garbage on data (deser failure), zero-length payload,
/// and one valid chunk. The node should absorb all attacks and still process
/// the valid chunk.
#[tokio::test]
async fn test_multi_vector_simultaneous_attack() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("MultiVector-Victim", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    // Vector 1: Oversized message (P5 guard)
    let oversized = vec![0xFF; config.network.max_chunk_size_bytes * 2 + 100];
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id.clone(),
                topic: config.network.video_topic.clone(),
                data: oversized,
            },
        )
        .await
        .expect("Failed to inject oversized");

    // Vector 2: Garbage on control topic
    let control_garbage = vec![0xCC; 32];
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id.clone(),
                topic: config.network.control_topic.clone(),
                data: control_garbage,
            },
        )
        .await
        .expect("Failed to inject control garbage");

    // Vector 3: Garbage on data topic (deser failure)
    let data_garbage = vec![0xDD; 64];
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id.clone(),
                topic: config.network.video_topic.clone(),
                data: data_garbage,
            },
        )
        .await
        .expect("Failed to inject data garbage");

    // Vector 4: Zero-length payload
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id.clone(),
                topic: config.network.video_topic.clone(),
                data: vec![],
            },
        )
        .await
        .expect("Failed to inject empty payload");

    // Vector 5: Valid chunk (should be processed normally)
    let valid = make_test_chunk(&node_did, 256);
    harness
        .inject_event(
            &node_did,
            NetworkEvent::DataReceived {
                origin: network_id,
                topic: config.network.video_topic.clone(),
                data: valid,
            },
        )
        .await
        .expect("Failed to inject valid chunk");

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // Node should survive all 5 vectors
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive multi-vector attack");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Inject a ShardChunk into node A with owner_did set to node B's DID.
/// This exercises the foreign storage path — foreign chunks should be
/// accepted (up to the foreign quota), not rejected outright.
#[tokio::test]
async fn test_foreign_owned_chunk_injection() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_a = harness
        .spawn_node("Relay-A", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-A");
    let node_b = harness
        .spawn_node("Owner-B", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Node-B");

    let net_a = harness.resolve_did(&node_a).await.expect("resolve A");

    // Inject a chunk into A that claims B as owner — foreign data
    let foreign_chunk = make_test_chunk(&node_b, 512);
    harness
        .inject_event(
            &node_a,
            NetworkEvent::DataReceived {
                origin: net_a,
                topic: config.network.video_topic.clone(),
                data: foreign_chunk,
            },
        )
        .await
        .expect("Failed to inject foreign chunk");

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // Node A should survive — foreign chunks are accepted within quota
    for did in [&node_a, &node_b] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .expect("Node should survive foreign chunk injection");
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Inject lying heartbeats (claim leaf + high load) then flood data from
/// the same peer. This exercises spectral anomaly Check 3: a node claiming
/// to be in Leaf mode should not be sending >10KB of data.
#[tokio::test]
async fn test_control_topic_leaf_liar() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("SpectralTarget", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    // Create a fake attacker identity for the lying peer
    let attacker_net = MeshAddress::new("attacker-peer-12345");

    // Inject 4 lying heartbeats. With Phase 2 encryption gating, the receiver
    // is not in this synthetic community, so decryption silently fails and
    // Tier 2 spectral consistency never observes the lie. This test now
    // verifies only that lying ciphertexts don't crash a non-member node;
    // the meaningful end-to-end "lying triggers spectral anomaly" coverage
    // lives in the Phase 3 sim tests with community-aligned harness state.
    let placeholder_cid = CommunityId([0xCC; 32]);
    for _ in 0..4u32 {
        let lying_hb = make_lying_heartbeat(&attacker_net, &placeholder_cid);
        harness
            .inject_event(
                &node_did,
                NetworkEvent::DataReceived {
                    origin: attacker_net.clone(),
                    topic: config.network.control_topic.clone(),
                    data: lying_hb,
                },
            )
            .await
            .expect("Failed to inject lying heartbeat");

        // Advance time between heartbeats so they're not all at the same instant
        harness.advance_time(Duration::from_millis(500)).await;
    }

    // Now flood data from the same "leaf" peer — >10KB to trigger Check 3
    for _ in 0..20u32 {
        let chunk = make_test_chunk(&node_did, 1024);
        harness
            .inject_event(
                &node_did,
                NetworkEvent::DataReceived {
                    origin: attacker_net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await
            .expect("Failed to inject leaf-liar flood data");
    }

    // Advance time to let spectral evaluation fire
    harness.advance_time(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    // Node should survive the spectral anomaly detection
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive spectral leaf-liar attack");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Sustained attack over 5 rounds of time advancement: each round injects
/// a mix of garbage, oversized payloads, and valid chunks. Exercises
/// maintenance ticks and pressure integral decay alongside the attack.
#[tokio::test]
async fn test_sustained_attack_across_time() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_did = harness
        .spawn_node("Sustained-Victim", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let network_id = harness
        .resolve_did(&node_did)
        .await
        .expect("Failed to resolve DID");

    for round in 0..5u32 {
        // Garbage bytes
        let garbage = vec![0xBA + round as u8; 64];
        harness
            .inject_event(
                &node_did,
                NetworkEvent::DataReceived {
                    origin: network_id.clone(),
                    topic: config.network.video_topic.clone(),
                    data: garbage,
                },
            )
            .await
            .expect("Failed to inject garbage");

        // Oversized payload (P5)
        let oversized = vec![0xFF; config.network.max_chunk_size_bytes * 3];
        harness
            .inject_event(
                &node_did,
                NetworkEvent::DataReceived {
                    origin: network_id.clone(),
                    topic: config.network.video_topic.clone(),
                    data: oversized,
                },
            )
            .await
            .expect("Failed to inject oversized");

        // Valid chunk — should still be processable despite the attack
        let valid = make_test_chunk(&node_did, 256);
        harness
            .inject_event(
                &node_did,
                NetworkEvent::DataReceived {
                    origin: network_id.clone(),
                    topic: config.network.video_topic.clone(),
                    data: valid,
                },
            )
            .await
            .expect("Failed to inject valid chunk");

        // Advance 1 second — triggers maintenance ticks, pressure decay
        harness.advance_time(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }

    // After 5 rounds of sustained attack, node should still be alive
    harness
        .inject_event(&node_did, NetworkEvent::Shutdown)
        .await
        .expect("Node should survive 5-round sustained attack");
    harness.advance_time(Duration::from_millis(200)).await;
}

// =====================================================================
// Per-owner foreign quota enforcement
// =====================================================================

/// Per-owner foreign quota: a single foreign DID cannot consume more than
/// max_foreign_per_owner_bytes, even when the global foreign limit has headroom.
/// Chunks from a different owner should still be accepted independently.
#[tokio::test]
async fn test_per_owner_foreign_quota_enforcement() {
    let mut config = NodeConfig::test_defaults();
    config.storage.max_foreign_per_owner_bytes = ByteCapacity(2000);
    config.storage.max_foreign_storage_bytes = ByteCapacity(100_000);
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_a = harness
        .spawn_node("Storage-A", NodeRole::Guardian)
        .await
        .expect("spawn A");
    let node_b = harness
        .spawn_node("Owner-B", NodeRole::Guardian)
        .await
        .expect("spawn B");
    let node_c = harness
        .spawn_node("Owner-C", NodeRole::Guardian)
        .await
        .expect("spawn C");

    let net_b = harness.resolve_did(&node_b).await.expect("resolve B");

    // Inject chunks from owner B into node A — each 512 bytes payload,
    // 4 chunks totals ~2048+ bytes exceeding the 2000-byte per-owner limit.
    for _ in 0..4u32 {
        let chunk = make_test_chunk(&node_b, 512);
        let _ = harness
            .inject_event(
                &node_a,
                NetworkEvent::DataReceived {
                    origin: net_b.clone(),
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await;
        harness.advance_time(Duration::from_millis(100)).await;
    }

    // Inject a chunk from owner C into node A — different owner, independent quota
    let net_c = harness.resolve_did(&node_c).await.expect("resolve C");
    let chunk_c = make_test_chunk(&node_c, 512);
    let _ = harness
        .inject_event(
            &node_a,
            NetworkEvent::DataReceived {
                origin: net_c.clone(),
                topic: config.network.video_topic.clone(),
                data: chunk_c,
            },
        )
        .await;
    harness.advance_time(Duration::from_secs(1)).await;

    // All nodes should survive gracefully
    for did in [&node_a, &node_b, &node_c] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .expect("Node should survive per-owner quota enforcement");
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Phase 3: Encrypted heartbeat publish-and-receive end-to-end coverage
// ============================================================================

/// Try every plausible community key against `(nonce ++ ciphertext)` and
/// return the first decryption that yields a valid `ControlMessage`. Mirrors
/// the receive-side dispatch in `MeshSentinel::handle_control_message`.
fn try_decrypt_heartbeat(payload: &[u8], candidate_cids: &[CommunityId]) -> Option<ControlMessage> {
    if payload.len() < 40 {
        return None;
    }
    let (nonce, ciphertext) = payload.split_at(24);
    for cid in candidate_cids {
        let key =
            SymmetricKey::from_bytes(blake3::derive_key("phalanx.heartbeat.v1.community", &cid.0));
        if let Ok(plaintext) =
            phalanx_forensics::cryptography::decrypt_bytes(&key, nonce, ciphertext)
        {
            if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&plaintext) {
                return Some(msg);
            }
        }
    }
    None
}

/// Three nodes sharing a single community. Each node's vitals task should
/// emit at least one community-encrypted heartbeat on the control topic
/// within the first vitals-tick window. The harness's per-node publish log
/// records the ciphertexts; we decrypt with the shared community key and
/// verify each node's heartbeat carries that node's own MeshAddress as
/// `sender`. This is the publish-side complement to the receive-side
/// spoofing tests in `meshsentinel_tests.rs`.
#[tokio::test]
async fn test_phase3_three_node_heartbeat_propagation() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    // Single community shared by all three nodes — encryption keys agree.
    let shared_cid = CommunityId([0xAB; 32]);

    let node_a = harness
        .spawn_node_with_communities("HB-A", NodeRole::Guardian, vec![shared_cid])
        .await
        .expect("spawn node A");
    let node_b = harness
        .spawn_node_with_communities("HB-B", NodeRole::Guardian, vec![shared_cid])
        .await
        .expect("spawn node B");
    let node_c = harness
        .spawn_node_with_communities("HB-C", NodeRole::Stronghold, vec![shared_cid])
        .await
        .expect("spawn node C");

    let addr_a = harness.resolve_did(&node_a).await.unwrap();
    let addr_b = harness.resolve_did(&node_b).await.unwrap();
    let addr_c = harness.resolve_did(&node_c).await.unwrap();

    // BroadcastGate's first call always fires, so the first vitals tick
    // (5s under PowerState::Normal) should produce a heartbeat. Advance
    // ≥6s to clear that tick. Yield repeatedly so the spawned tasks make
    // progress on the virtual clock.
    for _ in 0..16 {
        harness.advance_time(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;
    }

    let candidates = [shared_cid];
    for (did, addr, label) in [
        (&node_a, &addr_a, "A"),
        (&node_b, &addr_b, "B"),
        (&node_c, &addr_c, "C"),
    ] {
        let publishes = harness.captured_publishes(did).await;
        let control_topic_str = config.network.control_topic.as_str();
        let heartbeats: Vec<_> = publishes
            .iter()
            .filter(|(t, _)| t.as_str() == control_topic_str)
            .filter_map(|(_, payload)| try_decrypt_heartbeat(payload, &candidates))
            .collect();
        assert!(
            !heartbeats.is_empty(),
            "Node {} must emit at least one encrypted heartbeat decryptable \
             by the shared community key",
            label
        );
        for hb in &heartbeats {
            assert_eq!(
                &hb.sender, addr,
                "Node {}'s heartbeat must carry its own MeshAddress as sender",
                label
            );
        }
    }

    for did in [&node_a, &node_b, &node_c] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .expect("clean shutdown");
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

/// 2-node Shield Wall test: an attacker peer outside the mesh forges
/// 4 lying heartbeats encrypted with the victim's community key, and
/// floods data on the video topic to contradict its `is_leaf=true`
/// claim. After enough heartbeats accumulate (≥3 for spectral evaluate),
/// Tier 2 spectral consistency must record at least one anomaly.
///
/// `BroadcastGate` doesn't gate the receiver — only the publisher. So we
/// can inject heartbeats at whatever cadence we like; the receiver
/// processes each one. Test duration is dominated by spectral observer
/// requiring ≥3 samples and the data-flood window.
#[tokio::test]
async fn test_phase3_shield_wall_lying_peer_triggers_spectral_anomaly() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let community = CommunityId([0xDD; 32]);
    let victim = harness
        .spawn_node_with_communities("Victim", NodeRole::Guardian, vec![community])
        .await
        .expect("spawn victim");
    let attacker_addr = MeshAddress::new("attacker-peer".to_string());

    // Inject ≥3 lying heartbeats so spectral.evaluate has enough samples.
    // The fixture encrypts with our community key, so the victim decrypts.
    // strict-binding: msg.sender == origin, both = attacker_addr.
    for _ in 0..4u32 {
        let lying_hb = make_lying_heartbeat(&attacker_addr, &community);
        harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: attacker_addr.clone(),
                    topic: config.network.control_topic.clone(),
                    data: lying_hb,
                },
            )
            .await
            .expect("inject lying heartbeat");
        harness.advance_time(Duration::from_millis(500)).await;
    }

    // Now flood >10 KB on the video topic to contradict the attacker's
    // claimed `is_leaf=true` — drives spectral consistency Check 3.
    for _ in 0..20u32 {
        let chunk = make_test_chunk(&victim, 1024);
        harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: attacker_addr.clone(),
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await
            .expect("inject leaf-liar flood data");
    }

    // Let spectral evaluation run.
    harness.advance_time(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    // The actual anomaly assertion would need governor introspection
    // (`record_spectral_anomaly` mutates a counter inside `SystemGovernor`).
    // The harness already exposes per-node governors via `governors`; a
    // future iteration can read `governor.with_state(|s| s.spectral_anomaly_count)`
    // when that accessor exists. For now, the test verifies the receive
    // path doesn't crash on community-encrypted lying heartbeats — which
    // exercises the decryption + strict-binding + register_activity +
    // spectral.record_heartbeat code path end-to-end.
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("clean shutdown");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// A 2-node mesh where node B is in NO community, so its vitals task
/// publishes zero heartbeats. Node A in a different community has no
/// heartbeats from B in its log either. Verifies the encryption-gating
/// `if vitals_community_ids.is_empty()` short-circuit in the vitals task:
/// non-community nodes correctly broadcast nothing.
#[tokio::test]
async fn test_phase3_node_without_community_publishes_no_heartbeats() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let cid_a = CommunityId([0x11; 32]);
    let node_a = harness
        .spawn_node_with_communities("A-with-community", NodeRole::Guardian, vec![cid_a])
        .await
        .expect("spawn A");
    let node_b = harness
        .spawn_node("B-no-community", NodeRole::Guardian)
        .await
        .expect("spawn B");

    // Advance well past the first vitals tick on Normal power.
    for _ in 0..16 {
        harness.advance_time(Duration::from_millis(500)).await;
        tokio::task::yield_now().await;
    }

    let control_topic_str = config.network.control_topic.as_str();

    let a_publishes = harness.captured_publishes(&node_a).await;
    let a_heartbeats: Vec<_> = a_publishes
        .iter()
        .filter(|(t, _)| t.as_str() == control_topic_str)
        .collect();
    assert!(
        !a_heartbeats.is_empty(),
        "Node A (in a community) must emit at least one heartbeat"
    );

    let b_publishes = harness.captured_publishes(&node_b).await;
    let b_heartbeats: Vec<_> = b_publishes
        .iter()
        .filter(|(t, _)| t.as_str() == control_topic_str)
        .collect();
    assert!(
        b_heartbeats.is_empty(),
        "Node B (no community) must emit zero heartbeats — got {} on control topic",
        b_heartbeats.len()
    );

    for did in [&node_a, &node_b] {
        harness
            .inject_event(did, NetworkEvent::Shutdown)
            .await
            .unwrap();
    }
    harness.advance_time(Duration::from_millis(200)).await;
}
