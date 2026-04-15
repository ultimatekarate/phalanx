#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-node/tests/ingestion_tests.rs
//
// Unit tests for the IngestionActor's validation pipeline.
// Exercises: topic routing, power state filtering, trust standing,
// per-peer bandwidth, temporal validation, sybil endowment, and
// forensic violation mapping.

use phalanx_forensics::policy::{IngressGovernor, TrafficGovernor};
use phalanx_node::actors::egress::EgressCommand;
use phalanx_node::actors::ingestion::{IngestionActor, IngestionCommand};
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::actors::trust_actor::TrustCommand;
use phalanx_node::clock::TrustedClock;
use phalanx_node::config::NodeConfig;
use phalanx_node::trust::ReputationProjection;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::evidence::{ChunkType, ShardChunk};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity};
use phalanx_proto::prelude::{Did, EncodingSymbolId, MeshTopic, PhalanxTimestamp, ShardId};
use phalanx_proto::trust::TrustLevel;
use phalanx_proto::types::{PowerState, SystemStress};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Tuple returned from `build_test_ingestion`: the actor under test, its
/// command sender, observer receivers for storage/egress/trust side
/// effects, and the shared system governor. Named for clippy's
/// `type_complexity` lint.
type IngestionActorRig = (
    IngestionActor,
    mpsc::Sender<IngestionCommand>,
    mpsc::Receiver<StorageCommand>,
    mpsc::Receiver<EgressCommand>,
    mpsc::Receiver<TrustCommand>,
    Arc<SystemGovernor>,
);

/// Build an IngestionActor with standard test configuration.
/// Returns the actor and all channels for injecting commands / observing side effects.
fn build_test_ingestion(config: NodeConfig) -> IngestionActorRig {
    let (ingestion_tx, ingestion_rx) = mpsc::channel(32);
    let (storage_tx, storage_rx) = mpsc::channel(32);
    let (egress_tx, egress_rx) = mpsc::channel(32);
    let (trust_tx, trust_rx) = mpsc::channel(32);
    let system_governor = Arc::new(SystemGovernor::new());

    let identity = PhalanxIdentity::new_ephemeral();

    let actor = IngestionActor::new(
        config,
        Arc::new(identity),
        Arc::new(TrustedClock::new()),
        TrafficGovernor::new(),
        IngressGovernor::new(10),
        ReputationProjection::default(),
        storage_tx,
        egress_tx,
        trust_tx,
        system_governor.clone(),
        ingestion_rx,
    );

    (
        actor,
        ingestion_tx,
        storage_rx,
        egress_rx,
        trust_rx,
        system_governor,
    )
}

/// Serialize a valid ShardChunk for a given owner DID.
fn make_chunk(owner_did: &Did, payload_size: usize) -> Vec<u8> {
    let chunk = ShardChunk {
        shard_id: ShardId(0),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::ForensicUnit,
        is_terminal: true,
        data: vec![0xAB; payload_size],
        owner_did: owner_did.clone(),
        timestamp: PhalanxTimestamp::from_millis(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64,
        ),
    };
    postcard::to_allocvec(&chunk).unwrap_or_default()
}

// =====================================================================
// Topic Routing
// =====================================================================

/// Chunks on the video topic should reach the storage actor.
#[tokio::test]
async fn test_valid_video_topic_reaches_storage() {
    let config = NodeConfig::test_defaults();
    let video_topic = config.network.video_topic.clone();
    let (actor, tx, mut storage_rx, _egress_rx, _trust_rx, _gov) = build_test_ingestion(config);

    let owner_did = Did::new("did:key:z6MkTestOwner");
    let data = make_chunk(&owner_did, 128);
    let handle = tokio::spawn(actor.run());

    tx.send(IngestionCommand::ProcessChunk {
        peer_id: NetworkId("peer-1".to_string()),
        data,
        topic: video_topic,
    })
    .await
    .unwrap_or_default();

    // Storage should receive an Ingest command
    let received = tokio::time::timeout(Duration::from_secs(2), storage_rx.recv()).await;
    assert!(
        received.is_ok() && received.unwrap_or(None).is_some(),
        "Valid video chunk should be forwarded to storage"
    );

    drop(tx);
    let _ = handle.await;
}

/// Chunks on the audio topic should also reach storage.
#[tokio::test]
async fn test_valid_audio_topic_reaches_storage() {
    let config = NodeConfig::test_defaults();
    let audio_topic = config.network.audio_topic.clone();
    let (actor, tx, mut storage_rx, _egress_rx, _trust_rx, _gov) = build_test_ingestion(config);

    let owner_did = Did::new("did:key:z6MkTestOwner");
    let data = make_chunk(&owner_did, 128);
    let handle = tokio::spawn(actor.run());

    tx.send(IngestionCommand::ProcessChunk {
        peer_id: NetworkId("peer-1".to_string()),
        data,
        topic: audio_topic,
    })
    .await
    .unwrap_or_default();

    let received = tokio::time::timeout(Duration::from_secs(2), storage_rx.recv()).await;
    assert!(
        received.is_ok() && received.unwrap_or(None).is_some(),
        "Valid audio chunk should be forwarded to storage"
    );

    drop(tx);
    let _ = handle.await;
}

/// Chunks on an invalid topic should be silently dropped — never reach storage.
#[tokio::test]
async fn test_invalid_topic_dropped() {
    let config = NodeConfig::test_defaults();
    let (actor, tx, mut storage_rx, _egress_rx, _trust_rx, _gov) = build_test_ingestion(config);

    let owner_did = Did::new("did:key:z6MkTestOwner");
    let data = make_chunk(&owner_did, 128);
    let handle = tokio::spawn(actor.run());

    tx.send(IngestionCommand::ProcessChunk {
        peer_id: NetworkId("peer-1".to_string()),
        data,
        topic: MeshTopic::new("/phalanx/bogus"),
    })
    .await
    .unwrap_or_default();

    // Give the actor time to process, then check nothing arrived
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        storage_rx.try_recv().is_err(),
        "Invalid topic should be dropped before reaching storage"
    );

    drop(tx);
    let _ = handle.await;
}

/// The control topic should also be rejected — ingestion only accepts video/audio.
#[tokio::test]
async fn test_control_topic_rejected_by_ingestion() {
    let config = NodeConfig::test_defaults();
    let control_topic = config.network.control_topic.clone();
    let (actor, tx, mut storage_rx, _egress_rx, _trust_rx, _gov) = build_test_ingestion(config);

    let owner_did = Did::new("did:key:z6MkTestOwner");
    let data = make_chunk(&owner_did, 128);
    let handle = tokio::spawn(actor.run());

    tx.send(IngestionCommand::ProcessChunk {
        peer_id: NetworkId("peer-1".to_string()),
        data,
        topic: control_topic,
    })
    .await
    .unwrap_or_default();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        storage_rx.try_recv().is_err(),
        "Control topic should be rejected by ingestion"
    );

    drop(tx);
    let _ = handle.await;
}

// =====================================================================
// Deserialization Failure
// =====================================================================

/// Garbage bytes that fail deserialization should be silently dropped.
#[tokio::test]
async fn test_garbage_bytes_dropped() {
    let config = NodeConfig::test_defaults();
    let video_topic = config.network.video_topic.clone();
    let (actor, tx, mut storage_rx, _egress_rx, _trust_rx, _gov) = build_test_ingestion(config);
    let handle = tokio::spawn(actor.run());

    tx.send(IngestionCommand::ProcessChunk {
        peer_id: NetworkId("peer-1".to_string()),
        data: vec![0xFF, 0xFE, 0xFD, 0xFC], // Not valid postcard
        topic: video_topic,
    })
    .await
    .unwrap_or_default();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        storage_rx.try_recv().is_err(),
        "Garbage bytes should fail deserialization and never reach storage"
    );

    drop(tx);
    let _ = handle.await;
}

// =====================================================================
// Temporal Validation
// =====================================================================

/// A shard with a stale timestamp (well past the evidence TTL) should be dropped.
#[tokio::test]
async fn test_stale_shard_dropped() {
    let config = NodeConfig::test_defaults();
    let video_topic = config.network.video_topic.clone();
    let (actor, tx, mut storage_rx, _egress_rx, _trust_rx, _gov) = build_test_ingestion(config);
    let handle = tokio::spawn(actor.run());

    let owner_did = Did::new("did:key:z6MkTestOwner");
    // Create a chunk with a timestamp 1 hour in the past
    let stale_chunk = ShardChunk {
        shard_id: ShardId(0),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::ForensicUnit,
        is_terminal: true,
        data: vec![0xAB; 128],
        owner_did,
        timestamp: PhalanxTimestamp::from_millis(
            (std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64)
                .saturating_sub(3_600_000),
        ),
    };
    let data = postcard::to_allocvec(&stale_chunk).unwrap_or_default();

    tx.send(IngestionCommand::ProcessChunk {
        peer_id: NetworkId("peer-1".to_string()),
        data,
        topic: video_topic,
    })
    .await
    .unwrap_or_default();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        storage_rx.try_recv().is_err(),
        "Stale shard (1 hour old) should be dropped by temporal validation"
    );

    drop(tx);
    let _ = handle.await;
}

// =====================================================================
// Power State Filtering (TrafficGovernor)
// =====================================================================

/// In Leaf power state, only local (loopback) traffic should be accepted.
/// Remote peer traffic should be silently dropped.
#[tokio::test]
async fn test_leaf_power_state_rejects_remote_traffic() {
    let config = NodeConfig::test_defaults();
    let video_topic = config.network.video_topic.clone();

    let (ingestion_tx, ingestion_rx) = mpsc::channel(32);
    let (storage_tx, mut storage_rx) = mpsc::channel(32);
    let (egress_tx, _egress_rx) = mpsc::channel(32);
    let (trust_tx, _trust_rx) = mpsc::channel(32);
    let system_governor = Arc::new(SystemGovernor::new());

    // Drive SystemGovernor to Leaf — IngestionActor syncs TrafficGovernor
    // from SystemGovernor on every chunk (P9 fix), so this is the correct lever.
    *system_governor.recommended_state.write().unwrap() = PowerState::Leaf;

    let identity = PhalanxIdentity::new_ephemeral();

    let actor = IngestionActor::new(
        config,
        Arc::new(identity),
        Arc::new(TrustedClock::new()),
        TrafficGovernor::new(),
        IngressGovernor::new(10),
        ReputationProjection::default(),
        storage_tx,
        egress_tx,
        trust_tx,
        system_governor,
        ingestion_rx,
    );
    let handle = tokio::spawn(actor.run());

    let owner_did = Did::new("did:key:z6MkTestOwner");
    let data = make_chunk(&owner_did, 128);

    ingestion_tx
        .send(IngestionCommand::ProcessChunk {
            peer_id: NetworkId("remote-peer".to_string()), // Not the local peer
            data,
            topic: video_topic,
        })
        .await
        .unwrap_or_default();

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        storage_rx.try_recv().is_err(),
        "Remote traffic should be rejected in Leaf power state"
    );

    drop(ingestion_tx);
    let _ = handle.await;
}

// =====================================================================
// Ingress Governor (Slot Allocation Under Stress)
// =====================================================================

/// When the ingress governor has zero capacity (Critical stress, 1 slot),
/// the second concurrent peer should be rejected.
#[tokio::test]
async fn test_ingress_governor_rejects_under_critical_stress() {
    let mut governor = IngressGovernor::new(10);

    // Under Critical stress, capacity = 1
    let peer_a = NetworkId("peer-a".to_string());
    let result_a =
        governor.try_allocate(peer_a.clone(), TrustLevel::Verified, SystemStress::Critical);
    assert!(result_a.is_ok(), "First peer should get the single slot");

    // Second peer should fail
    let peer_b = NetworkId("peer-b".to_string());
    let result_b = governor.try_allocate(peer_b, TrustLevel::Verified, SystemStress::Critical);
    assert!(
        result_b.is_err(),
        "Second peer should be rejected at Critical stress"
    );

    // Release first slot, second should now succeed
    governor.release_slot(&peer_a);
    let peer_c = NetworkId("peer-c".to_string());
    let result_c = governor.try_allocate(peer_c, TrustLevel::Verified, SystemStress::Critical);
    assert!(result_c.is_ok(), "Slot should be available after release");
}

/// Under Nominal stress, all 10 slots should be available.
#[tokio::test]
async fn test_ingress_governor_nominal_full_capacity() {
    let mut governor = IngressGovernor::new(10);

    for i in 0..10u32 {
        let peer = NetworkId(format!("peer-{}", i));
        let result = governor.try_allocate(peer, TrustLevel::Verified, SystemStress::Nominal);
        assert!(
            result.is_ok(),
            "Slot {} should be available under Nominal stress",
            i
        );
    }

    // 11th peer should fail
    let overflow = NetworkId("peer-overflow".to_string());
    let result = governor.try_allocate(overflow, TrustLevel::Verified, SystemStress::Nominal);
    assert!(result.is_err(), "Should fail when all slots consumed");
}

/// Fair stress reduces capacity to base_max_slots / 3.
#[tokio::test]
async fn test_ingress_governor_fair_stress_reduces_capacity() {
    let governor = IngressGovernor::new(12);
    let capacity = governor.current_capacity(SystemStress::Fair);
    assert_eq!(
        capacity, 4,
        "Fair stress should reduce 12 slots to 12/3 = 4"
    );
}

// =====================================================================
// TrafficGovernor Power State Logic
// =====================================================================

/// Normal and Conserving states accept all traffic.
#[tokio::test]
async fn test_traffic_governor_normal_accepts_all() {
    let gov = TrafficGovernor::new(); // Defaults to Normal
    let local = NetworkId("local".to_string());
    let remote = NetworkId("remote".to_string());

    assert!(
        gov.should_accept(&remote, &local),
        "Normal should accept remote"
    );
    assert!(
        gov.should_accept(&local, &local),
        "Normal should accept local"
    );
}

/// Dormant state only accepts loopback traffic.
#[tokio::test]
async fn test_traffic_governor_dormant_rejects_remote() {
    let mut gov = TrafficGovernor::new();
    gov.set_state(PowerState::Dormant);
    let local = NetworkId("local".to_string());
    let remote = NetworkId("remote".to_string());

    assert!(
        !gov.should_accept(&remote, &local),
        "Dormant should reject remote"
    );
    assert!(
        gov.should_accept(&local, &local),
        "Dormant should accept loopback"
    );
}

// =====================================================================
// Multiple Valid Chunks in Sequence
// =====================================================================

/// Multiple valid chunks from different peers should all reach storage.
/// Uses 3 chunks to stay within the quadratic Sybil endowment budget
/// (ψ/(1+(ke)²) drops faster than the old linear form under rapid bursts).
#[tokio::test]
async fn test_multiple_chunks_from_different_peers() {
    let config = NodeConfig::test_defaults();
    let video_topic = config.network.video_topic.clone();
    let (actor, tx, mut storage_rx, _egress_rx, _trust_rx, _gov) = build_test_ingestion(config);
    let handle = tokio::spawn(actor.run());

    for i in 0..3u32 {
        let owner_did = Did::new(&format!("did:key:z6MkOwner{}", i));
        let data = make_chunk(&owner_did, 128);
        tx.send(IngestionCommand::ProcessChunk {
            peer_id: NetworkId(format!("peer-{}", i)),
            data,
            topic: video_topic.clone(),
        })
        .await
        .unwrap_or_default();
    }

    // All 3 should arrive at storage
    let mut received = 0;
    for _ in 0..3u32 {
        if tokio::time::timeout(Duration::from_secs(2), storage_rx.recv())
            .await
            .is_ok()
        {
            received += 1;
        }
    }
    assert_eq!(received, 3, "All 3 valid chunks should reach storage");

    drop(tx);
    let _ = handle.await;
}
