use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};

// Library Imports
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::base::types::MeshTopic;
use phalanx_core::primitives::identity::PhalanxIdentity;
use phalanx_core::primitives::shards::{
    ChunkType, DataPayload, Evidence, ShardChunk, ShardId, StorageSequence, VideoShard, VolleyId,
};
use phalanx_core::primitives::time::PhalanxTimestamp;
use phalanx_core::security::gate::WitnessGate;
use phalanx_core::security::telemetry::init_observability;
use phalanx_core::storage::journal::FileJournal;
use phalanx_core::storage::reassembler::Reassembler;
use phalanx_core::storage::stronghold::StorageActor; // Imported from library
use phalanx_core::storage::vault::Guardian;

use phalanx_core::security::telemetry::NodeRole;
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::transport::events::NetworkEvent;

#[tokio::test]
async fn test_stronghold_ingestion_and_persistence() {
    // 1. Setup Environment
    let temp_dir = tempfile::tempdir().unwrap();
    let mut config = PhalanxConfig::test_defaults();
    config.storage.vault_path = temp_dir.path().to_string_lossy().into_owned();

    let physics = PhalanxPhysics::test_profile();
    let (mut harness, _telemetry_rx) = SimulationHarness::init_mesh(config, physics);

    // 2. Spawn the Stronghold Node
    let stronghold_did = harness
        .spawn_node("vault-1", NodeRole::Stronghold)
        .await
        .expect("Failed to spawn stronghold");

    // 3. Prepare Mock Data (A legitimate chunk from an external peer)
    let (peer_identity, _) = PhalanxIdentity::generate().unwrap();
    let peer_net_id = peer_identity.to_network_id();
    let topic = MeshTopic::new("phalanx/video/1.0.0");

    let chunk = ShardChunk {
        shard_id: ShardId(101),
        chunk_index: 0,
        total_chunks: 1,
        data: vec![0xDE, 0xAD, 0xBE, 0xEF], // Mocked payload
        owner_did: peer_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    let payload = postcard::to_stdvec(&chunk).unwrap();

    // 4. Inject Network Event into the Stronghold
    harness
        .inject_event(
            &stronghold_did,
            NetworkEvent::DataReceived {
                origin: peer_net_id,
                topic,
                data: payload,
            },
        )
        .await
        .expect("Injection failed");

    // 5. Assert: Give the StorageActor a moment to write to the Vault
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Check the physical file system for the persistent shard
    let peer_safe_name = peer_identity.did.to_safe_name();
    let expected_path = temp_dir
        .path()
        .join("Vault-1_trust") // Harness names vaults based on node name
        .join(peer_safe_name);

    assert!(
        expected_path.exists(),
        "Stronghold failed to create peer directory in vault"
    );
}

#[tokio::test]
async fn test_storage_actor_metric_pipeline() {
    let _ = init_observability();

    // 1. Setup Component Dependencies
    let config = PhalanxConfig::default();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let local_peer = identity.to_network_id();

    let (chunk_tx, chunk_rx) = mpsc::channel(10);
    let storage_load = Arc::new(AtomicUsize::new(0));
    let actor_load_metric = Arc::clone(&storage_load);

    // Use an ephemeral WAL for the test
    let journal = FileJournal::new("test_actor_metrics_wal.bin")
        .await
        .expect("Failed to initialize test FileJournal");

    let guardian = Guardian::new("test_vault_metrics", &config, identity.did.clone());
    let shared_storage = Arc::new(RwLock::new(guardian));

    // 2. Instantiate the Actor directly from the Library
    let storage_actor = StorageActor {
        reassembler: Reassembler::new(),
        storage: shared_storage,
        config: config.clone(),
        identity: identity.clone(),
        chunk_rx,
        active_tasks_metric: actor_load_metric,
        physics: PhalanxPhysics::default_wan(),
        local_peer_id: local_peer.clone(),
        journal,
    };

    // 3. Start the Actor in a background task
    let actor_handle = tokio::spawn(async move {
        storage_actor.run().await;
    });

    // Verify initial state
    assert_eq!(storage_load.load(Ordering::Relaxed), 0);

    // 4. Generate and Sign Test Evidence
    let video_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("v1"),
        payload: DataPayload::Clear(vec![0xBA, 0xAD, 0xF0, 0x0D]),
    };

    let evidence = Evidence::Video(video_shard);

    // Seal evidence into a WitnessEnvelope
    let envelope = evidence
        .seal(&identity, local_peer.clone())
        .expect("Failed to seal evidence");

    let valid_data = postcard::to_stdvec(&envelope).expect("Serialization failed");

    // Create a chunk that the Reassembler will recognize
    let chunk = ShardChunk {
        shard_id: ShardId(101),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_data,
        owner_did: identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    let topic = MeshTopic::new("phalanx/video/1.0.0");

    // 5. Inject the chunk directly into the Actor's channel
    chunk_tx.send((chunk, topic, local_peer)).await.unwrap();

    // 6. Verification: Allow the actor to process the reassembly
    tokio::time::sleep(Duration::from_millis(100)).await;

    let load = storage_load.load(Ordering::Relaxed);

    // Cleanup
    actor_handle.abort();
    let _ = std::fs::remove_dir_all("test_vault_metrics");
    let _ = std::fs::remove_file("test_actor_metrics_wal.bin");

    // 7. Assert that the metric updated, proving the reassembly pipeline completed
    assert!(
        load > 0,
        "StorageActor failed to update lock-free metric after ingestion."
    );
}
