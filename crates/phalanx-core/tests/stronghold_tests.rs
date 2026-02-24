use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

// Library Imports
use phalanx_core::base::config::{PhalanxConfig, PhalanxPhysics};
use phalanx_core::base::engine::StorageActor; // Imported from library
use phalanx_core::base::types::MeshTopic;
use phalanx_core::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::ShardError;
use phalanx_core::primitives::shards::{
    ChunkType, DataPayload, Evidence, ShardChunk, ShardId, StorageSequence, VideoShard, VolleyId,
};
use phalanx_core::primitives::time::PhalanxTimestamp;
use phalanx_core::security::gate::WitnessGate;
use phalanx_core::security::telemetry::init_observability;
use phalanx_core::security::telemetry::NodeRole;
use phalanx_core::simulation::SimulationHarness;
use phalanx_core::storage::reassembler::Reassembler;
use phalanx_core::storage::reassembler::TransientJournal;
use phalanx_core::storage::vault::{Guardian, GuardianError};
use phalanx_core::transport::events::NetworkEvent;

use phalanx_core::base::engine::NoOpJournal;

/// A decorator for the Journal to track ingestion metrics via dependency inversion.
struct MetricJournal<J: TransientJournal> {
    inner: J,
    counter: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl<J: TransientJournal + Send> TransientJournal for MetricJournal<J> {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError> {
        self.inner.record_chunk(chunk).await?;
        self.counter.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), ShardError> {
        self.inner.sync().await
    }
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        self.inner.read_all_chunks().await
    }
    async fn clear(&mut self) -> Result<(), ShardError> {
        self.inner.clear().await
    }
}

#[tokio::test]
async fn test_stronghold_ingestion_and_persistence() {
    use phalanx_core::primitives::shards::{create_video_shard, WitnessEnvelope};
    // Ensure all other required types (PhalanxConfig, PhalanxPhysics, etc.) are imported at the top of your file.

    let _ = init_observability();
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

    let video_shard = create_video_shard(
        vec![vec![0xDE, 0xAD, 0xBE, 0xEF]],
        StorageSequence(1),
        30,
        VolleyId::new("v1"),
    )
    .expect("Failed to create video shard");

    // SEAL the evidence into a WitnessEnvelope
    // Includes the 4th argument 'None' for the causality anchor
    let envelope = WitnessEnvelope::new(
        Evidence::Video(video_shard),
        &peer_identity,
        peer_net_id.clone(),
        None,
    )
    .expect("Failed to seal evidence");

    // Serialize the ENVELOPE, not just raw bytes
    let valid_envelope_data = postcard::to_stdvec(&envelope).expect("Serialization failed");

    let chunk = ShardChunk {
        shard_id: ShardId(101),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_envelope_data, // NOW CONTAINS A SERIALIZED ENVELOPE
        owner_did: peer_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    // Note: The HARNESS expects the outer layer to be the ShardChunk
    let network_payload = postcard::to_stdvec(&chunk).unwrap();

    // 4. Inject Network Event
    harness
        .inject_event(
            &stronghold_did,
            NetworkEvent::DataReceived {
                origin: peer_net_id,
                topic: MeshTopic::new("phalanx/video/1.0.0"),
                data: network_payload,
            },
        )
        .await
        .expect("Injection failed");

    // 5. Assert: Give the StorageActor a moment to write to the Vault
    // 2200ms allows the 2000ms Crucible timeout to naturally trigger the flush
    tokio::time::sleep(Duration::from_millis(2200)).await;

    // Robust recursive check to find the file regardless of "vault-1" vs "DID" root naming
    fn find_file_recursive(path: &std::path::Path, target: &str) -> bool {
        if path.is_file() {
            return path.file_name().map(|n| n == target).unwrap_or(false);
        }
        if let Ok(entries) = std::fs::read_dir(path) {
            for entry in entries.flatten() {
                if find_file_recursive(&entry.path(), target) {
                    return true;
                }
            }
        }
        false
    }

    // Check the physical file system for the persistent shard
    assert!(
        // FIX: Search for the updated .volley extension instead of .vid.phlx
        find_file_recursive(temp_dir.path(), "v1.volley"),
        "Stronghold failed to create persistent shard in vault within the flush window"
    );
}

#[tokio::test]
async fn test_storage_actor_metric_pipeline() {
    let _ = init_observability();

    // 1. Setup Component Dependencies
    let config = PhalanxConfig::default();
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let local_peer_id = identity.to_network_id();

    let (chunk_tx, chunk_rx) = mpsc::channel(10);
    // Initialize the forensic escalation channel required by the actor
    let (forensic_tx, mut _forensic_rx) = mpsc::channel::<(NetworkId, Did, GuardianError)>(10);

    let storage_load = Arc::new(AtomicUsize::new(0));

    // 2. Initialize the Persistent Layer with Metric Tracking
    let base_journal = NoOpJournal; // Or FileJournal if available
    let journal = MetricJournal {
        inner: base_journal,
        counter: Arc::clone(&storage_load),
    };

    let guardian = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());
    let (_query_tx, query_rx) = tokio::sync::mpsc::channel(100);

    let storage_actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian,
        journal,
        config: config.clone(),
        identity: identity.clone(),
        chunk_rx,
        forensic_tx,
        local_peer_id: local_peer_id.clone(),
        query_rx,
    };

    // 3. Start the Actor in a background task
    let actor_handle = tokio::spawn(async move {
        storage_actor.run().await;
    });

    assert_eq!(storage_load.load(Ordering::Relaxed), 0);

    // 4. Generate and Sign Test Evidence
    let video_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("v1"),
        payload: DataPayload::Clear(vec![0xBA, 0xAD, 0xF0, 0x0D]),
    };

    let envelope = Evidence::Video(video_shard)
        .seal(&identity, local_peer_id.clone(), None)
        .expect("Failed to seal evidence");

    let valid_data = postcard::to_stdvec(&envelope).expect("Serialization failed");

    let chunk = ShardChunk {
        shard_id: ShardId(101),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_data,
        owner_did: identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
    };

    let topic = MeshTopic::new("phalanx/video/1.0.0");

    // 5. Inject the chunk
    chunk_tx.send((chunk, topic, local_peer_id)).await.unwrap();

    // 6. Verification: Wait for reassembly and journal commit
    tokio::time::sleep(Duration::from_millis(200)).await;

    let final_load = storage_load.load(Ordering::SeqCst);

    // Cleanup
    actor_handle.abort();

    // 7. Assert metric update
    // The counter increments when the actor calls journal.record_chunk()
    assert!(
        final_load > 0,
        "StorageActor failed to update metric via the Journal conduit. Load: {}",
        final_load
    );
}
