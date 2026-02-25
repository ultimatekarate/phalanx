use tempfile::tempdir;

use tracing::info;

use phalanx_core::base::config::PhalanxConfig;
use phalanx_core::base::types::MeshTopic;
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    ChunkType, DataPayload, EnvelopeState, Evidence, ShardChunk, SignatureHash, StorageSequence,
    VideoShard, VolleyId, WitnessEnvelope,
};
use phalanx_core::primitives::time::PhalanxTimestamp;
use phalanx_core::storage::reassembler::Reassembler;
use phalanx_core::storage::vault::{Guardian, GuardianError};
// Helper to generate mock chunks for testing Reassembler
use phalanx_core::base::engine::NoOpJournal;
use phalanx_core::primitives::shards::ShardId;

fn create_mock_chunks(
    identity: &PhalanxIdentity,
    shard_id: ShardId,
    total: u32,
) -> Vec<ShardChunk> {
    (0..total)
        .map(|i| {
            ShardChunk {
                shard_id,                            // Network-level grouping ID
                chunk_index: i,                      // Ordering (0, 1, 2...)
                total_chunks: total,                 // Expected MTU parts
                owner_did: identity.did.clone(),     // Identity for routing/deduplication
                chunk_type: ChunkType::ForensicUnit, // <--- FIXED: Network payload identifier (e.g., 1 for Video)
                data: vec![i as u8; 10],             // Mock payload bytes
            }
        })
        .collect()
}

#[tokio::test]
async fn test_reliability_swiss_cheese_recovery() {
    // 1. Setup Context Dependencies
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();
    let network_id = NetworkId::random();
    let topic = MeshTopic::new("phalanx/video/test");
    let mut journal = NoOpJournal; // Use a No-Op journal for simple logic tests

    let mut reassembler = Reassembler::new();
    let shard_id = ShardId(101);

    // 2. Create Chunks (MTU level)
    let chunks = create_mock_chunks(&identity, shard_id, 3);
    let swiss_cheese = vec![chunks[0].clone(), chunks[2].clone()];

    // 3. Process Incomplete Set
    for chunk in swiss_cheese {
        // PASS ALL 6 ARGUMENTS
        let result = reassembler
            .ingest_chunk(chunk, &mut journal, &topic, &config, &identity, network_id)
            .await
            .unwrap();

        // result is Option<EnvelopeState>
        let state = result.expect("Reassembler should return Fragmented state");
        assert!(matches!(state, EnvelopeState::Fragmented(_)));
    }

    // 4. Fill the hole (Chunk #1)
    let final_chunk = chunks[1].clone();
    let result = reassembler
        .ingest_chunk(
            final_chunk,
            &mut journal,
            &topic,
            &config,
            &identity,
            network_id,
        )
        .await
        .unwrap();

    // 5. SUCCESS: State transitions to Intact
    let state = result.expect("Reassembler should return completed state");
    assert!(matches!(state, EnvelopeState::Intact(_)));
}

#[tokio::test]
async fn test_reliability_deduplication_gate() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();
    let network_id = NetworkId::random();
    let topic = MeshTopic::new("phalanx/video/test");
    let mut journal = NoOpJournal;

    let mut reassembler = Reassembler::new();
    let shard_id = ShardId(202);
    let chunks = create_mock_chunks(&identity, shard_id, 1);
    let chunk = chunks[0].clone();

    // First ingestion works
    let first_result = reassembler
        .ingest_chunk(
            chunk.clone(),
            &mut journal,
            &topic,
            &config,
            &identity,
            network_id,
        )
        .await
        .unwrap();
    assert!(first_result.is_some());

    // Subsequent ingestions return None (Deduplicated)
    for _ in 0..10 {
        let dup_result = reassembler
            .ingest_chunk(
                chunk.clone(),
                &mut journal,
                &topic,
                &config,
                &identity,
                network_id,
            )
            .await
            .unwrap();

        assert!(
            dup_result.is_none(),
            "Deduplication failed: accepted redundant chunk"
        );
    }
}

#[tokio::test]
async fn test_reliability_timeline_integrity() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();

    // Test the Guardian directly to assert exact Error enums
    let mut guardian = Guardian::new(&vault_path, &config, identity.did.clone());
    let volley_id = VolleyId::new("v_timeline");

    // 1. ANCHOR: Establish the legitimate start of the timeline (Sequence 1)
    let shard_1 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Anchor Frame".to_vec()),
    };
    let anchor_envelope = WitnessEnvelope::new(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let anchor_hash = anchor_envelope.signature_hash(); // Get the true hash

    guardian
        .ingest_envelope(EnvelopeState::Intact(anchor_envelope))
        .await
        .expect("Anchor should be accepted");

    // 2. THE ATTACK: Attempt a "Hash Link Collision" on Sequence 2
    let shard_2 = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Hijacked Frame".to_vec()),
    };

    // We intentionally forge the causality chain by pointing to a bogus hash instead of anchor_hash
    let bogus_prev_hash = SignatureHash([0xFF; 32]);
    let hijacked_envelope = WitnessEnvelope::new(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
        Some(bogus_prev_hash),
    )
    .unwrap();

    // 3. VERIFICATION: The Guardian MUST catch the chain break.
    let attack_result = guardian
        .ingest_envelope(EnvelopeState::Intact(hijacked_envelope))
        .await;

    match attack_result {
        // Match the specific variant directly
        Err(GuardianError::ChainIntegrityViolation) => {
            info!("Reliability: Guardian successfully detected and rejected timeline hijack.");
        }
        // Fallback for debugging if the variant is wrapped
        Err(e) if format!("{:?}", e).contains("ChainIntegrity") => {
            info!("Reliability: Guardian rejected via debug match.");
        }
        other => panic!("Expected ChainIntegrityViolation, but got: {:?}", other),
    }
}
