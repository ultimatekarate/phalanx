use tempfile::tempdir;

use tracing::info;

use phalanx_core::base::config::PhalanxConfig;
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    DataPayload, EnvelopeState, Evidence, ShardChunk, StorageSequence, VideoShard, VolleyId,
    WitnessEnvelope,
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
    use phalanx_core::primitives::shards::{
        DataPayload, Evidence, StorageSequence, VideoShard, VolleyId,
    };
    use phalanx_core::primitives::time::PhalanxTimestamp;

    // 1. Create a REAL WitnessEnvelope
    let evidence = Evidence::Video(VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("test_volley"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    });

    let envelope =
        WitnessEnvelope::new(evidence, identity, identity.to_network_id(), None).unwrap();

    // 2. Serialize it to actual bytes
    let full_bytes = postcard::to_stdvec(&envelope).unwrap();

    // 3. Split those bytes into chunks
    let chunk_size = (full_bytes.len() + total as usize - 1) / total as usize;

    (0..total)
        .map(|i| {
            let start = i as usize * chunk_size;
            let end = std::cmp::min(start + chunk_size, full_bytes.len());
            let data = full_bytes[start..end].to_vec();

            ShardChunk {
                shard_id,
                chunk_index: i,
                total_chunks: total,
                owner_did: identity.did.clone(),
                chunk_type: phalanx_core::primitives::shards::ChunkType::Witnessed,
                data,
            }
        })
        .collect()
}

#[tokio::test]
async fn test_reliability_swiss_cheese_recovery() {
    // 1. Setup Context Dependencies
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let mut journal = NoOpJournal; // Use a No-Op journal for simple logic tests

    let mut reassembler = Reassembler::new();
    let shard_id = ShardId(101);

    // 2. Create Chunks (MTU level)
    let chunks = create_mock_chunks(&identity, shard_id, 3);
    let swiss_cheese = vec![chunks[0].clone(), chunks[2].clone()];

    // 3. Process Incomplete Set
    for chunk in swiss_cheese {
        // PASS ALL 6 ARGUMENTS
        let result = reassembler.ingest_chunk(chunk, &mut journal).await.unwrap();

        // result is Option<EnvelopeState>
        let state = result.expect("Reassembler should return Fragmented state");
        assert!(matches!(state, EnvelopeState::Fragmented(_)));
    }

    // 4. Fill the hole (Chunk #1)
    let final_chunk = chunks[1].clone();
    let result = reassembler
        .ingest_chunk(final_chunk, &mut journal)
        .await
        .unwrap();

    // 5. SUCCESS: State transitions to Intact
    let state = result.expect("Reassembler should return completed state");
    assert!(matches!(state, EnvelopeState::Intact(_)));
}

#[tokio::test]
async fn test_reliability_deduplication_gate() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let mut reassembler = Reassembler::new();
    let mut journal = NoOpJournal;
    let shard_id = ShardId(202);

    // CRITICAL: Use 2 chunks so the shard isn't cleared from RAM immediately
    let chunks = create_mock_chunks(&identity, shard_id, 2);
    let chunk = chunks[0].clone();

    // First ingestion works (returns Some(Fragmented))
    let first_result = reassembler
        .ingest_chunk(chunk.clone(), &mut journal)
        .await
        .unwrap();

    assert!(first_result.is_some(), "First chunk should be accepted");

    // Subsequent ingestion return None (Deduplicated)
    for _ in 0..10 {
        let dup_result = reassembler
            .ingest_chunk(chunk.clone(), &mut journal)
            .await
            .unwrap();

        assert!(
            dup_result.is_none(),
            "Deduplication failed: accepted redundant chunk index"
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
    let anchor_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Anchor Frame".to_vec()),
    };
    let anchor_envelope = WitnessEnvelope::new(
        Evidence::Video(anchor_shard),
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

    let valid_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Hijacked Frame".to_vec()),
    };

    let valid_envelope = WitnessEnvelope::new(
        Evidence::Video(valid_shard),
        &identity,
        NetworkId::random(),
        Some(anchor_hash),
    )
    .unwrap();

    // verify guardian doesn't just reject everything
    guardian
        .ingest_envelope(EnvelopeState::Intact(valid_envelope.clone()))
        .await
        .expect("Guardian should accept a valid cryptographic link");

    // THE ATTACK: Attempt a "Hash Link Collision" on Sequence 2
    let bogus_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(3),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Hijacked Frame".to_vec()),
    };

    // We intentionally forge the causality chain by pointing to a bogus hash instead of anchor_hash
    let hijacked_envelope = WitnessEnvelope::new(
        Evidence::Video(bogus_shard),
        &identity,
        NetworkId::random(),
        Some(anchor_hash),
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
