use phalanx_forensics::witness::WitnessAuthority;
use phalanx_forensics::Reassembler;
use phalanx_proto::evidence::ChunkType;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::prelude::{EnvelopeState, PhalanxIdentity, ShardChunk, ShardId};

fn create_mock_chunks(
    identity: &PhalanxIdentity,
    shard_id: ShardId,
    total: u32,
) -> Vec<ShardChunk> {
    // 1. Create a REAL WitnessEnvelope
    let evidence = Evidence::Video(VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("test_volley"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    });

    let envelope =
        WitnessEnvelope::sign_envelope(evidence, identity, identity.network_id, None).unwrap();

    // 2. Serialize it to actual bytes
    let full_bytes = postcard::to_vec(&envelope).unwrap();

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
                chunk_type: ChunkType::Witnessed,
                data,
            }
        })
        .collect()
}

#[tokio::test]
async fn test_reliability_swiss_cheese_recovery() {
    // 1. Setup Context Dependencies
    let identity = PhalanxIdentity::new_ephemeral();
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
    let identity = PhalanxIdentity::new_ephemeral();
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
