use phalanx_forensics::witness::WitnessAuthority;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_proto::evidence::ChunkType;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;

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
        WitnessEnvelope::sign_envelope(evidence, identity, identity.network_id.clone(), None)
            .unwrap();

    // 2. Serialize it to actual bytes
    let full_bytes = postcard::to_allocvec(&envelope).unwrap();

    // 3. Split those bytes into chunks
    let chunk_size = (full_bytes.len() + total as usize - 1) / total as usize;

    (0..total)
        .map(|i| {
            let start = i as usize * chunk_size;
            let end = std::cmp::min(start + chunk_size, full_bytes.len());
            let data = full_bytes[start..end].to_vec();
            let timestamp = PhalanxTimestamp::now();

            ShardChunk {
                shard_id,
                chunk_index: i,
                total_chunks: total,
                owner_did: identity.did.clone(),
                chunk_type: ChunkType::Witnessed,
                data,
                timestamp,
            }
        })
        .collect()
}

#[tokio::test]
async fn test_reliability_deduplication_gate() {
    let identity = PhalanxIdentity::new_ephemeral();
    let mut reassembler = Reassembler::new();
    let mut journal = NoOpJournal;
    let shard_id = ShardId(202);

    // Use 2 chunks so the shard isn't completed and cleared from RAM immediately
    let chunks = create_mock_chunks(&identity, shard_id, 2);
    let chunk = chunks[0].clone();

    // First ingestion: returns Some(Fragmented) with chunk 1 missing
    let first_result = reassembler
        .ingest_chunk(chunk.clone(), &mut journal)
        .await
        .unwrap();

    assert!(
        matches!(&first_result, Some(EnvelopeState::Fragmented(_))),
        "First chunk should be accepted and return Fragmented state"
    );

    let first_missing = match first_result.unwrap() {
        EnvelopeState::Fragmented(f) => f.gap_report.missing_indices.clone(),
        _ => panic!("Expected Fragmented"),
    };

    // Subsequent ingestions of the same chunk: buffer state must not change.
    // The dedup guard in ShardMold::ingest silently drops duplicate chunk indices,
    // so the gap report remains identical.
    for _ in 0..10 {
        let dup_result = reassembler
            .ingest_chunk(chunk.clone(), &mut journal)
            .await
            .unwrap();

        let dup_missing = match dup_result.unwrap() {
            EnvelopeState::Fragmented(f) => f.gap_report.missing_indices.clone(),
            _ => panic!("Duplicate ingestion should not complete reassembly"),
        };

        assert_eq!(
            dup_missing, first_missing,
            "Deduplication failed: buffer state changed on redundant chunk"
        );
    }
}
