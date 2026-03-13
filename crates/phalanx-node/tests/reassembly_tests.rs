use phalanx_forensics::reassembler::FountainChunkifier;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_proto::evidence::ChunkType;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::types::Fps;

/// Creates real fountain-coded ShardChunks from a signed WitnessEnvelope.
/// Uses the production encode path — no fake sequential splitting.
fn create_mock_fountain_chunks(identity: &PhalanxIdentity, shard_id: ShardId) -> Vec<ShardChunk> {
    // 1. Create a REAL WitnessEnvelope
    let evidence = Evidence::Video(VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: RecordingId::new("test_recording"),
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        lens_metrics: ForensicMetrics::default(),
    });

    let envelope =
        WitnessEnvelope::sign_envelope(evidence, identity, identity.network_id.clone(), None)
            .unwrap();

    // 2. Serialize it to actual bytes
    let full_bytes = postcard::to_allocvec(&envelope).unwrap();

    // 3. Fountain-encode into symbols (small symbol size → multiple symbols)
    full_bytes
        .fountain_chunkify(
            shard_id,
            identity.did.clone(),
            SymbolSize(64), // Small symbols → many symbols → good for partial tests
            ChunkType::Witnessed,
            RepairRatio::new(1.5), // 50% redundancy
        )
        .expect("Fountain encoding should succeed")
}

/// Verifies that the fountain deduplication guard works correctly:
/// - Duplicate symbols are silently dropped (ShardMold::ingest skips same ESI)
/// - Duplicate ingestion does not cause false completion
/// - After all unique symbols arrive, the decoder completes successfully
#[tokio::test]
async fn test_reliability_deduplication_gate() {
    let identity = PhalanxIdentity::new_ephemeral();
    let mut reassembler = Reassembler::new();
    let mut journal = NoOpJournal;
    let shard_id = ShardId(202);

    // Create fountain-coded chunks (multiple symbols from the encoder)
    let chunks = create_mock_fountain_chunks(&identity, shard_id);
    assert!(chunks.len() >= 3, "Need multiple symbols for dedup test");

    // Take only the FIRST chunk — not enough for the decoder to complete
    let chunk = chunks[0].clone();

    // First ingestion: decoder can't complete yet → returns None
    let first_result = reassembler
        .ingest_chunk(chunk.clone(), &mut journal)
        .await
        .unwrap();

    assert!(
        first_result.is_none(),
        "Single symbol should not complete fountain decoding"
    );

    // Subsequent ingestions of the SAME chunk: dedup guard in ShardMold::ingest
    // silently drops duplicate ESIs. The decoder still can't complete.
    for _ in 0..10 {
        let dup_result = reassembler
            .ingest_chunk(chunk.clone(), &mut journal)
            .await
            .unwrap();

        assert!(
            dup_result.is_none(),
            "Duplicate symbol ingestion should not complete reassembly"
        );
    }

    // Now send the remaining UNIQUE symbols — decoder should complete
    let mut completed = false;
    for c in chunks.iter().skip(1) {
        let result = reassembler
            .ingest_chunk(c.clone(), &mut journal)
            .await
            .unwrap();

        if result.is_some() {
            completed = true;
            break;
        }
    }

    assert!(
        completed,
        "Feeding all unique symbols should complete fountain decoding"
    );
}
