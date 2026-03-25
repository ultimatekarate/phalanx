//! ShardChunk fixtures.
//!
//! Provides pre-constructed chunks from serialized envelopes,
//! encapsulating the postcard serialization and field layout.

use phalanx_proto::evidence::{ChunkType, ShardChunk, WitnessEnvelope};
use phalanx_proto::identity::{Did, ShardId};
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::types::EncodingSymbolId;

/// ShardChunk wrapping a serialized WitnessEnvelope.
///
/// Produces a single terminal chunk with the full serialized envelope
/// as its data payload. Suitable for ingestion and simple reassembly tests.
///
/// For fountain-coded multi-chunk scenarios, use `FountainChunkifier`
/// from `phalanx-forensics` directly — that pattern requires test-specific
/// control over symbol size and repair ratio.
#[allow(clippy::expect_used)]
pub fn shard_chunk_from_envelope(
    envelope: &WitnessEnvelope,
    shard_id: ShardId,
    owner_did: &Did,
) -> ShardChunk {
    let data =
        postcard::to_allocvec(envelope).expect("serializing synthetic envelope should not fail");
    ShardChunk {
        shard_id,
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::Witnessed,
        is_terminal: true,
        data,
        owner_did: owner_did.clone(),
        timestamp: PhalanxTimestamp::from_millis(1_700_000_000_000),
    }
}
