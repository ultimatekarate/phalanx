// crates/phalanx-forensics/src/reassembler.rs

use crate::crucible::{Crucible, Mold};
use crate::prelude::TransientJournal;

use phalanx_proto::evidence::{
    AudioShard, ChunkType, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{Did, ShardId};
use phalanx_proto::prelude::{
    DataPayload, EnvelopeState, FragmentedEnvelope, PhalanxTimestamp, ShardChunk, ShardError,
    ShardGapReport, VolleyId,
};
use phalanx_proto::types::PowerState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// --- BLOCK-LEVEL UTILITIES ---

pub fn decompress_payload(data: &[u8]) -> Result<Vec<u8>, String> {
    lz4_flex::decompress_size_prepended(data).map_err(|e| format!("LZ4 Decompression error: {}", e))
}

pub fn compress_payload(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

// --- THE REASSEMBLER ---

pub struct Reassembler {
    pub active_shards: Crucible<ShardMold>,
    pub power_state: PowerState,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            active_shards: Crucible::new(ShardMold, std::time::Duration::from_secs(1)),
            power_state: PowerState::Normal,
        }
    }

    pub async fn ingest_chunk<J: TransientJournal>(
        &mut self,
        chunk: ShardChunk,
        journal: &mut J,
    ) -> Result<Option<EnvelopeState>, ShardError> {
        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        let shard_id = chunk.shard_id;
        let owner_did = chunk.owner_did.clone();

        match self.active_shards.process(chunk) {
            Some(envelope) => Ok(Some(EnvelopeState::Intact(envelope))),
            None => {
                let buffer = self.active_shards.get(&shard_id).unwrap();
                Ok(Some(EnvelopeState::Fragmented(FragmentedEnvelope {
                    shard_id,
                    owner_did,
                    gap_report: ShardGapReport {
                        shard_id,
                        missing_indices: buffer.missing_indices(),
                    },
                    partial_data: buffer.parts.clone(),
                })))
            }
        }
    }

    pub async fn recover_from_journal<J: TransientJournal>(
        &mut self,
        journal: &mut J,
    ) -> Result<(), ShardError> {
        let chunks = journal.read_all_chunks().await?;
        for chunk in chunks {
            // Replay the WAL chunks through the Crucible engine
            self.active_shards.process(chunk);
        }
        Ok(())
    }
}

// --- THE SHARD BUFFER (Evolution of ReassemblyBuffer) ---

#[derive(Debug, Serialize, Deserialize)]
pub struct ShardBuffer {
    pub total_chunks: u32,
    pub received_count: u32,
    pub parts: BTreeMap<u32, Vec<u8>>,
    pub owner_did: Did,
}

impl ShardBuffer {
    pub fn missing_indices(&self) -> Vec<u32> {
        (0..self.total_chunks)
            .filter(|i| !self.parts.contains_key(i))
            .collect()
    }
}

// --- THE SHARD MOLD ---

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ShardMold;

impl Mold for ShardMold {
    type Input = ShardChunk;
    type Output = WitnessEnvelope;
    type Key = ShardId;
    type Accumulator = ShardBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.shard_id
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        ShardBuffer {
            total_chunks: item.total_chunks,
            received_count: 0,
            parts: BTreeMap::new(),
            owner_did: item.owner_did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        if let std::collections::btree_map::Entry::Vacant(e) = acc.parts.entry(item.chunk_index) {
            e.insert(item.data);
            acc.received_count += 1;
        }
    }

    fn is_ready(acc: &Self::Accumulator, _elapsed: std::time::Duration) -> bool {
        acc.received_count == acc.total_chunks
    }

    fn assemble(&self, _key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        let mut full_payload = Vec::new();
        for i in 0..acc.total_chunks {
            full_payload.extend(acc.parts.get(&i)?);
        }
        postcard::from_bytes(&full_payload).ok()
    }
}

// --- WEAVER TRAITS ---

pub trait AudioWeaver {
    fn weave_audio(
        &self,
        sequence: StorageSequence,
        rate: u32,
        channels: u8,
        volley: VolleyId,
    ) -> AudioShard;
}

impl AudioWeaver for Vec<u8> {
    fn weave_audio(
        &self,
        sequence: StorageSequence,
        rate: u32,
        channels: u8,
        volley: VolleyId,
    ) -> AudioShard {
        AudioShard {
            payload: DataPayload::Compressed(compress_payload(self)),
            sequence_id: sequence,
            sample_rate: rate,
            channels,
            volley_id: volley,
            timestamp: PhalanxTimestamp::now(),
        }
    }
}

pub trait VideoWeaver {
    fn weave_video(
        &self,
        frames: Vec<Vec<u8>>,
        sequence: StorageSequence,
        fps: u8,
        volley: VolleyId,
    ) -> VideoShard;
}

impl VideoWeaver for Vec<u8> {
    fn weave_video(
        &self,
        frames: Vec<Vec<u8>>,
        sequence: StorageSequence,
        fps: u8,
        volley: VolleyId,
    ) -> VideoShard {
        let raw_bytes = postcard::to_allocvec(&frames).unwrap_or_default();
        VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: sequence,
            payload: DataPayload::Compressed(compress_payload(&raw_bytes)),
            fps,
            volley_id: volley,
        }
    }
}

// crates/phalanx-forensics/src/reassembler.rs

/// The formal trait for slicing forensic evidence into network packets.
pub trait Chunkifier {
    fn chunkify(
        &self,
        shard_id: ShardId,
        owner_did: Did,
        chunk_size: usize,
        chunk_type: ChunkType,
    ) -> Result<Vec<ShardChunk>, ShardError>;
}

impl Chunkifier for Vec<u8> {
    fn chunkify(
        &self,
        shard_id: ShardId,
        owner_did: Did,
        chunk_size: usize,
        chunk_type: ChunkType,
    ) -> Result<Vec<ShardChunk>, ShardError> {
        // 1. Safety check for empty data or invalid chunk sizes
        if self.is_empty() {
            return Ok(Vec::new());
        }
        if chunk_size == 0 {
            return Err(ShardError::InvalidSize("Chunk size cannot be zero".into()));
        }

        // 2. Calculate the "Forensic Bound" (Total Chunks)
        let total_chunks = (self.len() as f32 / chunk_size as f32).ceil() as u32;

        // 3. Slice and Map
        // We use the standard library's .chunks() for memory-efficient slicing
        let chunks = self
            .chunks(chunk_size)
            .enumerate()
            .map(|(index, data)| ShardChunk {
                shard_id,
                chunk_index: index as u32,
                total_chunks,
                data: data.to_vec(), // Convert slice to owned Vec for transport
                owner_did: owner_did.clone(),
                chunk_type,
            })
            .collect();

        Ok(chunks)
    }
}
