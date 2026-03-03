use crate::crucible::{Crucible, Mold};
use crate::prelude::TransientJournal;
use crate::ForensicError;
use image::DynamicImage;
use phalanx_proto::evidence::AudioShard;
use phalanx_proto::evidence::ChunkType;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::{Did, ShardId};
use phalanx_proto::prelude::DataPayload;
use phalanx_proto::prelude::*;
use phalanx_proto::types::PowerState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::error;
use tracing::warn;

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

    /// Primary entry point for the IngressOrchestrator.
    /// Manages the Write-Ahead Log (WAL) and the in-memory reassembly.
    pub async fn ingest_chunk<J: TransientJournal>(
        &mut self,
        chunk: ShardChunk,
        journal: &mut J,
    ) -> Result<Option<EnvelopeState>, ShardError> {
        // 1. Forensic Persistence (The WAL)
        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        let shard_id = chunk.shard_id;
        let owner_did = chunk.owner_did.clone();

        // 2. Delegate to the Crucible Engine
        match self.active_shards.process(chunk) {
            Some(envelope) => Ok(Some(EnvelopeState::Intact(envelope))),
            None => {
                // If not ready, return a "Swiss Cheese" gap report
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
            self.active_shards.process(chunk);
        }
        Ok(())
    }
}

// --- THE SHARD MOLD (The Strategy) ---
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
            estimated_chunk_size: 0,
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

#[derive(Debug, Serialize, Deserialize)]
pub struct ShardBuffer {
    pub total_chunks: u32,
    pub received_count: u32,
    pub parts: BTreeMap<u32, Vec<u8>>,
    pub estimated_chunk_size: usize,
    pub owner_did: Did,
}

impl ShardBuffer {
    pub fn missing_indices(&self) -> Vec<u32> {
        (0..self.total_chunks)
            .filter(|i| !self.parts.contains_key(i))
            .collect()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShardAmalgam;

impl Mold for ShardAmalgam {
    type Input = ShardChunk;
    type Output = EnvelopeState;
    type Key = ShardId;
    type Accumulator = ShardBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.shard_id
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let mut parts = BTreeMap::new();
        parts.insert(item.chunk_index, item.data.clone());
        ShardBuffer {
            total_chunks: item.total_chunks,
            received_count: 1,
            parts,
            estimated_chunk_size: item.data.len(),
            owner_did: item.owner_did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        if !acc.parts.contains_key(&item.chunk_index) {
            if item.data.len() > acc.estimated_chunk_size {
                acc.estimated_chunk_size = item.data.len();
            }
            acc.parts.insert(item.chunk_index, item.data);
            acc.received_count += 1;
        }
    }

    fn is_ready(acc: &Self::Accumulator, _elapsed: Duration) -> bool {
        acc.received_count == acc.total_chunks
    }

    fn assemble(&self, key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        // Incomplete or fragmented data - triggered by flush_stale/flush_all
        if acc.received_count != acc.total_chunks {
            warn!(?key, received=%acc.received_count, total=%acc.total_chunks, "ShardAmalgam: Incomplete shard, transitioning to Fragmented state");

            let mut missing_indices = Vec::new();
            for i in 0..acc.total_chunks {
                if !acc.parts.contains_key(&i) {
                    missing_indices.push(i);
                }
            }

            let gap_report = ShardGapReport {
                shard_id: key,
                missing_indices,
            };

            let fragmented = FragmentedEnvelope {
                shard_id: key,
                owner_did: acc.owner_did,
                gap_report,
                partial_data: acc.parts,
            };

            return Some(EnvelopeState::Fragmented(fragmented));
        }

        // Case 2: Happy path, every is there.
        let mut full_data = Vec::new();
        for i in 0..acc.total_chunks {
            if let Some(part) = acc.parts.get(&i) {
                full_data.extend_from_slice(part);
            } else {
                error!(?key, chunk_index=%i, "ShardAmalgam: Illegal internal state, missing chunk despite count match");
                return None;
            }
        }

        match postcard::from_bytes(&full_data) {
            Ok(env) => Some(EnvelopeState::Intact(env)),
            Err(e) => {
                error!(?key, error=%e, "ShardAmalgam: Deserialization failed on complete shard");
                None
            }
        }
    }
}

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
        if self.is_empty() || chunk_size == 0 {
            return Ok(Vec::new());
        }

        let total_chunks = (self.len() as f32 / chunk_size as f32).ceil() as u32;

        Ok(self
            .chunks(chunk_size)
            .enumerate()
            .map(|(i, data)| ShardChunk {
                shard_id,
                chunk_index: i as u32,
                total_chunks,
                data: data.to_vec(),
                owner_did: owner_did.clone(),
                chunk_type,
            })
            .collect())
    }
}

pub fn compress_frame(raw_data: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, String> {
    let img = DynamicImage::ImageRgb8(
        image::ImageBuffer::from_raw(width, height, raw_data)
            .ok_or("Failed to create image buffer")?,
    );

    let _jpeg_bytes = img.to_rgb8().to_vec();

    // Use the image crate's built-in buffer writer to avoid std::io::Cursor
    let mut output = Vec::new();
    let encoder = image::codecs::jpeg::JpegEncoder::new(&mut output);
    img.write_with_encoder(encoder)
        .map_err(|e| format!("Compression error: {}", e))?;

    Ok(output)
}

/// Creates a video shard with safe timestamp generation.
pub fn create_video_shard(
    frames: Vec<Vec<u8>>,
    sequence_id: StorageSequence,
    fps: u8,
    volley_id: VolleyId,
) -> Result<VideoShard, ShardError> {
    let now = PhalanxTimestamp::now();

    let raw_bytes = postcard::to_allocvec(&frames)
        .map_err(|e| ShardError::SerializationError(e.to_string()))?;

    Ok(VideoShard {
        timestamp: now,
        sequence_id,
        payload: DataPayload::Clear(raw_bytes),
        fps,
        volley_id,
    })
}

/// Creates an audio shard with safe timestamp generation.
pub fn create_audio_shard(
    audio_data: Vec<u8>,
    sequence_id: StorageSequence,
    sample_rate: u32,
    channels: u8,
    volley_id: VolleyId,
) -> Result<AudioShard, ShardError> {
    let now = PhalanxTimestamp::now(); // FIX: Remove the ? and TrustedClock

    Ok(AudioShard {
        timestamp: now,
        sequence_id,
        payload: DataPayload::Clear(audio_data),
        sample_rate,
        channels,
        volley_id,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassemblyBuffer {
    pub chunks: Vec<Option<Vec<u8>>>,
    pub total_chunks: usize,
    #[serde(skip, default = "std::time::Instant::now")]
    pub last_activity: std::time::Instant,
}

impl ReassemblyBuffer {
    #[must_use]
    #[allow(clippy::missing_errors_doc)]
    pub fn new(total_chunks: usize) -> Self {
        Self {
            chunks: vec![None; total_chunks],
            total_chunks,
            last_activity: std::time::Instant::now(),
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }

    /// Concatenates chunks into a single byte vector. Assumes is_complete() is true.
    #[must_use]
    pub fn assemble(&self) -> Vec<u8> {
        self.chunks.iter().flatten().flatten().cloned().collect()
    }
}

pub trait AudioWeaver {
    /// The "Birth" Verb for audio data.
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
        // This is where shards::create_audio_shard logic now lives
        AudioShard {
            payload: DataPayload::Clear(self.clone()),
            sequence_id: sequence,
            sample_rate: rate,
            channels,
            volley_id: volley,
            timestamp: PhalanxTimestamp::now(),
        }
    }
}

pub trait VideoWeaver {
    /// The "Transformation" Verb: Compresses raw RGB/YUV data.
    fn compress_frame(data: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, ForensicError>;

    /// The "Birth" Verb: Packages frames into a VideoShard.
    fn weave_video(&self, sequence: StorageSequence, fps: u8, volley: VolleyId) -> VideoShard;
}
