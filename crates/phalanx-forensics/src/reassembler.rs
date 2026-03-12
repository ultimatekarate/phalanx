// crates/phalanx-forensics/src/reassembler.rs

use crate::crucible::{Crucible, Mold};
use crate::prelude::TransientJournal;
use image::DynamicImage;
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

// BRIDGE API (Restored for Hardware Drivers) ---
pub fn compress_frame(raw_data: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, String> {
    let img = DynamicImage::ImageRgb8(
        image::ImageBuffer::from_raw(width, height, raw_data)
            .ok_or("Failed to create image buffer")?,
    );

    let mut output = Vec::new();
    let encoder = image::codecs::jpeg::JpegEncoder::new(&mut output);
    img.write_with_encoder(encoder)
        .map_err(|e| format!("JPEG Compression error: {}", e))?;

    Ok(output)
}

/// RESTORED: Factory for creating a network-ready VideoShard from a batch of frames.
pub fn create_video_shard(
    frames: Vec<Vec<u8>>,
    sequence: StorageSequence,
    fps: u8,
    volley: VolleyId,
) -> Result<VideoShard, ShardError> {
    let raw_bytes = postcard::to_allocvec(&frames)
        .map_err(|e| ShardError::InvalidSize(format!("Serialization fail: {}", e)))?;

    Ok(VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: sequence,
        // Automatically applies the new LZ4 block compression
        payload: DataPayload::Compressed(compress_payload(&raw_bytes)),
        fps,
        volley_id: volley,
    })
}

/// RESTORED: Factory for creating a network-ready AudioShard.
pub fn create_audio_shard(
    data: Vec<u8>,
    sequence: StorageSequence,
    rate: u32,
    channels: u8,
    volley: VolleyId,
) -> Result<AudioShard, ShardError> {
    Ok(AudioShard {
        payload: DataPayload::Compressed(compress_payload(&data)),
        sequence_id: sequence,
        sample_rate: rate,
        channels,
        volley_id: volley,
        timestamp: PhalanxTimestamp::now(),
    })
}

// --- BLOCK-LEVEL UTILITIES ---

/// S1 FIX: Decompression bomb guard.
/// Reads the claimed decompressed size from the LZ4 prepended header and rejects
/// payloads that would expand beyond MAX_DECOMPRESSED_BYTES, preventing OOM attacks.
const MAX_DECOMPRESSED_BYTES: usize = 128 * 1024 * 1024; // 128 MiB hard ceiling

pub fn decompress_payload(data: &[u8]) -> Result<Vec<u8>, String> {
    // S1 FIX: Check the claimed decompressed size before allocating.
    // lz4_flex prepends a 4-byte little-endian uncompressed size.
    if data.len() < 4 {
        return Err("LZ4 Decompression error: input too short for size header".into());
    }
    let claimed_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    if claimed_size > MAX_DECOMPRESSED_BYTES {
        return Err(format!(
            "LZ4 Decompression bomb: claimed size {} exceeds {} byte limit",
            claimed_size, MAX_DECOMPRESSED_BYTES
        ));
    }

    lz4_flex::decompress_size_prepended(data).map_err(|e| format!("LZ4 Decompression error: {}", e))
}

pub fn compress_payload(data: &[u8]) -> Vec<u8> {
    lz4_flex::compress_prepend_size(data)
}

// --- THE REASSEMBLER ---

/// P1 FIX: Maximum number of concurrent shard reassembly contexts per peer.
/// Prevents a single attacker from monopolizing the Crucible's capacity
/// by opening thousands of unique shard IDs from the same DID.
const MAX_CONTEXTS_PER_PEER: usize = 50;

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
            active_shards: Crucible::new(ShardMold, std::time::Duration::from_secs(1), 1000),
            power_state: PowerState::Normal,
        }
    }

    /// P1 FIX: Count how many active contexts belong to a specific peer.
    fn peer_context_count(&self, owner_did: &Did) -> usize {
        self.active_shards
            .contexts
            .values()
            .filter(|ctx| ctx.accumulator.owner_did == *owner_did)
            .count()
    }

    pub async fn ingest_chunk<J: TransientJournal>(
        &mut self,
        chunk: ShardChunk,
        journal: &mut J,
    ) -> Result<Option<EnvelopeState>, ShardError> {
        // P1 FIX: Per-peer quota enforcement.
        // Check if this peer already has too many active reassembly contexts.
        // Only enforce for NEW shard IDs (existing ones are already tracked).
        if !self.active_shards.contexts.contains_key(&chunk.shard_id)
            && self.peer_context_count(&chunk.owner_did) >= MAX_CONTEXTS_PER_PEER
        {
            tracing::warn!(
                peer = %chunk.owner_did,
                active_contexts = self.peer_context_count(&chunk.owner_did),
                limit = MAX_CONTEXTS_PER_PEER,
                "P1: Per-peer crucible quota exceeded"
            );
            return Err(ShardError::CapacityExceeded(MAX_CONTEXTS_PER_PEER as u64));
        }

        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        let shard_id = chunk.shard_id;
        let owner_did = chunk.owner_did.clone();

        match self.active_shards.process(chunk) {
            Ok(Some(envelope)) => Ok(Some(EnvelopeState::Intact(envelope))),
            Ok(None) => {
                if let Some(buffer) = self.active_shards.get(&shard_id) {
                    Ok(Some(EnvelopeState::Fragmented(FragmentedEnvelope {
                        shard_id,
                        owner_did,
                        gap_report: ShardGapReport {
                            shard_id,
                            missing_indices: buffer.missing_indices(),
                        },
                        partial_data: buffer.parts.clone(),
                    })))
                } else {
                    Err(ShardError::CapacityExceeded(0))
                }
            }
            // THE FIX: Map the Crucible's generic GuardianError back to a ShardError
            Err(guardian_error) => Err(ShardError::SerializationError(format!(
                "Reassembly rejected by Crucible: {:?}",
                guardian_error
            ))),
        }
    }

    pub async fn recover_from_journal<J: TransientJournal>(
        &mut self,
        journal: &mut J,
    ) -> Result<(), ShardError> {
        let chunks = journal.read_all_chunks().await?;
        for chunk in chunks {
            // Replay the WAL chunks through the Crucible engine
            let _ = self.active_shards.process(chunk);
        }
        Ok(())
    }
}

// --- THE SHARD BUFFER (Evolution of ReassemblyBuffer) ---

/// M1 FIX: Maximum bytes a single shard reassembly may accumulate.
/// Prevents memory amplification from attackers sending oversized chunks.
const MAX_SHARD_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

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

    /// Total bytes currently held across all received parts.
    pub fn accumulated_bytes(&self) -> usize {
        self.parts.values().map(|v| v.len()).sum()
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
    type Error = ShardError;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.shard_id
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        ShardBuffer {
            // FIXED: Clamp the requested chunks to our safe ceiling
            total_chunks: std::cmp::min(item.total_chunks, 10_000),
            received_count: 0,
            parts: BTreeMap::new(),
            owner_did: item.owner_did.clone(),
        }
    }

    // Byte-level buffers inherently lack cryptographic proof
    // thus this must be false.
    fn is_authoritative(_acc: &Self::Accumulator) -> bool {
        false
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) -> Result<(), Self::Error> {
        // M1 FIX: Enforce per-shard byte budget before accepting the chunk.
        let incoming_bytes = item.data.len();
        let current_bytes = acc.accumulated_bytes();
        if current_bytes + incoming_bytes > MAX_SHARD_BYTES {
            return Err(ShardError::CapacityExceeded(
                (current_bytes + incoming_bytes) as u64,
            ));
        }

        if let std::collections::btree_map::Entry::Vacant(e) = acc.parts.entry(item.chunk_index) {
            e.insert(item.data);
            acc.received_count += 1;
        }

        // Raw chunks have no causality, so we just return Ok
        Ok(())
    }

    fn is_ready(acc: &Self::Accumulator, _elapsed: std::time::Duration) -> bool {
        acc.received_count == acc.total_chunks
    }

    fn assemble(&self, _key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        // 1. O(n) Capacity Calculation: Prevent multiple reallocations
        // We sum the lengths of all chunks before allocating the final buffer.
        let total_size: usize = acc.parts.values().map(|v| v.len()).sum();

        // S3 FIX: Assembly size bound. Reject payloads that exceed our memory budget.
        if total_size > MAX_SHARD_BYTES {
            tracing::warn!(
                total_size,
                limit = MAX_SHARD_BYTES,
                "S3: Assembly rejected — total size exceeds safe limit"
            );
            return None;
        }

        // 2. Exact Allocation
        let mut full_payload = Vec::with_capacity(total_size);

        // 3. Sequential Assembly
        // Since we use a BTreeMap, iterating through 0..total_chunks
        // ensures the data is concatenated in the correct sequence.
        for i in 0..acc.total_chunks {
            let chunk_data = acc.parts.get(&i)?;
            full_payload.extend_from_slice(chunk_data);
        }

        // 4. Deserialization Gate
        crate::gate::unmarshal(&full_payload, "ShardMold::assemble").ok()
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
        let timestamp = PhalanxTimestamp::now();

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
                timestamp,
            })
            .collect();

        Ok(chunks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::judge::PayloadCipher;
    use crate::witness::WitnessAuthority;
    use phalanx_proto::crypto::SymmetricKey;
    use phalanx_proto::evidence::{Evidence, SignatureHash};
    use phalanx_proto::identity::PhalanxIdentity;
    use phalanx_proto::prelude::PendingEgress;
    use phalanx_proto::storage::HandoverProof;

    fn get_test_key() -> SymmetricKey {
        SymmetricKey([0x42; 32])
    }

    struct MockJournal;

    #[async_trait::async_trait]
    impl TransientJournal for MockJournal {
        async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
            Ok(())
        }
        async fn sync(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
            Ok(vec![])
        }
        async fn clear(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
        async fn record_pending_egress(
            &mut self,
            _pending: &[PendingEgress],
        ) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
            Ok(vec![])
        }
    }

    #[test]
    fn test_video_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let seq = StorageSequence(100);

        let mut shard = create_video_shard(frames.clone(), seq, 30, "volley_1".into())?;

        // create_video_shard produces Compressed payload
        if let DataPayload::Compressed(data) = &shard.payload {
            let decompressed = decompress_payload(data).expect("Decompression failed");
            let deserialized_frames: Vec<Vec<u8>> = postcard::from_bytes(&decompressed)?;
            assert_eq!(deserialized_frames, frames);
        } else {
            panic!("Newly created shard should be DataPayload::Compressed");
        }

        let key = get_test_key();
        shard.payload.apply_encryption(&key)?;

        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce.len(), 24, "XChaCha20Poly1305 requires 24-byte nonce");
                assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
            }
            _ => panic!("Shard payload should be Encrypted"),
        }

        // reveal() returns the compressed bytes; decompress to recover frames
        let decrypted_bytes = shard.payload.reveal(&key)?;
        let decompressed = decompress_payload(&decrypted_bytes).expect("Decompression failed");
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decompressed)?;
        assert_eq!(recovered_frames, frames);

        Ok(())
    }

    #[test]
    fn test_audio_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let audio_data = vec![10, 20, 30, 40];
        let seq = StorageSequence(200);
        let mut shard = create_audio_shard(audio_data.clone(), seq, 44100, 2, "volley_2".into())?;

        let key = get_test_key();
        shard.payload.apply_encryption(&key)?;

        // reveal() returns compressed bytes; decompress to recover audio
        let decrypted_bytes = shard.payload.reveal(&key)?;
        let decompressed = decompress_payload(&decrypted_bytes).expect("Decompression failed");
        assert_eq!(decompressed, audio_data);

        Ok(())
    }

    #[test]
    fn test_double_encryption_idempotency() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1]];
        let mut shard = create_video_shard(frames, StorageSequence(1), 30, "v1".into())?;
        let key = get_test_key();

        shard.payload.apply_encryption(&key)?;

        let (nonce1, cipher1) = match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => (nonce.clone(), ciphertext.clone()),
            _ => panic!("Should be encrypted"),
        };

        // Second call should be idempotent (already encrypted)
        shard.payload.apply_encryption(&key)?;

        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce, &nonce1, "Nonce changed on second encrypt call");
                assert_eq!(
                    ciphertext, &cipher1,
                    "Ciphertext changed on second encrypt call"
                );
            }
            _ => panic!("Should remain encrypted"),
        }

        Ok(())
    }

    #[test]
    fn test_serialization_roundtrip_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![255, 0, 255]];
        let mut shard = create_video_shard(frames, StorageSequence(50), 60, "v_net".into())?;
        let key = get_test_key();

        shard.payload.apply_encryption(&key)?;

        let wire_data = postcard::to_allocvec(&shard)?;
        let received_shard: VideoShard = postcard::from_bytes(&wire_data)?;

        let decrypted_payload = received_shard.payload.reveal(&key)?;
        let decompressed = decompress_payload(&decrypted_payload).expect("Decompression failed");
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decompressed)?;

        assert_eq!(recovered_frames[0], vec![255, 0, 255]);
        assert_eq!(received_shard.sequence_id.0, 50);
        assert_eq!(received_shard.volley_id, "v_net".into());

        Ok(())
    }

    #[tokio::test]
    async fn test_reassembler_chunk_reassembly() {
        let identity = PhalanxIdentity::new_ephemeral();
        let mut reassembler = Reassembler::new();
        let mut journal = MockJournal;
        let local_peer = identity.network_id.clone();

        // 1. Create a valid, fully-populated VideoShard
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("id"),
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        });

        // 2. Wrap in an envelope and sign it
        let original_envelope =
            WitnessEnvelope::sign_envelope(evidence, &identity.clone(), local_peer.clone(), None)
                .expect("Failed to sign envelope");

        let serialized_envelope =
            postcard::to_allocvec(&original_envelope).expect("Failed to serialize envelope");

        // 3. Shard the serialized bytes into two halves
        let mid = serialized_envelope.len() / 2;
        let (part1, part2) = serialized_envelope.split_at(mid);
        let timestamp = PhalanxTimestamp::now();

        let chunk_1 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 0,
            total_chunks: 2,
            data: part1.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
            timestamp,
        };

        let chunk_2 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 1,
            total_chunks: 2,
            data: part2.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
            timestamp,
        };

        // 4. First chunk: returns Fragmented (not yet complete)
        let result_1 = reassembler
            .ingest_chunk(chunk_1, &mut journal)
            .await
            .expect("ingest_chunk failed");

        assert!(
            matches!(result_1, Some(EnvelopeState::Fragmented(_))),
            "Buffer should return Fragmented state after first chunk"
        );

        // 5. Second chunk: completes reassembly
        let result_2 = reassembler
            .ingest_chunk(chunk_2, &mut journal)
            .await
            .expect("ingest_chunk failed");

        assert!(result_2.is_some(), "Reassembly should be complete");
        let recovered_envelope = match result_2.unwrap() {
            EnvelopeState::Intact(env) => env,
            EnvelopeState::Fragmented(gap) => {
                panic!(
                    "Expected Intact envelope, but received Fragmented state: {:?}",
                    gap
                );
            }
        };

        // Assert cryptographic integrity survived the sharding/ingestion process
        assert_eq!(
            recovered_envelope.witness_signature,
            original_envelope.witness_signature
        );
        assert_eq!(
            reassembler.active_shards.active_count(),
            0,
            "Memory leak: Buffer not cleared"
        );
    }

    #[test]
    fn test_shard_mold_gap_reporting() {
        // 1. Setup metadata
        let identity = PhalanxIdentity::new_ephemeral();
        let shard_id = ShardId(505);
        let vid = VolleyId::new("gap_test");

        // 2. Create a real WitnessEnvelope to simulate serialized data
        let video_shard =
            create_video_shard(vec![vec![0xAA, 0xBB]], StorageSequence(1), 30, vid).unwrap();

        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(video_shard),
            &identity.clone(),
            identity.network_id.clone(),
            None,
        )
        .unwrap();

        let full_serialized_data = postcard::to_allocvec(&envelope).unwrap();

        // Split data into 3 mock chunks
        let chunk_size = (full_serialized_data.len() / 3) + 1;
        let mut parts = BTreeMap::new();
        parts.insert(0, full_serialized_data[0..chunk_size].to_vec());
        // We SKIP index 1 to simulate a network drop
        parts.insert(2, full_serialized_data[(chunk_size * 2)..].to_vec());

        // 3. Manually populate the Accumulator (ShardBuffer)
        let acc = ShardBuffer {
            total_chunks: 3,
            received_count: 2, // 0 and 2 arrived, 1 is missing
            parts,
            owner_did: identity.did.clone(),
        };

        // 4. EXECUTE ASSEMBLE (The Triage Path)
        let strategy = ShardMold;
        // assemble returns None when parts are missing (can't concatenate with gaps)
        let result = strategy.assemble(shard_id, acc);

        // ShardMold::assemble returns None when a chunk is missing because
        // the loop `acc.parts.get(&i)?` short-circuits. Verify the buffer's
        // gap detection works correctly instead.
        assert!(
            result.is_none(),
            "Assemble should return None when chunks are missing"
        );

        // Verify the gap reporting logic independently
        let mut parts2 = BTreeMap::new();
        parts2.insert(0, vec![1]);
        parts2.insert(2, vec![3]);
        let buffer = ShardBuffer {
            total_chunks: 3,
            received_count: 2,
            parts: parts2,
            owner_did: identity.did.clone(),
        };
        assert_eq!(buffer.missing_indices(), vec![1]);
    }

    #[test]
    fn test_shard_mold_full_reassembly() {
        let identity = PhalanxIdentity::new_ephemeral();
        let shard_id = ShardId(707);

        // 1. Create a REAL envelope so postcard can deserialize it successfully
        use ed25519_dalek::Signer;
        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Handover(HandoverProof {
                volley_id: VolleyId::new("test"),
                sequence_id: StorageSequence(0),
                old_did: identity.did.clone(),
                new_did: identity.did.clone(),
                anchor_hash: SignatureHash([0; 32]),
                old_signature: identity.keypair.sign(b"test"),
                new_signature: identity.keypair.sign(b"test"),
            }),
            &identity,
            identity.network_id.clone(),
            None,
        )
        .unwrap();

        let data = postcard::to_allocvec(&envelope).unwrap();

        let mut parts = BTreeMap::new();
        parts.insert(0, data.clone());

        let acc = ShardBuffer {
            total_chunks: 1,
            received_count: 1,
            parts,
            owner_did: identity.did.clone(),
        };

        let strategy = ShardMold;
        let result = strategy
            .assemble(shard_id, acc)
            .expect("Should assemble successfully");

        // Verify the reassembled envelope matches the original
        assert_eq!(result.witness_signature, envelope.witness_signature);
    }
}
