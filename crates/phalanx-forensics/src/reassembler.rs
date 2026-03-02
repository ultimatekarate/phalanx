use crate::crucible::{Crucible, Mold};
use crate::prelude::TransientJournal;
use async_trait::async_trait;
use flate2::write::GzEncoder; // Compression lives in the Lab, not Proto
use flate2::Compression;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::{Did, ShardId};
use phalanx_proto::prelude::DataPayload;
use phalanx_proto::prelude::*;
use phalanx_proto::types::PowerState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::prelude::*;
use std::io::SeekFrom;
use tracing::{error, info};

#[async_trait]
impl TransientJournal for FileJournal {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError> {
        // 1. Serialize and explicitly map the postcard::Error to a String
        let payload = postcard::to_allocvec(chunk)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        // 2. Prepare length-prefix (4-byte unsigned little-endian)
        let payload_length = payload.len() as u32;
        let length_bytes = payload_length.to_le_bytes();

        // 3. Write framing length, then payload
        self.handle
            .write_all(&length_bytes)
            .await
            .map_err(ShardError::Io)?;
        self.handle
            .write_all(&payload)
            .await
            .map_err(ShardError::Io)?;

        // 4. Flush data to disk (excluding metadata for performance)
        self.handle.sync_data().await.map_err(ShardError::Io)?;

        Ok(())
    }

    async fn sync(&mut self) -> Result<(), ShardError> {
        self.handle.sync_all().await.map_err(ShardError::Io)
    }

    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        let mut chunks = Vec::new();

        // 1. Rewind the file pointer to the beginning for boot-time recovery
        self.handle
            .seek(SeekFrom::Start(0))
            .await
            .map_err(ShardError::Io)?;

        // 2. Stream chunks sequentially using the 4-byte length prefix
        loop {
            let mut len_buf = [0u8; 4];
            match self.handle.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // Deterministic EOF
                Err(e) => return Err(ShardError::Io(e)),
            }

            let payload_len = u32::from_le_bytes(len_buf);
            let mut payload = vec![0u8; payload_len as usize];

            match self.handle.read_exact(&mut payload).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::warn!(
                        "WAL corruption detected: Incomplete payload. Truncating remainder."
                    );
                    break;
                }
                Err(e) => return Err(ShardError::Io(e)),
            }

            if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&payload) {
                chunks.push(chunk);
            } else {
                tracing::warn!("WAL corruption detected: Failed to deserialize payload.");
                break;
            }
        }

        // 3. Reset the file pointer to the end to resume appending
        self.handle
            .seek(SeekFrom::End(0))
            .await
            .map_err(ShardError::Io)?;

        Ok(chunks)
    }

    async fn clear(&mut self) -> Result<(), ShardError> {
        self.handle = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.file_path)
            .await
            .map_err(ShardError::Io)?;
        Ok(())
    }

    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError> {
        let salvage_path = self.file_path.with_file_name("egress_salvage.bin");

        let encoded = postcard::to_allocvec(pending).map_err(|e| {
            ShardError::SerializationError(format!("Salvage serialization failed: {}", e))
        })?;

        tokio::fs::write(&salvage_path, encoded)
            .await
            .map_err(ShardError::Io)?;

        info!(path = ?salvage_path, "Egress Salvage: State persisted to journal");
        Ok(())
    }

    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        let salvage_path = self.file_path.with_file_name("egress_salvage.bin");
        if !salvage_path.exists() {
            return Ok(vec![]);
        }

        let encoded = tokio::fs::read(&salvage_path)
            .await
            .map_err(ShardError::Io)?;

        let pending: Vec<PendingEgress> = postcard::from_bytes(&encoded).map_err(|_| {
            ShardError::Encryption(crate::security::e2ee::CryptoError::DecryptionFailure)
        })?;

        // Cleanup after recovery to prevent replay of the same retry state
        let _ = tokio::fs::remove_file(salvage_path).await;

        Ok(pending)
    }
}

// --- THE REASSEMBLER ---
pub struct Reassembler {
    pub active_shards: Crucible<ShardMold>,
    pub power_state: PowerState,
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
        if !acc.parts.contains_key(&item.chunk_index) {
            acc.parts.insert(item.chunk_index, item.data);
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
                missing_indices: missing_indices,
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

pub trait ShardFactory {
    fn compress_frame(&self) -> Result<Vec<u8>, ForensicError>;

    fn create_shard(&self, id: ShardId, owner: Did, is_compressed: bool) -> Shard;
}

impl ShardFactory for Vec<u8> {
    fn compress_frame(&self) -> Result<Vec<u8>, ForensicError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder
            .write_all(self)
            .map_err(|_| ForensicError::Assembly("Compression failed".into()))?;
        Ok(encoder
            .finish()
            .map_err(|_| ForensicError::Assembly("Encoder flush failed".into()))?)
    }

    fn create_shard(&self, id: ShardId, owner: Did, is_compressed: bool) -> Shard {
        Shard {
            id,
            owner_did: owner,
            metadata: ShardMetadata {
                size: self.len() as u64,
                checksum: calculate_checksum(self), // Internal helper in weaver.rs
                is_compressed,
            },
            data: DataPayload::Clear(self.clone()),
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

    let mut jpeg_bytes = Vec::new();
    let mut cursor = Cursor::new(&mut jpeg_bytes);

    img.write_to(&mut cursor, ImageFormat::Jpeg)
        .map_err(|e| format!("Compression error: {}", e))?;

    Ok(jpeg_bytes)
}

/// Creates a video shard with safe timestamp generation.
pub fn create_video_shard(
    frames: Vec<Vec<u8>>,
    sequence_id: StorageSequence,
    fps: u8,
    volley_id: VolleyId,
) -> Result<VideoShard, ShardError> {
    let clock = TrustedClock::new();
    let now = clock.forensic_now()?;

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
    let clock = TrustedClock::new();
    let now = clock.forensic_now()?;

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
    #[serde(skip, default = "tokio::time::Instant::now")]
    pub last_activity: tokio::time::Instant,
}

impl ReassemblyBuffer {
    #[must_use]
    #[allow(clippy::missing_errors_doc)]
    pub fn new(total_chunks: usize) -> Self {
        Self {
            chunks: vec![None; total_chunks],
            total_chunks,
            last_activity: tokio::time::Instant::now(),
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

async fn process_media_egress(&mut self, evidence: Evidence, local_id: NetworkId) {
    let topic = MeshTopic::new("phalanx/1.0.0");
    let shard_id = ShardId(self.seq_counter as u32);

    let pipeline_result = evidence
        .safeguard(&self.network_key)
        .and_then(|ev| self.session.seal_evidence(ev))
        .and_then(|env| env.chunkify(shard_id));

    if let Ok(chunks) = pipeline_result {
        for chunk in chunks {
            // RE-INTEGRATION: Use local_id to verify the chunk is properly attributed
            // before it touches the wire.
            if chunk.owner_did != self.identity.did {
                error!(peer = %local_id, "Egress Gate: Attribution mismatch detected. Blocking publish.");
                continue;
            }

            if let Ok(data) = postcard::to_allocvec(&chunk) {
                let _ = self.network.publish(&topic, data).await;
            }
        }
        self.seq_counter += 1;
    }
}

use phalanx_proto::prelude::*;

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
            data: DataPayload::Clear(self.clone()),
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
#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;
    use std::fmt;
    use std::io::Cursor;
    use std::ops::{Add, Deref, Sub};

    // external crates
    use image::{DynamicImage, ImageFormat};
    use serde::{Deserialize, Serialize};

    use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
    use crate::primitives::time::{PhalanxTimestamp, TimeError, TrustedClock};
    use crate::security::e2ee::{decrypt_bytes, encrypt_bytes, CryptoError, SymmetricKey};
    use crate::security::gate::ChronosGate;
    use ed25519_dalek::Signature;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn get_test_key() -> SymmetricKey {
        SymmetricKey([0x42; 32])
    }

    #[test]
    fn test_video_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let seq = StorageSequence(100);

        // Handle result via '?'
        let mut shard = create_video_shard(frames.clone(), seq, 30, "volley_1".into())?;

        if let DataPayload::Clear(data) = &shard.payload {
            let deserialized_frames: Vec<Vec<u8>> = postcard::from_bytes(data)?;
            assert_eq!(deserialized_frames, frames);
        } else {
            panic!("Newly created shard should be DataPayload::Clear");
        }

        let key = get_test_key();
        shard.payload.encrypt(&key)?;

        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce.len(), 24, "XChaCha20Poly1305 requires 24-byte nonce");
                assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
                assert_ne!(ciphertext, &vec![1, 2, 3, 4, 5, 6]);
            }
            _ => panic!("Shard payload should be Encrypted"),
        }

        let decrypted_bytes = shard.payload.decrypt(&key)?;
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted_bytes)?;
        assert_eq!(recovered_frames, frames);

        Ok(())
    }

    #[test]
    fn test_audio_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let audio_data = vec![10, 20, 30, 40];
        let seq = StorageSequence(200);
        let mut shard = create_audio_shard(audio_data.clone(), seq, 44100, 2, "volley_2".into())?;

        let key = get_test_key();
        shard.payload.encrypt(&key)?;

        let decrypted_bytes = shard.payload.decrypt(&key)?;
        assert_eq!(decrypted_bytes, audio_data);

        Ok(())
    }

    #[test]
    fn test_wrong_key_decryption_fails() -> Result<(), Box<dyn std::error::Error>> {
        let audio_data = vec![1, 2, 3, 4];
        let mut shard = create_audio_shard(audio_data, StorageSequence(1), 44100, 2, "v1".into())?;

        let correct_key = SymmetricKey([1u8; 32]);
        let wrong_key = SymmetricKey([2u8; 32]);

        shard.payload.encrypt(&correct_key)?;

        let result = shard.payload.decrypt(&wrong_key);
        assert!(result.is_err(), "Decryption should fail with wrong key");

        Ok(())
    }

    #[test]
    fn test_double_encryption_idempotency() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1]];
        let mut shard = create_video_shard(frames, StorageSequence(1), 30, "v1".into())?;
        let key = get_test_key();

        shard.payload.encrypt(&key)?;

        let (nonce1, cipher1) = match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => (nonce.clone(), ciphertext.clone()),
            _ => panic!("Should be encrypted"),
        };

        shard.payload.encrypt(&key)?;

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

        shard.payload.encrypt(&key)?;

        let wire_data = postcard::to_allocvec(&shard)?;
        let received_shard: VideoShard = postcard::from_bytes(&wire_data)?;

        let decrypted_payload = received_shard.payload.decrypt(&key)?;
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted_payload)?;

        assert_eq!(recovered_frames[0], vec![255, 0, 255]);
        assert_eq!(received_shard.sequence_id.0, 50);
        assert_eq!(received_shard.volley_id, "v_net".into());

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_proto::prelude::*;
    use phalanx_proto::shards::{
        EnvelopeState, Evidence, HandoverProof, ShardBuffer, ShardId, StorageSequence, VolleyId,
        WitnessEnvelope,
    };
    use std::collections::BTreeMap;

    struct MockJournal;
    #[async_trait]
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

    #[tokio::test]
    async fn test_reassembler_chunk_reassembly() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let mut reassembler = Reassembler::new();
        let mut journal = MockJournal;
        let local_peer = identity.to_network_id();

        // 1. Create a valid, fully-populated VideoShard
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("id"),
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        });

        // 2. Wrap in an envelope and sign it
        let original_envelope = WitnessEnvelope::new(evidence, &identity, local_peer.clone(), None)
            .expect("Failed to sign envelope");

        let serialized_envelope =
            postcard::to_allocvec(&original_envelope).expect("Failed to serialize envelope");

        // 3. Shard the serialized bytes into two halves
        let mid = serialized_envelope.len() / 2;
        let (part1, part2) = serialized_envelope.split_at(mid);

        let chunk_1 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 0,
            total_chunks: 2,
            data: part1.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        let chunk_2 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 1,
            total_chunks: 2,
            data: part2.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        // 4. Execute Ingestion Flow
        let result_1 = reassembler
            .ingest_chunk(chunk_1, &mut journal)
            .await
            .unwrap();

        // Assert that we get a Fragmented report back on partial ingestion
        assert!(
            matches!(result_1.unwrap(), EnvelopeState::Fragmented(_)),
            "Buffer should return Fragmented state after first chunk"
        );

        let result_2 = reassembler
            .ingest_chunk(chunk_2, &mut journal)
            .await
            .unwrap();

        // 5. Final Verification
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
            reassembler.active_shards.len(),
            0,
            "Memory leak: Buffer not cleared"
        );
    }

    #[test]
    fn test_shard_amalgam_gap_reporting() {
        // 1. Setup metadata
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let shard_id = ShardId(505);
        let vid = VolleyId::new("gap_test");

        // 2. Create a real WitnessEnvelope to simulate serialized data
        let video_shard =
            create_video_shard(vec![vec![0xAA, 0xBB]], StorageSequence(1), 30, vid).unwrap();

        let envelope = WitnessEnvelope::new(
            Evidence::Video(video_shard),
            &identity,
            identity.to_network_id(),
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
            estimated_chunk_size: chunk_size,
            owner_did: identity.did.clone(),
        };

        // 4. EXECUTE ASSEMBLE (The Triage Path)
        let strategy = ShardAmalgam;
        let result = strategy
            .assemble(shard_id, acc)
            .expect("Should return a state");

        // 5. ASSERTIONS
        if let EnvelopeState::Fragmented(fragmented) = result {
            assert_eq!(fragmented.shard_id, shard_id);
            assert_eq!(fragmented.gap_report.missing_chunk_indices, vec![1]);
            assert_eq!(fragmented.gap_report.expected_total_chunks, 3);
            assert_eq!(
                fragmented.partial_data.len(),
                2,
                "Should preserve the data we DO have"
            );
        } else {
            panic!("Expected Fragmented state, got {:?}", result);
        }
    }

    #[test]
    fn test_shard_amalgam_full_reassembly() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let shard_id = ShardId(707);

        // 1. Create a REAL envelope so postcard can deserialize it successfully
        let envelope = WitnessEnvelope::new(
            Evidence::Handover(HandoverProof {
                volley_id: VolleyId::new("test"),
                sequence_id: StorageSequence(0),
                old_did: identity.did.clone(),
                new_did: identity.did.clone(),
                anchor_hash: SignatureHash([0; 32]),
                old_signature: identity.sign(b"test"),
                new_signature: identity.sign(b"test"),
            }),
            &identity,
            identity.to_network_id(),
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
            estimated_chunk_size: data.len(),
            owner_did: identity.did.clone(),
        };

        let strategy = ShardAmalgam;
        // This will now succeed because the bytes represent a valid WitnessEnvelope
        let result = strategy
            .assemble(shard_id, acc)
            .expect("Should assemble successfully");

        assert!(matches!(result, EnvelopeState::Intact(_)));
    }
}
