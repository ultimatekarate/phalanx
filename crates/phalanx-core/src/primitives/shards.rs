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
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

// =====================
// DATA STRUCTURES
// =====================

/// A strongly-typed wrapper for a SHA-256 hash of a witness signature.
/// Ensures causality links are not confused with other 32-byte primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

impl SignatureHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Deterministic map of missing chunks within a specific shard.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardGapReport {
    pub shard_id: ShardId,
    pub missing_chunk_indices: Vec<u32>,
    pub expected_total_chunks: u32,
}

/// Represents a shard that failed complete reassembly but possesses
/// sufficient metadata to remain in the forensic timeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentedEnvelope {
    pub shard_id: ShardId,
    pub owner_did: Did,
    pub gap_report: ShardGapReport,
    pub partial_data: BTreeMap<u32, Vec<u8>>,
}

/// The monadic output state of the Reassembler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvelopeState {
    Intact(WitnessEnvelope),
    Fragmented(FragmentedEnvelope),
}

#[derive(Debug, thiserror::Error)]
pub enum ShardError {
    #[error("Dataset capacity exceeded: calculated chunk count {0} exceeds u32 limit")]
    CapacityExceeded(u64),

    #[error("Invalid shard configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Serialization failed: {0}")]
    Serialization(String),

    #[error("Time source error.")]
    TimeSource(#[from] TimeError),

    #[error("Cryptographic signing failed: {0}")]
    SigningError(String),

    #[error("Encryption error: {0}")]
    Encryption(#[from] CryptoError),

    // NEW: Required for Write-Ahead Log disk operations
    #[error("Disk I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("Decompression Error: {0}")]
    DecompressionFailure(String),
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

/// Cryptographic proof of a witness rotation.
/// Witness A signs the identity of Witness B + the hash of the last unit to
/// permit the ChronosGate to accept the new identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoverProof {
    pub volley_id: VolleyId, // Required for attribution
    pub sequence_id: StorageSequence,
    pub new_witness_id: NetworkId,
    pub new_witness_did: Did,
    pub handover_signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence {
    Video(VideoShard),
    Audio(AudioShard),
    Gap(ForensicGap),
    Handover(HandoverProof),
}

impl Evidence {
    #[must_use]
    pub fn sequence_id(&self) -> StorageSequence {
        match self {
            Evidence::Video(s) => s.sequence_id,
            Evidence::Audio(s) => s.sequence_id,
            Evidence::Gap(g) => g.start_seq,
            Evidence::Handover(h) => h.sequence_id,
        }
    }

    #[must_use]
    pub fn volley_id(&self) -> &VolleyId {
        match self {
            Evidence::Video(s) => &s.volley_id,
            Evidence::Audio(s) => &s.volley_id,
            Evidence::Gap(g) => &g.volley_id,
            Evidence::Handover(h) => &h.volley_id,
        }
    }

    #[must_use]
    pub fn timestamp(&self) -> PhalanxTimestamp {
        match self {
            Evidence::Video(s) => s.timestamp,
            Evidence::Audio(s) => s.timestamp,
            Evidence::Gap(g) => g.detected_at,
            Evidence::Handover(_) => PhalanxTimestamp::now(),
        }
    }
}

/// The order of a data unit within a long-term storage session.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct StorageSequence(pub u32);

impl From<u32> for StorageSequence {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl Deref for StorageSequence {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Add<u32> for StorageSequence {
    type Output = Self;
    fn add(self, rhs: u32) -> Self::Output {
        StorageSequence(self.0 + rhs)
    }
}

impl Sub<u32> for StorageSequence {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self::Output {
        StorageSequence(self.0 - rhs)
    }
}

impl std::fmt::Display for StorageSequence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::ops::AddAssign<u32> for StorageSequence {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, Default,
)]
pub struct ShardId(pub u32);

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard:{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VideoShard {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    pub fps: u8,
    pub volley_id: VolleyId,
    pub payload: DataPayload,
}

impl VideoShard {
    pub fn encrypt(&mut self, key: &SymmetricKey) -> Result<(), CryptoError> {
        self.payload.encrypt(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AudioShard {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    pub sample_rate: u32,
    pub channels: u8,
    pub volley_id: VolleyId,
    pub payload: DataPayload,
}

impl AudioShard {
    pub fn encrypt(&mut self, key: &SymmetricKey) -> Result<(), CryptoError> {
        self.payload.encrypt(key)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
pub enum ChunkType {
    #[default]
    ForensicUnit,
    Witnessed,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardChunk {
    pub shard_id: ShardId,
    pub chunk_index: u32,
    pub chunk_type: ChunkType,
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub owner_did: Did,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicGap {
    pub volley_id: VolleyId,
    pub start_seq: StorageSequence,
    pub end_seq: StorageSequence,
    pub detected_at: PhalanxTimestamp,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct VolleyId(String);

impl VolleyId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VolleyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::str::FromStr for VolleyId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.trim().is_empty() {
            Err("VolleyId cannot be empty".to_string())
        } else {
            Ok(Self(s.to_string()))
        }
    }
}

impl From<String> for VolleyId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for VolleyId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Volley {
    pub id: VolleyId,
    pub owner_did: Did,
    pub artifacts: Vec<WitnessEnvelope>,
    pub gaps: Vec<ForensicGap>,
    pub is_complete: bool,
}

/// A stateful session that maintains the causality chain for a specific timeline.
pub struct CausalitySession {
    identity: Arc<PhalanxIdentity>,
    peer_id: NetworkId,
    last_hash: Option<SignatureHash>,
}

impl CausalitySession {
    pub fn new(identity: Arc<PhalanxIdentity>, peer_id: NetworkId) -> Self {
        Self {
            identity,
            peer_id,
            last_hash: None,
        }
    }

    /// The ONLY way to produce a sealed envelope.
    /// Automatically updates the internal hash chain.
    pub fn seal_evidence(&mut self, evidence: Evidence) -> Result<WitnessEnvelope, ShardError> {
        let envelope =
            WitnessEnvelope::new(evidence, &*self.identity, self.peer_id, self.last_hash)?;

        // Update the state for the NEXT call
        self.last_hash = Some(envelope.signature_hash());

        Ok(envelope)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub evidence: Evidence,
    pub witness_peer_id: NetworkId,
    pub witness_signature: Vec<u8>,
    pub did: Did,
    pub prev_hash: Option<SignatureHash>,
}

impl WitnessEnvelope {
    /// Verifies the envelope signature without panicking.
    #[must_use]
    pub fn verify(&self) -> bool {
        let clean_did = self.did.0.replace("did:key:", "");

        // Fail-safe: if decoding fails, signature is invalid
        let Ok(pubkey_bytes) = bs58::decode(clean_did).into_vec() else {
            return false;
        };

        let Ok(data_bytes) = postcard::to_stdvec(&self.evidence) else {
            return false;
        };

        PhalanxIdentity::verify(&pubkey_bytes, &data_bytes, &self.witness_signature)
    }

    /// Creates a new signed envelope.
    ///
    /// # Sentinel Safety
    /// Returns `Result` to propagate serialization errors instead of panicking.
    pub fn new(
        evidence: Evidence,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<Self, ShardError> {
        let data_to_sign =
            postcard::to_stdvec(&evidence).map_err(|e| ShardError::Serialization(e.to_string()))?;

        let signature = identity.sign(&data_to_sign);

        Ok(Self {
            evidence,
            witness_peer_id: peer_id,
            witness_signature: signature.to_vec(),
            did: identity.did.clone(),
            prev_hash,
        })
    }

    pub fn signature_hash(&self) -> SignatureHash {
        let mut hasher = Sha256::new();
        hasher.update(&self.witness_signature);
        let result = hasher.finalize();

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        SignatureHash(hash)
    }

    pub fn chunkify(self, shard_id: ShardId) -> Result<Vec<ShardChunk>, ShardError> {
        // 1. Capture the owner's DID for the chunks
        let owner_did = self.did.clone();

        // 2. Serialize the FULL envelope (Header + Signature + Data)
        let data =
            postcard::to_stdvec(&self).map_err(|e| ShardError::Serialization(e.to_string()))?;

        // 3. Split into chunks using the standalone helper
        chunkify(
            shard_id,
            data,
            4096, // Standard Phalanx MTU
            owner_did,
            ChunkType::Witnessed,
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataPayload {
    Clear(Vec<u8>),
    Encrypted { nonce: Vec<u8>, ciphertext: Vec<u8> },
    Missing(ShardGapReport),
}

impl Default for DataPayload {
    fn default() -> Self {
        DataPayload::Clear(Vec::new())
    }
}

impl DataPayload {
    pub fn encrypt(&mut self, key: &SymmetricKey) -> Result<(), CryptoError> {
        match self {
            DataPayload::Clear(data) => {
                let (nonce, ciphertext) = encrypt_bytes(key.as_bytes(), data)?;
                *self = DataPayload::Encrypted { nonce, ciphertext };
                Ok(())
            }
            DataPayload::Encrypted { .. } => Ok(()),
            DataPayload::Missing(_) => Ok(()), // Deterministic No-Op: Cannot encrypt gaps
        }
    }

    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
        match self {
            DataPayload::Clear(data) => Ok(data.clone()),
            DataPayload::Encrypted { nonce, ciphertext } => {
                decrypt_bytes(key.as_bytes(), nonce, ciphertext)
            }
            DataPayload::Missing(_) => {
                // Compile-time enforcement against reading gaps
                Err(CryptoError::EncryptionFailure)
            }
        }
    }
}

// HELPER FUNCTIONS

pub fn chunkify(
    shard_id: ShardId,
    data: Vec<u8>,
    chunk_size: usize,
    owner_did: Did,
    chunk_type: ChunkType,
) -> Result<Vec<ShardChunk>, ShardError> {
    if data.is_empty() || chunk_size == 0 {
        return Ok(Vec::new());
    }

    let total_len = data.len() as u64;
    let size_u64 = chunk_size as u64;

    // Checked math to prevent panic on zero (already handled) but good for robustness
    let count_u64 = total_len.div_ceil(size_u64);

    let total_chunks =
        u32::try_from(count_u64).map_err(|_| ShardError::CapacityExceeded(count_u64))?;

    let chunks = data
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk_slice)| ShardChunk {
            shard_id,
            chunk_index: index as u32,
            total_chunks,
            owner_did: owner_did.clone(),
            data: chunk_slice.to_vec(),
            chunk_type,
        })
        .collect();

    Ok(chunks)
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

    let raw_bytes =
        postcard::to_stdvec(&frames).map_err(|e| ShardError::Serialization(e.to_string()))?;

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

#[cfg(test)]
mod tests {
    use super::*;

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

        let wire_data = postcard::to_stdvec(&shard)?;
        let received_shard: VideoShard = postcard::from_bytes(&wire_data)?;

        let decrypted_payload = received_shard.payload.decrypt(&key)?;
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted_payload)?;

        assert_eq!(recovered_frames[0], vec![255, 0, 255]);
        assert_eq!(received_shard.sequence_id.0, 50);
        assert_eq!(received_shard.volley_id, "v_net".into());

        Ok(())
    }
}
