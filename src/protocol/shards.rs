
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Cursor}; 
use std::ops::{Add, Sub, Deref};
use std::fmt;

// external crates
use serde::{Serialize, Deserialize};
use image::{DynamicImage, ImageFormat}; 

use crate::security::identity::{PhalanxIdentity, Did, NetworkId};
use crate::security::e2ee;

// =====================
// DATA STRUCTURES
// =====================
pub struct ReassemblyBuffer {
    pub chunks: Vec<Option<Vec<u8>>>,
    pub total_chunks: usize,
    pub last_activity: tokio::time::Instant, // Added for Sentinel cleanup
}

impl ReassemblyBuffer {
    pub fn new(total_chunks: usize) -> Self {
        Self {
            chunks: vec![None; total_chunks],
            total_chunks,
            last_activity: tokio::time::Instant::now(),
        }
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }

    /// Concatenates chunks into a single byte vector. Assumes is_complete() is true.
    pub fn assemble(&self) -> Vec<u8> {
        self.chunks.iter()
            .flatten()
            .cloned()
            .flatten()
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence {
    Video(VideoShard),
    Audio(AudioShard),
    // Future expansion: Telemetry(TelemetryShard),
}

impl Evidence {
    /// Helper to retrieve the sequence ID regardless of the inner type.
    pub fn sequence_id(&self) -> StorageSequence {
        match self {
            Evidence::Video(s) => s.sequence_id,
            Evidence::Audio(s) => s.sequence_id,
        }
    }

    // gotta group everything into a cohesive file
    pub fn volley_id(&self) -> &str {
        match self {
            Evidence::Video(s) => &s.volley_id,
            Evidence::Audio(s) => &s.volley_id,
        }
    }

    /// Helper to retrieve the capture timestamp.
    pub fn timestamp(&self) -> u64 {
        match self {
            Evidence::Video(s) => s.timestamp,
            Evidence::Audio(s) => s.timestamp,
        }
    }
}
/// The order of a data unit within a long-term storage session.
/// We use PartialOrd and Ord so the Stronghold can sort sessions for archival.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct StorageSequence(pub u32);

impl From<u32> for StorageSequence {
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl Deref for StorageSequence {
    type Target = u32;

    /// Provides direct access to the underlying u32 value.
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Add<u32> for StorageSequence {
    type Output = Self;

    /// Increments the sequence by a u32 value, returning a new StorageSequence.
    fn add(self, rhs: u32) -> Self::Output {
        StorageSequence(self.0 + rhs)
    }
}

impl Sub<u32> for StorageSequence {
    type Output = Self;

    /// Decrements the sequence by a u32 value, returning a new StorageSequence.
    fn sub(self, rhs: u32) -> Self::Output {
        StorageSequence(self.0 - rhs)
    }
}

// Implement Display for cleaner logging in Stronghold
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize, Default)]
pub struct ShardId(pub u32);

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Formats as "shard:101" instead of just "101" in logs
        write!(f, "shard:{}", self.0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoShard {
    pub timestamp: u64,
    pub sequence_id: StorageSequence,
    pub fps: u8,
    pub volley_id: String,
    pub payload: DataPayload
}

impl VideoShard {
    pub fn encrypt(&mut self, key: &[u8; 32]) -> Result<(), e2ee::CryptoError> {
        self.payload.encrypt(key)
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioShard {
    pub timestamp: u64,
    pub sequence_id: StorageSequence,
    pub sample_rate: u32,
    pub channels: u8,
    pub volley_id: String,
    pub payload: DataPayload,
}

impl AudioShard {
    pub fn encrypt(&mut self, key: &[u8; 32]) -> Result<(), e2ee::CryptoError> {
        self.payload.encrypt(key)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardChunk {
    pub shard_id: ShardId,
    pub chunk_index: u32,   // 0, 1, 2...
    pub total_chunks: u32,
    pub data: Vec<u8>,
    pub owner_did: Did,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub evidence: Evidence, 
    pub witness_peer_id: NetworkId,     
    pub witness_signature: Vec<u8>, 
    pub did: Did,
}

impl WitnessEnvelope {
    pub fn verify(&self) -> bool {
        let clean_did = self.did.0.replace("did:key:", "");
        let Ok(pubkey_bytes) = bs58::decode(clean_did).into_vec() else { return false; };
        let Ok(data_bytes) = postcard::to_stdvec(&self.evidence) else { return false; };

        PhalanxIdentity::verify(&pubkey_bytes, &data_bytes, &self.witness_signature)
    }

    pub fn new(evidence: Evidence, identity: &PhalanxIdentity, peer_id: NetworkId) -> Self {
        let data_to_sign = postcard::to_stdvec(&evidence)
            .expect("Failed to serialize evidence for signing");
        
        let signature = identity.sign(&data_to_sign);

        Self {
            evidence,
            witness_peer_id: peer_id,
            witness_signature: signature.to_vec(),
            did: identity.did.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataPayload {
    Clear(Vec<u8>),
    Encrypted {
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    }
}

// Default to empty Clear payload
impl Default for DataPayload {
    fn default() -> Self {
        DataPayload::Clear(Vec::new())
    }
}

impl DataPayload {
    pub fn encrypt(&mut self, key: &[u8; 32]) -> Result<(), e2ee::CryptoError> {
        if let DataPayload::Clear(data) = self {
            let (nonce, ciphertext) = e2ee::encrypt_bytes(key, data)?;
            *self = DataPayload::Encrypted { nonce, ciphertext };
        }
        Ok(())
    }


    pub fn decrypt(&self, key: &[u8; 32]) -> Result<Vec<u8>, e2ee::CryptoError> {
        match self {
            DataPayload::Clear(data) => Ok(data.clone()),
            DataPayload::Encrypted { nonce, ciphertext } => {
                e2ee::decrypt_bytes(key, nonce, ciphertext)
            }
        }
    }
}
/// HELPER FUNCTIONS

pub fn chunkify(shard_id: ShardId, data: Vec<u8>, chunk_size: usize, owner_did: Did) -> Vec<ShardChunk> {
    let total_chunks = (data.len() as f64 / chunk_size as f64).ceil() as u32;
    data.chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk)| ShardChunk {
            shard_id,
            chunk_index: i as u32,
            total_chunks,
            data: chunk.to_vec(),
            owner_did: owner_did.clone(),
        })
        .collect()
}

pub fn compress_frame(raw_data: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, String> {
    let img = DynamicImage::ImageRgb8(
        image::ImageBuffer::from_raw(width, height, raw_data)
            .ok_or("Failed to create image buffer")?
    );

    let mut jpeg_bytes = Vec::new();
    let mut cursor = Cursor::new(&mut jpeg_bytes);
    
    // Pure Rust JPEG compression
    img.write_to(&mut cursor, ImageFormat::Jpeg)
        .map_err(|e| format!("Compression error: {}", e))?;

    Ok(jpeg_bytes)
}

pub fn create_video_shard(frames: Vec<Vec<u8>>, sequence_id: StorageSequence, fps: u8, volley_id: String) -> VideoShard {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let raw_bytes = postcard::to_stdvec(&frames).unwrap_or_default();

    VideoShard {
        timestamp: now,
        sequence_id,
        payload: DataPayload::Clear(raw_bytes),
        fps,
        volley_id: volley_id.clone(),
    }
}

pub fn create_audio_shard(
    audio_data: Vec<u8>,
    sequence_id: StorageSequence,
    sample_rate: u32,
    channels: u8,
    volley_id: String
) -> AudioShard {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    AudioShard {
        timestamp: now,
        sequence_id,
        payload: DataPayload::Clear(audio_data),
        sample_rate,
        channels,
        volley_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: A deterministic key for testing
    fn get_test_key() -> [u8; 32] {
        [0x42; 32] 
    }

    #[test]
    fn test_video_shard_encryption_cycle() {
        // 1. Create Clear Shard
        let frames = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let seq = StorageSequence(100);
        let mut shard = create_video_shard(frames.clone(), seq, 30, "volley_1".into());

        // Verify Initial State (Clear)
        if let DataPayload::Clear(data) = &shard.payload {
            // VideoShard uses postcard to serialize frames inside the payload
            let deserialized_frames: Vec<Vec<u8>> = postcard::from_bytes(data).unwrap();
            assert_eq!(deserialized_frames, frames);
        } else {
            panic!("Newly created shard should be DataPayload::Clear");
        }

        // 2. Encrypt
        let key = get_test_key();
        shard.payload.encrypt(&key).expect("Encryption failed");

        // Verify Encrypted State
        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce.len(), 24, "XChaCha20Poly1305 requires 24-byte nonce");
                assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
                // Ensure ciphertext is NOT the same as the original cleartext (sanity check)
                assert_ne!(ciphertext, &vec![1, 2, 3, 4, 5, 6]); 
            },
            _ => panic!("Shard payload should be DataPayload::Encrypted after .encrypt()"),
        }

        // 3. Decrypt
        let decrypted_bytes = shard.payload.decrypt(&key).expect("Decryption failed");
        
        // 4. Verify Content
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted_bytes).unwrap();
        assert_eq!(recovered_frames, frames);
    }

    #[test]
    fn test_audio_shard_encryption_cycle() {
        // 1. Create Clear Audio Shard
        let audio_data = vec![10, 20, 30, 40]; // Raw audio bytes
        let seq = StorageSequence(200);
        let mut shard = create_audio_shard(audio_data.clone(), seq, 44100, 2, "volley_2".into());

        // 2. Encrypt
        let key = get_test_key();
        shard.payload.encrypt(&key).expect("Encryption failed");

        // 3. Decrypt
        let decrypted_bytes = shard.payload.decrypt(&key).expect("Decryption failed");
        
        // 4. Verify Content
        assert_eq!(decrypted_bytes, audio_data);
    }

    #[test]
    fn test_wrong_key_decryption_fails() {
        let audio_data = vec![1, 2, 3, 4];
        let mut shard = create_audio_shard(audio_data, StorageSequence(1), 44100, 2, "v1".into());
        
        let correct_key = [1u8; 32];
        let wrong_key = [2u8; 32];

        shard.payload.encrypt(&correct_key).unwrap();

        // Attempt decrypt with wrong key
        let result = shard.payload.decrypt(&wrong_key);
        assert!(result.is_err(), "Decryption should fail with wrong key");
    }

    #[test]
    fn test_double_encryption_idempotency() {
        // Calling .encrypt() twice shouldn't double-encrypt (which would corrupt data)
        let frames = vec![vec![1]];
        let mut shard = create_video_shard(frames, StorageSequence(1), 30, "v1".into());
        let key = get_test_key();

        // First encryption
        shard.payload.encrypt(&key).unwrap();
        
        // Capture the state
        let (nonce1, cipher1) = match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => (nonce.clone(), ciphertext.clone()),
            _ => panic!("Should be encrypted"),
        };

        // Second encryption call
        shard.payload.encrypt(&key).unwrap();

        // Verify state is unchanged
        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce, &nonce1, "Nonce changed on second encrypt call");
                assert_eq!(ciphertext, &cipher1, "Ciphertext changed on second encrypt call");
            },
            _ => panic!("Should remain encrypted"),
        }
    }

    #[test]
    fn test_serialization_roundtrip_encrypted() {
        // Ensure the Encrypted Shard can travel over the network (serialize/deserialize)
        let frames = vec![vec![255, 0, 255]];
        let mut shard = create_video_shard(frames, StorageSequence(50), 60, "v_net".into());
        let key = get_test_key();
        
        // Encrypt locally
        shard.payload.encrypt(&key).unwrap();

        // 1. Network Transmission (Serialize)
        let wire_data = postcard::to_stdvec(&shard).unwrap();

        // 2. Reception (Deserialize)
        let received_shard: VideoShard = postcard::from_bytes(&wire_data).unwrap();

        // 3. Access (Decrypt)
        let decrypted_payload = received_shard.payload.decrypt(&key).unwrap();
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted_payload).unwrap();

        assert_eq!(recovered_frames[0], vec![255, 0, 255]);
        assert_eq!(received_shard.sequence_id.0, 50);
        assert_eq!(received_shard.volley_id, "v_net");
    }
}