
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Cursor}; 
use std::ops::{Add, Sub, Deref};
use std::fmt;

// external crates
use serde::{Serialize, Deserialize};
use image::{DynamicImage, ImageFormat}; 

use crate::identity::{PhalanxIdentity, Did, NetworkId};

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
    Audio(crate::audio::AudioShard),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
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
    pub frames: Vec<Vec<u8>>,
    pub sequence_id: StorageSequence,
    pub fps: u8
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
        let clean_did = self.did.0.replace("did:key:z", "");
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

pub fn create_video_shard(buffer: Vec<Vec<u8>>, sequence_id: StorageSequence, fps: u8) -> VideoShard {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    VideoShard {
        timestamp: now,
        frames: buffer,
        sequence_id,
        fps,
    }
}