
use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Cursor}; 

use crate::identity::PhalanxIdentity;

// external crates
use serde::{Serialize, Deserialize};
use image::{DynamicImage, ImageFormat}; 
use crate::audio;

// =====================
// DATA STRUCTURES
// =====================
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoShard {
    pub timestamp: u64,
    pub frames: Vec<Vec<u8>>,
    pub sequence_id: u32,
    pub fps: u8
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardChunk {
    pub shard_id: u32,      // Matches the VideoShard sequence_id
    pub chunk_index: u32,   // 0, 1, 2...
    pub total_chunks: u32,
    pub data: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub original_shard: VideoShard, 
    pub witness_peer_id: String,   
    pub receipt_timestamp: u64,    
    pub signature: Vec<u8>, 
    pub did: String,
    pub is_partial: bool,
}

impl WitnessEnvelope {
    pub fn verify(&self) -> bool {
        // Strip DID prefix and decode Base58 to get the raw public key
        let clean_did = self.did.replace("did:key:z", "");
        let Ok(pubkey_bytes) = bs58::decode(clean_did).into_vec() else {
            return false;
        };

        let Ok(data_bytes) = postcard::to_stdvec(&self.original_shard) else {
            return false;
        };

        PhalanxIdentity::verify(&pubkey_bytes, &data_bytes, &self.signature)
    }
    
    pub fn from_video(
        shard: VideoShard,
        identity: &crate::identity::PhalanxIdentity,
        peer_id: String,
    ) -> Self {
        let data_to_sign = postcard::to_stdvec(&shard)
            .expect("Failed to serialize shard for signing");
        
        let signature = identity.sign(&data_to_sign);

        Self {
            original_shard: shard,
            witness_peer_id: peer_id,
            receipt_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            signature,
            did: identity.did.clone(),
            is_partial: false,
        }
    }

    pub fn from_audio(
        shard: crate::audio::AudioShard,
        identity: &crate::identity::PhalanxIdentity,
        peer_id: String,
    ) -> Self {
        let pseudo_video = VideoShard {
            timestamp: shard.timestamp,
            frames: vec![shard.data], // Audio payload lives in the frame buffer
            sequence_id: shard.sequence_id,
            fps: 0, // 0 FPS signals Audio-Only to the Stronghold
        };

        // Serialize the inner shard for signing
        let data_to_sign = postcard::to_stdvec(&pseudo_video)
            .expect("Failed to serialize pseudo-video shard for signing");
        
        let signature = identity.sign(&data_to_sign);

        Self {
            original_shard: pseudo_video,
            witness_peer_id: peer_id,
            receipt_timestamp: shard.timestamp,
            signature,
            did: identity.did.clone(),
            is_partial: false,
        }
    }
}

pub fn wrap_audio_shard(
    shard: audio::AudioShard, 
    identity: &crate::identity::PhalanxIdentity,
    peer_id: String
) -> crate::shards::WitnessEnvelope {
    use crate::shards::{WitnessEnvelope, VideoShard};
    
    // We repurpose the WitnessEnvelope by wrapping the audio data
    // into a pseudo-VideoShard structure.
    // NOTE: In a future iteration, we may want a generic 'EvidenceShard' enum.
    let pseudo_video = VideoShard {
        timestamp: shard.timestamp,
        frames: vec![shard.data], // Audio data lives in the frame buffer
        sequence_id: shard.sequence_id,
        fps: 0, // 0 FPS indicates this is an Audio-Only shard
    };

    let data_to_sign = postcard::to_stdvec(&pseudo_video).unwrap();
    let signature = identity.sign(&data_to_sign);

    WitnessEnvelope {
        original_shard: pseudo_video,
        witness_peer_id: peer_id,
        receipt_timestamp: shard.timestamp,
        signature,
        did: identity.did.clone(),
        is_partial: false,
    }
}

/// Helper to split a large buffer into chunks
pub fn chunkify(shard_id: u32, data: Vec<u8>, chunk_size: usize) -> Vec<ShardChunk> {
    let total_chunks = (data.len() as f64 / chunk_size as f64).ceil() as u32;
    data.chunks(chunk_size)
        .enumerate()
        .map(|(i, chunk)| ShardChunk {
            shard_id,
            chunk_index: i as u32,
            total_chunks,
            data: chunk.to_vec(),
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

pub fn create_video_shard(buffer: Vec<Vec<u8>>, sequence_id: u32, fps: u8) -> VideoShard {
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
pub struct ReassemblyBuffer {
    /// Use Option to track exactly which chunks are present and which are missing
    pub chunks: Vec<Option<Vec<u8>>>,
    pub total_chunks: usize,
}

impl ReassemblyBuffer {
    pub fn new(total_chunks: usize) -> Self {
        Self {
            chunks: vec![None; total_chunks],
            total_chunks,
        }
    }

    pub fn try_salvage(self) -> Option<WitnessEnvelope> {
        if let Some(mut envelope) = self.assemble_partial() {
            envelope.is_partial = true;
            return Some(envelope);
        }
        None
    }

    fn assemble_partial(&self) -> Option<WitnessEnvelope> {
        // Find the average chunk size to fill gaps accurately.
        // If we don't have any chunks, we've already returned None.
        let known_chunk_size = self.chunks.iter()
            .flatten()
            .next()
            .map(|c| c.len())
            .unwrap_or(0);

        let mut salvaged_data = Vec::new();

        for chunk_opt in &self.chunks {
            match chunk_opt {
                Some(data) => salvaged_data.extend_from_slice(data),
                None => {
                    // CRITICAL: We fill missing gaps with zeros of the expected size.
                    // This preserves the offsets for subsequent fields in the struct.
                    salvaged_data.extend(std::iter::repeat(0).take(known_chunk_size));
                }
            }
        }

        if salvaged_data.is_empty() {
            return None;
        }

        // Postcard deserialization is attempted on the padded buffer.
        match postcard::from_bytes::<WitnessEnvelope>(&salvaged_data) {
            Ok(envelope) => {
                tracing::info!("Successfully salvaged partial envelope (seq: {})", envelope.original_shard.sequence_id);
                Some(envelope)
            },
            Err(e) => {
                tracing::warn!("Forensic salvage failed: {}. Data likely missing header chunks.", e);
                None
            }
        }
    }

    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }
}