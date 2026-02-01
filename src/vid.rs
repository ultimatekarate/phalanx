use std::time::{SystemTime, UNIX_EPOCH};
use std::io::{Cursor}; 

use crate::identity::PhalanxIdentity;

// external crates
use serde::{Serialize, Deserialize};
use image::{DynamicImage, ImageFormat}; 


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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub original_shard: VideoShard, 
    pub witness_peer_id: String,   
    pub receipt_timestamp: u64,    
    pub signature: Vec<u8>, 
    pub did: String,
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
}


pub struct Shredder {
    current_sequence: u32,
}


// =====
// CHUNKS
// =====
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ShardChunk {
    pub shard_id: u32,      // Matches the VideoShard sequence_id
    pub chunk_index: u32,   // 0, 1, 2...
    pub total_chunks: u32,
    pub data: Vec<u8>,
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

// =============
//   CORE LOGIC
// =============

impl Shredder {
    pub fn new() -> Self {
        Self { current_sequence: 0 }
    }

    pub fn current_id(&self) -> u32 {
        self.current_sequence
    }

    pub fn next_id(&mut self) -> u32 {
        let id = self.current_sequence;
        self.current_sequence += 1;
        id
    }

    pub fn create_shard(&mut self, buffer: Vec<Vec<u8>>) -> VideoShard {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        VideoShard {
            timestamp: now,
            frames: buffer,
            sequence_id: self.next_id(),
            fps: 15
        }
    }
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