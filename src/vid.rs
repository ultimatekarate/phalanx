use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::{self, File};
use std::io::{self, Write, Cursor}; // Added Cursor
use std::path::Path;
use std::collections::VecDeque;

// external crates
use serde::{Serialize, Deserialize};
use image::{DynamicImage, ImageFormat, GenericImage, RgbImage}; // Added Image traits
use ed25519_dalek::{SigningKey, Signer};

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
        // 1. Extract Public Key from DID (format: did:phlx:HEX_BYTES)
        let pub_key_hex = match self.did.strip_prefix("did:phlx:") {
            Some(hex) => hex,
            None => return false,
        };

        let pub_key_bytes = match hex::decode(pub_key_hex) {
            Ok(bytes) => bytes,
            Err(_) => return false,
        };

        // 2. Reconstruct the VerifyingKey
        use ed25519_dalek::{VerifyingKey, Signature, Verifier};
        let verifying_key = match VerifyingKey::from_bytes(
            &pub_key_bytes.try_into().unwrap_or([0u8; 32])
        ) {
            Ok(key) => key,
            Err(_) => return false,
        };

        // 3. Serialize the shard and verify against signature
        let shard_bytes = postcard::to_stdvec(&self.original_shard).unwrap_or_default();
        let sig_obj = match Signature::from_slice(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };

        verifying_key.verify(&shard_bytes, &sig_obj).is_ok()
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

// ================
//   ENCRYPTION
// ================

pub fn sign_witness_data(signing_key: &SigningKey, shard: &VideoShard) -> Vec<u8> {
    let shard_bytes = postcard::to_stdvec(shard).unwrap();
    let signature = signing_key.sign(&shard_bytes);
    signature.to_bytes().to_vec()
}

pub fn get_dalek_key(libp2p_key: &libp2p::identity::Keypair) -> Result<SigningKey, String> {
    let protobuf = libp2p_key.to_protobuf_encoding()
        .map_err(|e| format!("Key conversion failed: {}", e))?;
    
    if protobuf.len() < 32 {
        return Err("Key buffer too short".into());
    }
    
    let mut secret_bytes = [0u8; 32];
    secret_bytes.copy_from_slice(&protobuf[protobuf.len() - 32..]);
    
    Ok(SigningKey::from_bytes(&secret_bytes))
}

// ====================
//   DATA RECOVERY
// ====================

pub fn recover_vault_to_images(peer_id_str: &str) -> std::io::Result<()> {
    let vault_path = if peer_id_str.contains("vault") {
        Path::new(peer_id_str).to_path_buf()
    } else {
        Path::new("./vault").join(peer_id_str)
    };

    let pure_id = vault_path.file_name().unwrap().to_str().unwrap();
    let recovery_path = Path::new("./recovered").join(pure_id);

    fs::create_dir_all(&recovery_path)?;

    for entry in fs::read_dir(&vault_path)? {
        let path = entry?.path();
        if path.extension().and_then(|s| s.to_str()) == Some("phlx") {
            let encoded_data = fs::read(&path)?;
            
            if let Ok(shard) = postcard::from_bytes::<VideoShard>(&encoded_data) {
                for (i, frame_data) in shard.frames.iter().enumerate() {
                    let filename = format!("recovered_shard{}_frame{}.jpg", shard.sequence_id, i);
                    let save_path = recovery_path.join(filename);
                    
                    let mut file = File::create(save_path)?;
                    file.write_all(frame_data)?;
                }
            }
        }
    }
    println!("Status: Recovered peer {}", pure_id);
    Ok(())
}

pub fn seal_to_vault(peer_id: &libp2p::PeerId, shards: VecDeque<VideoShard>) -> std::io::Result<()> {
    let path = format!("./vault/{}/", peer_id);
    fs::create_dir_all(&path)?;

    for shard in &shards {
        let file_path = format!("{}shard_{}.phlx", path, shard.sequence_id);
        let mut file = File::create(file_path)?;

        let data = postcard::to_stdvec(&shard)
            .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        file.write_all(&data)?;
    }
    
    println!("Status: Sealed {} shards for peer {}", shards.len(), peer_id);
    Ok(())
}

pub fn seal_to_vault_from_vec(peer_id_str: &str, shards: Vec<VideoShard>) -> io::Result<()> {
    use std::collections::VecDeque;
    seal_to_vault_id_str(peer_id_str, VecDeque::from(shards))
}

pub fn seal_to_vault_id_str(id_str: &str, shards: VecDeque<VideoShard>) -> io::Result<()> {
    let vault_dir = format!("vault/{}", id_str);
    fs::create_dir_all(&vault_dir)?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let file_path = format!("{}/evidence_{}.bin", vault_dir, now);
    let mut file = File::create(&file_path)?;

    for shard in shards {
        for frame in shard.frames {
            file.write_all(&frame)?;
        }
    }

    file.flush()?;
    println!("Stronghold: Evidence sealed to {}", file_path);
    Ok(())
}

pub fn verify_video_motion(peer_id: &str) -> std::io::Result<()> {
    let input_dir = format!("./recovered/{}/", peer_id);
    let output_file = format!("./recovered/{}_contact_sheet.jpg", peer_id);

    let mut entries: Vec<_> = fs::read_dir(&input_dir)?
        .filter_map(|e| e.ok())
        .collect();
    
    entries.sort_by_key(|e| e.path());

    if entries.is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "No recovered frames found"));
    }

    // Grid config
    let frame_w = 1920;
    let frame_h = 1080;
    let mut contact_sheet = RgbImage::new(frame_w * 3, frame_h * 3);

    println!("Status: Generating contact sheet for {}", peer_id);

    for (idx, entry) in entries.iter().take(9).enumerate() {
        let img = image::open(entry.path())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
            .to_rgb8();
        
        let x = (idx % 3) as u32 * frame_w;
        let y = (idx / 3) as u32 * frame_h;
        
        contact_sheet.copy_from(&img, x, y)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    }

    contact_sheet.save(&output_file)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    println!("Status: Contact sheet created at {}", output_file);
    Ok(())
}

// ================
//  TESTS
// ================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shredder_id_increment() {
        let mut shredder = Shredder::new();
        assert_eq!(shredder.next_id(), 0);
        assert_eq!(shredder.next_id(), 1);
        assert_eq!(shredder.next_id(), 2);
    }
    #[test]
    fn test_video_shard_structure() {
        let mut shredder = Shredder::new();
        
        // Create a shard with two "frames"
        let frames = vec![b"frame_one".to_vec(), b"frame_two".to_vec()];
        let shard = VideoShard {
            timestamp: 123456789,
            frames: frames.clone(),
            sequence_id: shredder.next_id(),
            fps: 15,
        };

        assert_eq!(shard.sequence_id, 0);
        assert_eq!(shard.frames.len(), 2);
        assert_eq!(shard.frames[0], b"frame_one".to_vec());
    }

    #[test]
    fn test_vault_creation_multi_frame() {
        let test_id = libp2p::PeerId::random();
        let mut shards = VecDeque::new();
        
        // Create a test shard with 3 dummy frames
        shards.push_back(VideoShard {
            timestamp: 100,
            frames: vec![vec![1], vec![2], vec![3]],
            sequence_id: 99,
            fps: 15,
        });

        // Seal to disk
        let result = seal_to_vault(&test_id, shards);
        assert!(result.is_ok());

        // Verify file exists
        let path = format!("./vault/{}/shard_99.phlx", test_id);
        assert!(Path::new(&path).exists(), "Vault file was not created");

        // Cleanup
        let _ = std::fs::remove_dir_all(format!("./vault/{}", test_id));
    }

    #[test]
    fn test_recovery_logic_alignment() {
        // This test ensures that the recovery tool can handle the new Vec<Vec<u8>> structure
        // We'll create a manual vault, run recovery, and check for output files.
        let test_id_str = "test_peer_recovery";
        let vault_dir = format!("./vault/{}", test_id_str);
        fs::create_dir_all(&vault_dir).unwrap();

        let shard = VideoShard {
            timestamp: 100,
            frames: vec![b"fake_jpg_data".to_vec()],
            sequence_id: 1,
            fps: 15,
        };

        let data = postcard::to_stdvec(&shard).unwrap();
        fs::write(format!("{}/shard_1.phlx", vault_dir), data).unwrap();

        // Run recovery
        let result = recover_vault_to_images(test_id_str);
        assert!(result.is_ok());

        // Check if the recovered folder has our frame
        let recovered_file = format!("./recovered/{}/recovered_shard1_frame0.jpg", test_id_str);
        assert!(Path::new(&recovered_file).exists());

        // Cleanup
        let _ = std::fs::remove_dir_all("./vault/test_peer_recovery");
        let _ = std::fs::remove_dir_all("./recovered/test_peer_recovery");
    }

    #[test]
    fn manual_verify_motion() {
        // Replace with the PeerID folder currently in your ./recovered/ directory
        let peer_id = "12D3KooWRm8rukdtBLihH9U7mnJ6GGGxAaGBMvNBjtZWsrNiyAUS"; 
        let _ = verify_video_motion(peer_id);
    }
}


