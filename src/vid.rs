use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::collections::VecDeque;

// external crates
use serde::{Serialize, Deserialize};
use image::codecs::jpeg::JpegEncoder;
use image::{ExtendedColorType};
use nokhwa::Camera;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::pixel_format::RgbFormat;
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

pub struct WitnessEnvelope {
    pub original_shard: VideoShard, // The data from the uploader
    pub witness_peer_id: String,   // PeerID
    pub receipt_timestamp: u64,    // When YOU received it
    pub witness_signature: Vec<u8>, // cryptographic signature
}

pub struct Shredder {
    current_sequence: u32,
}
// =============
//   CORE LOGIC
// =============

impl Shredder {
    pub fn new() -> Self {
        Self { current_sequence: 0 }
    }

    pub fn next_id(&mut self) -> u32 {
        let id = self.current_sequence;
        self.current_sequence += 1;
        id
    }

    /// This is a single image fallback
    pub fn create_shard(&mut self, buffer: Vec<Vec<u8>>) -> VideoShard {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shard = VideoShard {
            timestamp: now,
            frames: buffer,
            sequence_id: self.current_sequence,
            fps: 15
        };

        self.current_sequence += 1;
        shard
    }


}

pub fn compress_frame(raw_pixels: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, String> {
    let mut compressed_data = Vec::new();
    
    // 1. Point an encoder at our empty vector
    let mut encoder = JpegEncoder::new_with_quality(&mut compressed_data, 50); 
    
    // 2. Encode the raw RGB pixels into JPEG format
    encoder.encode(&raw_pixels, width, height, ExtendedColorType::Rgb8)
        .map_err(|e| format!("Compression failed: {}", e))?;
    
    Ok(compressed_data)
}


// ================
//   ENCRYPTION
// ================

pub fn sign_witness_data(signing_key: &SigningKey, shard: &VideoShard) -> Vec<u8> {
    // Serialize the shard to bytes so we can sign it
    let shard_bytes = postcard::to_stdvec(shard).unwrap();
    
    // Sign the bytes with  private key
    let signature = signing_key.sign(&shard_bytes);
    
    // Return the signature as bytes
    signature.to_bytes().to_vec()
}

pub fn get_dalek_key(libp2p_key: &libp2p::identity::Keypair) -> Result<SigningKey, String> {
    // Extract the raw secret bytes from libp2p
    let protobuf = libp2p_key.to_protobuf_encoding()
        .map_err(|e| format!("Key conversion failed: {}", e))?;
    
    // We are using Ed25519 (libp2p default)
    // We take the last 32 bytes which represent the secret seed
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

    // Robust path reading.
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
                // Loop through all frames in this shard
                for (i, frame_data) in shard.frames.iter().enumerate() {
                    let filename = format!("recovered_shard{}_frame{}.jpg", shard.sequence_id, i);
                    let save_path = recovery_path.join(filename);
                    
                    let mut file = File::create(save_path)?;
                    file.write_all(frame_data)?;
                }
            }
        }
    }
    println!("Recovered: {}", pure_id);
    Ok(())
}

pub fn seal_to_vault(peer_id: &libp2p::PeerId, shards: VecDeque<VideoShard>) -> std::io::Result<()> {
    // Create the directory for this specific peer
    let path = format!("./vault/{}/", peer_id);
    fs::create_dir_all(&path)?;

    for shard in &shards {
        let file_path = format!("{}shard_{}.phlx", path, shard.sequence_id);
        let mut file = File::create(file_path)?;

        // Use Postcard to serialize the shard into a compact binary format
        let data = postcard::to_stdvec(&shard)
            .map_err(|e| std::io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        file.write_all(&data)?;
    }
    
    println!("[VAULT] Sealed {} shards for peer {}.", shards.len(), peer_id);
    Ok(())
}


// ===============
//  HARDWARE TEST
// ===============
pub fn test_single_capture() -> Result<usize, String> {
    // Identify the first camera
    let index = CameraIndex::Index(0);
    
    // Request a standard RGB format
    let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    
    // Initialize the hardware
    let mut camera = Camera::new(index, requested)
        .map_err(|e| format!("Failed to find camera: {}", e))?;

    // Open the stream
    camera.open_stream()
        .map_err(|e| format!("Failed to open stream: {}", e))?;

    // Capture one frame
    // Note: Some cameras need a moment to "warm up" (auto-exposure), 
    // but for a raw pixel test, the first frame is fine.
    let frame = camera.frame()
        .map_err(|e| format!("Failed to capture frame: {}", e))?;

    let decoded = frame.decode_image::<RgbFormat>()
        .map_err(|e| format!("Failed to decode pixels: {}", e))?;

    let bytes = decoded.into_raw();
    
    Ok(bytes.len())
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
    /*
    #[test]
    fn test_shredder_behavior() {
        let mut shredder = Shredder::new();
        let data = b"test_frame".to_vec();
        
        let shard = shredder.create_shard(data.clone());
        
        assert_eq!(shard.sequence_id, 0);
        assert_eq!(shard.data, data);
        assert!(shard.timestamp > 0);
        
        let shard2 = shredder.create_shard(b"second_frame".to_vec());
        assert_eq!(shard2.sequence_id, 1); // Increments correctly
    }

    #[test]
    fn test_vault_creation() {
        use std::collections::VecDeque;
        use std::path::Path;

        let test_id = libp2p::PeerId::random();
        let mut shards = VecDeque::new();
        shards.push_back(VideoShard {
            timestamp: 100,
            data: vec![0, 1, 2],
            sequence_id: 99,
            is_final: false,
        });

        let result = seal_to_vault(&test_id, shards);
        assert!(result.is_ok());

        let path = format!("./vault/{}/shard_99.phlx", test_id);
        assert!(Path::new(&path).exists());

        // Cleanup: remove the test vault folder
        let _ = std::fs::remove_dir_all(format!("./vault/{}", test_id));
    }

     #[test]
    fn test_camera_ingress() {
        let result = test_single_capture();
        assert!(result.is_ok(), "Camera failed: {:?}", result.err());
        let bytes = result.unwrap();
        println!("Captured frame size: {} bytes", bytes);
        assert!(bytes > 0);
    } 

    #[test]
    fn test_capture_and_save_image() {
        // 1. Capture the 6.2MB raw frame
        let index = nokhwa::utils::CameraIndex::Index(0);
        let requested = nokhwa::utils::RequestedFormat::new::<nokhwa::pixel_format::RgbFormat>(
            nokhwa::utils::RequestedFormatType::AbsoluteHighestFrameRate
        );
        let mut camera = nokhwa::Camera::new(index, requested).unwrap();
        camera.open_stream().expect("Could not open stream - Check if another app is using the cam!");
        let frame = match camera.frame() {
            Ok(f) => f,
            Err(e) => {
                panic!("ERROR: The camera is being used by another app! (Details: {:?})", e);
            }
        };
        let decoded = frame.decode_image::<nokhwa::pixel_format::RgbFormat>().unwrap();
        
        let (width, height) = (decoded.width(), decoded.height());
        let raw_bytes = decoded.into_raw();

        // 2. Compress it
        let jpeg_bytes = compress_frame(raw_bytes, width, height).expect("Compression failed");

        // 3. Save to disk in project root
        std::fs::write("sentinel_test_capture.jpg", &jpeg_bytes).unwrap();
        
        println!("Saved compressed image ({} bytes) to sentinel_test_capture.jpg", jpeg_bytes.len());
    }

    #[test]
    fn test_recovery_from_vault() {
        // folder_name is peerID in the vault directory
        let folder_name = "12D3KooWRm8rukdtBLihH9U7mnJ6GGGxAaGBMvNBjtZWsrNiyAUS"; 
        let result = recover_vault_to_images(folder_name);
        assert!(result.is_ok());
    }*/
}


