use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::{self, File};
use std::io::{self, Write};
use std::collections::VecDeque;
use serde::{Serialize, Deserialize};

use nokhwa::Camera;
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::pixel_format::RgbFormat;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VideoShard {
    pub timestamp: u64,
    pub data: Vec<u8>,
    pub sequence_id: u32,
    pub is_final: bool,
}

pub struct WitnessEnvelope {
    pub original_shard: VideoShard, // The data from the uploader
    pub witness_peer_id: String,   // Your PeerID
    pub receipt_timestamp: u64,    // When YOU received it
    pub witness_signature: Vec<u8>, // Your cryptographic signature
}

pub struct Shredder {
    current_sequence: u32,
}

impl Shredder {
    pub fn new() -> Self {
        Self { current_sequence: 0 }
    }

    /// Takes a raw buffer (from the camera) and "shreds" it into a Phalanx Shard
    pub fn create_shard(&mut self, buffer: Vec<u8>) -> VideoShard {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let shard = VideoShard {
            timestamp: now,
            data: buffer,
            sequence_id: self.current_sequence,
            is_final: false,
        };

        self.current_sequence += 1;
        shard
    }
}
#[allow(dead_code)]

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

pub fn test_single_capture() -> Result<usize, String> {
    // 1. Identify the first camera
    let index = CameraIndex::Index(0);
    
    // 2. Request a standard RGB format
    let requested = RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate);
    
    // 3. Initialize the hardware
    let mut camera = Camera::new(index, requested)
        .map_err(|e| format!("Failed to find camera: {}", e))?;

    // 4. Open the stream
    camera.open_stream()
        .map_err(|e| format!("Failed to open stream: {}", e))?;

    // 5. Capture one frame
    // Note: Some cameras need a moment to "warm up" (auto-exposure), 
    // but for a raw pixel test, the first frame is fine.
    let frame = camera.frame()
        .map_err(|e| format!("Failed to capture frame: {}", e))?;

    let decoded = frame.decode_image::<RgbFormat>()
        .map_err(|e| format!("Failed to decode pixels: {}", e))?;

    let bytes = decoded.into_raw();
    
    Ok(bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;

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
        camera.open_stream().unwrap();
        let frame = camera.frame().unwrap();
        let decoded = frame.decode_image::<nokhwa::pixel_format::RgbFormat>().unwrap();
        
        let (width, height) = (decoded.width(), decoded.height());
        let raw_bytes = decoded.into_raw();

        // 2. Compress it
        let jpeg_bytes = compress_frame(raw_bytes, width, height).expect("Compression failed");

        // 3. Save to disk in your project root
        std::fs::write("sentinel_test_capture.jpg", &jpeg_bytes).unwrap();
        
        println!("📸 Saved compressed image ({} bytes) to sentinel_test_capture.jpg", jpeg_bytes.len());
    }
}

