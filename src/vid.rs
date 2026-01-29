use std::time::{SystemTime, UNIX_EPOCH};
use std::fs::{self, File};
use std::io::{self, Write};
use std::collections::VecDeque;
use serde::{Serialize, Deserialize};
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
}

