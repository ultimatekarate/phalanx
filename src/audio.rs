use tokio::sync::mpsc::Sender;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

use std::fs::File;
use std::io::Write;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioShard {
    pub timestamp: u64,
    pub sequence_id: u32,
    pub data: Vec<u8>,
    pub sample_rate: u32,
    pub channels: u8,
}

pub struct PhalanxAudioThread {
    pub sample_rate: u32,
}

impl PhalanxAudioThread {
    pub fn spawn(self, mut sequence_id: u32, tx: Sender<AudioShard>) {
        std::thread::spawn(move || {
            // Placeholder for CPAL initialization
            // In a real implementation, you would use a buffer to collect 1 second of audio
            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let shard = AudioShard {
                    timestamp: now,
                    sequence_id,
                    data: vec![0u8; 1024], // Placeholder for encoded audio bytes
                    sample_rate: self.sample_rate,
                    channels: 1,
                };

                if tx.blocking_send(shard).is_err() {
                    break;
                }

                sequence_id += 1;
                // Sleep to simulate 1-second capture intervals
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }
}

pub fn seal_audio_to_vault(peer_id: &libp2p::PeerId, shards: std::collections::VecDeque<AudioShard>) -> std::io::Result<()> {
    let path = format!("./vault/{}/", peer_id);
    std::fs::create_dir_all(&path)?;

    for shard in &shards {
        let file_path = format!("{}shard_{}.aud", path, shard.sequence_id);
        let mut file = File::create(file_path)?;
        
        let data = postcard::to_stdvec(&shard)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        
        // This will now work because 'Write' is in scope
        file.write_all(&data)?;
    }
    
    println!("Status: Audio vault sealed for {}", peer_id);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;
    use tokio::sync::mpsc;
    use libp2p::PeerId;

    #[test]
    fn test_audio_shard_creation() {
        let shard = AudioShard {
            timestamp: 123456789,
            sequence_id: 1,
            data: vec![0u8; 10],
            sample_rate: 44100,
            channels: 1,
        };
        assert_eq!(shard.sequence_id, 1);
        assert_eq!(shard.data.len(), 10);
    }

    #[test]
    fn test_seal_audio_to_vault() {
        use std::collections::VecDeque;
        
        let peer_id = PeerId::random();
        let mut shards = VecDeque::new();
        
        // Create 2 dummy shards
        for i in 0..2 {
            shards.push_back(AudioShard {
                timestamp: 1000 + i as u64,
                sequence_id: i,
                data: vec![i as u8; 5],
                sample_rate: 44100,
                channels: 1,
            });
        }

        let result = seal_audio_to_vault(&peer_id, shards);
        assert!(result.is_ok());

        // Verify files exist on disk
        let path_str = format!("./vault/{}/shard_0.aud", peer_id);
        assert!(Path::new(&path_str).exists());

        // Cleanup
        let _ = fs::remove_dir_all(format!("./vault/{}", peer_id));
    }

    #[tokio::test]
    async fn test_audio_thread_production() {
        use std::time::Duration;

        let (tx, mut rx) = mpsc::channel(10);
        let audio_thread = PhalanxAudioThread { sample_rate: 44100 };

        // Spawn thread starting at sequence 100
        audio_thread.spawn(100, tx);

        // Wait for the first shard
        let shard = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Timeout waiting for audio shard")
            .expect("Channel closed");

        assert_eq!(shard.sequence_id, 100);
        assert!(!shard.data.is_empty());
    }
}