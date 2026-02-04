use tokio::sync::mpsc::Sender;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::{config::HardwareConfig, shards::StorageSequence};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioShard {
    pub timestamp: u64,
    pub sequence_id: StorageSequence,
    pub data: Vec<u8>, // Compressed audio bytes (AAC/Opus)
    pub sample_rate: u32,
    pub channels: u8,
    pub volley_id: String,
}

pub struct PhalanxAudioThread {
    pub sample_rate: u32,
    pub channels: u8,
}

impl PhalanxAudioThread {
    /// Spawns the audio capture thread using values from the HardwareConfig.
    pub fn spawn(self, tx: Sender<AudioShard>, config: HardwareConfig, volley_id: String,) {
        let sample_rate = config.audio_sample_rate;
        let channels = config.audio_channels;

        std::thread::spawn(move || {
            let mut sequence_id: StorageSequence = StorageSequence(0);
            
            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let shard = AudioShard {
                    timestamp: now,
                    sequence_id,
                    data: vec![0u8; 1024], // Simulation placeholder
                    sample_rate,
                    channels,
                    volley_id: volley_id.clone()
                };

                if tx.blocking_send(shard).is_err() {
                    break;
                }
                
                sequence_id += 1;
                // Capture 1-second chunks
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }
}