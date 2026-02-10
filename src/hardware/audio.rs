use tokio::sync::mpsc::Sender;
use crate::core::config::HardwareConfig;
use crate::protocol::shards::{self, AudioShard, StorageSequence};

pub struct PhalanxAudioThread {
    pub sample_rate: u32,
    pub channels: u8,
}

impl PhalanxAudioThread {
    /// Spawns the audio capture thread using values from the HardwareConfig.
    pub fn spawn(self, tx: Sender<AudioShard>, config: HardwareConfig, volley_id: String, secret_key: Option<[u8; 32]>) {
        let sample_rate = config.audio_sample_rate;
        let channels = config.audio_channels;

        std::thread::spawn(move || {
            let mut sequence_id: StorageSequence = StorageSequence(0);
            
            loop {
                let mut shard = shards::create_audio_shard(
                    vec![0u8; 1024], // Dummy data
                    sequence_id,
                    sample_rate,
                    channels,
                    volley_id.clone()
                );

                if let Some(key) = secret_key {
                    if let Err(e) = shard.encrypt(&key) {
                        eprintln!("[Audio] Encryption failed for seq {}: {}", sequence_id, e);
                        continue;
                    }
                }

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