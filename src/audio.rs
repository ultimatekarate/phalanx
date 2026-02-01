use tokio::sync::mpsc::Sender;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AudioShard {
    pub timestamp: u64,
    pub sequence_id: u32,
    pub data: Vec<u8>, // Compressed audio bytes (AAC/Opus)
    pub sample_rate: u32,
    pub channels: u8,
}

pub struct PhalanxAudioThread {
    pub sample_rate: u32,
    pub channels: u8,
}

impl PhalanxAudioThread {
    pub fn spawn(self, tx: Sender<AudioShard>) {
        let sample_rate = self.sample_rate;
        let channels = self.channels;

        std::thread::spawn(move || {
            let mut sequence_id: u32 = 0;
            
            // Placeholder for hardware initialization (e.g., CPAL)
            loop {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();

                let shard = AudioShard {
                    timestamp: now,
                    sequence_id,
                    data: vec![0u8; 1024], // Replace with actual captured buffer
                    sample_rate,
                    channels,
                };

                if tx.blocking_send(shard).is_err() {
                    break;
                }
                
                sequence_id += 1;
                // Sleep for ~1 second to simulate 1s audio chunks
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        });
    }
}

/// Helper for main.rs to create a signed envelope for audio
pub fn wrap_audio_shard(
    shard: AudioShard, 
    identity: &crate::identity::PhalanxIdentity,
    peer_id: String
) -> crate::vid::WitnessEnvelope {
    use crate::vid::{WitnessEnvelope, VideoShard};
    
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
    }
}