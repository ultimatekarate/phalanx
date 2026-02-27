use phalanx_proto::prelude::*;
use phalanx_proto::{ShardChunk, ShardId, DataPayload, Did};

use phalanx_proto::{Shard, ShardId, ShardMetadata, DataPayload, Did};
use flate2::write::GzEncoder; // Compression lives in the Lab, not Proto
use flate2::Compression;
use std::io::prelude::*;


pub struct Weaver;

pub trait ShardFactory {
    fn compress_frame(&self) -> Result<Vec<u8>, ForensicError>;
    
    fn create_shard(
        &self, 
        id: ShardId, 
        owner: Did,
        is_compressed: bool
    ) -> Shard;
}

impl ShardFactory for Vec<u8> {
    fn compress_frame(&self) -> Result<Vec<u8>, ForensicError> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(self).map_err(|_| ForensicError::Assembly("Compression failed".into()))?;
        Ok(encoder.finish().map_err(|_| ForensicError::Assembly("Encoder flush failed".into()))?)
    }

    fn create_shard(&self, id: ShardId, owner: Did, is_compressed: bool) -> Shard {
        Shard {
            id,
            owner_did: owner,
            metadata: ShardMetadata {
                size: self.len() as u64,
                checksum: calculate_checksum(self), // Internal helper in weaver.rs
                is_compressed,
            },
            data: DataPayload::Clear(self.clone()),
        }
    }
}

pub trait Chunkifier {
    fn chunkify(
        &self, 
        shard_id: ShardId, 
        owner: Did, 
        chunk_size: usize
    ) -> Vec<ShardChunk>;
}

impl Chunkifier for Vec<u8> {
    fn chunkify(
        shard_id: ShardId,
        data: Vec<u8>,
        chunk_size: usize,
        owner_did: Did,
        chunk_type: ChunkType,
    ) -> Result<Vec<ShardChunk>, ShardError> {
        if data.is_empty() || chunk_size == 0 {
            return Ok(Vec::new());
        }

        let total_len = data.len() as u64;
        let size_u64 = chunk_size as u64;

        // Checked math to prevent panic on zero (already handled) but good for robustness
        let count_u64 = total_len.div_ceil(size_u64);

        let total_chunks =
            u32::try_from(count_u64).map_err(|_| ShardError::CapacityExceeded(count_u64))?;

        let chunks = data
            .chunks(chunk_size)
            .enumerate()
            .map(|(index, chunk_slice)| ShardChunk {
                shard_id,
                chunk_index: index as u32,
                total_chunks,
                owner_did: owner_did.clone(),
                data: chunk_slice.to_vec(),
                chunk_type,
            })
            .collect();

        Ok(chunks)
    }
}

pub fn compress_frame(raw_data: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, String> {
    let img = DynamicImage::ImageRgb8(
        image::ImageBuffer::from_raw(width, height, raw_data)
            .ok_or("Failed to create image buffer")?,
    );

    let mut jpeg_bytes = Vec::new();
    let mut cursor = Cursor::new(&mut jpeg_bytes);

    img.write_to(&mut cursor, ImageFormat::Jpeg)
        .map_err(|e| format!("Compression error: {}", e))?;

    Ok(jpeg_bytes)
}

/// Creates a video shard with safe timestamp generation.
pub fn create_video_shard(
    frames: Vec<Vec<u8>>,
    sequence_id: StorageSequence,
    fps: u8,
    volley_id: VolleyId,
) -> Result<VideoShard, ShardError> {
    let clock = TrustedClock::new();
    let now = clock.forensic_now()?;

    let raw_bytes =
        postcard::to_stdvec(&frames).map_err(|e| ShardError::SerializationError(e.to_string()))?;

    Ok(VideoShard {
        timestamp: now,
        sequence_id,
        payload: DataPayload::Clear(raw_bytes),
        fps,
        volley_id,
    })
}

/// Creates an audio shard with safe timestamp generation.
pub fn create_audio_shard(
    audio_data: Vec<u8>,
    sequence_id: StorageSequence,
    sample_rate: u32,
    channels: u8,
    volley_id: VolleyId,
) -> Result<AudioShard, ShardError> {
    let clock = TrustedClock::new();
    let now = clock.forensic_now()?;

    Ok(AudioShard {
        timestamp: now,
        sequence_id,
        payload: DataPayload::Clear(audio_data),
        sample_rate,
        channels,
        volley_id,
    })
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReassemblyBuffer {
    pub chunks: Vec<Option<Vec<u8>>>,
    pub total_chunks: usize,
    #[serde(skip, default = "tokio::time::Instant::now")]
    pub last_activity: tokio::time::Instant,
}

impl ReassemblyBuffer {
    #[must_use]
    #[allow(clippy::missing_errors_doc)]
    pub fn new(total_chunks: usize) -> Self {
        Self {
            chunks: vec![None; total_chunks],
            total_chunks,
            last_activity: tokio::time::Instant::now(),
        }
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.chunks.iter().all(|c| c.is_some())
    }

    /// Concatenates chunks into a single byte vector. Assumes is_complete() is true.
    #[must_use]
    pub fn assemble(&self) -> Vec<u8> {
        self.chunks.iter().flatten().flatten().cloned().collect()
    }
}

async fn process_media_egress(&mut self, evidence: Evidence, local_id: NetworkId) {
        let topic = MeshTopic::new("phalanx/1.0.0");
        let shard_id = ShardId(self.seq_counter as u32);

        let pipeline_result = evidence
            .safeguard(&self.network_key)
            .and_then(|ev| self.session.seal_evidence(ev))
            .and_then(|env| env.chunkify(shard_id));

        if let Ok(chunks) = pipeline_result {
            for chunk in chunks {
                // RE-INTEGRATION: Use local_id to verify the chunk is properly attributed
                // before it touches the wire.
                if chunk.owner_did != self.identity.did {
                    error!(peer = %local_id, "Egress Gate: Attribution mismatch detected. Blocking publish.");
                    continue;
                }

                if let Ok(data) = postcard::to_stdvec(&chunk) {
                    let _ = self.network.publish(&topic, data).await;
                }
            }
            self.seq_counter += 1;
        }
    }
    
use phalanx_proto::prelude::*;

pub trait AudioWeaver {
    /// The "Birth" Verb for audio data.
    fn weave_audio(
        &self,
        sequence: StorageSequence,
        rate: u32,
        channels: u8,
        volley: VolleyId,
    ) -> AudioShard;
}

impl AudioWeaver for Vec<u8> {
    fn weave_audio(
        &self,
        sequence: StorageSequence,
        rate: u32,
        channels: u8,
        volley: VolleyId,
    ) -> AudioShard {
        // This is where shards::create_audio_shard logic now lives
        AudioShard {
            data: DataPayload::Clear(self.clone()),
            sequence_id: sequence,
            sample_rate: rate,
            channels,
            volley_id: volley,
            timestamp: PhalanxTimestamp::now(),
        }
    }
}

pub trait VideoWeaver {
    /// The "Transformation" Verb: Compresses raw RGB/YUV data.
    fn compress_frame(data: Vec<u8>, width: u32, height: u32) -> Result<Vec<u8>, ForensicError>;

    /// The "Birth" Verb: Packages frames into a VideoShard.
    fn weave_video(
        &self,
        sequence: StorageSequence,
        fps: u8,
        volley: VolleyId,
    ) -> VideoShard;
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::TryFrom;
    use std::fmt;
    use std::io::Cursor;
    use std::ops::{Add, Deref, Sub};

    // external crates
    use image::{DynamicImage, ImageFormat};
    use serde::{Deserialize, Serialize};

    use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
    use crate::primitives::time::{PhalanxTimestamp, TimeError, TrustedClock};
    use crate::security::e2ee::{decrypt_bytes, encrypt_bytes, CryptoError, SymmetricKey};
    use crate::security::gate::ChronosGate;
    use ed25519_dalek::Signature;
    use sha2::{Digest, Sha256};
    use std::collections::BTreeMap;
    use std::sync::Arc;

    fn get_test_key() -> SymmetricKey {
        SymmetricKey([0x42; 32])
    }

    #[test]
    fn test_video_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1, 2, 3], vec![4, 5, 6]];
        let seq = StorageSequence(100);

        // Handle result via '?'
        let mut shard = create_video_shard(frames.clone(), seq, 30, "volley_1".into())?;

        if let DataPayload::Clear(data) = &shard.payload {
            let deserialized_frames: Vec<Vec<u8>> = postcard::from_bytes(data)?;
            assert_eq!(deserialized_frames, frames);
        } else {
            panic!("Newly created shard should be DataPayload::Clear");
        }

        let key = get_test_key();
        shard.payload.encrypt(&key)?;

        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce.len(), 24, "XChaCha20Poly1305 requires 24-byte nonce");
                assert!(!ciphertext.is_empty(), "Ciphertext should not be empty");
                assert_ne!(ciphertext, &vec![1, 2, 3, 4, 5, 6]);
            }
            _ => panic!("Shard payload should be Encrypted"),
        }

        let decrypted_bytes = shard.payload.decrypt(&key)?;
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted_bytes)?;
        assert_eq!(recovered_frames, frames);

        Ok(())
    }

    #[test]
    fn test_audio_shard_encryption_cycle() -> Result<(), Box<dyn std::error::Error>> {
        let audio_data = vec![10, 20, 30, 40];
        let seq = StorageSequence(200);
        let mut shard = create_audio_shard(audio_data.clone(), seq, 44100, 2, "volley_2".into())?;

        let key = get_test_key();
        shard.payload.encrypt(&key)?;

        let decrypted_bytes = shard.payload.decrypt(&key)?;
        assert_eq!(decrypted_bytes, audio_data);

        Ok(())
    }

    #[test]
    fn test_wrong_key_decryption_fails() -> Result<(), Box<dyn std::error::Error>> {
        let audio_data = vec![1, 2, 3, 4];
        let mut shard = create_audio_shard(audio_data, StorageSequence(1), 44100, 2, "v1".into())?;

        let correct_key = SymmetricKey([1u8; 32]);
        let wrong_key = SymmetricKey([2u8; 32]);

        shard.payload.encrypt(&correct_key)?;

        let result = shard.payload.decrypt(&wrong_key);
        assert!(result.is_err(), "Decryption should fail with wrong key");

        Ok(())
    }

    #[test]
    fn test_double_encryption_idempotency() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![1]];
        let mut shard = create_video_shard(frames, StorageSequence(1), 30, "v1".into())?;
        let key = get_test_key();

        shard.payload.encrypt(&key)?;

        let (nonce1, cipher1) = match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => (nonce.clone(), ciphertext.clone()),
            _ => panic!("Should be encrypted"),
        };

        shard.payload.encrypt(&key)?;

        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce, &nonce1, "Nonce changed on second encrypt call");
                assert_eq!(
                    ciphertext, &cipher1,
                    "Ciphertext changed on second encrypt call"
                );
            }
            _ => panic!("Should remain encrypted"),
        }

        Ok(())
    }

    #[test]
    fn test_serialization_roundtrip_encrypted() -> Result<(), Box<dyn std::error::Error>> {
        let frames = vec![vec![255, 0, 255]];
        let mut shard = create_video_shard(frames, StorageSequence(50), 60, "v_net".into())?;
        let key = get_test_key();

        shard.payload.encrypt(&key)?;

        let wire_data = postcard::to_stdvec(&shard)?;
        let received_shard: VideoShard = postcard::from_bytes(&wire_data)?;

        let decrypted_payload = received_shard.payload.decrypt(&key)?;
        let recovered_frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted_payload)?;

        assert_eq!(recovered_frames[0], vec![255, 0, 255]);
        assert_eq!(received_shard.sequence_id.0, 50);
        assert_eq!(received_shard.volley_id, "v_net".into());

        Ok(())
    }
}
