use crate::base::config::PhalanxConfig;
use crate::base::types::{MeshTopic, PowerState};
use crate::primitives::identity::{NetworkId, PhalanxIdentity};
use crate::primitives::shards::{
    AudioShard, ChunkType, Evidence, ReassemblyBuffer, ShardChunk, ShardError, ShardId, VideoShard,
    WitnessEnvelope,
};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::time::Instant;

use tracing::{info, instrument};

// =====================
// REASSEMBLER CORE
// =====================
#[async_trait]
pub trait TransientJournal: Send + Sync {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>; // Added for Freeze Protocol
}

pub struct Reassembler {
    pub video_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub audio_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub power_state: PowerState,
}

impl Default for Reassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            video_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            power_state: PowerState::Normal,
        }
    }

    pub async fn ingest_chunk<J: TransientJournal>(
        &mut self,
        chunk: ShardChunk,
        journal: &mut J,
        topic: &MeshTopic,
        config: &PhalanxConfig,
        identity: &PhalanxIdentity,
        local_peer_id: NetworkId,
    ) -> Result<Option<WitnessEnvelope>, ShardError> {
        // 1. Forensic Persistence (WAL)
        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        // 2. Buffer Selection
        let is_video = topic == &config.network.video_topic;
        let (buffers, _capacity_limit) = if is_video {
            (&mut self.video_buffers, config.storage.max_video_buffer)
        } else {
            (&mut self.audio_buffers, config.storage.max_audio_buffer)
        };

        let shard_id = chunk.shard_id;

        // 3. Aggregation Logic
        let buffer = buffers
            .entry(shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        buffer.last_activity = Instant::now();
        if chunk.chunk_index < chunk.total_chunks {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        // 4. Finalization
        if buffer.is_complete() {
            let reassembled_raw_data = buffer.assemble();
            buffers.remove(&shard_id);

            self.finalize_envelope(
                reassembled_raw_data,
                chunk.chunk_type,
                is_video,
                identity,
                local_peer_id,
            )
        } else {
            Ok(None)
        }
    }

    #[instrument(skip(self, journal, config, identity))]
    pub async fn recover_from_journal<J: TransientJournal>(
        &mut self,
        journal: &mut J,
        config: &PhalanxConfig,
        identity: &PhalanxIdentity,
        local_peer_id: NetworkId,
    ) -> Result<Vec<WitnessEnvelope>, ShardError> {
        let mut recovered_envelopes = Vec::new();

        let chunks = journal.read_all_chunks().await?;

        for chunk in chunks {
            // Bypass IngressOrchestrator because WAL data is internally trusted
            let topic = if chunk.chunk_type == ChunkType::ForensicUnit {
                &config.network.video_topic
            } else {
                &config.network.audio_topic
            };

            if let Some(envelope) = self
                .ingest_chunk(chunk, journal, topic, config, identity, local_peer_id)
                .await?
            {
                recovered_envelopes.push(envelope);
            }
        }

        info!(
            recovered_count = recovered_envelopes.len(),
            "Forensic recovery complete"
        );
        Ok(recovered_envelopes)
    }

    fn finalize_envelope(
        &self,
        data: Vec<u8>,
        chunk_type: ChunkType,
        is_video: bool,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
    ) -> Result<Option<WitnessEnvelope>, ShardError> {
        match chunk_type {
            ChunkType::Witnessed => postcard::from_bytes::<WitnessEnvelope>(&data)
                .map(Some)
                .map_err(|e| ShardError::Serialization(e.to_string())),
            ChunkType::ForensicUnit => {
                let evidence = if is_video {
                    postcard::from_bytes::<VideoShard>(&data).map(Evidence::Video)
                } else {
                    postcard::from_bytes::<AudioShard>(&data).map(Evidence::Audio)
                }
                .map_err(|e| ShardError::Serialization(e.to_string()))?;

                WitnessEnvelope::new(evidence, identity, peer_id).map(Some)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::shards::{DataPayload, StorageSequence, VolleyId};
    use crate::primitives::time::PhalanxTimestamp;

    struct MockJournal;
    #[async_trait]
    impl TransientJournal for MockJournal {
        async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
            Ok(())
        }
        async fn sync(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
            Ok(vec![])
        }
        async fn clear(&mut self) -> Result<(), ShardError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn test_reassembler_chunk_reassembly() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let config = PhalanxConfig::default();
        let mut reassembler = Reassembler::new();
        let mut journal = MockJournal;
        let local_peer = identity.to_network_id();
        let topic = MeshTopic::new("phalanx/video");

        // 1. Create a valid, fully-populated VideoShard
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("id"),
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        });

        // 2. Wrap in an envelope and sign it
        let original_envelope = WitnessEnvelope::new(evidence, &identity, local_peer.clone())
            .expect("Failed to sign envelope");

        let serialized_envelope =
            postcard::to_stdvec(&original_envelope).expect("Failed to serialize envelope");

        // 3. Shard the serialized bytes into two halves
        let mid = serialized_envelope.len() / 2;
        let (part1, part2) = serialized_envelope.split_at(mid);

        let chunk_1 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 0,
            total_chunks: 2,
            data: part1.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        let chunk_2 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 1,
            total_chunks: 2,
            data: part2.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        // 4. Execute Ingestion Flow
        let result_1 = reassembler
            .ingest_chunk(
                chunk_1,
                &mut journal,
                &topic,
                &config,
                &identity,
                local_peer.clone(),
            )
            .await
            .unwrap();
        assert!(
            result_1.is_none(),
            "Buffer should be pending after first chunk"
        );

        let result_2 = reassembler
            .ingest_chunk(
                chunk_2,
                &mut journal,
                &topic,
                &config,
                &identity,
                local_peer,
            )
            .await
            .unwrap();

        // 5. Final Verification
        assert!(result_2.is_some(), "Reassembly should be complete");
        let recovered_envelope = result_2.unwrap();

        // Assert cryptographic integrity survived the sharding/ingestion process
        assert_eq!(
            recovered_envelope.witness_signature,
            original_envelope.witness_signature
        );
        assert_eq!(
            reassembler.video_buffers.len(),
            0,
            "Memory leak: Buffer not cleared"
        );
    }
}
