use crate::base::config::PhalanxConfig;
use crate::base::types::{MeshTopic, PowerState};
use crate::primitives::identity::{NetworkId, PhalanxIdentity};
use crate::primitives::shards::{ChunkType, ShardChunk, ShardError, WitnessEnvelope};
use crate::storage::crucible::Crucible;
use crate::storage::strategies::ShardAmalgam;
use async_trait::async_trait;
use tracing::{info, instrument};

// =====================
// REASSEMBLER CORE
// =====================
#[async_trait]
pub trait TransientJournal: Send + Sync {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;
}

pub struct Reassembler {
    pub crucible: Crucible<ShardAmalgam>,
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
            crucible: Crucible::new(),
            power_state: PowerState::Normal,
        }
    }

    /// Proactive maintenance tick to flush stale shards.
    /// This prevents memory leaks from incomplete network broadcasts.
    pub fn check_and_finalize_shards(
        &mut self,
        timeout: std::time::Duration,
    ) -> Vec<WitnessEnvelope> {
        let salvaged_envelopes = self.crucible.flush_stale(timeout);

        if !salvaged_envelopes.is_empty() {
            tracing::info!(
                count = salvaged_envelopes.len(),
                "Salvaged incomplete envelopes from reassembler workbench"
            );
        }

        salvaged_envelopes
    }

    pub async fn ingest_chunk<J: TransientJournal>(
        &mut self,
        chunk: ShardChunk,
        journal: &mut J,
        _topic: &MeshTopic,
        _config: &PhalanxConfig,
        _identity: &PhalanxIdentity,
        _local_peer_id: NetworkId,
    ) -> Result<Option<WitnessEnvelope>, ShardError> {
        // 1. Forensic Persistence (WAL)
        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        // 2. Crucible Aggregation
        Ok(self.crucible.process(chunk))
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

        // Apply salvage protocols to transient states post-recovery
        let salvaged_envelopes = self.crucible.flush_all();
        recovered_envelopes.extend(salvaged_envelopes);

        info!(
            recovered_count = recovered_envelopes.len(),
            "Forensic recovery complete"
        );
        Ok(recovered_envelopes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::shards::{DataPayload, StorageSequence, VolleyId};
    use crate::primitives::shards::{Evidence, ShardId, VideoShard};
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
            reassembler.crucible.contexts.len(),
            0,
            "Memory leak: Buffer not cleared"
        );
    }
}
