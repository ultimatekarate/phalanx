use crate::base::engine::PendingEgress;
use crate::base::types::PowerState;
use crate::primitives::identity::NetworkId;
use crate::primitives::shards::{
    EnvelopeState, ShardChunk, ShardError, ShardGapReport, ShardId, WitnessEnvelope,
};
use crate::storage::strategies::ShardBuffer;
use async_trait::async_trait;
use std::collections::HashMap;
use tracing::instrument;

// =====================
// REASSEMBLER CORE
// =====================

#[async_trait]
pub trait TransientJournal: Send + Sync {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;
    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError>;
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError>;
}

pub struct Reassembler {
    pub active_shards: HashMap<ShardId, ShardBuffer>,
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
            active_shards: HashMap::new(),
            power_state: PowerState::Normal,
        }
    }

    /// Proactive maintenance tick to flush stale shards.
    /// This prevents memory leaks from incomplete network broadcasts.
    pub fn check_and_finalize_shards(
        &mut self,
        _timeout: std::time::Duration,
    ) -> Vec<EnvelopeState> {
        let mut salvaged_envelopes = Vec::new();
        let mut stale_keys = Vec::new();

        // In a true implementation, ShardBuffer needs a 'created_at' timestamp to check against `timeout`.
        // For now, we flush all pending buffers as fragmented.
        for (key, acc) in self.active_shards.iter() {
            let mut missing_indices = Vec::new();
            for i in 0..acc.total_chunks {
                if !acc.parts.contains_key(&i) {
                    missing_indices.push(i);
                }
            }

            let gap_report = ShardGapReport {
                shard_id: *key,
                missing_chunk_indices: missing_indices,
                expected_total_chunks: acc.total_chunks,
            };

            let fragmented = crate::primitives::shards::FragmentedEnvelope {
                shard_id: *key,
                owner_did: acc.owner_did.clone(),
                gap_report,
                partial_data: acc.parts.clone(),
            };

            salvaged_envelopes.push(EnvelopeState::Fragmented(fragmented));
            stale_keys.push(*key);
        }

        for key in stale_keys {
            self.active_shards.remove(&key);
        }

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
    ) -> Result<Option<EnvelopeState>, ShardError> {
        // 1. Forensic Persistence (WAL)
        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        let shard_id = chunk.shard_id;

        // 2. Access the buffer directly
        let buffer = self
            .active_shards
            .entry(shard_id)
            .or_insert_with(|| ShardBuffer {
                total_chunks: chunk.total_chunks,
                received_count: 0,
                parts: std::collections::BTreeMap::new(),
                estimated_chunk_size: chunk.data.len(),
                owner_did: chunk.owner_did.clone(),
            });

        // 3. Deduplication: Fast, direct check
        if buffer.parts.contains_key(&chunk.chunk_index) {
            return Ok(None);
        }

        // 4. Ingest data
        if chunk.data.len() > buffer.estimated_chunk_size {
            buffer.estimated_chunk_size = chunk.data.len();
        }
        buffer.parts.insert(chunk.chunk_index, chunk.data);
        buffer.received_count += 1;

        // 5. Check Completion
        if buffer.received_count == buffer.total_chunks {
            let finalized = self.active_shards.remove(&shard_id).unwrap();

            // Concatenate MTU fragments into a single byte stream
            let mut full_payload = Vec::with_capacity(
                finalized.estimated_chunk_size * finalized.total_chunks as usize,
            );
            for i in 0..finalized.total_chunks {
                if let Some(part) = finalized.parts.get(&i) {
                    full_payload.extend(part);
                } else {
                    tracing::error!(?shard_id, chunk_index=%i, "Reassembler: Illegal internal state, missing chunk despite count match");
                    return Err(ShardError::SalvageError(
                        "Missing chunk despite count match".into(),
                    ));
                }
            }

            // Deserialize the assembled WitnessEnvelope
            let envelope = postcard::from_bytes::<WitnessEnvelope>(&full_payload)
                .map_err(|e| ShardError::SerializationError(e.to_string()))?;

            Ok(Some(EnvelopeState::Intact(envelope)))
        } else {
            // 6. SWISS CHEESE ACKNOWLEDGMENT: Return Fragmented state
            let mut missing_indices = Vec::new();
            for i in 0..buffer.total_chunks {
                if !buffer.parts.contains_key(&i) {
                    missing_indices.push(i);
                }
            }
            Ok(Some(EnvelopeState::Fragmented(
                crate::primitives::shards::FragmentedEnvelope {
                    shard_id,
                    owner_did: buffer.owner_did.clone(),
                    gap_report: ShardGapReport {
                        shard_id,
                        missing_chunk_indices: missing_indices,
                        expected_total_chunks: buffer.total_chunks,
                    },
                    partial_data: buffer.parts.clone(),
                },
            )))
        }
    }

    #[instrument(skip(self, journal,))]
    pub async fn recover_from_journal<J: TransientJournal>(
        &mut self,
        journal: &mut J,
        _local_peer_id: NetworkId,
    ) -> Result<Vec<EnvelopeState>, ShardError> {
        let chunks = journal.read_all_chunks().await?;
        let mut recovered_count = 0;

        for chunk in chunks {
            // Bypass `ingest_chunk` to prevent duplicating entries in the WAL
            let shard_id = chunk.shard_id;
            let buffer = self
                .active_shards
                .entry(shard_id)
                .or_insert_with(|| ShardBuffer {
                    total_chunks: chunk.total_chunks,
                    received_count: 0,
                    parts: std::collections::BTreeMap::new(),
                    estimated_chunk_size: chunk.data.len(),
                    owner_did: chunk.owner_did.clone(),
                });

            if !buffer.parts.contains_key(&chunk.chunk_index) {
                if chunk.data.len() > buffer.estimated_chunk_size {
                    buffer.estimated_chunk_size = chunk.data.len();
                }
                buffer.parts.insert(chunk.chunk_index, chunk.data);
                buffer.received_count += 1;
                recovered_count += 1;
            }
        }

        tracing::info!(
            recovered_chunks = recovered_count,
            active_volleys = self.active_shards.len(),
            "Forensic recovery phase complete"
        );

        // Return an empty vector; incomplete volleys remain in active_shards awaiting final chunks.
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::identity::PhalanxIdentity;
    use crate::primitives::shards::ChunkType;
    use crate::primitives::shards::{DataPayload, StorageSequence, VolleyId, WitnessEnvelope};
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
        async fn record_pending_egress(
            &mut self,
            _pending: &[PendingEgress],
        ) -> Result<(), ShardError> {
            Ok(())
        }
        async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_reassembler_chunk_reassembly() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let mut reassembler = Reassembler::new();
        let mut journal = MockJournal;
        let local_peer = identity.to_network_id();

        // 1. Create a valid, fully-populated VideoShard
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("id"),
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        });

        // 2. Wrap in an envelope and sign it
        let original_envelope = WitnessEnvelope::new(evidence, &identity, local_peer.clone(), None)
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
            .ingest_chunk(chunk_1, &mut journal)
            .await
            .unwrap();

        // Assert that we get a Fragmented report back on partial ingestion
        assert!(
            matches!(result_1.unwrap(), EnvelopeState::Fragmented(_)),
            "Buffer should return Fragmented state after first chunk"
        );

        let result_2 = reassembler
            .ingest_chunk(chunk_2, &mut journal)
            .await
            .unwrap();

        // 5. Final Verification
        assert!(result_2.is_some(), "Reassembly should be complete");
        let recovered_envelope = match result_2.unwrap() {
            EnvelopeState::Intact(env) => env,
            EnvelopeState::Fragmented(gap) => {
                panic!(
                    "Expected Intact envelope, but received Fragmented state: {:?}",
                    gap
                );
            }
        };

        // Assert cryptographic integrity survived the sharding/ingestion process
        assert_eq!(
            recovered_envelope.witness_signature,
            original_envelope.witness_signature
        );
        assert_eq!(
            reassembler.active_shards.len(),
            0,
            "Memory leak: Buffer not cleared"
        );
    }
}
