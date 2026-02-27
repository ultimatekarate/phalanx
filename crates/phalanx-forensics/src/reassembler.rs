use phalanx_proto::prelude::*;
use crate::crucible::{Crucible, Mold};
use async_trait::async_trait;
use tracing::{info, instrument, error};
use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};

// --- THE JOURNAL TRAIT ---
// Allows the Lab to describe the NEED for persistence without 
// depending on a specific database or filesystem.
#[async_trait]
pub trait TransientJournal: Send + Sync {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;
    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError>;
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError>;
}

// --- THE REASSEMBLER ---
pub struct Reassembler {
    pub active_shards: Crucible<ShardMold>,
    pub power_state: PowerState,
}

impl Reassembler {
    pub fn new() -> Self {
        Self {
            active_shards: Crucible::new(ShardMold, std::time::Duration::from_secs(1)),
            power_state: PowerState::Normal,
        }
    }

    /// Primary entry point for the IngressOrchestrator.
    /// Manages the Write-Ahead Log (WAL) and the in-memory reassembly.
    pub async fn ingest_chunk<J: TransientJournal>(
        &mut self,
        chunk: ShardChunk,
        journal: &mut J,
    ) -> Result<Option<EnvelopeState>, ShardError> {
        // 1. Forensic Persistence (The WAL)
        journal.record_chunk(&chunk).await?;
        journal.sync().await?;

        let shard_id = chunk.shard_id;
        let owner_did = chunk.owner_did.clone();
        
        // 2. Delegate to the Crucible Engine
        match self.active_shards.process(chunk) {
            Some(envelope) => Ok(Some(EnvelopeState::Intact(envelope))),
            None => {
                // If not ready, return a "Swiss Cheese" gap report
                let buffer = self.active_shards.get(&shard_id).unwrap();
                Ok(Some(EnvelopeState::Fragmented(FragmentedEnvelope {
                    shard_id,
                    owner_did,
                    gap_report: ShardGapReport {
                        shard_id,
                        missing_chunk_indices: buffer.missing_indices(),
                        expected_total_chunks: buffer.total_chunks,
                    },
                    partial_data: buffer.parts.clone(),
                })))
            }
        }
    }

    pub async fn recover_from_journal<J: TransientJournal>(
        &mut self,
        journal: &mut J,
    ) -> Result<(), ShardError> {
        let chunks = journal.read_all_chunks().await?;
        for chunk in chunks {
            self.active_shards.process(chunk);
        }
        Ok(())
    }
}

// --- THE SHARD MOLD (The Strategy) ---
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ShardMold;

impl Mold for ShardMold {
    type Input = ShardChunk;
    type Output = WitnessEnvelope;
    type Key = ShardId;
    type Accumulator = ShardBuffer;

    fn get_key(item: &Self::Input) -> Self::Key { item.shard_id }
    
    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        ShardBuffer {
            total_chunks: item.total_chunks,
            received_count: 0,
            parts: BTreeMap::new(),
            owner_did: item.owner_did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        if !acc.parts.contains_key(&item.chunk_index) {
            acc.parts.insert(item.chunk_index, item.data);
            acc.received_count += 1;
        }
    }

    fn is_ready(acc: &Self::Accumulator, _elapsed: std::time::Duration) -> bool {
        acc.received_count == acc.total_chunks
    }

    fn assemble(&self, _key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        let mut full_payload = Vec::new();
        for i in 0..acc.total_chunks {
            full_payload.extend(acc.parts.get(&i)?);
        }
        postcard::from_bytes(&full_payload).ok()
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShardAmalgam;

impl Mold for ShardAmalgam {
    type Input = ShardChunk;
    type Output = EnvelopeState;
    type Key = ShardId;
    type Accumulator = ShardBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.shard_id
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let mut parts = BTreeMap::new();
        parts.insert(item.chunk_index, item.data.clone());
        ShardBuffer {
            total_chunks: item.total_chunks,
            received_count: 1,
            parts,
            estimated_chunk_size: item.data.len(),
            owner_did: item.owner_did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        if !acc.parts.contains_key(&item.chunk_index) {
            if item.data.len() > acc.estimated_chunk_size {
                acc.estimated_chunk_size = item.data.len();
            }
            acc.parts.insert(item.chunk_index, item.data);
            acc.received_count += 1;
        }
    }

    fn is_ready(acc: &Self::Accumulator, _elapsed: Duration) -> bool {
        acc.received_count == acc.total_chunks
    }

    fn assemble(&self, key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        // Incomplete or fragmented data - triggered by flush_stale/flush_all
        if acc.received_count != acc.total_chunks {
            warn!(?key, received=%acc.received_count, total=%acc.total_chunks, "ShardAmalgam: Incomplete shard, transitioning to Fragmented state");

            let mut missing_indices = Vec::new();
            for i in 0..acc.total_chunks {
                if !acc.parts.contains_key(&i) {
                    missing_indices.push(i);
                }
            }

            let gap_report = ShardGapReport {
                shard_id: key,
                missing_chunk_indices: missing_indices,
                expected_total_chunks: acc.total_chunks,
            };

            let fragmented = FragmentedEnvelope {
                shard_id: key,
                owner_did: acc.owner_did,
                gap_report,
                partial_data: acc.parts,
            };

            return Some(EnvelopeState::Fragmented(fragmented));
        }

        // Case 2: Happy path, every is there.
        let mut full_data = Vec::new();
        for i in 0..acc.total_chunks {
            if let Some(part) = acc.parts.get(&i) {
                full_data.extend_from_slice(part);
            } else {
                error!(?key, chunk_index=%i, "ShardAmalgam: Illegal internal state, missing chunk despite count match");
                return None;
            }
        }

        match postcard::from_bytes(&full_data) {
            Ok(env) => Some(EnvelopeState::Intact(env)),
            Err(e) => {
                error!(?key, error=%e, "ShardAmalgam: Deserialization failed on complete shard");
                None
            }
        }
    }
}


#[cfg(test)]
mod tests {
use super::*;
    use phalanx_proto::prelude::*;
    use phalanx_proto::shards::{
        Evidence, ShardId, StorageSequence, VolleyId, 
        WitnessEnvelope, EnvelopeState, ShardBuffer, HandoverProof
    };
    use std::collections::BTreeMap;

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


    #[test]
    fn test_shard_amalgam_gap_reporting() {
        // 1. Setup metadata
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let shard_id = ShardId(505);
        let vid = VolleyId::new("gap_test");

        // 2. Create a real WitnessEnvelope to simulate serialized data
        let video_shard =
            create_video_shard(vec![vec![0xAA, 0xBB]], StorageSequence(1), 30, vid).unwrap();

        let envelope = WitnessEnvelope::new(
            Evidence::Video(video_shard),
            &identity,
            identity.to_network_id(),
            None,
        )
        .unwrap();

        let full_serialized_data = postcard::to_stdvec(&envelope).unwrap();

        // Split data into 3 mock chunks
        let chunk_size = (full_serialized_data.len() / 3) + 1;
        let mut parts = BTreeMap::new();
        parts.insert(0, full_serialized_data[0..chunk_size].to_vec());
        // We SKIP index 1 to simulate a network drop
        parts.insert(2, full_serialized_data[(chunk_size * 2)..].to_vec());

        // 3. Manually populate the Accumulator (ShardBuffer)
        let acc = ShardBuffer {
            total_chunks: 3,
            received_count: 2, // 0 and 2 arrived, 1 is missing
            parts,
            estimated_chunk_size: chunk_size,
            owner_did: identity.did.clone(),
        };

        // 4. EXECUTE ASSEMBLE (The Triage Path)
        let strategy = ShardAmalgam;
        let result = strategy
            .assemble(shard_id, acc)
            .expect("Should return a state");

        // 5. ASSERTIONS
        if let EnvelopeState::Fragmented(fragmented) = result {
            assert_eq!(fragmented.shard_id, shard_id);
            assert_eq!(fragmented.gap_report.missing_chunk_indices, vec![1]);
            assert_eq!(fragmented.gap_report.expected_total_chunks, 3);
            assert_eq!(
                fragmented.partial_data.len(),
                2,
                "Should preserve the data we DO have"
            );
        } else {
            panic!("Expected Fragmented state, got {:?}", result);
        }
    }

    #[test]
    fn test_shard_amalgam_full_reassembly() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let shard_id = ShardId(707);

        // 1. Create a REAL envelope so postcard can deserialize it successfully
        let envelope = WitnessEnvelope::new(
            Evidence::Handover(HandoverProof {
                volley_id: VolleyId::new("test"),
                sequence_id: StorageSequence(0),
                old_did: identity.did.clone(),
                new_did: identity.did.clone(),
                anchor_hash: SignatureHash([0; 32]),
                old_signature: identity.sign(b"test"),
                new_signature: identity.sign(b"test"),
            }),
            &identity,
            identity.to_network_id(),
            None,
        )
        .unwrap();

        let data = postcard::to_stdvec(&envelope).unwrap();

        let mut parts = BTreeMap::new();
        parts.insert(0, data.clone());

        let acc = ShardBuffer {
            total_chunks: 1,
            received_count: 1,
            parts,
            estimated_chunk_size: data.len(),
            owner_did: identity.did.clone(),
        };

        let strategy = ShardAmalgam;
        // This will now succeed because the bytes represent a valid WitnessEnvelope
        let result = strategy
            .assemble(shard_id, acc)
            .expect("Should assemble successfully");

        assert!(matches!(result, EnvelopeState::Intact(_)));
    }
}
