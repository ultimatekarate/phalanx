use crate::crucible::Mold;
use crate::identity::Did;
use crate::shards::{ShardChunk, ShardId, StorageSequence, WitnessEnvelope};
use std::collections::BTreeMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};

// --- STRATEGY 1: SHARD REASSEMBLY (Chunks -> Envelope) ---

pub struct ShardAmalgam;

pub struct ShardBuffer {
    total_chunks: u32,
    received_count: u32,
    parts: BTreeMap<u32, Vec<u8>>,
    estimated_chunk_size: usize,
}

impl Mold for ShardAmalgam {
    type Input = ShardChunk;
    type Output = WitnessEnvelope;
    type Key = ShardId;      // Group by Envelope ID
    type Accumulator = ShardBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.shard_id.clone()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        ShardBuffer {
            total_chunks: item.total_chunks,
            received_count: 0,
            parts: BTreeMap::new(),
            estimated_chunk_size: item.data.len(),
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
        // Ready when we have ALL pieces. Time is irrelevant for readiness here (staleness handles timeouts).
        acc.received_count == acc.total_chunks
    }

    fn assemble(_key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        // Stitch bytes
        let mut full_data = Vec::new();
        for i in 0..acc.total_chunks {
            if let Some(part) = acc.parts.get(&i) {
                full_data.extend_from_slice(part);
            } else {
                // dirty seal by padding zeros
                full_data.extend(std::iter::repeat(0).take(acc.estimated_chunk_size));
            }
        }
        // Deserialize
        postcard::from_bytes(&full_data).ok()
    }
}

// --- STRATEGY 2: VOLLEY ASSEMBLY (Envelopes -> Volley) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicGap {
    pub start_seq: u32,
    pub end_seq: u32,
    pub detected_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Volley {
    pub id: String,
    pub owner_did: String,
    pub artifacts: Vec<WitnessEnvelope>,
    pub gaps: Vec<ForensicGap>,
    pub is_complete: bool
}

pub struct VolleyAmalgam;

pub struct VolleyBuffer {
    pub artifacts: BTreeMap<StorageSequence, WitnessEnvelope>,
    pub volley_id: String,
    pub owner_did: Did
}

impl Mold for VolleyAmalgam {
    type Input = WitnessEnvelope;
    type Output = Volley;
    type Key = String; // Peer DID
    type Accumulator = VolleyBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.did.to_string()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        VolleyBuffer {
            artifacts: BTreeMap::new(),
            volley_id: item.evidence.volley_id().to_string(),
            owner_did: item.did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        // TODO: Maybe check if item.volley_id matches acc.volley_id
        // and force a seal if they differ?
        
        // but for this phase, we assume sequential consistency.

        let seq = item.evidence.sequence_id();
        acc.artifacts.insert(seq, item);
    }

    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool {
        // Seal if we have > 50 frames OR it's been > 5 seconds
        // Magic constants for now
        acc.artifacts.len() >= 50 || elapsed > Duration::from_secs(5)
    }

    fn assemble(_key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        if acc.artifacts.is_empty() { return None; }

        let mut sorted_artifacts: Vec<WitnessEnvelope> = Vec::with_capacity(acc.artifacts.len());
        let mut gaps = Vec::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let mut expected_seq: Option<u32> = None;

        // Iterate through sorted keys to detect gaps
        for (seq, env) in acc.artifacts {
            let current_seq = seq.0;

            if let Some(expected) = expected_seq {
                if current_seq > expected {
                    // GAP DETECTED: Missing sequences between expected and current
                    gaps.push(ForensicGap {
                        start_seq: expected,
                        end_seq: current_seq - 1,
                        detected_at: now,
                    });
                }
            }

            // Expect the immediate next integer
            expected_seq = Some(current_seq + 1);
            sorted_artifacts.push(env);
        }

        Some(Volley {
            id: acc.volley_id,
            owner_did: acc.owner_did.to_string(),
            artifacts: sorted_artifacts,
            gaps,
            is_complete: true,
        })
    }
}