const VOLLEY_SIZE_THRESHOLD: usize = 50;
const VOLLEY_TIME_THRESHOLD: Duration = Duration::from_secs(1);

use crate::storage::crucible::Mold;
use crate::primitives::identity::Did;
use crate::primitives::shards::{ForensicGap, ShardChunk, ShardId, StorageSequence, Volley, WitnessEnvelope};
use std::collections::BTreeMap;
use std::time::Duration;

use tracing::{info, warn, error}; // <--- ADDED TRACING

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
    type Key = ShardId;      
    type Accumulator = ShardBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.shard_id.clone()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let mut parts = BTreeMap::new();
        parts.insert(item.chunk_index, item.data.clone());
        ShardBuffer {
            total_chunks: item.total_chunks,
            received_count: 1, 
            parts,
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
        acc.received_count == acc.total_chunks
    }

    fn assemble(key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        // 🔍 DEBUG: Log Shard Assembly
        if acc.received_count != acc.total_chunks {
            warn!(?key, received=%acc.received_count, total=%acc.total_chunks, "ShardAmalgam: Attempted assembly of incomplete shard");
            return None;
        }

        let mut full_data = Vec::new();
        for i in 0..acc.total_chunks {
            if let Some(part) = acc.parts.get(&i) {
                full_data.extend_from_slice(part);
            } else {
                error!(?key, chunk_index=%i, "ShardAmalgam: Missing chunk despite count match!");
                return None; 
            }
        }
        
        match postcard::from_bytes(&full_data) {
            Ok(env) => Some(env),
            Err(e) => {
                error!(?key, error=%e, "ShardAmalgam: Deserialization failed");
                None
            }
        }
    }
}

// --- STRATEGY 2: VOLLEY ASSEMBLY (Envelopes -> Volley) ---
pub struct VolleyAmalgam;

pub struct VolleyBuffer {
    pub artifacts: BTreeMap<StorageSequence, WitnessEnvelope>,
    pub volley_id: String, // keep this string for now
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
        let mut artifacts = BTreeMap::new();
        artifacts.insert(item.evidence.sequence_id(), item.clone());

        VolleyBuffer {
            artifacts,
            volley_id: item.evidence.volley_id().to_string(),
            owner_did: item.did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        let seq = item.evidence.sequence_id();
        acc.artifacts.insert(seq, item);
    }

    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool {
        acc.artifacts.len() >= VOLLEY_SIZE_THRESHOLD || elapsed > VOLLEY_TIME_THRESHOLD
    }

    fn assemble(key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        // 🔍 DEBUG: Log Volley Assembly
        info!(key=%key, count=%acc.artifacts.len(), "VolleyAmalgam: Assembling volley...");

        if acc.artifacts.is_empty() { 
            warn!(key=%key, "VolleyAmalgam: Artifacts empty. Aborting.");
            return None; 
        }

        let mut sorted_artifacts: Vec<WitnessEnvelope> = Vec::with_capacity(acc.artifacts.len());
        let mut gaps = Vec::new();
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let mut expected_seq: Option<u32> = None;

        for (seq, env) in acc.artifacts {
            let current_seq = seq.0;

            if let Some(expected) = expected_seq {
                if current_seq > expected {
                    gaps.push(ForensicGap {
                        start_seq: expected,
                        end_seq: current_seq - 1,
                        detected_at: now,
                    });
                }
            }
            expected_seq = Some(current_seq + 1);
            sorted_artifacts.push(env);
        }

        info!(id=%acc.volley_id, "VolleyAmalgam: Assembly SUCCESS");
        
        Some(Volley {
            id: acc.volley_id.into(),
            owner_did: acc.owner_did.to_string(),
            artifacts: sorted_artifacts,
            gaps,
            is_complete: true,
        })
    }
}
