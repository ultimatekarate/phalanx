use crate::Crucible::Mold;
use crate::shards::{ShardChunk, WitnessEnvelope, ShardId};
use std::collections::BTreeMap;
use std::time::Duration;
use serde::{Serialize, Deserialize};

// --- STRATEGY 1: SHARD REASSEMBLY (Chunks -> Envelope) ---

pub struct ShardAssembler;

pub struct FragmentBuffer {
    total_chunks: u32,
    received_count: u32,
    parts: BTreeMap<u32, Vec<u8>>,
}

impl Mold for ShardAssembler {
    type Input = ShardChunk;
    type Output = WitnessEnvelope;
    type Key = ShardId;      // Group by Envelope ID
    type Accumulator = FragmentBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.envelope_id.clone()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        FragmentBuffer {
            total_chunks: item.total_chunks,
            received_count: 0,
            parts: BTreeMap::new(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        if !acc.parts.contains_key(&item.chunk_index) {
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
                return None; // Should not happen given is_ready check
            }
        }
        // Deserialize
        postcard::from_bytes(&full_data).ok()
    }
}

// --- STRATEGY 2: VOLLEY ASSEMBLY (Envelopes -> Volley) ---

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicGap {
    pub start_seq: u64,
    pub end_seq: u64,
    pub detected_at: u64,
}

#[derive(Serialize, Deserialize)]
pub struct Volley {
    pub id: String,
    pub artifacts: BTreeMap<u64, WitnessEnvelope>,
    pub gaps: Vec<ForensicGap>,
}

pub struct VolleyAssembler;

pub struct VolleyBuffer {
    pub artifacts: BTreeMap<u64, WitnessEnvelope>,
    pub gaps: Vec<ForensicGap>,
    pub expected_next_seq: u64,
    pub start_seq: u64,
}

impl Mold for VolleyAssembler {
    type Input = WitnessEnvelope;
    type Output = Volley;
    type Key = String; // Peer DID
    type Accumulator = VolleyBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.provenance.signer_did.to_string()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let seq = item.evidence.sequence_id().0;
        VolleyBuffer {
            artifacts: BTreeMap::new(),
            gaps: Vec::new(),
            expected_next_seq: seq,
            start_seq: seq,
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        let seq = item.evidence.sequence_id().0;
        
        // Gap Detection Logic
        if seq > acc.expected_next_seq {
            acc.gaps.push(ForensicGap {
                start_seq: acc.expected_next_seq,
                end_seq: seq - 1,
                detected_at: chrono::Utc::now().timestamp() as u64,
            });
            acc.expected_next_seq = seq + 1;
        } else if seq == acc.expected_next_seq {
            acc.expected_next_seq += 1;
        }
        // Late frames are just added, we don't retroactively fix gaps yet for simplicity
        acc.artifacts.insert(seq, item);
    }

    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool {
        // Seal if we have > 50 frames OR it's been > 5 seconds
        acc.artifacts.len() >= 50 || elapsed > Duration::from_secs(5)
    }

    fn assemble(key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
        Some(Volley {
            id: format!("vol_{}_{}", key, acc.start_seq),
            artifacts: acc.artifacts,
            gaps: acc.gaps,
        })
    }
}