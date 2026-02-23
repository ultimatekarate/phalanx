const VOLLEY_SIZE_THRESHOLD: usize = 50;
const VOLLEY_TIME_THRESHOLD: Duration = Duration::from_secs(1);

use crate::primitives::identity::Did;
use crate::primitives::shards::{
    EnvelopeState, ForensicGap, FragmentedEnvelope, ShardChunk, ShardGapReport, ShardId,
    SignatureHash, StorageSequence, Volley, VolleyId, WitnessEnvelope,
};
use crate::primitives::time::TrustedClock;
use crate::security::gate::ChronosGate;
use crate::storage::crucible::Mold;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;
use tracing::{error, info, warn};

#[derive(Debug, Serialize, Deserialize)]
pub struct ShardBuffer {
    pub total_chunks: u32,
    pub received_count: u32,
    pub parts: BTreeMap<u32, Vec<u8>>,
    pub estimated_chunk_size: usize,
    pub owner_did: Did,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VolleyBuffer {
    pub volley_id: VolleyId,
    pub owner_did: Did,
    pub artifacts: BTreeMap<StorageSequence, WitnessEnvelope>,
}
// --- STRATEGY 1: SHARD REASSEMBLY (Chunks -> Envelope) --
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

    fn assemble(key: Self::Key, acc: Self::Accumulator) -> Option<Self::Output> {
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

// --- STRATEGY 2: VOLLEY ASSEMBLY (Envelopes -> Volley) ---
pub struct VolleyAmalgam;

impl Mold for VolleyAmalgam {
    type Input = WitnessEnvelope;
    type Output = Volley;
    type Key = VolleyId;
    type Accumulator = VolleyBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.evidence.volley_id().clone()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(item.evidence.sequence_id(), item.clone());

        VolleyBuffer {
            artifacts,
            volley_id: item.evidence.volley_id().clone(),
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

    fn assemble(key: VolleyId, acc: Self::Accumulator) -> Option<Self::Output> {
        if acc.artifacts.is_empty() {
            return None;
        }

        let mut sorted_envelopes: Vec<WitnessEnvelope> = Vec::with_capacity(acc.artifacts.len());
        let mut gaps = Vec::new();
        let clock = TrustedClock::new();
        let now = clock.forensic_now().ok()?;

        let mut expected_seq: Option<StorageSequence> = None;
        let mut last_signature_hash: Option<SignatureHash> = None;

        // BTreeMap guarantees we iterate by StorageSequence order
        for (seq, env) in acc.artifacts {
            let current_seq: StorageSequence = seq;

            // 1. SEQUENCE CONTINUITY CHECK
            if let Some(expected) = expected_seq {
                if current_seq > expected {
                    // Detected a sequence gap - create an attributed ForensicGap
                    gaps.push(ForensicGap {
                        volley_id: key.clone(), // FIX: Every gap belongs to the Volley
                        start_seq: expected,
                        end_seq: current_seq - 1,
                        detected_at: now,
                    });

                    // Note: A gap breaks the hash-link by definition.
                    // In a 'Healable' timeline, we reset the link anchor here.
                    last_signature_hash = None;
                }
            }

            // 2. CAUSALITY (HASH-LINK) VERIFICATION
            // Only verify link if there wasn't just a gap or if it's not the first unit
            if let (Some(expected_hash), Some(actual_link)) = (last_signature_hash, env.prev_hash) {
                if expected_hash != actual_link {
                    error!(
                        volley_id = %key,
                        seq = %current_seq,
                        "VolleyAmalgam: CAUSALITY BREACH - Hash link mismatch detected"
                    );
                    // In Zero-Trust, a breach means we discard the assembly to prevent corruption
                    return None;
                }
            }

            // Update state for next iteration
            expected_seq = Some(current_seq + 1);
            last_signature_hash = Some(env.signature_hash());
            sorted_envelopes.push(env);
        }

        info!(
            volley_id = %key,
            artifacts = %sorted_envelopes.len(),
            gaps = %gaps.len(),
            "VolleyAmalgam: Finalized chain with verified causality"
        );

        let gaps_2 = gaps.clone();

        Some(Volley {
            id: key.clone(),
            owner_did: acc.owner_did,
            artifacts: sorted_envelopes,
            gaps,
            is_complete: gaps_2.is_empty(),
        })
    }
}
