use phalanx_proto::prelude::*;
use crate::crucible::Mold;

const VOLLEY_SIZE_THRESHOLD: usize = 50;
const VOLLEY_TIME_THRESHOLD: Duration = Duration::from_secs(1);

// --- STRATEGY 1: SHARD REASSEMBLY (Chunks -> Envelope) --

// --- STRATEGY 2: VOLLEY ASSEMBLY (Envelopes -> Volley) ---
#[derive(Debug, Serialize, Deserialize)]
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

        match &item.evidence {
            Evidence::Handover(proof) => {
                // 1. Verify the bridge connects to the CURRENT legal owner
                if proof.old_did == acc.owner_did {
                    tracing::info!(
                        volley = %acc.volley_id,
                        "Crucible: Advancing stream ownership via HandoverProof"
                    );

                    // Transfer legal ownership of the active buffer
                    acc.owner_did = proof.new_did.clone();
                    acc.artifacts.insert(seq, item);
                } else {
                    tracing::warn!(
                        volley = %acc.volley_id,
                        "Crucible rejected HandoverProof: Unauthorized origin"
                    );
                }
            }
            _ => {
                // 2. Standard Frame Verification
                if item.did == acc.owner_did {
                    acc.artifacts.insert(seq, item);
                } else {
                    // ZERO-TRUST DROP: Prevent buffer bloat from malicious peers
                    tracing::warn!(
                        volley = %acc.volley_id,
                        seq = %seq.0,
                        "Crucible dropped illegal frame: Causality Breach (Identity Mismatch)"
                    );
                }
            }
        }
    }

    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool {
        acc.artifacts.len() >= VOLLEY_SIZE_THRESHOLD || elapsed > VOLLEY_TIME_THRESHOLD
    }

    fn assemble(&self, key: VolleyId, acc: Self::Accumulator) -> Option<Self::Output> {
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
