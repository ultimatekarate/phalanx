// crates/phalanx-stronghold/src/ops/corroborate.rs
//
// One-shot corroboration: decrypt recordings with grants, run the
// Corroboration Gate, sign and store the proof.
//
// Hands layer — owns IO. Keys are zeroized on drop (SymmetricKey
// derives ZeroizeOnDrop). No persistent decrypted state.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use phalanx_forensics::corroboration::corroborate;
use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_forensics::judge::{JudgeExt, PayloadCipher};
use phalanx_proto::community::CommunityId;
use phalanx_proto::corroboration::CorroborationProof;
use phalanx_proto::crypto::{SealedLocator, SymmetricKey};
use phalanx_proto::evidence::Evidence;
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};

use tracing::{debug, info};

use crate::config::CorroborationConfig;
use crate::error::StrongholdError;
use crate::persistence::evidence_store::EvidenceStore;
use crate::persistence::proof_store::ProofStore;

/// One-shot corroboration operation.
///
/// Loads grants, decrypts recordings, runs the Corroboration Gate,
/// signs the proof with the Stronghold's identity, stores it, and
/// returns the signed proof. Called by the CLI (`stronghold corroborate`).
pub async fn run_corroboration(
    identity: &PhalanxIdentity,
    evidence_store: &EvidenceStore,
    proof_store: &ProofStore,
    config: &CorroborationConfig,
    community_id: &CommunityId,
    grant_paths: &[PathBuf],
    recording_ids: &[RecordingId],
) -> Result<CorroborationProof, StrongholdError> {
    // ── 1. Load and unlock grants ─────────────────────────────────────
    //
    // Each grant file is a postcard-serialized SealedLocator. We unlock
    // it with our identity to recover the SymmetricKey, then map the
    // target RecordingId to the key.
    //
    // RT-9 (partial): verify that each grant's target recording matches
    // one of the requested recording_ids.

    let mut key_map: HashMap<RecordingId, SymmetricKey> = HashMap::new();

    for path in grant_paths {
        let grant_bytes = tokio::fs::read(path).await.map_err(|e| {
            StrongholdError::Grant(format!("Failed to read grant file {}: {e}", path.display()))
        })?;

        let locator: SealedLocator = postcard::from_bytes(&grant_bytes).map_err(|e| {
            StrongholdError::Grant(format!(
                "Failed to deserialize grant {}: {e}",
                path.display()
            ))
        })?;

        // RT-9: The grant's target must reference one of the requested recordings.
        if !recording_ids.contains(&locator.target) {
            return Err(StrongholdError::Grant(format!(
                "Grant target {} does not match any requested recording",
                locator.target.as_str()
            )));
        }

        let raw_key = locator.unlock(identity).map_err(|e| {
            StrongholdError::Grant(format!(
                "Failed to unlock grant for {}: {e}",
                locator.target.as_str()
            ))
        })?;

        debug!(recording = %locator.target.as_str(), "Grant unlocked");
        key_map.insert(locator.target, SymmetricKey::from_bytes(raw_key));
    }

    // ── 2. Load recordings ────────────────────────────────────────────

    let mut recordings = Vec::with_capacity(recording_ids.len());
    for rid in recording_ids {
        let rec = evidence_store.read_recording(community_id, rid).await?;
        recordings.push(rec);
    }

    // ── 3. Decrypt encrypted payloads in place ────────────────────────
    //
    // For each recording, iterate artifacts. If the inner Evidence
    // carries an encrypted DataPayload and we hold the corresponding
    // key, replace the payload with the decrypted cleartext.

    for rec in &mut recordings {
        let key = match key_map.get(&rec.id) {
            Some(k) => k,
            None => {
                return Err(StrongholdError::RecordingEncrypted(rec.id.clone()));
            }
        };

        for env in &mut rec.artifacts {
            match &mut env.evidence {
                Evidence::Video(shard) => {
                    let clear = shard.payload.reveal(key).map_err(|e| {
                        StrongholdError::Grant(format!(
                            "Decryption failed for video shard in {}: {e}",
                            rec.id.as_str()
                        ))
                    })?;
                    shard.payload = phalanx_proto::evidence::DataPayload::Clear(clear);
                }
                Evidence::Audio(shard) => {
                    let clear = shard.payload.reveal(key).map_err(|e| {
                        StrongholdError::Grant(format!(
                            "Decryption failed for audio shard in {}: {e}",
                            rec.id.as_str()
                        ))
                    })?;
                    shard.payload = phalanx_proto::evidence::DataPayload::Clear(clear);
                }
                // Gap, Handover, and Proximity evidence carry no encrypted payload.
                _ => {}
            }
        }
    }

    // ── 4. Collect proximity witnesses ────────────────────────────────

    let proximity_log = evidence_store.list_proximity(community_id).await?;

    // ── 5. Run the Corroboration Gate ─────────────────────────────────

    let recording_refs: Vec<&_> = recordings.iter().collect();
    let min_overlap = Duration::from_millis(config.min_overlap_ms);

    let mut proof = corroborate(
        &recording_refs,
        &proximity_log,
        min_overlap,
        config.divergence_alpha,
    )?;

    // ── 6. Sign the proof ─────────────────────────────────────────────
    //
    // Serialize the proof body (event_window + attestations + divergences
    // + proximity_evidence), hash with blake3, sign with Ed25519.

    let proof_body = (
        &proof.event_window,
        &proof.attestations,
        &proof.divergences,
        &proof.proximity_evidence,
    );

    let body_bytes = postcard::to_allocvec(&proof_body).map_err(|e| {
        StrongholdError::Serialization(format!("Failed to serialize proof body: {e}"))
    })?;

    let hash: [u8; 32] = blake3::hash(&body_bytes).into();
    let signature = identity.sign(&hash);

    proof.producer_did = identity.did.clone();
    proof.producer_signature = signature.to_bytes().to_vec();
    proof.proof_hash = hash;

    // ── 7. Store and return ───────────────────────────────────────────

    proof_store.store_proof(community_id, &proof).await?;

    info!(
        proof_hash = %hex_hash(&proof.proof_hash),
        attestations = proof.attestations.len(),
        divergences = proof.divergences.len(),
        proximity = proof.proximity_evidence.len(),
        "Corroboration proof signed and stored"
    );

    // Keys in key_map are dropped here → ZeroizeOnDrop wipes memory.
    Ok(proof)
}

/// Format a 32-byte hash as a hex string for logging.
fn hex_hash(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
