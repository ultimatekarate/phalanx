// crates/phalanx-stronghold/src/ops/export.rs
//
// One-shot export: re-decrypt with grants, re-verify gate bindings (zero trust),
// serialize proof + decrypted evidence to disk as postcard files.
//
// Hands layer — owns IO. Keys are zeroized on drop (SymmetricKey
// derives ZeroizeOnDrop). No persistent decrypted state.
//
// TODO: C2PA manifest building. For v1, we write postcard-serialized
// proof + evidence binaries. The C2PA packaging path (c2pa_ext.rs)
// will be wired in once the Builder API is stabilized for multi-asset
// manifests with embedded forensic assertions.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_forensics::judge::PayloadCipher;
use phalanx_proto::community::CommunityId;
use phalanx_proto::crypto::{SealedLocator, SymmetricKey};
use phalanx_proto::evidence::Evidence;
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};

use tracing::{debug, info, warn};

use crate::config::CorroborationConfig;
use crate::error::StrongholdError;
use crate::persistence::evidence_store::EvidenceStore;
use crate::persistence::proof_store::ProofStore;
use crate::signing::create_stronghold_signer;

/// One-shot export operation.
///
/// Loads a previously-stored proof, re-decrypts the contributing recordings
/// with grants (zero trust — never cache decrypted state), and writes
/// postcard-serialized evidence files to `output_dir`.
///
/// Returns the paths of all files written.
#[allow(clippy::too_many_arguments, clippy::cast_possible_truncation)]
pub async fn run_export(
    identity: &PhalanxIdentity,
    evidence_store: &EvidenceStore,
    proof_store: &ProofStore,
    config: &CorroborationConfig,
    community_id: &CommunityId,
    proof_hash: &[u8; 32],
    grant_paths: &[PathBuf],
    output_dir: &Path,
) -> Result<Vec<PathBuf>, StrongholdError> {
    // ── 1. Load the proof ──────────────────────────────────────────────
    let proof = proof_store.load_proof(community_id, proof_hash).await?;

    info!(
        attestations = proof.attestations.len(),
        proof_hash = %hex_hash(proof_hash),
        "Export: proof loaded"
    );

    // ── 2. Collect recording IDs from the proof's attestations ─────────
    let recording_ids: Vec<RecordingId> = proof
        .attestations
        .iter()
        .map(|a| a.recording_id.clone())
        .collect();

    // ── 3. Load and unlock grants ──────────────────────────────────────
    //
    // Same pattern as corroborate: each grant file is a postcard-serialized
    // SealedLocator. We unlock with our identity to recover the SymmetricKey.
    //
    // RT-9: verify grant-community binding — the grant's target recording
    // must reference one of the recordings in this proof.

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

        // RT-9: The grant's target must reference one of the proof's recordings.
        if !recording_ids.contains(&locator.target) {
            return Err(StrongholdError::Grant(format!(
                "Grant target {} does not match any recording in the proof",
                locator.target.as_str()
            )));
        }

        let raw_key = locator.unlock(identity).map_err(|e| {
            StrongholdError::Grant(format!(
                "Failed to unlock grant for {}: {e}",
                locator.target.as_str()
            ))
        })?;

        debug!(recording = %locator.target.as_str(), "Grant unlocked for export");
        key_map.insert(locator.target, SymmetricKey(raw_key));
    }

    // ── 4. Load recordings for each attestation ────────────────────────

    let mut recordings = Vec::with_capacity(recording_ids.len());
    for rid in &recording_ids {
        let rec = evidence_store.read_recording(community_id, rid).await?;
        recordings.push(rec);
    }

    // ── 5. Decrypt encrypted payloads in memory ────────────────────────
    //
    // Same pattern as corroborate: iterate artifacts, decrypt DataPayload
    // in place using the corresponding grant key.

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

    // ── 6. Write export files ──────────────────────────────────────────
    //
    // For v1: postcard-serialized binary files.
    // TODO: Build C2PA manifest with embedded forensic assertions.
    //       Wire through C2paOrchestrator::build_manifest_with_lens()
    //       once multi-asset manifest signing is stabilized.

    tokio::fs::create_dir_all(output_dir).await.map_err(|e| {
        StrongholdError::Export(format!(
            "Failed to create output directory {}: {e}",
            output_dir.display()
        ))
    })?;

    let mut written_paths: Vec<PathBuf> = Vec::new();

    // Write each recording's decrypted envelopes
    for rec in &recordings {
        let filename = format!("{}.evidence.bin", rec.id.as_str());
        let path = output_dir.join(&filename);

        let bytes = postcard::to_allocvec(&rec.artifacts).map_err(|e| {
            StrongholdError::Serialization(format!(
                "Failed to serialize evidence for {}: {e}",
                rec.id.as_str()
            ))
        })?;

        tokio::fs::write(&path, &bytes).await.map_err(|e| {
            StrongholdError::Export(format!("Failed to write {}: {e}", path.display()))
        })?;

        debug!(path = %path.display(), bytes = bytes.len(), "Evidence file written");
        written_paths.push(path);
    }

    // Write the proof itself
    let proof_path = output_dir.join("proof.bin");
    let proof_bytes = postcard::to_allocvec(&proof)
        .map_err(|e| StrongholdError::Serialization(format!("Failed to serialize proof: {e}")))?;

    tokio::fs::write(&proof_path, &proof_bytes)
        .await
        .map_err(|e| {
            StrongholdError::Export(format!("Failed to write {}: {e}", proof_path.display()))
        })?;

    written_paths.push(proof_path);

    // ── 7. Build and sign C2PA sidecar manifest ─────────────────────
    //
    // The C2PA sidecar is the court-facing artifact. Readable by any
    // C2PA-compatible verification tool (Adobe CAI, Truepic, etc.).

    match build_c2pa_sidecar(identity, config, &proof, output_dir).await {
        Ok(c2pa_path) => {
            info!(path = %c2pa_path.display(), "C2PA sidecar manifest written");
            written_paths.push(c2pa_path);
        }
        Err(e) => {
            // C2PA sidecar is supplementary — don't fail the entire export.
            // The binary evidence and proof files are the primary output.
            warn!(error = %e, "C2PA sidecar generation failed — binary export is still valid");
        }
    }

    info!(
        files = written_paths.len(),
        output = %output_dir.display(),
        "Export complete"
    );

    // Keys in key_map are dropped here → ZeroizeOnDrop wipes memory.
    Ok(written_paths)
}

/// Build and sign a C2PA sidecar manifest for the corroboration proof.
///
/// The sidecar embeds the proof's forensic assertions (event window, device
/// attestations, sensor divergences, proximity count) as structured C2PA claims.
/// Readable by any C2PA-compatible verification tool.
#[allow(clippy::cast_possible_truncation)] // Overlap duration millis — bounded by event window.
async fn build_c2pa_sidecar(
    identity: &PhalanxIdentity,
    config: &CorroborationConfig,
    proof: &phalanx_proto::corroboration::CorroborationProof,
    output_dir: &Path,
) -> Result<PathBuf, StrongholdError> {
    use phalanx_forensics::c2pa_ext::C2paOrchestrator;
    use std::io::Cursor;

    // Build the manifest with corroboration assertions (Laboratory — pure logic).
    let mut builder = C2paOrchestrator::build_corroboration_manifest(identity.did.as_ref(), proof)
        .map_err(|e| StrongholdError::Export(format!("C2PA manifest build failed: {e}")))?;

    // Create the signer (Hands — wiring).
    let signer = create_stronghold_signer(identity, config)?;

    // Create a JSON summary as the "source" asset for the sidecar.
    let proof_summary = serde_json::json!({
        "type": "PhalanxCorroborationProof",
        "version": 1,
        "proof_hash": hex_hash(&proof.proof_hash),
        "producer": identity.did.as_ref(),
        "device_count": proof.attestations.len(),
        "overlap_duration_ms": proof.event_window.overlap_duration().as_millis() as u64,
    });
    let source_bytes = serde_json::to_vec_pretty(&proof_summary).map_err(|e| {
        StrongholdError::Serialization(format!("Failed to serialize proof summary: {e}"))
    })?;

    // Sign the manifest, producing the C2PA sidecar bytes.
    let mut source = Cursor::new(&source_bytes);
    let mut dest = Cursor::new(Vec::new());

    builder
        .sign(signer.as_ref(), "application/json", &mut source, &mut dest)
        .map_err(|e| StrongholdError::Export(format!("C2PA signing failed: {e}")))?;

    // Write the sidecar to disk.
    let c2pa_path = output_dir.join("proof.c2pa");
    tokio::fs::write(&c2pa_path, dest.into_inner())
        .await
        .map_err(|e| StrongholdError::Export(format!("Failed to write C2PA sidecar: {e}")))?;

    Ok(c2pa_path)
}

/// Format a 32-byte hash as a hex string for logging.
fn hex_hash(hash: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in hash {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
