// crates/phalanx-stronghold/src/ops/export.rs
//
// One-shot export: re-decrypt with grants, re-verify gate bindings (zero trust),
// write postcard binaries (machine-readable archive) and C2PA manifest
// (court-facing artifact, failure is fatal).
//
// Hands layer — owns IO. Keys are zeroized on drop (SymmetricKey
// derives ZeroizeOnDrop). No persistent decrypted state.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use phalanx_forensics::cryptography::grant::GrantAuthority;
use phalanx_forensics::judge::PayloadCipher;
use phalanx_proto::community::CommunityId;
use phalanx_proto::crypto::{SealedLocator, SymmetricKey};
use phalanx_proto::evidence::Evidence;
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};

use tracing::{debug, info};

use crate::config::CorroborationConfig;
use crate::error::StrongholdError;
use crate::persistence::evidence_store::EvidenceStore;
use crate::persistence::proof_store::ProofStore;
use crate::signing::create_stronghold_signer;

/// Load and unlock grants, returning a map of recording ID to symmetric key.
///
/// Same pattern as corroborate: each grant file is a postcard-serialized
/// SealedLocator. We unlock with our identity to recover the SymmetricKey.
///
/// RT-9: verify grant-community binding — the grant's target recording
/// must reference one of the recordings in this proof.
async fn load_grants(
    identity: &PhalanxIdentity,
    grant_paths: &[PathBuf],
    recording_ids: &[RecordingId],
) -> Result<HashMap<RecordingId, SymmetricKey>, StrongholdError> {
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

    Ok(key_map)
}

/// Decrypt encrypted payloads in memory using grant keys.
///
/// Same pattern as corroborate: iterate artifacts, decrypt DataPayload
/// in place using the corresponding grant key.
fn decrypt_recordings(
    recordings: &mut [phalanx_proto::evidence::Recording],
    key_map: &HashMap<RecordingId, SymmetricKey>,
) -> Result<(), StrongholdError> {
    for rec in recordings {
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
    Ok(())
}

/// One-shot export operation.
///
/// Loads a previously-stored proof, re-decrypts the contributing recordings
/// with grants (zero trust — never cache decrypted state), and writes
/// postcard binaries + C2PA manifest to a content-addressed subdirectory
/// under `output_dir`.
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
    let key_map = load_grants(identity, grant_paths, &recording_ids).await?;

    // ── 4. Load recordings for each attestation ────────────────────────

    let mut recordings = Vec::with_capacity(recording_ids.len());
    for rid in &recording_ids {
        let rec = evidence_store.read_recording(community_id, rid).await?;
        recordings.push(rec);
    }

    // ── 5. Decrypt encrypted payloads in memory ────────────────────────
    decrypt_recordings(&mut recordings, &key_map)?;

    // ── 6. Write export files ──────────────────────────────────────────
    //
    // Postcard binaries are the machine-readable archive.
    // C2PA manifest is the court-facing artifact (fatal on failure).

    // Content-addressed subdirectory: first 8 bytes (16 hex chars) of proof hash.
    let hash_prefix = &hex_hash(proof_hash)[..16];
    let export_dir = output_dir.join(hash_prefix);

    tokio::fs::create_dir_all(&export_dir).await.map_err(|e| {
        StrongholdError::Export(format!(
            "Failed to create export directory {}: {e}",
            export_dir.display()
        ))
    })?;

    let mut written_paths: Vec<PathBuf> = Vec::new();

    // Write each recording's decrypted envelopes
    for rec in &recordings {
        let filename = format!("{}.evidence.bin", rec.id.as_str());
        let path = export_dir.join(&filename);

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
    let proof_path = export_dir.join("proof.bin");
    let proof_bytes = postcard::to_allocvec(&proof)
        .map_err(|e| StrongholdError::Serialization(format!("Failed to serialize proof: {e}")))?;

    tokio::fs::write(&proof_path, &proof_bytes)
        .await
        .map_err(|e| {
            StrongholdError::Export(format!("Failed to write {}: {e}", proof_path.display()))
        })?;

    written_paths.push(proof_path);

    // ── 7. Build and sign C2PA manifest ──────────────────────────────
    //
    // The C2PA manifest is the court-facing artifact. Readable by any
    // C2PA-compatible verification tool (Adobe CAI, Truepic, etc.).
    // Failure is fatal — an export without C2PA has no standards-compliant
    // verification path.

    let c2pa_path = build_c2pa_sidecar(identity, config, &proof, &export_dir).await?;
    info!(path = %c2pa_path.display(), "C2PA manifest written");
    written_paths.push(c2pa_path);

    info!(
        files = written_paths.len(),
        output = %output_dir.display(),
        "Export complete"
    );

    // Keys in key_map are dropped here → ZeroizeOnDrop wipes memory.
    Ok(written_paths)
}

/// Build and sign a C2PA manifest for the corroboration proof.
///
/// Embeds the proof's forensic assertions (event window, device attestations,
/// sensor divergences, proximity count, ingredient references) as structured
/// C2PA claims. Readable by any C2PA-compatible verification tool.
///
/// The source asset is a minimal 1x1 JPEG carrier. C2PA requires a supported
/// media format for signing; the forensic data lives entirely in the manifest
/// assertions, not in the carrier pixels.
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

    // Minimal 1x1 white JPEG — carrier asset for C2PA signing.
    // The forensic data lives in manifest assertions, not in the pixels.
    #[rustfmt::skip]
    const CARRIER_JPEG: &[u8] = &[
        0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01,
        0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0xFF, 0xDB, 0x00, 0x43,
        0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09,
        0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12,
        0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
        0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29,
        0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32,
        0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01,
        0x00, 0x01, 0x01, 0x01, 0x11, 0x00, 0xFF, 0xC4, 0x00, 0x1F, 0x00, 0x00,
        0x01, 0x05, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0xFF, 0xC4, 0x00, 0xB5, 0x10, 0x00, 0x02, 0x01, 0x03,
        0x03, 0x02, 0x04, 0x03, 0x05, 0x05, 0x04, 0x04, 0x00, 0x00, 0x01, 0x7D,
        0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12, 0x21, 0x31, 0x41, 0x06,
        0x13, 0x51, 0x61, 0x07, 0x22, 0x71, 0x14, 0x32, 0x81, 0x91, 0xA1, 0x08,
        0x23, 0x42, 0xB1, 0xC1, 0x15, 0x52, 0xD1, 0xF0, 0x24, 0x33, 0x62, 0x72,
        0x82, 0x09, 0x0A, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x25, 0x26, 0x27, 0x28,
        0x29, 0x2A, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x43, 0x44, 0x45,
        0x46, 0x47, 0x48, 0x49, 0x4A, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59,
        0x5A, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x73, 0x74, 0x75,
        0x76, 0x77, 0x78, 0x79, 0x7A, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89,
        0x8A, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A, 0xA2, 0xA3,
        0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xB2, 0xB3, 0xB4, 0xB5, 0xB6,
        0xB7, 0xB8, 0xB9, 0xBA, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9,
        0xCA, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xE1, 0xE2,
        0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xF1, 0xF2, 0xF3, 0xF4,
        0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01,
        0x00, 0x00, 0x3F, 0x00, 0x7B, 0x94, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xD9,
    ];

    // Sign the manifest into the JPEG carrier, producing C2PA-embedded output.
    let mut source = Cursor::new(CARRIER_JPEG);
    let mut dest = Cursor::new(Vec::new());

    builder
        .sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)
        .map_err(|e| StrongholdError::Export(format!("C2PA signing failed: {e}")))?;

    // Write the signed manifest to disk.
    let c2pa_path = output_dir.join("proof.c2pa");
    tokio::fs::write(&c2pa_path, dest.into_inner())
        .await
        .map_err(|e| StrongholdError::Export(format!("Failed to write C2PA manifest: {e}")))?;

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
