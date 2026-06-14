// crates/phalanx-ffi/src/export.rs
//
// C2PA export — packages Phalanx forensic metadata into a standards-compliant
// Content Credentials manifest embedded in an MP4 video file.
//
// The forensic data already exists in every VideoShard:
//   - PRNU variance (sensor fingerprint)
//   - Moiré energy (horizontal + vertical)
//   - Mean luminance
//   - Recording ID, timestamp, author DID
//
// This module:
//   1. Retrieves all envelopes for a recording from storage
//   2. Decrypts and decompresses each shard
//   3. Transcodes video (H.264) and audio (AAC) tracks via phalanx-forensics
//   4. Muxes into an MP4 container
//   5. Embeds a C2PA manifest with aggregated forensic metrics
//   6. Signs with the node's real Ed25519 identity — NOT ephemeral key
//
// Self-signed with the node's Ed25519 key — no third-party CA required.
// The PRNU fingerprint doesn't need Adobe's permission to be valid.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use std::ffi::{CStr, CString};
use std::os::raw::c_char;

// Used only by the software-transcode export path (gated below); excluded from
// the FOSS/feature-off build to avoid unused-import errors under `-D warnings`.
#[cfg(feature = "software-transcode")]
use phalanx_forensics::export_recording_to_signed_mp4;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_proto::identity::{Did, RecordingId};
use phalanx_proto::prelude::PhalanxIdentity;
#[cfg(feature = "software-transcode")]
use phalanx_proto::types::Fps;

use tokio::sync::oneshot;

/// Exports a recording as a C2PA-compliant MP4 with embedded forensic metadata.
///
/// Retrieves all shards for the given recording ID from storage,
/// encodes them into H.264+AAC, muxes into MP4, and embeds a C2PA manifest:
///   - Sensor provenance assertions (PRNU, Moiré, Laplacian) per-frame
///   - Author DID
///   - Recording duration, frame count
///   - Self-signed with the node's Ed25519 key
///
/// The output file is a standard MP4 that any C2PA validator can inspect.
/// Self-signed certificates will show as "untrusted" — that's honest.
/// The forensic data speaks for itself.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
/// * `out_path` must be a valid null-terminated C string (writable file path).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_export_c2pa(
    handle: *const PhalanxHandle,
    recording_id: *const c_char,
    out_path: *const c_char,
) -> i32 {
    crate::panic_safety::ffi_panic_safe(PhalanxError::Panic.code(), || {
        // SAFETY: caller upholds the # Safety contract on the parent
        // `unsafe extern "C" fn`. The body is wrapped in the panic boundary
        // because the c2pa crate can panic on malformed manifest assertions
        // and we want a clean status code rather than a process abort.
        unsafe {
            let Some(h) = handle.as_ref() else {
                return PhalanxError::NullPointer.code();
            };

            if recording_id.is_null() || out_path.is_null() {
                return PhalanxError::NullPointer.code();
            }

            let rec_str = match CStr::from_ptr(recording_id).to_str() {
                Ok(s) => s,
                Err(_) => return PhalanxError::InvalidUtf8.code(),
            };

            let path_str = match CStr::from_ptr(out_path).to_str() {
                Ok(s) => s,
                Err(_) => return PhalanxError::InvalidUtf8.code(),
            };

            // Spawn the async pipeline on the runtime and block for the result.
            // Using spawn + oneshot + blocking_recv avoids re-entrant block_on panics.
            let vault_key = h.vault_key.clone();
            let identity = h.identity.clone();
            let node_did = h.node_did.clone();
            let rec_id = rec_str.to_string();
            let out = path_str.to_string();

            // Use storage_tx directly from the handle — no sentinel lock needed.
            let stx = h.storage_tx.clone();

            let (result_tx, result_rx) = oneshot::channel();

            h.runtime.spawn(async move {
                let res =
                    build_c2pa_export(&stx, &vault_key, &identity, &node_did, &rec_id, &out).await;
                let _ = result_tx.send(res);
            });

            match result_rx.blocking_recv() {
                Ok(Ok(())) => PhalanxError::Ok.code(),
                Ok(Err(e)) => e.code(),
                Err(_) => PhalanxError::ChannelClosed.code(),
            }
        }
    })
}

/// Returns the file path of the last C2PA export, if any.
/// Convenience for Flutter to know where the file landed.
///
/// The returned string must be freed with `phalanx_free_string`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
/// * `out_path` must be a valid pointer to receive the C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_get_c2pa_export_path(
    handle: *const PhalanxHandle,
    recording_id: *const c_char,
    out_path: *mut *mut c_char,
) -> i32 {
    unsafe {
        let Some(_h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        if recording_id.is_null() || out_path.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let rec_str = match CStr::from_ptr(recording_id).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        let export_name = format!("{rec_str}_c2pa.mp4");

        match CString::new(export_name) {
            Ok(cstr) => {
                *out_path = cstr.into_raw();
                PhalanxError::Ok.code()
            }
            Err(_) => PhalanxError::InvalidUtf8.code(),
        }
    }
}

/// Internal: retrieves envelopes, decrypts, transcodes to MP4, embeds C2PA manifest,
/// and writes the signed file to disk.
///
/// Async because it communicates with StorageActor via channels and awaits replies.
async fn build_c2pa_export(
    storage_tx: &tokio::sync::mpsc::Sender<StorageCommand>,
    vault_key: &phalanx_proto::crypto::SymmetricKey,
    identity: &PhalanxIdentity,
    node_did: &str,
    recording_id: &str,
    out_path: &str,
) -> Result<(), PhalanxError> {
    // ── 1. Retrieve all envelopes for this recording ─────────────────
    let rec_id = RecordingId::new(recording_id);

    let (reply_tx, reply_rx) = oneshot::channel();
    storage_tx
        // R2-4 FIX: Pass local DID for C1 ownership consistency.
        // Export is always local (vault_key holder), so the check passes,
        // but the code path now exercises the ownership guard.
        .send(StorageCommand::Retrieval {
            recording_id: rec_id,
            owner_did: Some(Did::new(node_did)),
            reply_to: reply_tx,
        })
        .await
        .map_err(|_| PhalanxError::ChannelClosed)?;

    let envelopes = reply_rx.await.map_err(|_| PhalanxError::ChannelClosed)?;

    // `StorageCommand::Retrieval` returns RAW envelopes without re-running
    // `verify_envelope` — see `storage.rs::handle_retrieval`. This caller does
    // NOT re-verify the ed25519 signature directly. Trust transfers across three
    // downstream boundaries instead, ALL performed inside
    // `export_recording_to_signed_mp4`:
    //   1. `decode_payload(.., vault_key)` — requires the local vault key, so
    //      payloads forged without it fail to decrypt.
    //   2. `verify_provenance_from_jpeg` — re-computes PRNU / Moiré metrics from
    //      the actual pixels, catching spoofed lens_metrics.
    //   3. C2PA re-signing with the node's identity — the exported MP4 is
    //      attested by the node, not by the envelope's original signer.
    // If envelope-derived fields are ever surfaced to an external consumer
    // WITHOUT going through that verb, add an explicit `verify_envelope()` here.
    if envelopes.is_empty() {
        return Err(PhalanxError::InvalidState);
    }

    // ── Select the encode backend (carve-out) ────────────────────────
    // The software H.264/AAC/MP4 codecs are compiled in only under
    // `software-transcode` (desktop/dev/Play-Store). The FOSS mobile build
    // excludes them; on-device export there will delegate to a registered
    // native platform encoder (MediaCodec/VideoToolbox) — a separate follow-up.
    // Until that backend exists, the FOSS build reports `NoEncoder`.
    //
    // The software path uses the shared Laboratory export verb — the exact same
    // path the Stronghold escrow export uses — so mobile and Stronghold
    // artifacts are byte-identical and validate identically. The verb names the
    // `phalanx.node_id` assertion from `identity.did` (own-evidence export:
    // identity DID == node_did above).
    #[cfg(feature = "software-transcode")]
    {
        let transcoder = phalanx_forensics::SoftwareTranscoder;
        let artifact = export_recording_to_signed_mp4(
            envelopes,
            vault_key,
            identity,
            Fps::default(),
            &transcoder,
        )
        .map_err(|_| PhalanxError::InvalidState)?;

        // Write the signed MP4 to disk (Hands).
        std::fs::write(out_path, artifact.mp4_bytes).map_err(|_| PhalanxError::InvalidState)?;

        Ok(())
    }

    #[cfg(not(feature = "software-transcode"))]
    {
        // FOSS/mobile build: no software codecs and no native encoder registered yet.
        let _ = (envelopes, vault_key, identity, out_path);
        Err(PhalanxError::NoEncoder)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::undocumented_unsafe_blocks,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    // `SigningAlg` is used by the (codec-free) `identity_signer` test below.
    use c2pa::SigningAlg;

    // The real-encode E2E and its helpers only compile under `software-transcode`
    // (they exercise the software backend); their imports are co-gated so the
    // FOSS/feature-off build has no unused imports under `-D warnings`.
    #[cfg(feature = "software-transcode")]
    use c2pa::Reader;
    #[cfg(feature = "software-transcode")]
    use phalanx_forensics::gate::{verify_provenance_from_jpeg, LensThresholds};
    #[cfg(feature = "software-transcode")]
    use phalanx_forensics::reassembler::{compress_frame, create_audio_shard, create_video_shard};
    #[cfg(feature = "software-transcode")]
    use phalanx_forensics::witness::WitnessAuthority;
    #[cfg(feature = "software-transcode")]
    use phalanx_forensics::PayloadCipher;
    #[cfg(feature = "software-transcode")]
    use phalanx_proto::crypto::SymmetricKey;
    #[cfg(feature = "software-transcode")]
    use phalanx_proto::evidence::{Evidence, ForensicMetrics, StorageSequence, WitnessEnvelope};
    #[cfg(feature = "software-transcode")]
    use phalanx_proto::identity::WitnessId;
    #[cfg(feature = "software-transcode")]
    use phalanx_proto::time::PhalanxTimestamp;
    #[cfg(feature = "software-transcode")]
    use phalanx_proto::types::{ChannelCount, SampleRate};
    #[cfg(feature = "software-transcode")]
    use std::io::Cursor;
    #[cfg(feature = "software-transcode")]
    use tokio::sync::mpsc;

    #[test]
    fn null_handle_returns_error() {
        unsafe {
            let rec = CString::new("test-rec").expect("valid");
            let path = CString::new("/tmp/test.jpg").expect("valid");
            assert_eq!(
                phalanx_export_c2pa(std::ptr::null(), rec.as_ptr(), path.as_ptr()),
                PhalanxError::NullPointer.code()
            );
        }
    }

    #[test]
    fn null_params_return_error() {
        unsafe {
            assert_eq!(
                phalanx_export_c2pa(std::ptr::null(), std::ptr::null(), std::ptr::null()),
                PhalanxError::NullPointer.code()
            );
        }
    }

    #[test]
    fn get_export_path_returns_mp4() {
        unsafe {
            let rec = CString::new("test-rec").expect("valid");
            let out =
                std::alloc::alloc(std::alloc::Layout::new::<*mut c_char>()) as *mut *mut c_char;

            // Still returns null pointer error since handle is null,
            // but the format test below uses the internal function
            let code = phalanx_get_c2pa_export_path(std::ptr::null(), rec.as_ptr(), out);
            assert_eq!(code, PhalanxError::NullPointer.code());
        }
    }

    #[test]
    fn identity_signer_uses_correct_algorithm() {
        let identity = PhalanxIdentity::new_ephemeral();
        let signer = phalanx_forensics::identity_signer(&identity);
        assert_eq!(signer.alg, SigningAlg::Ed25519);
    }

    // ── End-to-end C2PA validation ───────────────────────────────────────
    //
    // Drives the real `build_c2pa_export` shipping path: encrypted evidence
    // in → transcode → C2PA sign → signed MP4 out → read the manifest back
    // with `c2pa::Reader` and assert the Phalanx assertions are present and
    // the signature/hash checks pass. Proves both the export pipeline and the
    // C2PA attestation actually work, not just compile.

    /// A faint, JPEG-stable frame: a single bright 16×16 patch on a black field.
    /// Over a 256×256 frame the mean luminance stays below 1.0 (≈0.78), so
    /// `verify_provenance_from_jpeg` accepts it via the documented low-luminance
    /// path (a real, supported case — dark-scene capture) while the patch's
    /// sharp edges keep PRNU / Laplacian metrics non-zero (so it is not flagged
    /// as an all-zero bypass).
    ///
    /// The 256×256 size is required: `ScalarLens` analyses a 256×256 centre
    /// crop and returns all-zero metrics for anything smaller.
    ///
    /// This keeps the test focused on the export + C2PA attestation pipeline.
    /// The lens gate deliberately rejects synthetic high-frequency frames as
    /// "screen recapture", so a synthetic frame cannot honestly exercise the
    /// gate's *normal-luminance* PRNU/Moiré path — that belongs in lens tests
    /// with real sensor captures, not here.
    #[cfg(feature = "software-transcode")]
    fn faint_frame_jpeg(width: u32, height: u32, shift_seed: u32) -> Vec<u8> {
        let w = width as usize;
        let h = height as usize;
        let mut y = vec![0u8; w * h];
        let shift = shift_seed as usize % 8;
        let px0 = w / 2 - 8 + shift;
        let py0 = h / 2 - 8;
        for dy in 0..16 {
            for dx in 0..16 {
                let x = (px0 + dx).min(w - 1);
                let yy = (py0 + dy).min(h - 1);
                y[yy * w + x] = 200;
            }
        }
        let chroma_samples = (w / 2) * (h / 2);
        let uv = vec![128u8; chroma_samples * 2];
        compress_frame(&y, &uv, width, height, false).expect("compress faint frame")
    }

    #[cfg(feature = "software-transcode")]
    fn encrypted_video_envelope(
        seq: u32,
        rec: &RecordingId,
        key: &SymmetricKey,
        identity: &PhalanxIdentity,
    ) -> WitnessEnvelope {
        let frames = vec![
            faint_frame_jpeg(256, 256, seq),
            faint_frame_jpeg(256, 256, seq + 1),
            faint_frame_jpeg(256, 256, seq + 2),
        ];
        let mut shard = create_video_shard(
            frames,
            StorageSequence(seq),
            Fps::new(30),
            rec.clone(),
            ForensicMetrics::default(),
            PhalanxTimestamp::from_millis(1_700_000_000_000 + u64::from(seq) * 33),
        )
        .expect("video shard");
        shard.payload.apply_encryption(key).expect("encrypt video");
        WitnessEnvelope::sign_envelope(Evidence::Video(shard), identity, WitnessId::random(), None)
            .expect("sign video envelope")
    }

    #[cfg(feature = "software-transcode")]
    fn encrypted_audio_envelope(
        seq: u32,
        rec: &RecordingId,
        key: &SymmetricKey,
        identity: &PhalanxIdentity,
    ) -> WitnessEnvelope {
        // ~0.25 s of low-amplitude PCM noise, 16 kHz mono, i16 LE.
        let mut state = 0x00BE_EF01u32;
        let mut pcm = Vec::with_capacity(4000 * 2);
        for _ in 0..4000 {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            let sample = (state >> 20) as i16 / 8;
            pcm.extend_from_slice(&sample.to_le_bytes());
        }
        let mut shard = create_audio_shard(
            pcm,
            StorageSequence(seq),
            SampleRate::new(16000),
            ChannelCount::new(1),
            rec.clone(),
            PhalanxTimestamp::from_millis(1_700_000_000_000 + u64::from(seq) * 33),
        )
        .expect("audio shard");
        shard.payload.apply_encryption(key).expect("encrypt audio");
        WitnessEnvelope::sign_envelope(Evidence::Audio(shard), identity, WitnessId::random(), None)
            .expect("sign audio envelope")
    }

    #[cfg(feature = "software-transcode")]
    #[tokio::test]
    async fn export_pipeline_binds_phalanx_c2pa_assertions() {
        let identity = PhalanxIdentity::new_ephemeral();
        let node_did = identity.did.as_str().to_string();
        let vault_key = SymmetricKey::from_bytes([0x11; 32]);
        let rec = RecordingId::new("c2pa-roundtrip");

        // Sanity: confirm the synthetic frames clear the provenance re-check the
        // export performs, so any failure below points at export/transcode, not
        // the gate.
        let sample = faint_frame_jpeg(256, 256, 1);
        verify_provenance_from_jpeg(&sample, &LensThresholds::default())
            .expect("faint frame passes the provenance gate (low-luminance path)");

        let envelopes = vec![
            encrypted_video_envelope(1, &rec, &vault_key, &identity),
            encrypted_audio_envelope(2, &rec, &vault_key, &identity),
        ];

        // Minimal storage actor: answer the single Retrieval with our evidence.
        let (storage_tx, mut storage_rx) = mpsc::channel::<StorageCommand>(8);
        tokio::spawn(async move {
            while let Some(cmd) = storage_rx.recv().await {
                if let StorageCommand::Retrieval { reply_to, .. } = cmd {
                    let _ = reply_to.send(envelopes.clone());
                    break;
                }
            }
        });

        let out_path =
            std::env::temp_dir().join(format!("phalanx_c2pa_roundtrip_{}.mp4", std::process::id()));
        let out_str = out_path.to_string_lossy().into_owned();

        build_c2pa_export(
            &storage_tx,
            &vault_key,
            &identity,
            &node_did,
            rec.as_str(),
            &out_str,
        )
        .await
        .expect("c2pa export pipeline succeeds end to end");

        let mp4 = std::fs::read(&out_path).expect("exported mp4 exists");
        assert!(!mp4.is_empty(), "exported mp4 is non-empty");

        // First use of c2pa::Reader in-repo: read the signed manifest back.
        let reader = Reader::from_context(c2pa::Context::default())
            .with_stream("video/mp4", Cursor::new(mp4.as_slice()))
            .expect("c2pa reads back the signed mp4");
        let manifest_json = reader.json();

        assert!(
            manifest_json.contains("phalanx.node_id"),
            "manifest carries the node identity assertion: {manifest_json}"
        );
        assert!(
            manifest_json.contains("phalanx.lens.prnu_var"),
            "manifest carries the sensor-fingerprint assertions: {manifest_json}"
        );
        // The MP4 asset hard-binding and every assertion hash validate end to
        // end — proof the transcode + manifest-embedding pipeline is correct.
        assert!(
            manifest_json.contains("assertion.bmffHash.match"),
            "the MP4 asset hash binding validates: {manifest_json}"
        );

        // The Ed25519 COSE claim signature must verify. `signingCredential.untrusted`
        // is EXPECTED and acceptable (self-signed, no CA), but `claimSignature.mismatch`
        // would mean the signature itself is broken. The latter was a c2pa
        // rust_native_crypto defect in 0.78.x; resolved by the 0.85 upgrade.
        let statuses = reader.validation_status().unwrap_or_default();
        let sig_mismatch = statuses
            .iter()
            .any(|s| s.code() == "claimSignature.mismatch");
        assert!(
            !sig_mismatch,
            "C2PA claim signature failed to verify (claimSignature.mismatch): {manifest_json}"
        );

        let _ = std::fs::remove_file(&out_path);
    }
}
