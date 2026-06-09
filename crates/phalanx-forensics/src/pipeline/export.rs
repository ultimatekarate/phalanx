// crates/phalanx-forensics/src/pipeline/export.rs
//
// The Export Verb (Laboratory): turn a recording's owner-signed, encrypted
// envelopes into a C2PA-signed MP4 artifact. Pure transform — decrypt, verify
// provenance from the real pixels, transcode (H.264 + AAC), embed the Phalanx
// forensic manifest, and sign with the exporter's Ed25519 identity. No IO: the
// caller supplies the envelopes (retrieval) and writes the returned bytes.
//
// Shared by phalanx-ffi (mobile self-export with the vault key) and
// phalanx-stronghold (autonomous escrow export with a grant-unlocked DEK), so
// both produce byte-identical, validator-checked artifacts from one code path —
// no second copy of the crypto-sensitive pipeline to drift out of sync.

use std::io::Cursor;

use c2pa::{CallbackSigner, SigningAlg};
use ed25519_dalek::Signer;
use thiserror::Error;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{Evidence, ForensicMetrics, MediaType, WitnessEnvelope};
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::types::Fps;

use crate::c2pa_ext::{generate_self_signed_cert, C2paOrchestrator};
use crate::gate::{verify_provenance_from_jpeg, LensThresholds};
use crate::judge::decode_payload;
use crate::transcode::{
    transcode_recording, DecodedAudioShard, DecodedVideoShard, MediaTranscoder,
};

/// Failure modes of the export verb. Deliberately coarse — callers map these to
/// their own surface (FFI status code, Stronghold log line) without leaking
/// internal detail to an untrusted consumer.
#[derive(Debug, Error)]
pub enum ExportError {
    #[error("no media envelopes to export")]
    EmptyRecording,
    #[error("decrypt/decompress failed")]
    Decrypt,
    #[error("frame deserialization failed")]
    Deserialize,
    #[error("provenance re-check failed (spoofed lens metrics or screen recapture)")]
    Provenance,
    #[error("transcode to mp4 failed")]
    Transcode,
    #[error("c2pa manifest build failed")]
    Manifest,
    #[error("c2pa signing failed")]
    Sign,
}

/// A signed MP4 artifact plus the facts an export/custody receipt needs to
/// attest it (hash the bytes, record the duration/frame count).
#[derive(Debug, Clone)]
pub struct ExportedArtifact {
    /// Complete C2PA-signed MP4 file bytes.
    pub mp4_bytes: Vec<u8>,
    /// Total media duration in milliseconds.
    pub duration_ms: u64,
    /// Total number of video frames encoded.
    pub frame_count: u32,
}

/// Decrypt → verify provenance → transcode → C2PA-sign a recording's envelopes
/// into a signed MP4.
///
/// `key` decrypts the payloads — the vault key for own evidence (mobile) or the
/// grant-unlocked DEK for escrow export (Stronghold). `signing_identity` both
/// names the `phalanx.node_id` assertion and signs the COSE claim, so the
/// exported artifact is attested by *whoever exported it*, independently of the
/// envelopes' original witness signatures.
///
/// `transcoder` is the injected encode backend (software H.264/AAC on the
/// Stronghold and desktop; a native platform encoder on mobile) — the codec
/// choice does not affect the surrounding decrypt/provenance/sign pipeline.
///
/// Pure: no disk, no network. Retrieval and the final write are the caller's.
pub fn export_recording_to_signed_mp4(
    envelopes: Vec<WitnessEnvelope>,
    key: &SymmetricKey,
    signing_identity: &PhalanxIdentity,
    fps: Fps,
    transcoder: &dyn MediaTranscoder,
) -> Result<ExportedArtifact, ExportError> {
    if envelopes.is_empty() {
        return Err(ExportError::EmptyRecording);
    }

    // ── Decrypt + decompress + deserialize by evidence type ──────────
    let mut video_shards: Vec<DecodedVideoShard> = Vec::new();
    let mut audio_shards: Vec<DecodedAudioShard> = Vec::new();
    let thresholds = LensThresholds::default();

    for envelope in envelopes {
        match envelope.evidence {
            Evidence::Video(v) => {
                // Canonical decrypt + decompress Verb.
                let decompressed =
                    decode_payload(v.payload, Some(key)).map_err(|_| ExportError::Decrypt)?;
                // Deserialize postcard → Vec<Vec<u8>> (JPEG frames).
                let jpeg_frames: Vec<Vec<u8>> =
                    postcard::from_bytes(&decompressed).map_err(|_| ExportError::Deserialize)?;
                // Re-verify provenance from the actual pixels. Honest evidence
                // passes automatically; spoofed lens_metrics or screen-recapture
                // is caught here, before it is signed into an attested artifact.
                for frame in &jpeg_frames {
                    verify_provenance_from_jpeg(frame, &thresholds)
                        .map_err(|_| ExportError::Provenance)?;
                }
                video_shards.push(DecodedVideoShard {
                    jpeg_frames,
                    metrics: v.lens_metrics,
                });
            }
            Evidence::Audio(a) => {
                let pcm_bytes =
                    decode_payload(a.payload, Some(key)).map_err(|_| ExportError::Decrypt)?;
                audio_shards.push(DecodedAudioShard {
                    pcm_bytes,
                    sample_rate: a.sample_rate,
                    channels: a.channels,
                });
            }
            // Gap, Handover, Proximity, ManifestEntry — no media to transcode.
            _ => {}
        }
    }

    // ── Transcode to MP4 via the injected backend ────────────────────
    let transcoded = transcode_recording(transcoder, video_shards, audio_shards, fps)
        .map_err(|_| ExportError::Transcode)?;

    // ── Build the Phalanx C2PA manifest with aggregate forensic metrics ──
    let aggregate = &transcoded.aggregate_metrics;
    let summary_metrics = ForensicMetrics {
        h_energy: aggregate.mean_h_energy,
        v_energy: aggregate.mean_v_energy,
        prnu_var: aggregate.mean_prnu_var,
        mean_luminance: 0.0, // not aggregated across shards
    };
    let node_did = signing_identity.did.as_str();
    let mut builder =
        C2paOrchestrator::build_manifest_with_lens(node_did, MediaType::VideoMp4, &summary_metrics)
            .map_err(|_| ExportError::Manifest)?;

    // ── Sign with the exporter's real Ed25519 identity ───────────────
    let signer = identity_signer(signing_identity);
    let mut source = Cursor::new(&transcoded.mp4_bytes);
    let mut dest = Cursor::new(Vec::new());
    builder
        .sign(&signer, "video/mp4", &mut source, &mut dest)
        .map_err(|_| ExportError::Sign)?;

    Ok(ExportedArtifact {
        mp4_bytes: dest.into_inner(),
        duration_ms: transcoded.duration_ms,
        frame_count: transcoded.frame_count,
    })
}

/// A C2PA callback signer backed by a real `PhalanxIdentity` Ed25519 key — NOT
/// an ephemeral key (ephemeral signers break the provenance chain). The
/// self-signed cert wraps the verifying key so validators can check the COSE
/// claim signature without a trusted CA; it reports as untrusted, which is
/// honest — the forensic data, not a CA, is the trust anchor.
#[must_use]
pub fn identity_signer(identity: &PhalanxIdentity) -> CallbackSigner {
    let signing_key = identity.keypair.clone();
    let cert_pem = generate_self_signed_cert(&signing_key);
    let callback = move |_context: *const (), data: &[u8]| -> c2pa::Result<Vec<u8>> {
        Ok(signing_key.sign(data).to_bytes().to_vec())
    };
    CallbackSigner::new(callback, SigningAlg::Ed25519, cert_pem)
}
