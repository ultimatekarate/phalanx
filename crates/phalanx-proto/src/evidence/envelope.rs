// crates/phalanx-proto/src/evidence.rs
use crate::identity::{Did, RecordingId, ShardId, WitnessId};
use crate::revocation::RevocationKey;
use crate::storage::HandoverProof;
use crate::time::PhalanxTimestamp;
use crate::types::{ChannelCount, EncodingSymbolId, Fps, SampleRate};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::ops::{Add, AddAssign, Deref, Sub};

/// The Forensic Payload: Represents the state of data within a shard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DataPayload {
    Clear(Vec<u8>),
    Encrypted {
        nonce: Vec<u8>,
        ciphertext: Vec<u8>,
    },
    Compressed(Vec<u8>),
    /// Placeholder for gap markers in forensic timelines.
    Missing,
}

impl Default for DataPayload {
    fn default() -> Self {
        DataPayload::Clear(Vec::new())
    }
}

/// A physical slice of an envelope for network transport.
/// Each chunk carries a single RaptorQ encoding symbol (fountain-coded).
/// Completeness is derived from data, never from sender-declared fields.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ShardChunk {
    pub shard_id: ShardId,
    /// RaptorQ encoding symbol identifier. Not an array index — it's a symbol address.
    pub encoding_symbol_id: EncodingSymbolId,
    pub chunk_type: ChunkType,
    /// `true` on the last emitted symbol in a source block (graceful completion signal).
    pub is_terminal: bool,
    /// Payload: 12-byte OTI prefix + RaptorQ symbol data.
    pub data: Vec<u8>,
    pub owner_did: Did,
    pub timestamp: PhalanxTimestamp,
}

/// The Witness Envelope: The primary "Noun" of the Phalanx Forensic Timeline.
///
/// To create a signed envelope, import [`phalanx_forensics::witness::WitnessAuthority`]
/// and call `WitnessEnvelope::sign_envelope(evidence, identity, peer_id, prev_hash)`.
/// Signing is a Verb — it lives in the Laboratory (forensics), not the Dictionary (proto).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessEnvelope {
    pub evidence: Evidence,
    pub evidence_hash: [u8; 32],
    pub witness_peer_id: WitnessId,
    pub witness_signature: Vec<u8>,
    pub did: Did,
    pub prev_hash: Option<SignatureHash>,
    /// Revocation authority for this recording. Derived from the recorder's
    /// BIP39 mnemonic (seed bytes [32..64]). Embedded in every envelope so any
    /// node can verify a RevocationToken without needing the genesis shard.
    #[serde(default)]
    pub revocation_key: RevocationKey,
}

/// A cryptographic anchor for a specific unit of evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureHash(pub [u8; 32]);

impl SignatureHash {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// The Evidence Enum: Wraps all possible forensic data types.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Evidence {
    Video(VideoShard),
    Audio(AudioShard),
    Gap(ForensicGap),
    Handover(HandoverProof),
    /// Proximity witness: two devices observed on the same local mesh.
    /// Captured by MeshSentinel during recording, flows through the standard
    /// evidence pipeline (signed, sharded, distributed) to the Stronghold.
    Proximity(crate::corroboration::ProximityWitness),
    /// Manifest entry: catalogs a publishable child recording at the
    /// moment it starts. Appended to a deterministic per-identity manifest
    /// recording so a fresh-restored sentinel can enumerate (and then
    /// fetch + decrypt) every recording it has ever published, using only
    /// the BIP39 phrase. See `ManifestEntry` and
    /// `phalanx_forensics::derive_manifest_recording_id`.
    ManifestEntry(ManifestEntry),
}

/// Catalog entry: appended to the manifest recording at the start of every
/// publishable child recording, so a fresh-restored sentinel can enumerate
/// what to fetch from the mesh. The `recording_id` field is the manifest's
/// own (deterministic) id; `child_recording_id` is the recording being
/// cataloged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    /// The manifest's recording id — deterministic from the identity's
    /// `dek_master`. Carried explicitly so `EvidenceExt::recording_id`
    /// has the same shape as Video/Audio/Gap/Handover/Proximity.
    pub recording_id: RecordingId,
    /// The recording being cataloged.
    pub child_recording_id: RecordingId,
}

/// Sensor fingerprint metrics computed by the ForensicLens pipeline.
/// Non-optional: every VideoShard MUST carry a sensor fingerprint.
/// Zero-valued metrics (all 0.0) are themselves a forensic signal —
/// the LensGate can flag them as a possible bypass attempt.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq)]
pub struct ForensicMetrics {
    /// Horizontal Moiré energy (Laplacian).
    pub h_energy: f32,
    /// Vertical Moiré energy (Laplacian).
    pub v_energy: f32,
    /// Photo Response Non-Uniformity variance (sensor fingerprint).
    pub prnu_var: f32,
    /// Mean luminance of the analysis crop (0.0–255.0).
    /// Used by LensGate to scale calibrated thresholds for auto-exposure
    /// resilience: `raw_metric > T_calibrated × mean_luminance`.
    /// Computed once during Y-plane extraction — no SIMD changes needed.
    pub mean_luminance: f32,
}

/// Per-device sensor calibration result (legacy).
///
/// Produced by the batch PRNU calibration pipeline during explicit device setup.
/// Superseded by `PrnuPosterior` for online Bayesian calibration, but retained
/// for backward compatibility with existing serialized configs.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct SensorCalibration {
    /// Calibrated PRNU floor: `mean(prnu_var/luminance) − 3σ`, clamped
    /// above `PRNU_FLOOR_MINIMUM` (0.1). Lower values from degenerate
    /// calibration are rejected.
    pub prnu_floor: f32,
    /// Number of valid frames used in calibration (after dark-frame filtering).
    pub frame_count: u16,
}

/// Bayesian linear regression sufficient statistics for online PRNU calibration.
///
/// Models `prnu_var = α · luminance + β + ε` where α is the shot noise
/// coefficient (device-specific) and β is the read noise floor. Six f64
/// sufficient statistics enable O(1) online updates and luminance-conditioned
/// threshold derivation.
///
/// Every video frame updates the posterior automatically — no explicit
/// calibration step required. The threshold tightens as the posterior converges.
///
/// Persisted in the vault, encrypted at rest alongside the content keyring.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub struct PrnuPosterior {
    /// Number of valid frames observed (after dark/degenerate filtering).
    pub n: u32,
    /// Σ luminance_i — accumulated mean luminance values.
    pub sum_x: f64,
    /// Σ prnu_var_i — accumulated PRNU variance values.
    pub sum_y: f64,
    /// Σ luminance_i² — for computing S_xx (luminance spread).
    pub sum_xx: f64,
    /// Σ luminance_i · prnu_var_i — for computing S_xy (cross term).
    pub sum_xy: f64,
    /// Σ prnu_var_i² — for computing residual sum of squares.
    pub sum_yy: f64,
}

impl PrnuPosterior {
    /// Create an uninformed (empty) posterior with no observations.
    ///
    /// All sufficient statistics are zero. The system falls back to
    /// `PRNU_FLOOR_MINIMUM × luminance` until at least 3 frames are observed
    /// (minimum for linear regression).
    #[must_use]
    pub fn new_uninformed() -> Self {
        Self {
            n: 0,
            sum_x: 0.0,
            sum_y: 0.0,
            sum_xx: 0.0,
            sum_xy: 0.0,
            sum_yy: 0.0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VideoShard {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    pub fps: Fps,
    pub recording_id: RecordingId,
    pub payload: DataPayload,
    /// Mandatory sensor fingerprint from the ForensicLens pipeline.
    pub lens_metrics: ForensicMetrics,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AudioShard {
    pub timestamp: PhalanxTimestamp,
    pub sequence_id: StorageSequence,
    pub sample_rate: SampleRate,
    pub channels: ChannelCount,
    pub recording_id: RecordingId,
    pub payload: DataPayload,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForensicGap {
    pub recording_id: RecordingId,
    pub start_seq: StorageSequence,
    pub end_seq: StorageSequence,
    pub detected_at: PhalanxTimestamp,
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct StorageSequence(pub u32);

impl fmt::Display for StorageSequence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// --- Traits & Helper Nouns ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum ChunkType {
    #[default]
    ForensicUnit,
    Witnessed,
}

/// Fountain-mode evidence state. Sequential gap reporting is removed —
/// the RaptorQ decoder handles completeness internally.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EnvelopeState {
    /// Decoder succeeded — full envelope recovered from fountain symbols.
    Intact(WitnessEnvelope),
}

// --- Deref/Ops Impls ---

impl Deref for StorageSequence {
    type Target = u32;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[allow(clippy::arithmetic_side_effects)] // Trait impl — wrapping semantics intentional for sequence arithmetic.
impl Add<u32> for StorageSequence {
    type Output = Self;
    fn add(self, rhs: u32) -> Self {
        StorageSequence(self.0 + rhs)
    }
}

#[allow(clippy::arithmetic_side_effects)] // Trait impl — wrapping semantics intentional for sequence arithmetic.
impl AddAssign<u32> for StorageSequence {
    fn add_assign(&mut self, rhs: u32) {
        self.0 += rhs;
    }
}

#[allow(clippy::arithmetic_side_effects)] // Trait impl — wrapping semantics intentional for sequence arithmetic.
impl Sub<u32> for StorageSequence {
    type Output = Self;
    fn sub(self, rhs: u32) -> Self {
        StorageSequence(self.0 - rhs)
    }
}

#[derive(Debug, Clone)]
pub struct AudioFrame {
    pub data: Vec<u8>,  // PCM Data
    pub timestamp: u64, // True Monotonic Network Time (ms)
    pub sequence: u64,
    pub sample_rate: u32,
    pub channels: u8,
}

#[derive(Debug, Clone)]
pub struct VideoFrame {
    pub data: Vec<u8>,
    pub timestamp: u64, // True Monotonic Network Time (ms)
    pub sequence: u64,
    pub width: u32,
    pub height: u32,
}

impl fmt::Display for ShardId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "shard:{}", self.0)
    }
}

impl fmt::Display for RecordingId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Forensic unit for session handovers between nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoverShard {
    pub previous_node: WitnessId,
    pub next_node: WitnessId,
    pub session_transfer_token: Vec<u8>,
}

/// The stateful reassembly container for a complete forensic session.
#[derive(Serialize, Deserialize)]
pub struct Recording {
    pub id: RecordingId,
    pub owner_did: Did,
    pub artifacts: Vec<WitnessEnvelope>,
    pub gaps: Vec<ForensicGap>,
    pub is_complete: bool,
}

/// Local-only per-recording policy state.
///
/// Persisted in the vault next to `content_keyring.bin`, encrypted under
/// `vault_key`. Distinct from `Recording` — that struct is the forensic
/// noun (evidence content), this struct is operator-policy metadata that
/// must never leak into signed evidence.
///
/// On a fresh-restored device the file is gone, so all recordings revert
/// to default policy. The operator can re-mark anything they want kept
/// local after recovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordingMetadata {
    /// Schema version of this metadata entry. Starts at 1; bump on field
    /// additions and gate decode on the version.
    pub schema_version: u16,
    /// Agency lever: when `true` (default), a successful shard write
    /// notifies MeshSentinel which announces the recording on the mesh.
    /// When `false`, the recording stays vault-local and is never gossiped
    /// — useful for sensitive captures the sentinel does not want
    /// replicated even in encrypted form.
    pub publishable: bool,
}

/// The pinned schema version of `RecordingMetadata`. Bump alongside any
/// field addition.
pub const RECORDING_METADATA_VERSION: u16 = 1;

impl Default for RecordingMetadata {
    fn default() -> Self {
        Self {
            schema_version: RECORDING_METADATA_VERSION,
            publishable: true,
        }
    }
}

/// Per-recording options surfaced at `start_recording_with_options`.
///
/// Distinct from `RecordingMetadata`: this is the *capture-time input*
/// shape (what the FFI / CLI accepts), while `RecordingMetadata` is the
/// *persisted shape* (what lives on disk). Today the two have one field
/// in common; keeping them separate means future capture-only options
/// (e.g. a transient session-key flag) don't bloat the on-disk schema.
#[derive(Debug, Clone, Copy)]
pub struct RecordingOptions {
    pub publishable: bool,
}

impl Default for RecordingOptions {
    fn default() -> Self {
        Self { publishable: true }
    }
}

impl RecordingOptions {
    /// Convenience: project the options onto a fresh `RecordingMetadata`.
    #[must_use]
    pub fn into_metadata(self) -> RecordingMetadata {
        RecordingMetadata {
            schema_version: RECORDING_METADATA_VERSION,
            publishable: self.publishable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MediaType {
    #[serde(rename = "video/mp4")]
    VideoMp4,
    #[serde(rename = "application/json")]
    ForensicManifest,
    #[serde(rename = "image/jpeg")]
    StillImage,
}

impl MediaType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VideoMp4 => "video/mp4",
            Self::ForensicManifest => "application/json",
            Self::StillImage => "image/jpeg",
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            Self::VideoMp4 => "mp4",
            Self::ForensicManifest => "json",
            Self::StillImage => "jpg",
        }
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
