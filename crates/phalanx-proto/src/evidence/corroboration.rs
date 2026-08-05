// crates/phalanx-proto/src/corroboration.rs
//
// The Corroboration Proof: irrefutable multi-device evidence.
//
// Dictionary layer — inert nouns. No IO, no tokio, no libp2p.
// These types are produced by the Corroboration Gate (Laboratory)
// and consumed by the Stronghold's export path (Hands).

use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::identity::Did;
use crate::time::PhalanxTimestamp;

// ── Event Window ────────────────────────────────────────────────────────

/// The temporal bounds of a corroborated event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventWindow {
    /// Earliest recording start across all devices.
    pub start: PhalanxTimestamp,
    /// Latest recording end across all devices.
    pub end: PhalanxTimestamp,
    /// Start of the overlap region where ALL contributing recordings are active.
    pub overlap_start: PhalanxTimestamp,
    /// End of the overlap region.
    pub overlap_end: PhalanxTimestamp,
}

impl EventWindow {
    /// Duration of the overlap region.
    pub fn overlap_duration(&self) -> Duration {
        Duration::from_millis(self.overlap_end.0.saturating_sub(self.overlap_start.0))
    }
}

// ── PRNU Profile ────────────────────────────────────────────────────────

/// Statistical PRNU fingerprint for a device across N frames.
///
/// Aggregated from per-frame `ForensicMetrics` within the overlap window.
/// Used for pairwise sensor divergence testing (Kolmogorov-Smirnov).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrnuProfile {
    pub mean_prnu_var: f32,
    pub std_prnu_var: f32,
    pub mean_h_energy: f32,
    pub mean_v_energy: f32,
    /// Number of frames sampled to produce this profile.
    pub sample_count: u32,
}

// ── Sensor Divergence ───────────────────────────────────────────────────

/// Pairwise statistical divergence between two devices' PRNU profiles.
///
/// Produced by a two-sample Kolmogorov-Smirnov test on the `prnu_var`
/// distributions. Lower p-value = stronger evidence of different sensors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SensorDivergence {
    pub device_a: Did,
    pub device_b: Did,
    /// KS test statistic: maximum absolute difference between empirical CDFs.
    pub ks_statistic: f64,
    /// p-value: probability that both distributions are from the same sensor.
    /// < 0.01 = strong evidence of different sensors.
    pub p_value: f64,
}

// ── Device Attestation ──────────────────────────────────────────────────

/// One device's contribution to the corroboration proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAttestation {
    pub did: Did,
    pub recording_id: crate::identity::RecordingId,
    /// Number of evidence frames in the overlap window.
    pub frame_count: u32,
    /// Aggregate PRNU statistics for this device.
    pub prnu_profile: PrnuProfile,
    /// First evidence_hash in the chain (proves chain start).
    pub chain_head: [u8; 32],
    /// Last evidence_hash in the chain (proves chain end).
    pub chain_tail: [u8; 32],
}

// ── Corroboration Proof ─────────────────────────────────────────────────

/// A forensic proof of independent multi-device capture.
///
/// Produced by the Corroboration Gate (Laboratory) on the Stronghold.
/// Consumed by the C2PA export path for court-admissible packaging.
///
/// Proves: different physical sensors (PRNU divergence), same event
/// (temporal overlap), intact custody chains, and non-coordination
/// (distinct DIDs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorroborationProof {
    /// The event window this proof covers.
    pub event_window: EventWindow,
    /// Per-device attestations (one per contributing recording).
    pub attestations: Vec<DeviceAttestation>,
    /// Pairwise sensor divergence results.
    pub divergences: Vec<SensorDivergence>,
    /// DID of the Stronghold that produced this proof.
    pub producer_did: Did,
    /// Ed25519 signature by the producer over the serialized proof body.
    pub producer_signature: Vec<u8>,
    /// SHA-256 hash of the proof body (event_window + attestations + divergences).
    pub proof_hash: [u8; 32],
}

// ── Corroboration Error ─────────────────────────────────────────────────

/// Reasons the Corroboration Gate may reject a set of recordings.
#[derive(Debug, thiserror::Error)]
pub enum CorroborationError {
    #[error("Insufficient recordings: need at least 2, got {0}")]
    InsufficientRecordings(usize),

    #[error("No temporal overlap: recordings do not share a common time window")]
    NoTemporalOverlap,

    #[error("Overlap too short: {0:?} < minimum required {1:?}")]
    OverlapTooShort(Duration, Duration),

    #[error("Duplicate DID: {0} appears in multiple recordings")]
    DuplicateDid(Did),

    #[error("Sensor divergence insufficient: devices {0} and {1} have p-value {2} >= threshold")]
    InsufficientDivergence(Did, Did, f64),

    #[error("Chain integrity failure for device {0}")]
    ChainIntegrityFailure(Did),

    #[error("Insufficient frames for PRNU profiling: device {0} has only {1} frames")]
    InsufficientFrames(Did, u32),
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
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    #[test]
    fn event_window_overlap_duration() {
        let window = EventWindow {
            start: PhalanxTimestamp(1000),
            end: PhalanxTimestamp(10000),
            overlap_start: PhalanxTimestamp(3000),
            overlap_end: PhalanxTimestamp(8000),
        };
        assert_eq!(window.overlap_duration(), Duration::from_millis(5000));
    }

    #[test]
    fn event_window_zero_overlap() {
        let window = EventWindow {
            start: PhalanxTimestamp(1000),
            end: PhalanxTimestamp(5000),
            overlap_start: PhalanxTimestamp(3000),
            overlap_end: PhalanxTimestamp(3000),
        };
        assert_eq!(window.overlap_duration(), Duration::from_millis(0));
    }

    #[test]
    fn corroboration_error_messages() {
        let err = CorroborationError::InsufficientRecordings(1);
        assert!(err.to_string().contains("at least 2"));

        let err = CorroborationError::DuplicateDid(Did::new("did:key:zdup"));
        assert!(err.to_string().contains("did:key:zdup"));
    }
}
