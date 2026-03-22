// crates/phalanx-forensics/src/gate.rs
//
// The Monadic Gate System: Composable forensic verification combinators.
// Each gate is a trait that can be chained in a Result pipeline.

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{Evidence, ForensicMetrics, SignatureHash, WitnessEnvelope};
use phalanx_proto::prelude::*;
use phalanx_proto::time::TrustedClock;
use std::collections::HashMap;
use tracing::{error, warn};

// Extension traits from sibling modules that provide methods on proto types.
use crate::crucible::EvidenceExt;
use crate::judge::{PayloadCipher, TimeJudge};
use crate::trust::ReputationGate;
use crate::witness::WitnessAuthority;

use sha2::{Digest, Sha256};

/// S2 FIX: Maximum input size for deserialization.
/// Prevents amplification attacks where an attacker submits enormous byte buffers
/// to exhaust memory during postcard deserialization.
const MAX_UNMARSHAL_INPUT_BYTES: usize = 64 * 1024 * 1024; // 64 MiB

/// Deserialization Gate: Unified postcard deserialization with forensic logging.
pub fn unmarshal<T: serde::de::DeserializeOwned>(
    data: &[u8],
    context: &str,
) -> Result<T, ShardError> {
    // S2 FIX: Reject oversized inputs before attempting deserialization.
    if data.len() > MAX_UNMARSHAL_INPUT_BYTES {
        warn!(
            event = "deserialization_rejected",
            context,
            size = data.len(),
            limit = MAX_UNMARSHAL_INPUT_BYTES,
            "S2: Input exceeds maximum unmarshal size"
        );
        return Err(ShardError::SerializationError(format!(
            "Input size {} exceeds unmarshal limit of {} bytes",
            data.len(),
            MAX_UNMARSHAL_INPUT_BYTES
        )));
    }

    postcard::from_bytes(data).map_err(|e| {
        warn!(event = "deserialization_failure", context, error = %e);
        ShardError::SerializationError(e.to_string())
    })
}

/// Gate 0b: Deserialize + enforce semantic wire bounds in one monadic step.
///
/// Chains Gate 0a (byte-size rejection) → postcard decoding → Gate 0b
/// (structural validation via [`WireBound`]). Use this for any type
/// received over the wire that declares its own invariants.
pub fn unmarshal_checked<T: serde::de::DeserializeOwned + phalanx_proto::wire::WireBound>(
    data: &[u8],
    context: &str,
) -> Result<T, ShardError> {
    let mut val: T = unmarshal(data, context)?;
    val.enforce_wire_bounds();
    Ok(val)
}

/// Gate 0: The Trust Gate (Peer Standing)
pub trait TrustGate {
    fn verify_standing(&self, oracle: &dyn ReputationGate) -> Result<(), ShardError>;
}

impl TrustGate for Did {
    fn verify_standing(&self, oracle: &dyn ReputationGate) -> Result<(), ShardError> {
        if oracle.is_blacklisted(self) {
            warn!(event = "trust_gate_rejection", did = %self, "Blacklisted DID rejected");
            return Err(ShardError::Unauthorized(
                "Trust Gate: DID is blacklisted".into(),
            ));
        }
        Ok(())
    }
}

/// Gate 1: The Witnessing Gate
pub trait WitnessGate {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError>;
}

impl WitnessGate for Evidence {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError> {
        WitnessEnvelope::sign_envelope(self, identity, peer_id, prev_hash).map_err(|e| {
            error!(event = "signing_failure", error = %e, "Witness Gate: Failed to seal unit");
            e
        })
    }
}

/// Gate 2: The Integrity Gate (Reception Side)
pub trait IntegrityGate {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        clock: &dyn TrustedClock,
        tolerance: std::time::Duration,
        anchor: Option<SignatureHash>,
    ) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl IntegrityGate for WitnessEnvelope {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        clock: &dyn TrustedClock,
        tolerance: std::time::Duration,
        _anchor: Option<SignatureHash>,
    ) -> Result<Self, ShardError> {
        // 1. UNCONDITIONAL CRYPTOGRAPHIC VERIFICATION
        // Forensic Zero-Trust: Never operate on data without signature verification.
        if !self.verify_envelope() {
            error!(
                event = "integrity_failure",
                node = %node_id,
                peer = %self.did,
                "SIGNATURE_INVALID"
            );
            return Err(ShardError::SigningError(
                "Cryptographic verification failed: Signature mismatch".into(),
            ));
        }

        // 2. UNCONDITIONAL TEMPORAL GATE
        // T3 FIX: Temporal validation ALWAYS runs, even for anchored units.
        // Without this, an attacker who knows a valid prev_hash can inject
        // evidence with timestamps years in the future, corrupting timelines.
        let now = clock.now();
        if let Err(e) = self.evidence.timestamp().verify_freshness(now, tolerance) {
            error!(
                event = "temporal_failure",
                node = %node_id,
                peer = %self.did,
                "TIME_INVALID"
            );
            return Err(ShardError::InvalidConfiguration(e.to_string()));
        }

        // 3. STICKY TRUST OPTIMIZATION (POST-VERIFICATION)
        // Signature and temporal freshness already verified above.
        // If anchored, skip remaining secondary checks (e.g. continuity).
        // This is now safe — future-dated evidence is rejected by step 2.
        Ok(self)
    }
}

/// Gate 4: The Privacy Gate (Egress)
pub trait PrivacyGate {
    fn safeguard(self, key: &SymmetricKey) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl PrivacyGate for Evidence {
    fn safeguard(mut self, key: &SymmetricKey) -> Result<Self, ShardError> {
        let res = match &mut self {
            Evidence::Video(s) => s.payload.apply_encryption(key),
            Evidence::Audio(s) => s.payload.apply_encryption(key),
            _ => Ok(()),
        };

        res.map(|_| self).map_err(|e| {
            error!(event = "privacy_failure", error = %e, "Safeguarding failed");
            ShardError::Encryption(e.to_string())
        })
    }
}

/// Per-device calibrated thresholds for the LensGate.
///
/// Established during device setup by running ForensicLens on N test frames
/// from the actual camera sensor to measure baseline PRNU and Moiré profiles.
/// Stored in the device's `NodeConfig`.
///
/// **Auto-exposure resilience:** Raw metrics from the ForensicLens scale with
/// luminance. Rather than per-pixel normalization in the kernel (expensive SIMD
/// division), the LensGate scales these thresholds by `mean_luminance` at
/// comparison time: `raw_metric > T_calibrated × mean_luminance`.
/// One scalar multiply per check — no SIMD changes needed.
#[derive(Debug, Clone, Copy)]
pub struct LensThresholds {
    /// Minimum expected PRNU variance per unit luminance.
    /// Below `prnu_floor × mean_luminance` → possible synthetic/AI-generated
    /// image (no sensor noise). Typical calibrated value: 0.5–2.0.
    pub prnu_floor: f32,
    /// Maximum expected Moiré energy per unit luminance.
    /// Above `moire_ceiling × mean_luminance` → possible screen recapture.
    /// Typical calibrated value: 50.0–200.0.
    pub moire_ceiling: f32,
}

impl Default for LensThresholds {
    /// Conservative defaults. Per-device calibration should override these.
    fn default() -> Self {
        Self {
            prnu_floor: 1.0,
            moire_ceiling: 100.0,
        }
    }
}

/// Gate 3: The Lens Gate (Sensor Provenance)
///
/// Mandatory forensic gate that verifies sensor fingerprint authenticity.
/// Evidence with suspicious metrics is blocked before entering the pipeline.
///
/// Detection rules:
/// - All-zero metrics → bypass attempt (evidence generated without lens analysis)
/// - PRNU variance below threshold → possible synthetic/AI-generated image
/// - Moiré energy above threshold → possible screen recapture
///
/// Thresholds are scaled by `mean_luminance` for auto-exposure resilience.
pub trait LensGate {
    fn check_provenance(&self, thresholds: &LensThresholds) -> Result<(), ShardError>;
}

impl LensGate for ForensicMetrics {
    fn check_provenance(&self, thresholds: &LensThresholds) -> Result<(), ShardError> {
        // Rule 1: All-zero metrics → bypass attempt.
        // A real sensor always produces non-zero PRNU variance and some luminance.
        if self.h_energy == 0.0
            && self.v_energy == 0.0
            && self.prnu_var == 0.0
            && self.mean_luminance == 0.0
        {
            warn!(
                event = "lens_gate_rejection",
                reason = "all_zero_metrics",
                "LensGate: All-zero metrics detected — possible bypass attempt"
            );
            return Err(ShardError::InvalidConfiguration(
                "LensGate: All-zero forensic metrics — evidence lacks sensor fingerprint".into(),
            ));
        }

        // Scale calibrated thresholds by mean luminance for auto-exposure resilience.
        // Guard: if mean_luminance is near-zero, the frame is too dark for reliable
        // fingerprinting. Accept it with a warning — the all-zero check above
        // catches the true bypass case.
        if self.mean_luminance < 1.0 {
            warn!(
                event = "lens_gate_low_luminance",
                mean_luminance = self.mean_luminance,
                "LensGate: Very low luminance — threshold scaling unreliable"
            );
            return Ok(());
        }

        let scaled_prnu_floor = thresholds.prnu_floor * self.mean_luminance;
        let scaled_moire_ceiling = thresholds.moire_ceiling * self.mean_luminance;

        // Rule 2: PRNU variance below scaled threshold → possible synthetic image.
        // Real camera sensors always exhibit photo response non-uniformity.
        if self.prnu_var < scaled_prnu_floor {
            warn!(
                event = "lens_gate_rejection",
                reason = "low_prnu",
                prnu_var = self.prnu_var,
                threshold = scaled_prnu_floor,
                mean_luminance = self.mean_luminance,
                "LensGate: PRNU variance below threshold — possible synthetic image"
            );
            return Err(ShardError::InvalidConfiguration(
                "LensGate: PRNU variance below threshold — possible synthetic/AI-generated image"
                    .into(),
            ));
        }

        // Rule 3: Moiré energy above scaled threshold → possible screen recapture.
        // Screen recapture produces characteristic interference patterns.
        let max_moire = if self.h_energy > self.v_energy {
            self.h_energy
        } else {
            self.v_energy
        };

        if max_moire > scaled_moire_ceiling {
            warn!(
                event = "lens_gate_rejection",
                reason = "high_moire",
                h_energy = self.h_energy,
                v_energy = self.v_energy,
                threshold = scaled_moire_ceiling,
                mean_luminance = self.mean_luminance,
                "LensGate: Moiré energy above threshold — possible screen recapture"
            );
            return Err(ShardError::InvalidConfiguration(
                "LensGate: Moiré energy above threshold — possible screen recapture".into(),
            ));
        }

        Ok(())
    }
}

/// Gate 5: The Memory Buffer Gate
pub trait BufferCapacityGate {
    fn enforce_capacity_limit(
        &mut self,
        incoming_shard: &ShardId,
        capacity_limit: usize,
    ) -> Result<&mut Self, ShardError>;
}

impl BufferCapacityGate for HashMap<ShardId, crate::crucible::WorkContext<Vec<u8>>> {
    fn enforce_capacity_limit(
        &mut self,
        incoming_shard: &ShardId,
        limit: usize,
    ) -> Result<&mut Self, ShardError> {
        if !self.contains_key(incoming_shard) && self.len() >= limit {
            let stale = self
                .iter()
                .min_by_key(|(_, ctx)| ctx.created_at)
                .map(|(k, _)| *k);

            if let Some(id) = stale {
                warn!(event = "buffer_eviction", evicted = %id, "Memory limit reached");
                self.remove(&id);
            } else {
                return Err(ShardError::InvalidConfiguration("Zero capacity".into()));
            }
        }
        Ok(self)
    }
}

/// Monadic Observation Extension
pub trait ForensicGate<T, E> {
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E>;
}

impl<T, E: std::fmt::Display> ForensicGate<T, E> for Result<T, E> {
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E> {
        if let Err(ref e) = self {
            error!(event = event, node = %node, error = %e, "{msg}");
        }
        self
    }
}

// In crates/phalanx-forensics/src/gate.rs

/// Gate 7: The Coasting Gate (Probabilistic Integrity)
pub trait CoastingGate {
    fn verify_fast_hash(self, peer_id: &NetworkId) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl CoastingGate for WitnessEnvelope {
    fn verify_fast_hash(self, peer_id: &NetworkId) -> Result<Self, ShardError> {
        // Serialize evidence to compute actual hash
        let actual_bytes = postcard::to_allocvec(&self.evidence)?;

        let mut hasher = Sha256::new();
        sha2::Digest::update(&mut hasher, &actual_bytes);
        let computed_hash: [u8; 32] = hasher.finalize().into();

        if computed_hash != self.evidence_hash {
            tracing::error!(
                event = "integrity_failure",
                peer = %peer_id,
                "Coasting Gate: Fast hash mismatch detected"
            );
            return Err(ShardError::InvalidConfiguration(
                "Payload hash does not match declared evidence_hash".into(),
            ));
        }

        Ok(self)
    }
}

pub trait ContinuityGate {
    fn verify_link(self, last_known_hash: &SignatureHash) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl ContinuityGate for WitnessEnvelope {
    fn verify_link(self, last_known_hash: &SignatureHash) -> Result<Self, ShardError> {
        if let Some(ref link) = self.prev_hash {
            if link == last_known_hash {
                return Ok(self); // The chain is unbroken; trust is inherited.
            }
        }

        Err(ShardError::InvalidConfiguration(
            "Causality Break: Hash mismatch".into(),
        ))
    }
}

use phalanx_proto::types::{ForensicUnit, Unverified, Verified};

/// Trait for promoting a ForensicUnit from Unverified to Verified state.
pub trait PromotionGate {
    fn promote(
        self,
        node_id: &NetworkId,
        clock: &dyn TrustedClock,
        tolerance: std::time::Duration,
        anchor: Option<SignatureHash>,
    ) -> Result<ForensicUnit<WitnessEnvelope, Verified>, ShardError>;
}

impl PromotionGate for ForensicUnit<WitnessEnvelope, Unverified> {
    /// The Gate Entrance: Orchestrates the gauntlet.
    ///
    /// This method consumes an `Unverified` unit and returns a `Verified` unit
    /// only if all forensic gates (Integrity, Continuity, Time) are passed.
    fn promote(
        self,
        node_id: &NetworkId,
        clock: &dyn TrustedClock,
        tolerance: std::time::Duration,
        anchor: Option<SignatureHash>,
    ) -> Result<ForensicUnit<WitnessEnvelope, Verified>, ShardError> {
        // Integrity Gate (Signature + Time + Sticky Trust)
        let mut envelope = self
            .data
            .check_integrity(node_id, clock, tolerance, anchor)?;

        // Coasting Gate (Fast hash on anchored path)
        if anchor.is_some() && anchor == envelope.prev_hash {
            envelope = envelope.verify_fast_hash(node_id)?;
        }

        // Continuity Gate (Chain Enforcement)
        if let Some(ref a) = anchor {
            envelope = envelope.verify_link(a)?;
        }

        Ok(ForensicUnit {
            data: envelope,
            _state: std::marker::PhantomData,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lens_gate_all_zero_rejected() {
        // All-zero metrics = bypass attempt (evidence generated without lens analysis)
        let metrics = ForensicMetrics::default();
        let thresholds = LensThresholds::default();

        let result = metrics.check_provenance(&thresholds);
        assert!(result.is_err(), "All-zero metrics should be rejected");

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("All-zero"),
            "Error should mention all-zero: {}",
            err
        );
    }

    #[test]
    fn test_lens_gate_legitimate_metrics_accepted() {
        // Real camera metrics: moderate PRNU, low Moiré, medium luminance
        let metrics = ForensicMetrics {
            h_energy: 5.0,
            v_energy: 3.0,
            prnu_var: 200.0,
            mean_luminance: 128.0,
        };
        let thresholds = LensThresholds::default(); // prnu_floor=1.0, moire_ceiling=100.0

        // prnu_var (200) > prnu_floor (1.0) × mean_luminance (128) = 128 ✓
        // max_moire (5) < moire_ceiling (100) × mean_luminance (128) = 12800 ✓
        let result = metrics.check_provenance(&thresholds);
        assert!(
            result.is_ok(),
            "Legitimate metrics should pass: {:?}",
            result
        );
    }

    #[test]
    fn test_lens_gate_synthetic_image_rejected() {
        // Synthetic/AI-generated image: near-zero PRNU (no real sensor noise)
        let metrics = ForensicMetrics {
            h_energy: 2.0,
            v_energy: 1.5,
            prnu_var: 0.5, // Suspiciously low for real sensor
            mean_luminance: 128.0,
        };
        let thresholds = LensThresholds::default();

        // prnu_var (0.5) < prnu_floor (1.0) × mean_luminance (128) = 128 → REJECT
        let result = metrics.check_provenance(&thresholds);
        assert!(result.is_err(), "Low PRNU should be rejected as synthetic");

        let err = result.unwrap_err().to_string();
        assert!(err.contains("PRNU"), "Error should mention PRNU: {}", err);
    }

    #[test]
    fn test_lens_gate_screen_recapture_rejected() {
        // Screen recapture: very high Moiré energy (interference patterns)
        let metrics = ForensicMetrics {
            h_energy: 50000.0, // Massive horizontal interference
            v_energy: 40000.0,
            prnu_var: 300.0, // Normal PRNU
            mean_luminance: 128.0,
        };
        let thresholds = LensThresholds::default();

        // max_moire (50000) > moire_ceiling (100) × mean_luminance (128) = 12800 → REJECT
        let result = metrics.check_provenance(&thresholds);
        assert!(
            result.is_err(),
            "High Moiré should be rejected as screen recapture"
        );

        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("Moiré") || err.contains("recapture"),
            "Error should mention Moiré/recapture: {}",
            err
        );
    }

    #[test]
    fn test_lens_gate_low_luminance_accepted() {
        // Very dark frame: mean_luminance < 1.0 → threshold scaling unreliable.
        // Accept with warning rather than reject (all-zero check catches bypasses).
        let metrics = ForensicMetrics {
            h_energy: 0.1,
            v_energy: 0.1,
            prnu_var: 0.05,
            mean_luminance: 0.5, // Very dark but not zero
        };
        let thresholds = LensThresholds::default();

        let result = metrics.check_provenance(&thresholds);
        assert!(
            result.is_ok(),
            "Very dark frames should be accepted: {:?}",
            result
        );
    }

    #[test]
    fn test_lens_gate_auto_exposure_scaling() {
        // The same sensor fingerprint at different exposure levels should be
        // treated consistently. A bright frame naturally has higher raw metrics.
        let thresholds = LensThresholds {
            prnu_floor: 2.0,
            moire_ceiling: 50.0,
        };

        // Dark frame (mean_luminance = 50): threshold = 2.0 × 50 = 100
        let dark = ForensicMetrics {
            h_energy: 10.0,
            v_energy: 8.0,
            prnu_var: 150.0, // 150 > 100 ✓
            mean_luminance: 50.0,
        };
        assert!(
            dark.check_provenance(&thresholds).is_ok(),
            "Dark frame should pass"
        );

        // Bright frame (mean_luminance = 200): threshold = 2.0 × 200 = 400
        let bright = ForensicMetrics {
            h_energy: 40.0,
            v_energy: 32.0,
            prnu_var: 500.0, // 500 > 400 ✓
            mean_luminance: 200.0,
        };
        assert!(
            bright.check_provenance(&thresholds).is_ok(),
            "Bright frame should pass"
        );

        // Same bright frame but low PRNU (synthetic at high exposure)
        let synthetic_bright = ForensicMetrics {
            h_energy: 10.0,
            v_energy: 8.0,
            prnu_var: 50.0, // 50 < 400 → REJECT
            mean_luminance: 200.0,
        };
        assert!(
            synthetic_bright.check_provenance(&thresholds).is_err(),
            "Synthetic image at high exposure should be rejected"
        );
    }
}
