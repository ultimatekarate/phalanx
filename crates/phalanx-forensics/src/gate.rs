// crates/phalanx-forensics/src/gate.rs
//
// The Monadic Gate System: Composable forensic verification combinators.
// Each gate is a trait that can be chained in a Result pipeline.

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{Evidence, SignatureHash, WitnessEnvelope};
use phalanx_proto::prelude::*;
use phalanx_proto::time::PhalanxTimestamp;
use std::collections::HashMap;
use tracing::{error, warn};

// Extension traits from sibling modules that provide methods on proto types.
use crate::crucible::{EnvelopeHashExt, EvidenceExt};
use crate::judge::{PayloadCipher, TimeJudge};
use crate::witness::WitnessAuthority;

use sha2::{Digest, Sha256};
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

/// Gate 2: The Chronos Gate (Timeline Integrity)
pub trait ChronosGate {
    fn verify_continuity(&self, envelopes: &[WitnessEnvelope]) -> Result<(), ShardError>;
}

impl ChronosGate for Vec<WitnessEnvelope> {
    fn verify_continuity(&self, envelopes: &[WitnessEnvelope]) -> Result<(), ShardError> {
        if envelopes.is_empty() {
            return Ok(());
        }

        for window in envelopes.windows(2) {
            let (prev, curr) = (&window[0], &window[1]);

            if curr.prev_hash != Some(prev.signature_hash()) {
                return Err(ShardError::InvalidConfiguration("Causality Break".into()));
            }

            if curr.evidence.timestamp() < prev.evidence.timestamp() {
                return Err(ShardError::InvalidConfiguration("Temporal Paradox".into()));
            }
        }
        Ok(())
    }
}

/// Gate 3: The Integrity Gate (Reception Side)
pub trait IntegrityGate {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        now: PhalanxTimestamp,
        tolerance: u64,
        anchor: Option<SignatureHash>,
    ) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl IntegrityGate for WitnessEnvelope {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        now: PhalanxTimestamp,
        tolerance: u64,
        anchor: Option<SignatureHash>,
    ) -> Result<Self, ShardError> {
        // Sticky Trust Pipeline:
        // If the envelope's prev_hash matches the trusted anchor, we skip
        // the expensive signature verification. This is the "Fast" path.
        let is_anchored = anchor.is_some() && anchor == self.prev_hash;

        if !is_anchored && !self.verify_envelope() {
            error!(event = "integrity_failure", node = %node_id, peer = %self.did, "SIGNATURE_INVALID");
            return Err(ShardError::SigningError(
                "Signature verification failed".into(),
            ));
        }

        match self.evidence.timestamp().verify_freshness(now, tolerance) {
            Ok(_) => Ok(self),
            Err(e) => {
                error!(event = "temporal_failure", node = %node_id, peer = %self.did, "TIME_INVALID");
                Err(ShardError::InvalidConfiguration(e.to_string()))
            }
        }
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

/// Gate 5: The Ingress Capacity Gate
pub trait CapacityGate {
    fn check_capacity(
        self,
        peer: &NetworkId,
        pending: usize,
        limit: usize,
    ) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl CapacityGate for WitnessEnvelope {
    fn check_capacity(
        self,
        peer: &NetworkId,
        pending: usize,
        limit: usize,
    ) -> Result<Self, ShardError> {
        if pending > limit {
            warn!(event = "capacity_shedding", peer = %peer, "Node saturated");
            return Err(ShardError::CapacityExceeded(pending as u64));
        }
        Ok(self)
    }
}

/// Gate 6: The Memory Buffer Gate
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
        let actual_bytes = postcard::to_allocvec(&self.evidence)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

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
        now: PhalanxTimestamp,
        tolerance: u64,
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
        now: PhalanxTimestamp,
        tolerance: u64,
        anchor: Option<SignatureHash>,
    ) -> Result<ForensicUnit<WitnessEnvelope, Verified>, ShardError> {
        // 1. Integrity Gate (Signature + Time + Sticky Trust)
        let mut envelope = self.data.check_integrity(node_id, now, tolerance, anchor)?;

        // 2. Continuity Gate (Chain Enforcement)
        if let Some(ref a) = anchor {
            envelope = envelope.verify_link(a)?;
        }

        Ok(ForensicUnit {
            data: envelope,
            _state: std::marker::PhantomData,
        })
    }
}
