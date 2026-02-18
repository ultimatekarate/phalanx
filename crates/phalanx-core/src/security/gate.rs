use crate::primitives::identity::{NetworkId, PhalanxIdentity};
use crate::primitives::shards::{Evidence, WitnessEnvelope};
use crate::primitives::time::TrustedClock;
use tracing::error;

/// Gate 1: The Witnessing Gate
/// Converts raw Evidence into a signed, verifiable WitnessEnvelope.
pub trait WitnessGate {
    fn seal(self, identity: &PhalanxIdentity, peer_id: NetworkId) -> Option<WitnessEnvelope>;
}

impl WitnessGate for Evidence {
    fn seal(self, identity: &PhalanxIdentity, peer_id: NetworkId) -> Option<WitnessEnvelope> {
        match WitnessEnvelope::new(self, identity, peer_id) {
            Ok(env) => Some(env),
            Err(e) => {
                error!(event = "signing_failure", error = %e, "Forensic Gate: Dropped unit during sealing");
                None
            }
        }
    }
}

/// Gate 2: The Forensic Pipeline Gate
/// Turns any Result into a fault-tolerant Option while logging failures.
pub trait ForensicGate<T> {
    fn ok_or_log(self, event: &str, node: &NetworkId, msg: &str) -> Option<T>;
}

impl<T, E: std::fmt::Display> ForensicGate<T> for Result<T, E> {
    fn ok_or_log(self, event: &str, node: &NetworkId, msg: &str) -> Option<T> {
        match self {
            Ok(val) => Some(val),
            Err(e) => {
                error!(event = event, node = %node, error = %e, "{msg}");
                None
            }
        }
    }
}

/// Gate 3: The Integrity Gate (Reception Side)
/// Validates incoming Envelopes before they reach storage or the Crucible.
pub trait IntegrityGate {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        clock: &TrustedClock,
        tolerance: u64,
    ) -> Option<Self>
    where
        Self: Sized;
}

impl IntegrityGate for WitnessEnvelope {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        clock: &TrustedClock,
        tolerance: u64,
    ) -> Option<Self> {
        // 1. Cryptographic Verification
        if !self.verify() {
            error!(event = "integrity_failure", node = %node_id, peer = %self.did, "SIGNATURE_INVALID");
            return None;
        }

        // 2. Temporal Freshness (Replay Protection)
        match self.evidence.timestamp().verify_freshness(clock, tolerance) {
            Ok(_) => Some(self),
            Err(e) => {
                error!(event = "temporal_failure", node = %node_id, peer = %self.did, error = %e, "TIME_INVALID");
                None
            }
        }
    }
}
