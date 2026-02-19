use crate::primitives::identity::{NetworkId, PhalanxIdentity};
use crate::primitives::shards::{Evidence, ShardError, WitnessEnvelope};
use crate::primitives::time::TrustedClock;
use crate::security::e2ee::SymmetricKey;
use tracing::{error, warn};

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

/// Gate 4: The Privacy Gate (Egress)
/// Enforces Confidentiality.
/// Ensures that no evidence leaves this node without XChaCha20Poly1305 encryption.
pub trait PrivacyGate {
    fn safeguard(self, key: &SymmetricKey) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl PrivacyGate for Evidence {
    fn safeguard(mut self, key: &SymmetricKey) -> Result<Self, ShardError> {
        // We perform the encryption in place.
        // If it fails (e.g., bad nonce gen), we drop the packet to prevent leakage.
        let encryption_result = match &mut self {
            Evidence::Video(s) => s.encrypt(key),
            Evidence::Audio(s) => s.encrypt(key),
        };

        match encryption_result {
            Ok(_) => Ok(self),
            Err(crypto_error) => {
                // Log the failure at the point of origin for forensic auditability
                error!(
                    event = "privacy_failure",
                    error = %crypto_error,
                    "Cryptographic safeguarding failed; evidence unit is unsafe for promotion"
                );

                // Propagate the specific error to the caller (e.g., Guardian Layer)
                // so it can definitively drop the packet and update peer reputation.
                Err(ShardError::Encryption(crypto_error))
            }
        }
    }
}

/// Gate 5: The Capacity Gate (Ingress)
/// Enforces Availability.
/// Prevents Denial of Service (DoS) by checking quotas BEFORE cryptographic verification.
pub trait CapacityGate {
    fn check_capacity(self, peer: &NetworkId, pending_bytes: usize, limit: usize) -> Option<Self>
    where
        Self: Sized;
}

impl CapacityGate for WitnessEnvelope {
    fn check_capacity(self, peer: &NetworkId, pending_bytes: usize, limit: usize) -> Option<Self> {
        // 1. Basic Size Check
        // Postcard serialization usually handles this, but a logical check is good.
        // (Here we assume pending_bytes tracks the accumulation buffer)

        if pending_bytes > limit {
            warn!(
                event = "capacity_shedding",
                peer = %peer,
                current = pending_bytes,
                limit = limit,
                "Dropping packet: Node is saturated"
            );
            return None;
        }

        // 2. (Optional) Check Blocklist/Allowlist here
        // if blacklist.contains(peer) { return None; }

        Some(self)
    }
}

/// Gate 6: The Chronos Gate (System Resource)
/// Enforces Temporal Availability.
/// Safely acquires the current forensic time, logging critical system failures
/// if the clock is poisoned or skewed beyond recovery.
pub trait ChronosGate {
    fn forensic_now(&self) -> Option<u64>;
}

impl ChronosGate for TrustedClock {
    fn forensic_now(&self) -> Option<u64> {
        match self.now() {
            Ok(t) => Some(t),
            Err(e) => {
                // Critical system failure: Time is broken.
                error!(
                    event = "clock_failure",
                    error = %e,
                    "Chronos Gate: Time source unavailable"
                );
                None
            }
        }
    }
}
