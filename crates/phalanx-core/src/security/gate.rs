use crate::primitives::identity::{NetworkId, PhalanxIdentity};
use crate::primitives::shards::{Evidence, ShardError, WitnessEnvelope};
use crate::primitives::time::{PhalanxTimestamp, TimeError, TrustedClock};
use crate::security::e2ee::SymmetricKey;
use tracing::{error, warn};

/// Gate 1: The Witnessing Gate
/// Converts raw Evidence into a signed, verifiable WitnessEnvelope.
pub trait WitnessGate {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
    ) -> Result<WitnessEnvelope, ShardError>;
}

impl WitnessGate for Evidence {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
    ) -> Result<WitnessEnvelope, ShardError> {
        WitnessEnvelope::new(self, identity, peer_id).map_err(|e| {
            error!(event = "signing_failure", error = %e, "Witness Gate: Failed to cryptographically seal unit");
            e
        })
    }
}

/// Gate 2: The Forensic Pipeline Gate (DEPRECATED)
/// REMOVED: The `ok_or_log` anti-pattern has been eradicated.
/// Use the standard library `Result::inspect_err` directly in the pipeline for side-effect telemetry.

/// Gate 3: The Integrity Gate (Reception Side)
/// Validates incoming Envelopes before they reach storage or the Crucible.
pub trait IntegrityGate {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        clock: &TrustedClock,
        tolerance: u64,
    ) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl IntegrityGate for WitnessEnvelope {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        clock: &TrustedClock,
        tolerance: u64,
    ) -> Result<Self, ShardError> {
        // 1. Cryptographic Verification
        if !self.verify() {
            error!(event = "integrity_failure", node = %node_id, peer = %self.did, "SIGNATURE_INVALID");
            // Maps to ShardError::SigningError to enable GossipSub rejection and peer penalization
            return Err(ShardError::SigningError(
                "Cryptographic signature verification failed".to_string(),
            ));
        }

        // 2. Temporal Freshness (Replay Protection)
        match self.evidence.timestamp().verify_freshness(clock, tolerance) {
            Ok(_) => Ok(self),
            Err(e) => {
                error!(event = "temporal_failure", node = %node_id, peer = %self.did, error = %e, "TIME_INVALID");
                Err(ShardError::TimeSource(e))
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
        let encryption_result = match &mut self {
            Evidence::Video(s) => s.encrypt(key),
            Evidence::Audio(s) => s.encrypt(key),
        };

        match encryption_result {
            Ok(_) => Ok(self),
            Err(crypto_error) => {
                error!(
                    event = "privacy_failure",
                    error = %crypto_error,
                    "Cryptographic safeguarding failed; evidence unit is unsafe for promotion"
                );
                Err(ShardError::Encryption(crypto_error))
            }
        }
    }
}

/// Gate 5: The Capacity Gate (Ingress)
/// Enforces Availability.
/// Prevents Denial of Service (DoS) by checking quotas BEFORE cryptographic verification.
pub trait CapacityGate {
    fn check_capacity(
        self,
        peer: &NetworkId,
        pending_bytes: usize,
        limit: usize,
    ) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl CapacityGate for WitnessEnvelope {
    fn check_capacity(
        self,
        peer: &NetworkId,
        pending_bytes: usize,
        limit: usize,
    ) -> Result<Self, ShardError> {
        if pending_bytes > limit {
            warn!(
                event = "capacity_shedding",
                peer = %peer,
                current = pending_bytes,
                limit = limit,
                "Capacity Gate: Node saturated, rejecting payload"
            );
            return Err(ShardError::CapacityExceeded(pending_bytes as u64));
        }

        // 2. (Optional) Check Blocklist/Allowlist here
        // if blacklist.contains(peer) { return Err(ShardError::PeerBlacklisted); }

        Ok(self)
    }
}

/// Gate 6: The Chronos Gate (System Resource)
/// Enforces Temporal Availability.
/// Safely acquires the current forensic time, propagating strict TimeError types.
pub trait ChronosGate {
    fn forensic_now(&self) -> Result<PhalanxTimestamp, TimeError>;
}

impl ChronosGate for TrustedClock {
    fn forensic_now(&self) -> Result<PhalanxTimestamp, TimeError> {
        self.now().map_err(|e| {
            // Critical system failure: Time is broken.
            error!(
                event = "clock_failure",
                error = %e,
                "Chronos Gate: Time source unavailable or poisoned"
            );
            e
        })
    }
}

/// The core extension for monadic forensic gating.
pub trait ForensicGate<T, E> {
    /// Observes a Result in the pipeline, logging failures with forensic context
    /// while preserving the original Result for the next link in the chain.
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E>;
}

impl<T, E: std::fmt::Display> ForensicGate<T, E> for Result<T, E> {
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E> {
        if let Err(ref e) = self {
            error!(
                event = event,
                node = %node,
                error = %e,
                "{msg}"
            );
        }
        self
    }
}
