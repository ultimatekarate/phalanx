use crate::evidence::SignatureHash;
use crate::evidence::WitnessEnvelope;
use crate::identity::NetworkId;
use crate::identity::PhalanxIdentity;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, Default)]
#[serde(transparent)]
pub struct PhalanxTimestamp(pub u64);

impl PhalanxTimestamp {
    pub fn from_u64(raw: u64) -> Self {
        Self(raw)
    }
    pub fn as_u64(&self) -> u64 {
        self.0
    }
    pub fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// Returns the current wall-clock timestamp.
    ///
    /// # Visibility: `pub(crate)`
    ///
    /// If the OS clock is catastrophically broken (goes backward), this panics.
    /// Phalanx cannot solve a broken OS clock. All security-critical paths go
    /// through `TrustedClockTrait`, which is enforced at compile time by this
    /// visibility restriction. Code outside proto must use `SystemClock` (for
    /// non-critical timestamps) or a `TrustedClockTrait` implementor (for
    /// security-critical timestamps, e.g., the NTP-corrected `TrustedClock`
    /// in phalanx-node).
    #[allow(clippy::expect_used, clippy::cast_possible_truncation)]
    pub(crate) fn now() -> Self {
        // expect: SystemTime before UNIX_EPOCH is an unrecoverable OS-level fault.
        // truncation: u128 millis won't exceed u64 until year 584,942,417.
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_millis() as u64;

        Self(millis)
    }
}

pub trait TrustedClock: Send + Sync {
    fn now(&self) -> PhalanxTimestamp;
}

/// A default TrustedClock that delegates directly to PhalanxTimestamp::now().
/// Used in tests and as a fallback when no NTP-corrected clock is available.
pub struct SystemClock;

impl TrustedClock for SystemClock {
    fn now(&self) -> PhalanxTimestamp {
        PhalanxTimestamp::now()
    }
}

/// A stateful session that maintains the causality chain for a specific timeline.
///
/// M6: The identity field is skipped during serialization to prevent
/// accidental private key leakage. It must be re-injected after deserialization.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CausalitySession {
    #[serde(skip, default = "default_identity")]
    pub identity: Arc<PhalanxIdentity>,
    pub peer_id: NetworkId,
    pub last_hash: Option<SignatureHash>,
}

fn default_identity() -> Arc<PhalanxIdentity> {
    Arc::new(PhalanxIdentity::default())
}

impl CausalitySession {
    pub fn new(identity: Arc<PhalanxIdentity>, peer_id: NetworkId) -> Self {
        Self {
            identity,
            peer_id,
            last_hash: None,
        }
    }

    /// Validates the incoming envelope against the session's continuity chain.
    /// If valid, it updates the session state to point to the new head.
    pub fn verify_next(&mut self, envelope: &WitnessEnvelope) -> Result<(), TimeError> {
        let incoming_prev = envelope.prev_hash;

        // Link Validation
        match (self.last_hash, incoming_prev) {
            // Sequential case: Ensure incoming prev matches our current head
            (Some(expected), Some(found)) if expected == found => Ok(()),

            // Genesis case: New session expects a None prev_hash
            (None, None) => Ok(()),

            // Violation: Mismatch or unexpected link state
            (expected, found) => Err(TimeError::CausalityBreak { expected, found }),
        }?;

        // State Advancement: Promote the new hash as the chain head
        self.last_hash = Some(SignatureHash(envelope.evidence_hash));

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum TimeError {
    #[error("System clock drift detected: {0}")]
    ClockSkew(String),
    #[error("Time synchronization lock poisoned: {0}")]
    LockPoisoned(String),
    #[error("Timestamp is too far in the past: {0}s difference")]
    Stale(u64),
    #[error("Timestamp is in the future: {0}s difference")]
    Future(u64),
    #[error("NTP Sync failed: {0}")]
    NtpError(String),
    #[error("Clock skew detected: timestamp is in the future")]
    FutureTimestamp,
    #[error("Resource expired")]
    Expired,
    #[error("Causality violation: Expected prev_hash {expected:?}, found {found:?}")]
    CausalityBreak {
        expected: Option<SignatureHash>,
        found: Option<SignatureHash>,
    },
}

/// Monotonic elapsed-time counter (seconds since arbitrary reference point).
/// Unlike `PhalanxTimestamp` (wall-clock millis since UNIX_EPOCH), this counter
/// never goes backward — used for trust recovery cooldowns and eclipse detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct MonotonicClock(pub u64);

impl MonotonicClock {
    pub fn elapsed_since(&self, earlier: Self) -> u64 {
        self.0.saturating_sub(earlier.0)
    }
}
