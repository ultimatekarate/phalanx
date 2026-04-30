use crate::evidence::SignatureHash;
use crate::evidence::WitnessEnvelope;
use crate::identity::PhalanxIdentity;
use crate::identity::WitnessId;
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
    pub peer_id: WitnessId,
    pub last_hash: Option<SignatureHash>,
}

fn default_identity() -> Arc<PhalanxIdentity> {
    Arc::new(PhalanxIdentity::default())
}

impl CausalitySession {
    pub fn new(identity: Arc<PhalanxIdentity>, peer_id: WitnessId) -> Self {
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

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod causality_tests {
    use super::*;
    use crate::evidence::{Evidence, ForensicGap, StorageSequence, WitnessEnvelope};
    use crate::identity::{PhalanxIdentity, RecordingId, WitnessId};
    use crate::revocation::RevocationKey;

    fn stub_envelope(
        prev_hash: Option<SignatureHash>,
        evidence_hash_first_byte: u8,
    ) -> WitnessEnvelope {
        let mut evidence_hash = [0u8; 32];
        evidence_hash[0] = evidence_hash_first_byte;
        WitnessEnvelope {
            evidence: Evidence::Gap(ForensicGap {
                recording_id: RecordingId::new("causality-probe"),
                start_seq: StorageSequence(0),
                end_seq: StorageSequence(1),
                detected_at: PhalanxTimestamp::from_millis(1_700_000_000_000),
            }),
            evidence_hash,
            witness_peer_id: WitnessId::new("test-peer"),
            witness_signature: vec![],
            did: PhalanxIdentity::new_ephemeral().did,
            prev_hash,
            revocation_key: RevocationKey::default(),
        }
    }

    fn fresh_session() -> CausalitySession {
        let identity = Arc::new(PhalanxIdentity::new_ephemeral());
        CausalitySession::new(identity, WitnessId::new("peer-under-test"))
    }

    #[test]
    fn genesis_envelope_is_accepted_and_advances_head() {
        let mut session = fresh_session();
        assert!(session.last_hash.is_none());

        let env = stub_envelope(None, 0xAA);
        session
            .verify_next(&env)
            .expect("genesis envelope must be accepted");

        assert_eq!(
            session.last_hash,
            Some(SignatureHash(env.evidence_hash)),
            "verify_next must promote evidence_hash to chain head"
        );
    }

    #[test]
    fn sequential_envelope_matching_head_is_accepted() {
        let mut session = fresh_session();
        let genesis = stub_envelope(None, 0x11);
        session.verify_next(&genesis).expect("genesis ok");

        let head = SignatureHash(genesis.evidence_hash);
        let next = stub_envelope(Some(head), 0x22);
        session
            .verify_next(&next)
            .expect("sequential chain must be accepted");

        assert_eq!(session.last_hash, Some(SignatureHash(next.evidence_hash)));
    }

    #[test]
    fn mismatched_prev_hash_returns_causality_break() {
        let mut session = fresh_session();
        let genesis = stub_envelope(None, 0x33);
        session.verify_next(&genesis).expect("genesis ok");

        // Forged envelope claims to follow a hash that was never our head.
        let wrong_prev = SignatureHash([0xFF; 32]);
        let forged = stub_envelope(Some(wrong_prev), 0x44);
        let err = session
            .verify_next(&forged)
            .expect_err("mismatched prev_hash must be rejected");
        assert!(
            matches!(err, TimeError::CausalityBreak { .. }),
            "expected CausalityBreak, got {err:?}"
        );
    }

    #[test]
    fn non_genesis_into_fresh_session_is_rejected() {
        // A fresh session (last_hash = None) must reject an envelope that
        // claims to follow some earlier hash. Without this, an attacker can
        // splice fabricated chains into a newly started session.
        let mut session = fresh_session();
        let intrusive = stub_envelope(Some(SignatureHash([0x77; 32])), 0x88);
        let err = session
            .verify_next(&intrusive)
            .expect_err("non-genesis prev into empty session must be rejected");
        assert!(matches!(err, TimeError::CausalityBreak { .. }));
    }

    #[test]
    fn genesis_envelope_into_established_session_is_rejected() {
        // Once the chain is established, an envelope with prev_hash=None
        // would effectively re-genesis the session. Must fail.
        let mut session = fresh_session();
        session
            .verify_next(&stub_envelope(None, 0x01))
            .expect("genesis ok");

        let regenesis = stub_envelope(None, 0x02);
        let err = session
            .verify_next(&regenesis)
            .expect_err("second genesis must be rejected");
        assert!(matches!(err, TimeError::CausalityBreak { .. }));
    }

    #[test]
    fn monotonic_elapsed_since_is_correct_forward() {
        let earlier = MonotonicClock(100);
        let later = MonotonicClock(250);
        assert_eq!(later.elapsed_since(earlier), 150);
    }

    #[test]
    fn monotonic_elapsed_since_saturates_on_underflow() {
        // saturating_sub is the deliberate behaviour: `elapsed_since` of a
        // future moment must return 0, not panic or wrap. Without this,
        // a tick ordering bug would crash the cooldown machinery.
        let earlier = MonotonicClock(100);
        let later = MonotonicClock(250);
        assert_eq!(earlier.elapsed_since(later), 0);
    }
}
