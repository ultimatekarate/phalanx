// crates/phalanx-proto/src/revocation.rs
//
// The Revocation Nouns: Cryptographic forgetting for the Phalanx mesh.
//
// RevocationKey is a newtype over [u8; 32] — the public half of a revocation
// keypair derived from the BIP39 mnemonic (seed bytes [32..64]). It cannot be
// confused with SymmetricKey, SignatureHash, or nonce values.
//
// RevocationToken is a signed intent to destroy all evidence for a recording.
// The signature is produced by the revocation keypair, which is derived from
// the BIP39 mnemonic and never stored on the device.

use crate::identity::RecordingId;
use crate::time::PhalanxTimestamp;
use crate::wire::WireBound;
use serde::{Deserialize, Serialize};

/// The public half of the revocation keypair. Derived from the BIP39 mnemonic
/// (seed bytes [32..64]). A newtype over [u8; 32] to prevent confusion with
/// SymmetricKey, SignatureHash, or nonce values.
///
/// Follows the Values axis: a RevocationKey cannot be confused with a SymmetricKey.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RevocationKey(pub [u8; 32]);

impl RevocationKey {
    /// Returns true for legacy/ephemeral identities that don't support revocation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0 == [0u8; 32]
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// A signed intent to destroy all evidence for a recording.
/// The signature is produced by the revocation keypair, which is derived
/// from the BIP39 mnemonic and never stored on the device.
///
/// Revocation is permanent and irreversible by design. Once a valid token
/// is broadcast, no mechanism exists to cancel it — even the mnemonic
/// holder cannot un-revoke. The threat model prioritizes the user's right
/// to destroy their own evidence over recoverability from accidental
/// revocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationToken {
    pub recording_id: RecordingId,
    pub issued_at: PhalanxTimestamp,
    pub nonce: [u8; 32],
    /// Ed25519 signature from the revocation keypair (NOT the device key).
    /// Covers: recording_id || issued_at || nonce
    pub signature: Vec<u8>,
    /// The revocation public key — makes the token self-verifiable.
    pub revocation_key: RevocationKey,
}

impl WireBound for RevocationToken {
    fn enforce_wire_bounds(&mut self) {
        // Signature must be exactly 64 bytes (Ed25519).
        if self.signature.len() != 64 {
            self.signature.truncate(64);
        }
        // Recording ID must not be empty.
        if self.recording_id.as_str().is_empty() {
            self.recording_id = RecordingId::new("_invalid_");
        }
    }
}

#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
pub enum RevocationError {
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Revocation key mismatch: token key does not match recording's embedded key")]
    KeyMismatch,

    #[error("Already revoked: {0}")]
    AlreadyRevoked(RecordingId),

    #[error("Revocation not supported: recording has empty revocation key (legacy/ephemeral)")]
    NotSupported,
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    fn token_with_signature(signature: Vec<u8>, recording_id: &str) -> RevocationToken {
        RevocationToken {
            recording_id: RecordingId::new(recording_id),
            issued_at: PhalanxTimestamp::from_millis(1_700_000_000_000),
            nonce: [7u8; 32],
            signature,
            revocation_key: RevocationKey([1u8; 32]),
        }
    }

    #[test]
    fn enforce_wire_bounds_truncates_oversized_signature() {
        // Gate 0b contract: signatures longer than the Ed25519 size must be clamped,
        // otherwise memory amplification on the wire is possible.
        let mut token = token_with_signature(vec![0u8; 128], "over-sized");
        token.enforce_wire_bounds();
        assert_eq!(token.signature.len(), 64);
    }

    #[test]
    fn enforce_wire_bounds_is_idempotent_on_valid_input() {
        // Calling twice must not corrupt an already-valid token.
        let mut token = token_with_signature(vec![0u8; 64], "valid");
        token.enforce_wire_bounds();
        let first_signature = token.signature.clone();
        let first_recording = token.recording_id.clone();
        token.enforce_wire_bounds();
        assert_eq!(token.signature, first_signature);
        assert_eq!(token.recording_id, first_recording);
    }

    #[test]
    fn enforce_wire_bounds_replaces_empty_recording_id() {
        // An empty recording_id is structurally invalid: RevocationToken must
        // always name the recording it destroys.
        let mut token = token_with_signature(vec![0u8; 64], "");
        token.enforce_wire_bounds();
        assert_eq!(token.recording_id.as_str(), "_invalid_");
    }

    #[test]
    fn enforce_wire_bounds_does_not_grow_short_signature() {
        // The bound is one-sided: too long is truncated, too short stays short
        // (will fail signature verification later, which is the right place
        // to reject it — Gate 0b is about structural caps, not content validity).
        let mut token = token_with_signature(vec![0u8; 32], "short");
        token.enforce_wire_bounds();
        assert_eq!(token.signature.len(), 32);
    }
}
