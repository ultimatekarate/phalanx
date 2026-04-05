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
