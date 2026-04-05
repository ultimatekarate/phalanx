// crates/phalanx-forensics/src/revocation.rs
//
// The Revocation Verbs: Pure cryptographic logic for Cryptographic Forgetting.
//
// Three pure functions:
//   create_revocation_token  — signs a revocation intent
//   verify_revocation_token  — verifies the token's self-contained signature
//   authorize_revocation     — binds token to a recording's embedded key

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use phalanx_proto::identity::RecordingId;
use phalanx_proto::revocation::{RevocationError, RevocationKey, RevocationToken};
use phalanx_proto::time::PhalanxTimestamp;
use rand_core::{OsRng, RngCore};

/// Construct the canonical message bytes for signing/verification.
/// Covers: recording_id || issued_at || nonce
fn canonical_message(
    recording_id: &RecordingId,
    issued_at: PhalanxTimestamp,
    nonce: &[u8; 32],
) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(recording_id.as_str().as_bytes());
    msg.extend_from_slice(&issued_at.0.to_le_bytes());
    msg.extend_from_slice(nonce);
    msg
}

/// Create a signed revocation token for a recording.
///
/// The signing key is the revocation private key (seed[32..64]), which is
/// derived from the BIP39 mnemonic and never stored on the device.
/// The caller must provide it — this function is pure crypto.
pub fn create_revocation_token(
    recording_id: RecordingId,
    revocation_signing_key: &SigningKey,
    timestamp: PhalanxTimestamp,
) -> RevocationToken {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let msg = canonical_message(&recording_id, timestamp, &nonce);
    let signature = revocation_signing_key.sign(&msg);

    let revocation_key = RevocationKey(revocation_signing_key.verifying_key().to_bytes());

    RevocationToken {
        recording_id,
        issued_at: timestamp,
        nonce,
        signature: signature.to_bytes().to_vec(),
        revocation_key,
    }
}

/// Verify a revocation token's self-contained Ed25519 signature.
///
/// Reconstructs the signed message from the token's fields and verifies
/// the signature against the embedded revocation public key. Pure crypto —
/// no external lookups needed. A valid signature proves the token was created
/// by someone who possessed the revocation private key.
pub fn verify_revocation_token(token: &RevocationToken) -> Result<(), RevocationError> {
    let verifying_key = VerifyingKey::from_bytes(token.revocation_key.as_bytes())
        .map_err(|e| RevocationError::InvalidSignature(format!("Invalid public key: {e}")))?;

    let sig_bytes: [u8; 64] = token
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| RevocationError::InvalidSignature("Signature must be 64 bytes".into()))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let msg = canonical_message(&token.recording_id, token.issued_at, &token.nonce);

    verifying_key
        .verify_strict(&msg, &signature)
        .map_err(|e| RevocationError::InvalidSignature(format!("Verification failed: {e}")))
}

/// Authorize a revocation token against a recording's embedded revocation key.
///
/// This is the binding: the token's key must match the key embedded in the
/// recording's WitnessEnvelopes. If the envelope key `is_empty()`, the recording
/// is legacy/ephemeral and does not support revocation.
///
/// Type-safe: compares `RevocationKey == RevocationKey`, not anonymous `[u8; 32]`s.
pub fn authorize_revocation(
    token: &RevocationToken,
    envelope_key: &RevocationKey,
) -> Result<(), RevocationError> {
    if envelope_key.is_empty() {
        return Err(RevocationError::NotSupported);
    }
    if token.revocation_key != *envelope_key {
        return Err(RevocationError::KeyMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn test_keypair() -> SigningKey {
        let mut bytes = [0u8; 32];
        OsRng.fill_bytes(&mut bytes);
        SigningKey::from_bytes(&bytes)
    }

    #[test]
    fn create_verify_roundtrip() {
        let key = test_keypair();
        let recording_id = RecordingId::new("test-recording-001");
        let timestamp = PhalanxTimestamp(0);

        let token = create_revocation_token(recording_id, &key, timestamp);
        let result = verify_revocation_token(&token);
        assert!(result.is_ok(), "Valid token should verify: {:?}", result);
    }

    #[test]
    fn authorize_matching_key() {
        let key = test_keypair();
        let recording_id = RecordingId::new("test-recording-002");
        let timestamp = PhalanxTimestamp(0);

        let token = create_revocation_token(recording_id, &key, timestamp);
        let envelope_key = RevocationKey(key.verifying_key().to_bytes());

        let result = authorize_revocation(&token, &envelope_key);
        assert!(result.is_ok());
    }

    #[test]
    fn authorize_wrong_key_returns_mismatch() {
        let key = test_keypair();
        let wrong_key = test_keypair();
        let recording_id = RecordingId::new("test-recording-003");
        let timestamp = PhalanxTimestamp(0);

        let token = create_revocation_token(recording_id, &key, timestamp);
        let wrong_envelope_key = RevocationKey(wrong_key.verifying_key().to_bytes());

        let result = authorize_revocation(&token, &wrong_envelope_key);
        assert!(matches!(result, Err(RevocationError::KeyMismatch)));
    }

    #[test]
    fn authorize_empty_key_returns_not_supported() {
        let key = test_keypair();
        let recording_id = RecordingId::new("test-recording-004");
        let timestamp = PhalanxTimestamp(0);

        let token = create_revocation_token(recording_id, &key, timestamp);
        let empty_key = RevocationKey::default();

        let result = authorize_revocation(&token, &empty_key);
        assert!(matches!(result, Err(RevocationError::NotSupported)));
    }

    #[test]
    fn tampered_token_fails_verification() {
        let key = test_keypair();
        let recording_id = RecordingId::new("test-recording-005");
        let timestamp = PhalanxTimestamp(0);

        let mut token = create_revocation_token(recording_id, &key, timestamp);
        // Tamper with the recording ID
        token.recording_id = RecordingId::new("tampered-id");

        let result = verify_revocation_token(&token);
        assert!(matches!(result, Err(RevocationError::InvalidSignature(_))));
    }
}
