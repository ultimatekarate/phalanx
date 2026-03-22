// crates/phalanx-forensics/src/cryptography/grant.rs
use crate::cryptography::bridge::{ed_to_x25519_pk, ed_to_x25519_sk, resolve_did_pk};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use phalanx_proto::crypto::{CryptoError, GrantPermissions, SealedLocator};
use phalanx_proto::prelude::*;
use rand_core::OsRng;
use rand_core::RngCore;

/// The Verb "To Authorize": Defines the forensic capability to secure and recover
/// symmetric keys using asymmetric identities.
pub trait GrantAuthority {
    /// Seals a symmetric RecordingKey into a locator targeted at a specific recipient.
    /// Implements ECDH over X25519 with XChaCha20-Poly1305 authenticated encryption.
    fn seal(
        target: RecordingId,
        key: &[u8; 32],
        sender: &PhalanxIdentity,
        recipient_did: Did,
        permissions: GrantPermissions,
    ) -> Result<SealedLocator, CryptoError>;

    /// Attempts to recover the symmetric key using the local node's identity.
    fn unlock(&self, my_identity: &PhalanxIdentity) -> Result<[u8; 32], CryptoError>;
}

impl GrantAuthority for SealedLocator {
    fn seal(
        target: RecordingId,
        key: &[u8; 32],
        sender: &PhalanxIdentity,
        recipient_did: Did,
        permissions: GrantPermissions,
    ) -> Result<Self, CryptoError> {
        // Resolve Recipient Public Key and convert to X25519 for encryption
        let recipient_ed = resolve_did_pk(&recipient_did)?;
        let recipient_x_bytes = ed_to_x25519_pk(&recipient_ed)?;
        let recipient_pub = x25519_dalek::PublicKey::from(recipient_x_bytes);

        // Convert Sender Private Key to X25519
        let sender_x = ed_to_x25519_sk(&sender.keypair)?;

        // Derive Shared Secret (ECDH)
        let shared_secret = sender_x.diffie_hellman(&recipient_pub);

        // Authenticated Encryption (AEAD)
        let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Build AAD: sender DID + serialized permissions.
        // Including permissions in AAD prevents MITM from flipping export:false to export:true.
        let permissions_bytes =
            postcard::to_allocvec(&permissions).map_err(|_| CryptoError::EncryptionFailure)?;
        let mut aad = sender.did.as_ref().as_bytes().to_vec();
        aad.extend_from_slice(&permissions_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: key,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailure)?;

        Ok(Self {
            target,
            recipient: recipient_did,
            sender: sender.did.clone(),
            sealed_key: ciphertext,
            nonce: nonce_bytes.to_vec(),
            permissions,
        })
    }

    fn unlock(&self, me: &PhalanxIdentity) -> Result<[u8; 32], CryptoError> {
        // Enforce Recipient Sovereignty
        if self.recipient != me.did {
            return Err(CryptoError::DecryptionFailure);
        }

        // Resolve Sender Public Key and convert to X25519
        let sender_ed = resolve_did_pk(&self.sender)?;
        let sender_x_bytes = ed_to_x25519_pk(&sender_ed)?;
        let sender_pub = x25519_dalek::PublicKey::from(sender_x_bytes);

        // Convert My Private Key to X25519
        let my_x = ed_to_x25519_sk(&me.keypair)?;

        // Re-derive the identical Shared Secret (ECDH)
        let shared_secret = my_x.diffie_hellman(&sender_pub);

        // Rebuild AAD: sender DID + serialized permissions (must match seal).
        let permissions_bytes =
            postcard::to_allocvec(&self.permissions).map_err(|_| CryptoError::DecryptionFailure)?;
        let mut aad = self.sender.as_ref().as_bytes().to_vec();
        aad.extend_from_slice(&permissions_bytes);

        // Decrypt and Verify Integrity (AAD mismatch = tampered permissions)
        let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());
        let nonce = XNonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &self.sealed_key,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::DecryptionFailure)?;

        // Ensure the result is a valid 32-byte symmetric key
        plaintext
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_proto::crypto::CryptoError;

    // Notice how we simplify this helper to just return the PhalanxIdentity!
    fn generate_identity() -> PhalanxIdentity {
        PhalanxIdentity::new_ephemeral()
    }

    // MOCK Bridge for tests (ensure your resolve_did_pk handles this correctly or mock it out)
    // If your resolve_did_pk relies on external network calls, you might need a local mock inside the tests.

    #[test]
    fn test_grant_lifecycle_success() {
        let sender = generate_identity();
        let recipient = generate_identity();
        let recording_key = [0x42u8; 32];
        let recording_id = RecordingId::new("recording-test-001");

        // Use the Seal Verb
        let locator = SealedLocator::seal(
            recording_id.clone(),
            &recording_key,
            &sender,
            recipient.did.clone(),
            GrantPermissions::default(),
        )
        .expect("Failed to create sealed locator");

        assert_eq!(locator.sender, sender.did);
        assert_eq!(locator.recipient, recipient.did);

        // Use the Unlock Verb with the recipient identity
        let decrypted_key = locator
            .unlock(&recipient)
            .expect("Recipient failed to decrypt grant");

        assert_eq!(decrypted_key, recording_key);
    }

    #[test]
    fn test_wrong_recipient_cannot_unlock() {
        let sender = generate_identity();
        let recipient = generate_identity();
        let attacker = generate_identity();

        let locator = SealedLocator::seal(
            RecordingId::new("v2"),
            &[0xAA; 32],
            &sender,
            recipient.did.clone(),
            GrantPermissions::default(),
        )
        .unwrap();

        // The attacker tries to unlock using their own identity
        let result = locator.unlock(&attacker);
        assert!(matches!(result, Err(CryptoError::DecryptionFailure)));
    }

    #[test]
    fn test_tampered_payload_fails() {
        let sender = generate_identity();
        let recipient = generate_identity();

        let mut locator = SealedLocator::seal(
            RecordingId::new("v1"),
            &[0xBB; 32],
            &sender,
            recipient.did.clone(),
            GrantPermissions::default(),
        )
        .unwrap();

        // Tamper with the ciphertext payload
        if let Some(byte) = locator.sealed_key.get_mut(0) {
            *byte ^= 0xFF;
        }

        assert!(matches!(
            locator.unlock(&recipient),
            Err(CryptoError::DecryptionFailure)
        ));
    }

    #[test]
    fn test_display_formatting() {
        let sender = generate_identity();
        let recipient = generate_identity();

        let locator = SealedLocator::seal(
            RecordingId::new("test-id"),
            &[0u8; 32],
            &sender,
            recipient.did.clone(),
            GrantPermissions::default(),
        )
        .unwrap();

        let uri = locator.to_string();
        assert!(uri.starts_with("phx-grant://"));
        assert!(uri.contains("test-id"));
    }
}
