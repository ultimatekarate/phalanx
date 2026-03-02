// crates/phalanx-forensics/src/cryptography/grant.rs

use crate::cryptography::bridge::{ed_to_x25519_pk, ed_to_x25519_sk, resolve_did_pk};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use phalanx_proto::crypto::{CryptoError, SealedLocator};
use phalanx_proto::prelude::*;

/// The Verb "To Authorize": Defines the forensic capability to secure and recover
/// symmetric keys using asymmetric identities.
pub trait GrantAuthority {
    /// Seals a symmetric VolleyKey into a locator targeted at a specific recipient.
    /// Implements ECDH over X25519 with XChaCha20-Poly1305 authenticated encryption.
    fn seal(
        target: VolleyId,
        key: &[u8; 32],
        sender: &PhalanxIdentity,
        recipient_did: Did,
    ) -> Result<SealedLocator, CryptoError>;

    /// Attempts to recover the symmetric key using the local node's identity.
    fn unlock(&self, my_identity: &PhalanxIdentity) -> Result<[u8; 32], CryptoError>;
}

impl GrantAuthority for SealedLocator {
    fn seal(
        target: VolleyId,
        key: &[u8; 32],
        sender: &PhalanxIdentity,
        recipient_did: Did,
    ) -> Result<Self, CryptoError> {
        // 1. Resolve Recipient Public Key and convert to X25519 for encryption
        let recipient_ed = resolve_did_pk(&recipient_did)?;
        let recipient_x_bytes = ed_to_x25519_pk(&recipient_ed)?;
        let recipient_pub = x25519_dalek::PublicKey::from(recipient_x_bytes);

        // 2. Convert Sender Private Key to X25519
        let sender_x = ed_to_x25519_sk(&sender.keypair)?;

        // 3. Derive Shared Secret (ECDH)
        let shared_secret = sender_x.diffie_hellman(&recipient_pub);

        // 4. Authenticated Encryption (AEAD)
        let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());
        let nonce_bytes = rand::random::<[u8; 24]>();
        let nonce = XNonce::from_slice(&nonce_bytes);

        // Include Sender DID in Authenticated Associated Data (AAD) to prevent spoofing
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: key,
                    aad: sender.did.as_ref().as_bytes(),
                },
            )
            .map_err(|_| CryptoError::EncryptionFailure)?;

        Ok(Self {
            target,
            recipient: recipient_did,
            sender: sender.did.clone(),
            sealed_key: ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    fn unlock(&self, me: &PhalanxIdentity) -> Result<[u8; 32], CryptoError> {
        // 1. Enforce Recipient Sovereignty
        if self.recipient != me.did {
            return Err(CryptoError::DecryptionFailure);
        }

        // 2. Resolve Sender Public Key and convert to X25519
        let sender_ed = resolve_did_pk(&self.sender)?;
        let sender_x_bytes = ed_to_x25519_pk(&sender_ed)?;
        let sender_pub = x25519_dalek::PublicKey::from(sender_x_bytes);

        // 3. Convert My Private Key to X25519
        let my_x = ed_to_x25519_sk(&me.keypair)?;

        // 4. Re-derive the identical Shared Secret (ECDH)
        let shared_secret = my_x.diffie_hellman(&sender_pub);

        // 5. Decrypt and Verify Integrity
        let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());
        let nonce = XNonce::from_slice(&self.nonce);

        let plaintext = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: &self.sealed_key,
                    aad: self.sender.as_ref().as_bytes(),
                },
            )
            .map_err(|_| CryptoError::DecryptionFailure)?;

        // 6. Ensure the result is a valid 32-byte symmetric key
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
        let volley_key = [0x42u8; 32];
        let volley_id = VolleyId::new("volley-test-001");

        // Use the Seal Verb
        let locator = SealedLocator::seal(
            volley_id.clone(),
            &volley_key,
            &sender,
            recipient.did.clone(),
        )
        .expect("Failed to create sealed locator");

        assert_eq!(locator.sender, sender.did);
        assert_eq!(locator.recipient, recipient.did);

        // Use the Unlock Verb with the recipient identity
        let decrypted_key = locator
            .unlock(&recipient)
            .expect("Recipient failed to decrypt grant");

        assert_eq!(decrypted_key, volley_key);
    }

    #[test]
    fn test_wrong_recipient_cannot_unlock() {
        let sender = generate_identity();
        let recipient = generate_identity();
        let attacker = generate_identity();

        let locator = SealedLocator::seal(
            VolleyId::new("v2"),
            &[0xAA; 32],
            &sender,
            recipient.did.clone(),
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
            VolleyId::new("v1"),
            &[0xBB; 32],
            &sender,
            recipient.did.clone(),
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
            VolleyId::new("test-id"),
            &[0u8; 32],
            &sender,
            recipient.did.clone(),
        )
        .unwrap();

        let uri = locator.to_string();
        assert!(uri.starts_with("phx-grant://"));
        assert!(uri.contains("test-id"));
    }
}
