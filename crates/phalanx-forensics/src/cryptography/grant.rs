// crates/phalanx-forensics/src/cryptography/grant.rs

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use phalanx_proto::crypto::{CryptoError, SealedLocator};
use phalanx_proto::prelude::*;
use crate::cryptography::bridge::{ed_to_x25519_pk, ed_to_x25519_sk, resolve_did_pk};

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
        let recipient_x = ed_to_x25519_pk(&recipient_ed)?;

        // 2. Convert Sender Private Key to X25519
        let sender_x = ed_to_x25519_sk(&sender.keypair.to_bytes());

        // 3. Derive Shared Secret (ECDH)
        let shared_secret = sender_x.diffie_hellman(&recipient_x);

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
        // 1. Enforce Recipient Sovereignty: Only the intended recipient can attempt decryption
        if self.recipient != me.did {
            return Err(CryptoError::DecryptionFailure);
        }

        // 2. Resolve Sender Public Key and convert to X25519
        let sender_ed = resolve_did_pk(&self.sender)?;
        let sender_x = ed_to_x25519_pk(&sender_ed)?;

        // 3. Convert My Private Key to X25519
        let my_x = ed_to_x25519_sk(&me.keypair.to_bytes());

        // 4. Re-derive the identical Shared Secret (ECDH)
        let shared_secret = my_x.diffie_hellman(&sender_x);

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