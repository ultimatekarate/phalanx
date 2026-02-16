use crate::primitives::identity::{Did}; // Assumed wrappers
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use crate::storage::strategies::VolleyId;

/// A targeted access grant.
///
/// Unlike the `PhalanxLocator`, this struct does NOT expose the raw key.
/// It contains a sealed payload that only `recipient` can decrypt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedLocator {
    /// The content we are pointing to.
    pub target: VolleyId,
    /// The DID of the intended recipient (Who can open this?).
    pub recipient: Did,
    /// The DID of the sender (Who signed/sealed this?).
    pub sender: Did,
    /// The Encrypted VolleyKey (ChaCha20-Poly1305 key).
    /// Encrypted via X25519(SenderPriv, RecipientPub).
    #[serde(with = "base64_serde")]
    pub sealed_key: Vec<u8>,
    /// Ephemeral Nonce for the encryption wrapper.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
}

impl SealedLocator {
    /// Constructs a safe link for a specific user.
    ///
    /// # Arguments
    /// * `volley_id` - The evidence ID.
    /// * `volley_key` - The actual symmetric key to the evidence (32 bytes).
    /// * `sender_sk` - Your private key (to derive shared secret).
    /// * `recipient_pk` - Their public key (to derive shared secret).
    pub fn new(
        volley_id: VolleyId,
        volley_key: &[u8; 32],
        sender: Did,
        sender_sk: &SecretKey,
        recipient: Did,
        recipient_pk: &PublicKey
    ) -> Result<Self, CryptoError> {
        // 1. Derive Shared Secret (ECDH)
        // Note: Implementation depends on specific crypto crate (e.g. sodium/dalek)
        let shared_secret = derive_ecdh(sender_sk, recipient_pk);

        // 2. Encrypt the VolleyKey
        let nonce = generate_nonce();
        let sealed_key = encrypt_payload(&shared_secret, &nonce, volley_key)?;

        Ok(Self {
            target: volley_id,
            recipient,
            sender,
            sealed_key,
            nonce,
        })
    }

    /// Attempts to unlock the locator.
    /// Returns the raw VolleyKey if the recipient matches the local identity.
    pub fn unlock(&self, my_sk: &SecretKey) -> Result<[u8; 32], CryptoError> {
        // 1. Re-derive Shared Secret (ECDH) using Sender's Public Key
        // The sender's DID must resolve to their Public Key via the Identity system.
        let sender_pk = self.sender.resolve_public_key()?; 
        let shared_secret = derive_ecdh(my_sk, &sender_pk);

        // 2. Decrypt
        let raw_key = decrypt_payload(&shared_secret, &self.nonce, &self.sealed_key)?;
        
        raw_key.try_into().map_err(|_| CryptoError::InvalidKeyLength)
    }
}

// --- URI Format Handling ---

impl fmt::Display for SealedLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format: phx-grant://<ID>#<RECIPIENT>@<SENDER>:<NONCE>:<CIPHERTEXT>
        let b64_cipher = URL_SAFE_NO_PAD.encode(&self.sealed_key);
        let b64_nonce = URL_SAFE_NO_PAD.encode(&self.nonce);
        
        write!(
            f, 
            "phx-grant://{}#{}@{}?n={}&p={}", 
            self.target, 
            self.recipient, 
            self.sender,
            b64_nonce,
            b64_cipher
        )
    }
}

// ... FromStr implementation would reverse the Display logic ...

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed")]
    EncryptionFailure,
    #[error("Decryption failed - Invalid Identity or Key")]
    DecryptionFailure,
    #[error("Key length mismatch")]
    InvalidKeyLength,
    #[error("Could not resolve DID to Public Key")]
    IdentityResolutionError,
}

// Stub for serialization helper
mod base64_serde {
    use super::*;
    use serde::{Deserializer, Serializer};
    
    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where D: Deserializer<'de> {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}