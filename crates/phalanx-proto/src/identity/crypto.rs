use crate::identity::Did;
use crate::identity::RecordingId;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

#[derive(Debug, Error, Serialize, Deserialize)]
pub enum CryptoError {
    #[error("Encryption failure")]
    EncryptionFailure,
    #[error("Decryption failure")]
    DecryptionFailure,
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("DID resolution failure")]
    DidResolutionFailure,
    #[error("Encoding error: {0}")]
    EncodingError(String),
    #[error("Decompression failure")]
    DecompressionFailure,
}

/// M5 FIX: Removed Serialize/Deserialize to prevent accidental key leakage.
/// Added Zeroize + ZeroizeOnDrop so key material is wiped from memory on drop.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct SymmetricKey(pub [u8; 32]);

impl SymmetricKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for SymmetricKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SymmetricKey").field(&"[REDACTED]").finish()
    }
}

/// Permission flags on a sealed locator.
///
/// Authenticated via AAD in the ECDH seal — a MITM cannot modify
/// permissions without breaking the cryptographic seal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantPermissions {
    /// Recipient may play back the recording.
    pub playback: bool,
    /// Recipient may C2PA-export the recording.
    pub export: bool,
}

impl Default for GrantPermissions {
    fn default() -> Self {
        Self {
            playback: true,
            export: false,
        }
    }
}

/// A targeted access grant.
///
/// Unlike the `PhalanxLocator`, this struct does NOT expose the raw key.
/// It contains a sealed payload that only `recipient` can decrypt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SealedLocator {
    /// The content we are pointing to.
    pub target: RecordingId,
    /// The DID of the intended recipient (Who can open this?).
    pub recipient: Did,
    /// The DID of the sender (Who signed/sealed this?).
    pub sender: Did,
    /// The Encrypted RecordingKey (ChaCha20-Poly1305 key).
    /// Encrypted via X25519(SenderPriv, RecipientPub).
    #[serde(with = "base64_serde")]
    pub sealed_key: Vec<u8>,
    /// Ephemeral Nonce for the encryption wrapper.
    #[serde(with = "base64_serde")]
    pub nonce: Vec<u8>,
    /// What the recipient is authorized to do. Authenticated via AAD.
    pub permissions: GrantPermissions,
}

impl fmt::Display for SealedLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b64_cipher = URL_SAFE_NO_PAD.encode(&self.sealed_key);
        let b64_nonce = URL_SAFE_NO_PAD.encode(&self.nonce);

        write!(
            f,
            "phx-grant://{}#{}@{}?n={}&p={}",
            self.target, self.recipient, self.sender, b64_nonce, b64_cipher
        )
    }
}

mod base64_serde {
    use super::*;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        URL_SAFE_NO_PAD.decode(s).map_err(serde::de::Error::custom)
    }
}
