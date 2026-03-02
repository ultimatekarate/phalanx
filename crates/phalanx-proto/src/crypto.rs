use crate::Did;
use crate::VolleyId;
use serde::{Deserialize, Serialize};
use thiserror;

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum CryptoError {
    #[error("Encryption failure")]
    EncryptionFailure,
    #[error("Decryption failure")]
    DecryptionFailure,
}

impl std::error::Error for CryptoError {}

#[derive(Clone, Serialize, Deserialize)]
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
// Stub for serialization helper
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prelude::PhalanxIdentity;
    use crate::Did;
    use crate::VolleyId;
    // Using Nouns from the Dictionary
    /// --- TEST HELPER: Generate Identity ---
    /// Bridges PhalanxIdentity to the multibase 'did:key' format for testing.
    fn generate_identity() -> (Did, [u8; 32]) {
        let identity = PhalanxIdentity::generate();
        let secret_bytes = identity.keypair.to_bytes();
        let pub_bytes = identity.keypair.verifying_key().to_bytes();

        let mut prefix = vec![0xed, 0x01];
        prefix.extend_from_slice(&pub_bytes);
        let multibase = bs58::encode(prefix).into_string();
        let did_string = format!("did:key:z{}", multibase);

        (Did(did_string), secret_bytes)
    }

    #[test]
    fn test_grant_lifecycle_success() {
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, recipient_sk) = generate_identity();
        let volley_key = [0x42u8; 32];
        let volley_id = VolleyId::new("volley-test-001");

        let locator = SealedLocator::new(
            volley_id.clone(),
            &volley_key,
            sender_did.clone(),
            &sender_sk,
            recipient_did.clone(),
        )
        .expect("Failed to create sealed locator");

        assert_eq!(locator.sender, sender_did);
        assert_eq!(locator.recipient, recipient_did);

        let decrypted_key = locator
            .unlock(&recipient_sk)
            .expect("Recipient failed to decrypt grant");

        assert_eq!(decrypted_key, volley_key);
    }

    #[test]
    fn test_wrong_recipient_cannot_unlock() {
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, _) = generate_identity();
        let (_, attacker_sk) = generate_identity();

        let locator = SealedLocator::new(
            VolleyId::new("v2"),
            &[0xAA; 32],
            sender_did,
            &sender_sk,
            recipient_did,
        )
        .unwrap();

        let result = locator.unlock(&attacker_sk);
        assert!(matches!(result, Err(CryptoError::DecryptionFailure)));
    }

    #[test]
    fn test_tampered_payload_fails() {
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, recipient_sk) = generate_identity();

        let mut locator = SealedLocator::new(
            VolleyId::new("v1"),
            &[0xBB; 32],
            sender_did,
            &sender_sk,
            recipient_did,
        )
        .unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = locator.sealed_key.get_mut(0) {
            *byte ^= 0xFF;
        }

        assert!(matches!(
            locator.unlock(&recipient_sk),
            Err(CryptoError::DecryptionFailure)
        ));
    }

    #[test]
    fn test_display_formatting() {
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, _) = generate_identity();

        let locator = SealedLocator::new(
            VolleyId::new("test-id"),
            &[0u8; 32],
            sender_did,
            &sender_sk,
            recipient_did,
        )
        .unwrap();

        let uri = locator.to_string();
        assert!(uri.starts_with("phx-grant://"));
        assert!(uri.contains("test-id"));
    }
}
