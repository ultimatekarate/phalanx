
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, thiserror::Error)]
pub enum CryptoError {
    #[error("Encryption failure")]
    EncryptionFailure,
    #[error("Decryption failure")]
    DecryptionFailure,
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
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

impl SealedLocator {
    /// Creates a new access grant.
    ///
    /// # Arguments
    /// * `volley_id` - The ID of the evidence being shared.
    /// * `volley_key` - The symmetric key (32 bytes) unlocking the video evidence.
    /// * `sender_did` - Your DID.
    /// * `sender_sk_bytes` - Your raw Ed25519 private key bytes (32 bytes).
    /// * `recipient_did` - The Target DID.
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        volley_id: VolleyId,
        volley_key: &[u8; 32],
        sender_did: Did,
        sender_sk_bytes: &[u8; 32],
        recipient_did: Did,
    ) -> Result<Self, CryptoError> {
        // 1. Resolve Recipient's Public Key from DID
        let recipient_ed_pk = resolve_did_public_key(&recipient_did)?;
        let recipient_x25519 = x25519_dalek::PublicKey::from(ed_to_x25519_pk(&recipient_ed_pk)?);

        // 2. Convert Sender's Private Key to X25519
        let sender_x25519 = ed_to_x25519_sk(sender_sk_bytes)?;

        // 3. Derive Shared Secret (ECDH)
        let shared_secret = sender_x25519.diffie_hellman(&recipient_x25519);

        // 4. Encrypt the Volley Key
        // We use XChaCha20Poly1305 for the wrapper encryption
        let cipher = XChaCha20Poly1305::new(shared_secret.as_bytes().into());
        let nonce_bytes = rand::random::<[u8; 24]>(); // 24-byte nonce for XChaCha
        let nonce = XNonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: volley_key,
                    aad: sender_did.as_ref().as_bytes(), // Authenticate sender DID
                },
            )
            .map_err(|_| CryptoError::EncryptionFailure)?;

        Ok(Self {
            target: volley_id,
            recipient: recipient_did,
            sender: sender_did,
            sealed_key: ciphertext,
            nonce: nonce_bytes.to_vec(),
        })
    }

    /// Attempts to unlock the locator using the recipient's private key.
    ///
    /// # Arguments
    /// * `my_sk_bytes` - The raw Ed25519 private key of the recipient.
    pub fn unlock(&self, my_sk_bytes: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
        // 1. Resolve Sender's Public Key from DID (to complete ECDH)
        let sender_ed_pk = resolve_did_public_key(&self.sender)?;
        let sender_x25519_pk = x25519_dalek::PublicKey::from(ed_to_x25519_pk(&sender_ed_pk)?);

        // 2. Convert My Private Key to X25519
        let my_x25519 = ed_to_x25519_sk(my_sk_bytes)?;

        // 3. Re-derive Shared Secret
        let shared_secret = my_x25519.diffie_hellman(&sender_x25519_pk);

        // 4. Decrypt
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

        plaintext
            .try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)
    }
}

impl fmt::Display for SealedLocator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Format: phx-grant://<ID>#<RECIPIENT>@<SENDER>:<NONCE>:<CIPHERTEXT>
        let b64_cipher = URL_SAFE_NO_PAD.encode(&self.sealed_key);
        let b64_nonce = URL_SAFE_NO_PAD.encode(&self.nonce);

        write!(
            f,
            "phx-grant://{}#{}@{}?n={}&p={}",
            self.target, self.recipient, self.sender, b64_nonce, b64_cipher
        )
    }
}

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
    #[error("Encoding error: {0}")]
    EncodingError(String),
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
    // Using Nouns from the Dictionary
    use phalanx_proto::identity::{Did, PhalanxIdentity};
    use phalanx_proto::shards::VolleyId;
    use phalanx_proto::crypto::{SealedLocator, CryptoError};

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
        ).expect("Failed to create sealed locator");

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
        ).unwrap();

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
        ).unwrap();

        // Tamper with the ciphertext
        if let Some(byte) = locator.sealed_key.get_mut(0) {
            *byte ^= 0xFF;
        }

        assert!(matches!(locator.unlock(&recipient_sk), Err(CryptoError::DecryptionFailure)));
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
        ).unwrap();

        let uri = locator.to_string();
        assert!(uri.starts_with("phx-grant://"));
        assert!(uri.contains("test-id"));
    }
}