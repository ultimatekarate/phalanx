use crate::primitives::identity::Did;
use crate::primitives::shards::VolleyId;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// --- Crypto Imports ---
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};

// Low-level curve math for key conversion
use curve25519_dalek::edwards::CompressedEdwardsY;

// ==========================================
// 1. CRYPTO BRIDGE: Ed25519 <-> X25519
// ==========================================

/// Converts an Ed25519 Public Key (Signing) to X25519 (Encryption).
/// This allows us to send encrypted messages to a DID without needing a separate encryption key.
fn ed_to_x25519_pk(ed_bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    // 1. Decompress the Ed25519 point (Y-coordinate + sign bit)
    let ed_point = CompressedEdwardsY::from_slice(ed_bytes)
        .map_err(|_| CryptoError::IdentityResolutionError)?;

    // 2. Convert to Montgomery form (Birational equivalence)
    // This allows us to use the same key for Diffie-Hellman
    let mont_point = ed_point
        .decompress()
        .ok_or(CryptoError::IdentityResolutionError)?
        .to_montgomery();

    Ok(mont_point.to_bytes())
}

/// Converts an Ed25519 Secret Key to X25519.
/// Warning: This is a one-way street for the session.
fn ed_to_x25519_sk(ed_bytes: &[u8]) -> x25519_dalek::StaticSecret {
    // We must hash the Ed25519 key to get a valid X25519 scalar (clamped)
    // Standard Ed25519 logic uses SHA-512
    use sha2::{Digest, Sha512};
    let mut hasher = Sha512::new();
    hasher.update(ed_bytes);
    let h = hasher.finalize();

    let mut x25519_bytes = [0u8; 32];
    x25519_bytes.copy_from_slice(&h[0..32]);
    x25519_dalek::StaticSecret::from(x25519_bytes)
}

// ==========================================
// 2. SEALED LOCATOR (The Grant)
// ==========================================

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
        let sender_x25519 = ed_to_x25519_sk(sender_sk_bytes);

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
        let my_x25519 = ed_to_x25519_sk(my_sk_bytes);

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

// ==========================================
// 3. HELPERS: DID Parsing
// ==========================================

fn resolve_did_public_key(did: &Did) -> Result<[u8; 32], CryptoError> {
    // Assumes Did implements AsRef<str> or Deref<Target=str> via the newtype
    // Format: did:key:z6MkhaXgBZD...
    let s = did.0.as_str();
    if !s.starts_with("did:key:") {
        return Err(CryptoError::IdentityResolutionError);
    }

    let multibase_str = &s["did:key:".len()..];

    // Assume z-base58 (standard for did:key)
    if !multibase_str.starts_with('z') {
        return Err(CryptoError::IdentityResolutionError);
    }

    let bytes = bs58::decode(&multibase_str[1..])
        .into_vec()
        .map_err(|_| CryptoError::IdentityResolutionError)?;

    // multicodec prefix for ed25519-pub is 0xed01 (2 bytes)
    // We strip that to get the raw 32-byte key
    if bytes.len() == 34 && bytes[0] == 0xed && bytes[1] == 0x01 {
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes[2..]);
        Ok(key)
    } else {
        Err(CryptoError::IdentityResolutionError)
    }
}

// ==========================================
// 4. ERRORS & FORMATTING
// ==========================================

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
    use crate::primitives::identity::PhalanxIdentity;

    // --- TEST HELPER: Generate Identity ---
    // Generates a random Ed25519 keypair and the corresponding correct did:key string.
    // Logic matches 'resolve_did_public_key' expectations: did:key:z + base58(0xed01 + pubkey)
    fn generate_identity() -> (Did, [u8; 32]) {
        // 1. Generate core identity using the system standard
        let (identity, _) = PhalanxIdentity::generate();
        let secret_bytes = identity.keypair.to_bytes();
        let pub_bytes = identity.keypair.verifying_key().to_bytes();

        // 2. Format as did:key (z-base58 multibase with 0xed01 prefix)
        // This bridges the gap between PhalanxIdentity's internal PeerID format
        // and the did:key format required by resolve_did_public_key.
        let mut prefix = vec![0xed, 0x01];
        prefix.extend_from_slice(&pub_bytes);
        let multibase = bs58::encode(prefix).into_string();
        let did_string = format!("did:key:z{}", multibase);

        (Did(did_string), secret_bytes)
    }

    #[test]
    fn test_grant_lifecycle_success() {
        // 1. Setup Identities
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, recipient_sk) = generate_identity();

        // 2. The Secret Evidence Key
        let volley_key = [0x42u8; 32];
        let volley_id = VolleyId::new("volley-test-001");

        // 3. Sender Creates Grant
        let locator = SealedLocator::new(
            volley_id.clone(),
            &volley_key,
            sender_did.clone(),
            &sender_sk,
            recipient_did.clone(),
        )
        .expect("Failed to create sealed locator");

        // 4. Verify Structure
        assert_eq!(locator.sender, sender_did);
        assert_eq!(locator.recipient, recipient_did);
        assert!(!locator.sealed_key.is_empty());
        assert_eq!(locator.nonce.len(), 24); // XChaCha20 uses 24-byte nonce

        // 5. Recipient Unlocks Grant
        let decrypted_key = locator
            .unlock(&recipient_sk)
            .expect("Recipient failed to decrypt grant");

        assert_eq!(
            decrypted_key, volley_key,
            "Decrypted key must match original secret"
        );
    }

    #[test]
    fn test_wrong_recipient_cannot_unlock() {
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, _recipient_sk) = generate_identity();
        let (_attacker_did, attacker_sk) = generate_identity();

        let volley_key = [0xAAu8; 32];
        let volley_id = VolleyId::new("volley-secret-002");

        // Sender grants access to Recipient
        let locator = SealedLocator::new(
            volley_id,
            &volley_key,
            sender_did,
            &sender_sk,
            recipient_did,
        )
        .unwrap();

        // Attacker (Wrong Private Key) tries to unlock
        let result = locator.unlock(&attacker_sk);

        // Should fail because Shared Secret (ECDH) will be different
        assert!(
            matches!(result, Err(CryptoError::DecryptionFailure)),
            "Attacker should not be able to decrypt payload"
        );
    }

    #[test]
    fn test_tampered_payload_fails() {
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, recipient_sk) = generate_identity();
        let volley_key = [0xBBu8; 32];

        let mut locator = SealedLocator::new(
            VolleyId::new("v1"),
            &volley_key,
            sender_did,
            &sender_sk,
            recipient_did,
        )
        .unwrap();

        // TAMPER: Flip a bit in the ciphertext
        if let Some(byte) = locator.sealed_key.get_mut(0) {
            *byte ^= 0xFF;
        }

        let result = locator.unlock(&recipient_sk);

        // Poly1305 MAC check should fail
        assert!(matches!(result, Err(CryptoError::DecryptionFailure)));
    }

    #[test]
    fn test_sender_spoofing_fails() {
        let (real_sender_did, real_sender_sk) = generate_identity();
        let (fake_sender_did, _fake_sk) = generate_identity();
        let (recipient_did, recipient_sk) = generate_identity();
        let volley_key = [0xCCu8; 32];

        // Real sender creates the grant
        let mut locator = SealedLocator::new(
            VolleyId::new("v1"),
            &volley_key,
            real_sender_did,
            &real_sender_sk,
            recipient_did,
        )
        .unwrap();

        // ATTACK: Man-in-the-Middle changes the 'sender' field to someone else
        // (Trying to frame 'fake_sender' or trick recipient)
        locator.sender = fake_sender_did;

        // Recipient tries to unlock using the Fake Sender's Public Key (derived from DID)
        // This causes the ECDH shared secret derivation to mismatch the one used for encryption
        let result = locator.unlock(&recipient_sk);

        assert!(matches!(result, Err(CryptoError::DecryptionFailure)));
    }

    #[test]
    fn test_display_formatting() {
        let (sender_did, sender_sk) = generate_identity();
        let (recipient_did, _) = generate_identity();
        let volley_key = [0u8; 32];

        let locator = SealedLocator::new(
            VolleyId::new("test-id"),
            &volley_key,
            sender_did,
            &sender_sk,
            recipient_did,
        )
        .unwrap();

        let uri = locator.to_string();

        assert!(uri.starts_with("phx-grant://"));
        assert!(uri.contains("test-id"));
        assert!(uri.contains("?n=")); // Nonce param
        assert!(uri.contains("&p=")); // Payload param
    }
}
