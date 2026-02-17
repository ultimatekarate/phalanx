use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use libp2p::PeerId;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::str::FromStr;
use std::{fmt, fs};

// --- CONSTANTS ---
pub const IDENTITY_VERSION: u32 = 1;

// --- ERROR TYPES ---
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Entropy generation failed: {0}")]
    EntropyError(String),
    #[error("Mnemonic parsing failed: {0}")]
    MnemonicError(String),
    #[error("Cryptographic derivation failed: {0}")]
    CryptoError(String),
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Identity data corruption: {0}")]
    Corruption(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
/// A strong type for Decentralized Identifiers (DIDs).
///
/// Wraps a standard string to ensure semantic distinction from other string types.
/// Defaults to `did:key:anonymous` if not initialized.
pub struct Did(pub String);

impl Did {
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Sanitizes the DID string for use in file paths or unsafe contexts.
    /// Replaces colons `:` with underscores `_`.
    pub fn to_safe_name(&self) -> String {
        self.0.replace(":", "_")
    }
}

impl Default for Did {
    fn default() -> Self {
        Self("did:key:anonymous".to_string())
    }
}

impl std::fmt::Display for Did {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<String> for Did {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl From<&str> for Did {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// A strong type for network routing addresses.
///
/// Wraps `libp2p::PeerId`.
/// Implements `serde` serialization to/from Base58 strings, ensuring
/// that JSON/Postcard representations remain human-readable or standard-compliant.
pub struct NetworkId(pub libp2p::PeerId);

impl NetworkId {
    /// Generates a random NetworkId (wrapping a random PeerId).
    /// I wrote this purely for testing purposes. This stupid thing
    /// has saved me so much trouble.
    pub fn random() -> Self {
        Self(PeerId::random())
    }
}

impl Serialize for NetworkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0.to_base58())
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let peer_id = s.parse().map_err(serde::de::Error::custom)?;
        Ok(NetworkId(peer_id))
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.to_base58())
    }
}

impl From<PeerId> for NetworkId {
    fn from(peer_id: PeerId) -> Self {
        Self(peer_id)
    }
}

impl From<&PeerId> for NetworkId {
    fn from(peer_id: &PeerId) -> Self {
        Self(*peer_id)
    }
}

impl FromStr for NetworkId {
    type Err = libp2p::identity::ParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let peer_id = PeerId::from_str(s)?;
        Ok(Self(peer_id))
    }
}

// Ensure the inner PeerId is accessible if needed
impl AsRef<PeerId> for NetworkId {
    fn as_ref(&self) -> &PeerId {
        &self.0
    }
}

/// The sovereign cryptographic root for a Phalanx Node.
///
/// Constraints: Contains a `SigningKey` used for Ed25519 forensic proofs.
/// When transitioning to the networking layer, this must be transcoded
/// into a `libp2p::identity::Keypair` to ensure the NodeId matches
/// the forensic signature authority.
#[derive(Serialize, Deserialize, Clone)]
pub struct PhalanxIdentity {
    pub version: u32, // <--- Strict Versioning
    pub did: Did,
    pub keypair: SigningKey,
}

impl fmt::Debug for PhalanxIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhalanxIdentity")
            .field("version", &self.version)
            .field("did", &self.did)
            .field("keypair", &"[REDACTED]")
            .finish()
    }
}

impl PhalanxIdentity {
    /// Generates a new identity and its corresponding BIP39 mnemonic.
    ///
    /// # Functional Specification
    /// - Input: None (uses system entropy).
    /// - Output: `Result<(Self, String), IdentityError>`
    /// - Behavior: Propagates RNG or derivation failures to the caller.
    pub fn generate() -> Result<(Self, String), IdentityError> {
        let mut rng = rand::rng();
        let mut entropy = [0u8; 16];
        
        // rng.fill_bytes is infallible in current rand crate versions for OsRng, 
        // but if we ever switch RNGs, we maintain the pattern.
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| IdentityError::EntropyError(e.to_string()))?;
        
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");

        // Safe slice access
        let secret_slice = seed.get(0..32)
            .ok_or_else(|| IdentityError::CryptoError("Seed generation produced insufficient length".into()))?;

        let secret_bytes: [u8; 32] = secret_slice.try_into()
            .map_err(|_| IdentityError::CryptoError("Seed conversion failed".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        
        // Validate Libp2p compatibility immediately
        let mut keypair_bytes = signing_key.to_bytes();
        let peer_id = libp2p::identity::Keypair::ed25519_from_bytes(&mut keypair_bytes)
            .map_err(|e| IdentityError::CryptoError(format!("Libp2p key rejection: {}", e)))?
            .public()
            .to_peer_id();

        let identity = PhalanxIdentity {
            version: IDENTITY_VERSION,
            did: Did(peer_id.to_base58()),
            keypair: signing_key,
        };
        
        Ok((identity, phrase))
    }

    /// Restores an identity from an existing BIP39 mnemonic phrase.
    pub fn restore(phrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| IdentityError::MnemonicError(e.to_string()))?;
        
        let seed = mnemonic.to_seed("");
        
        let secret_slice = seed.get(0..32)
            .ok_or_else(|| IdentityError::CryptoError("Seed generation produced insufficient length".into()))?;
        
        let secret_bytes: [u8; 32] = secret_slice.try_into()
            .map_err(|_| IdentityError::CryptoError("Seed conversion failed".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        
        let mut keypair_bytes = signing_key.to_bytes();
        let peer_id = libp2p::identity::Keypair::ed25519_from_bytes(&mut keypair_bytes)
            .map_err(|e| IdentityError::CryptoError(format!("Key derivation failed: {}", e)))?
            .public()
            .to_peer_id();

        Ok(PhalanxIdentity {
            version: IDENTITY_VERSION,
            did: Did(peer_id.to_base58()),
            keypair: signing_key,
        })
    }

    /// Validates a signature using either raw Ed25519 keys or Libp2p protobuf-encoded keys.
    ///
    /// # Functional Specification
    /// - Returns `false` on any error (encoding, length, or signature mismatch).
    /// - No panics.
    pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let key_bytes_opt: Option<&[u8]> = if pubkey.len() == 32 {
            Some(pubkey)
        } else if pubkey.len() == 38 && pubkey.starts_with(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]) {
            pubkey.get(6..)
        } else {
            None
        };

        if let Some(bytes) = key_bytes_opt {
            if let Ok(key_array) = bytes.try_into() {
                if let Ok(vk) = VerifyingKey::from_bytes(key_array) {
                    if let Ok(signature) = Signature::from_slice(sig) {
                        return vk.verify_strict(msg, &signature).is_ok();
                    }
                }
            }
        }
        false
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.keypair.sign(msg)
    }

    /// Converts the internal Ed25519 key to a Libp2p Keypair.
    pub fn to_libp2p_keypair(&self) -> Result<libp2p::identity::Keypair, IdentityError> {
        let mut bytes = self.keypair.to_bytes();
        libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes)
            .map_err(|e| IdentityError::CryptoError(e.to_string()))
    }

    pub fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let bytes = postcard::to_stdvec(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;
        fs::write(path, bytes).map_err(IdentityError::IoError)
    }

    pub fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let bytes = fs::read(&path).map_err(IdentityError::IoError)?;

        // Modern format
        if let Ok(identity) = postcard::from_bytes::<PhalanxIdentity>(&bytes) {
            if identity.version != IDENTITY_VERSION {
                return Err(IdentityError::Corruption(format!(
                    "Version mismatch: Expected {}, found {}", 
                    IDENTITY_VERSION, identity.version
                )));
            }
            return Ok(identity);
        }

        // Legacy format (raw 32 bytes)
        if bytes.len() == 32 {
            let arr: [u8; 32] = bytes
                .as_slice()
                .try_into()
                .map_err(|_| IdentityError::Corruption("Invalid key length for legacy upgrade".into()))?;
            
            let key = SigningKey::from_bytes(&arr);
            
            let mut keypair_bytes = key.to_bytes();
            let peer_id = libp2p::identity::Keypair::ed25519_from_bytes(&mut keypair_bytes)
                .map_err(|e| IdentityError::CryptoError(e.to_string()))?
                .public()
                .to_peer_id();

            let identity = PhalanxIdentity {
                version: IDENTITY_VERSION,
                did: Did(peer_id.to_base58()),
                keypair: key,
            };

            // Attempt upgrade save, but do not fail load if write fails
            let _ = identity.save_to_disk(&path);
            return Ok(identity);
        }

        Err(IdentityError::Corruption("Unknown identity format".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation_and_did() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        assert!(!identity.did.0.starts_with("did:key:"));
        assert!(identity.did.0.len() > 40);
        assert_eq!(identity.version, IDENTITY_VERSION);
    }

    #[test]
    fn test_signing_and_verification() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let message = b"evidence_shard_001";
        let signature = identity.sign(message);
        let pubkey = identity.keypair.verifying_key().to_bytes();

        assert!(PhalanxIdentity::verify(
            &pubkey,
            message,
            &signature.to_bytes()
        ));
    }

    #[test]
    fn test_mnemonic_recovery() {
        let (original, phrase) = PhalanxIdentity::generate().unwrap();
        let original_did = original.did.clone();

        let recovered = PhalanxIdentity::restore(&phrase).expect("Failed to restore");

        assert_eq!(original_did, recovered.did);
        assert_eq!(original.keypair.to_bytes(), recovered.keypair.to_bytes());
        assert_eq!(recovered.version, IDENTITY_VERSION);
    }

    #[test]
    fn test_libp2p_key_format_handling() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let message = b"compatibility_check";
        let signature = identity.sign(message);
        let raw_key = identity.keypair.verifying_key().to_bytes();
        let mut peer_id_bytes = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        peer_id_bytes.extend_from_slice(&raw_key);

        assert_eq!(peer_id_bytes.len(), 38);
        assert!(PhalanxIdentity::verify(
            &peer_id_bytes,
            message,
            &signature.to_bytes()
        ));
    }

    #[test]
    fn test_persistence_upgrade() {
        // Test that we can save and load the new format
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let path = "test_identity_v1.bin";

        identity.save_to_disk(path).unwrap();
        let loaded = PhalanxIdentity::load_from_disk(path).unwrap();

        assert_eq!(identity.did, loaded.did);
        assert_eq!(loaded.version, IDENTITY_VERSION);

        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_legacy_upgrade() {
        // Manually create a legacy file (raw 32 bytes)
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let path = "test_identity_legacy.bin";
        fs::write(path, identity.keypair.to_bytes()).unwrap();

        // Load it (should trigger upgrade logic)
        let loaded = PhalanxIdentity::load_from_disk(path).unwrap();
        assert_eq!(identity.did, loaded.did);
        assert_eq!(loaded.version, IDENTITY_VERSION);

        // Check that it was rewritten to the new format (size > 32)
        let new_size = fs::metadata(path).unwrap().len();
        assert!(new_size > 32);

        let _ = fs::remove_file(path);
    }
}
