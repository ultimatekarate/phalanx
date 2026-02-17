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

// id types because I kept I was a moron man that kept using strings.

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
    /// Generates a pristine PhalanxIdentity using system entropy.
    ///
    /// This process involves:
    /// 1. Sampling 16 bytes of entropy from the OS RNG.
    /// 2. Generating a BIP39 mnemonic phrase (English) for human-readable backup.
    /// 3. Deriving an Ed25519 private key from the mnemonic seed.
    /// 4. wrapping the key in the versioned `PhalanxIdentity` struct.
    ///
    /// # Returns
    /// * `(PhalanxIdentity, String)` - The identity struct and the BIP39 mnemonic phrase.
    pub fn generate() -> (Self, String) {
        let mut rng = rand::rng();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Failed to create mnemonic");
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");

        let secret_bytes: [u8; 32] = seed[0..32].try_into().expect("Seed invalid");
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        (Self::from_key(signing_key), phrase)
    }

    /// Recovers a PhalanxIdentity from a BIP39 mnemonic phrase.
    ///
    /// This method is deterministic; the same phrase will always yield the same
    /// private key and resulting PeerID.
    ///
    /// # Arguments
    /// * `phrase` - A string containing the space-separated BIP39 mnemonic words.
    ///
    /// # Returns
    /// * `Ok(Self)` - The recovered identity.
    /// * `Err(String)` - If the mnemonic is invalid or the checksum fails.
    pub fn restore(phrase: &str) -> Result<Self, String> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| format!("Invalid mnemonic: {}", e))?;
        let seed = mnemonic.to_seed("");
        let secret_bytes: [u8; 32] = seed[0..32].try_into().expect("Seed invalid");
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        Ok(Self::from_key(signing_key))
    }

    fn from_key(keypair: SigningKey) -> Self {
        let peer_id = libp2p::identity::Keypair::ed25519_from_bytes(keypair.to_bytes())
            .expect("Key conv failed")
            .public()
            .to_peer_id();

        let did_str = peer_id.to_base58();

        PhalanxIdentity {
            version: IDENTITY_VERSION, // Set Version
            did: Did(did_str),
            keypair,
        }
    }

    /// Cryptographically signs a byte slice using the internal Ed25519 private key.
    ///
    /// Used for attaching forensic proof to data shards or network messages.
    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.keypair.sign(msg)
    }

    /// Verifies a signature against a public key.
    ///
    /// This method supports two public key formats for interoperability:
    /// 1. **Raw Ed25519**: 32 bytes.
    /// 2. **Libp2p Protobuf**: 38 bytes (includes the `0x00240801...` multicodec prefix).
    ///
    /// # Returns
    /// * `true` if the signature is valid for the given message and key.
    /// * `false` if the key format is unrecognized or the signature is invalid.
    pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let key_bytes_opt: Option<&[u8]> = if pubkey.len() == 32 {
            Some(pubkey)
        } else if pubkey.len() == 38 && pubkey.starts_with(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]) {
            Some(&pubkey[6..])
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

    /// Converts the internal forensic key into a Libp2p Keypair.
    ///
    /// This transformation allows the networking stack to use the same cryptographic
    /// root for TLS handshakes and peer routing.
    pub fn to_libp2p_keypair(&self) -> libp2p::identity::Keypair {
        let mut bytes = self.keypair.to_bytes();
        libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes).unwrap()
    }

    /// Serializes the identity to disk using Postcard binary encoding.
    ///
    /// # Arguments
    /// * `path` - The file path for the output.
    pub fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let bytes = postcard::to_stdvec(self)
            .map_err(std::io::Error::other)?;
        fs::write(path, bytes)
    }

    /// Loads an identity from disk with automatic version handling.
    ///
    /// # Migration Logic
    /// 1. **Primary**: Attempts to deserialize as a versioned `PhalanxIdentity` struct.
    ///    - Checks `identity.version` against `IDENTITY_VERSION` (currently 1).
    /// 2. **Fallback**: If deserialization fails, checks if the file is exactly 32 bytes.
    ///    - If yes, treats it as a legacy raw key, upgrades it to v1, and **overwrites the file** with the new format.
    ///
    /// # Returns
    /// * `Ok(Self)` - The loaded (and potentially migrated) identity.
    /// * `Err(io::Error)` - If the file is missing, corrupt, or has a version mismatch.
    pub fn load_from_disk<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let bytes = fs::read(&path)?;

        // 1. Try to load as Versioned Struct (New Format)
        if let Ok(identity) = postcard::from_bytes::<PhalanxIdentity>(&bytes) {
            if identity.version != IDENTITY_VERSION {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Identity version mismatch. Expected {}, got {}",
                        IDENTITY_VERSION, identity.version
                    ),
                ));
            }
            return Ok(identity);
        }

        // 2. Fallback: Legacy 32-byte Key Check
        // If "Strictly Enforce" means "No Legacy", comment this block out.
        // But for development continuity, we auto-migrate.
        if bytes.len() == 32 {
            println!(
                "WARNING: Legacy Identity Format Detected. Upgrading to v{}...",
                IDENTITY_VERSION
            );
            let arr: [u8; 32] = bytes.try_into().unwrap();
            let key = SigningKey::from_bytes(&arr);
            let identity = Self::from_key(key);

            // Auto-save the upgraded format back to disk
            identity.save_to_disk(path)?;
            return Ok(identity);
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "Unknown identity format",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation_and_did() {
        let (identity, _) = PhalanxIdentity::generate();
        assert!(!identity.did.0.starts_with("did:key:"));
        assert!(identity.did.0.len() > 40);
        assert_eq!(identity.version, IDENTITY_VERSION);
    }

    #[test]
    fn test_signing_and_verification() {
        let (identity, _) = PhalanxIdentity::generate();
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
        let (original, phrase) = PhalanxIdentity::generate();
        let original_did = original.did.clone();

        let recovered = PhalanxIdentity::restore(&phrase).expect("Failed to restore");

        assert_eq!(original_did, recovered.did);
        assert_eq!(original.keypair.to_bytes(), recovered.keypair.to_bytes());
        assert_eq!(recovered.version, IDENTITY_VERSION);
    }

    #[test]
    fn test_libp2p_key_format_handling() {
        let (identity, _) = PhalanxIdentity::generate();
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
        let (identity, _) = PhalanxIdentity::generate();
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
        let (identity, _) = PhalanxIdentity::generate();
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
