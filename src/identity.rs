use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature, Verifier};
// Re-exported traits ensure ed25519-dalek is happy with the RNG version
use dalek_rand::{OsRng}; 
use serde::{Serialize, Deserialize};
use std::{fs, fmt};
use std::path::Path;
use bs58;
use libp2p::PeerId;


/// Represents a Decentralized User Identity (Application Layer)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Identity(pub String);

impl fmt::Display for Identity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct Did(pub String);

impl Did {
    /// Returns true if the inner DID string is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

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

// Allows using .as_ref() for path logic
impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// Represents a Network Node Address (Transport Layer)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId(pub libp2p::PeerId);

impl NetworkId {

    
    /// Generates a cryptographically secure random NetworkId.
    /// Useful for simulations and initializing peer-to-peer identities.
    pub fn random() -> Self {
        Self(PeerId::random())
    }
}

impl Serialize for NetworkId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: serde::Serializer {
        serializer.serialize_str(&self.0.to_base58())
    }
}

impl<'de> Deserialize<'de> for NetworkId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: serde::Deserializer<'de> {
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
#[derive(Serialize, Deserialize, Clone)]
pub struct PhalanxIdentity {
    pub did: Did,             
    pub signing_key: SigningKey,
}

impl PhalanxIdentity {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        // This call requires the CryptoRngCore trait to be in scope
        let signing_key = SigningKey::generate(&mut rng);
        
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        let did = Did(format!("did:key:z{}", bs58::encode(verifying_key.as_bytes()).into_string()));
        
        Self { did, signing_key }
    }

    pub fn load_from_disk<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let bytes = fs::read(path)?;
        let signing_key = SigningKey::from_bytes(bytes.as_slice().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key length")
        })?);
        
        let verifying_key = signing_key.verifying_key();
        let did = Did(format!("did:key:z{}", bs58::encode(verifying_key.as_bytes()).into_string()));

        Ok(Self { did, signing_key })
    }

    pub fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let bytes = self.signing_key.to_bytes();
        fs::write(path, bytes)
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.signing_key.sign(data).to_bytes().to_vec()
    }


    pub fn verify(pubkey_bytes: &[u8], data: &[u8], signature_bytes: &[u8]) -> bool {
        let Ok(public_key) = VerifyingKey::try_from(pubkey_bytes) else {
            return false;
        };

        let Ok(sig) = Signature::from_slice(signature_bytes) else {
            return false;
        };

        public_key.verify(data, &sig).is_ok()
    }

    pub fn to_libp2p_keypair(&self) -> libp2p::identity::Keypair {
        let mut bytes = self.signing_key.to_bytes();
        
        // We use the raw bytes to cross the type boundary safely
        libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes)
            .expect("Critical: Failed to convert valid Dalek key to Libp2p key")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation_and_did() {
        let identity = PhalanxIdentity::generate();
        assert!(identity.did.0.starts_with("did:key:z"));
        // Ed25519 Public keys are 32 bytes; bs58 encoding will be longer
        assert!(identity.did.0.len() > 40);
    }

    #[test]
    fn test_signing_and_verification() {
        let identity = PhalanxIdentity::generate();
        let message = b"evidence_shard_001";
        
        let signature = identity.sign(message);
        let pubkey = identity.signing_key.verifying_key().to_bytes();
        
        assert!(PhalanxIdentity::verify(&pubkey, message, &signature));
    }

    #[test]
    fn test_verification_failure_on_tamper() {
        let identity = PhalanxIdentity::generate();
        let message = b"authentic_data";
        let tampered_message = b"tampered_data";
        
        let signature = identity.sign(message);
        let pubkey = identity.signing_key.verifying_key().to_bytes();
        
        assert!(!PhalanxIdentity::verify(&pubkey, tampered_message, &signature));
    }

    #[test]
    fn test_persistence() {
        let identity = PhalanxIdentity::generate();
        let path = "test_identity.key";
        
        identity.save_to_disk(path).unwrap();
        let loaded = PhalanxIdentity::load_from_disk(path).unwrap();
        
        assert_eq!(identity.did, loaded.did);
        assert_eq!(identity.signing_key.to_bytes(), loaded.signing_key.to_bytes());
        
        let _ = fs::remove_file(path);
    }

    #[test]
    fn test_network_id_serde_roundtrip() {
        use libp2p::PeerId;

        let peer_id = PeerId::random();
        let network_id = NetworkId(peer_id);
        
        let serialized = serde_json::to_string(&network_id).unwrap();
        let deserialized: NetworkId = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(network_id, deserialized);
        assert_eq!(peer_id, deserialized.0);
    }
}