use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature};
use serde::{Serialize, Deserialize};
use std::{fs, fmt};
use std::path::Path;
use libp2p::PeerId;
use rand::RngCore;
use bip39::{Mnemonic, Language};

// --- DIDs & Network IDs ---

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
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn to_safe_name(&self) -> String {
        self.0.replace(":", "_")
    }
}

impl Default for Did {
    fn default() -> Self {
        Self("anonymous".to_string())
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
pub struct NetworkId(pub libp2p::PeerId);

impl NetworkId {
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

// --- THE IDENTITY ---

#[derive(Serialize, Deserialize, Clone)]
pub struct PhalanxIdentity {
    pub did: Did,             
    pub keypair: SigningKey,
}

impl fmt::Debug for PhalanxIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PhalanxIdentity")
        .field("did", &self.did)
        .field("keypair", &"[REDACTED]")
        .finish()
    }
}

impl PhalanxIdentity {
    pub fn generate() -> (Self, String) {
        let mut rng = rand::rng(); 
        let mut entropy = [0u8; 16]; 
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .expect("Failed to create mnemonic");
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");
        
        let secret_bytes: [u8; 32] = seed[0..32].try_into().expect("Seed invalid");
        let signing_key = SigningKey::from_bytes(&secret_bytes);
        (Self::from_key(signing_key), phrase)
    }

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

        // FIX: Use RAW PeerID string. 'did:key:' prefix confuses libp2p parsers.
        let did_str = peer_id.to_base58();

        PhalanxIdentity {
            did: Did(did_str),
            keypair,
        }
    }

    pub fn sign(&self, msg: &[u8]) -> Signature {
        self.keypair.sign(msg)
    }

    pub fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        // --- SMART EXTRACTION LOGIC ---
        let key_bytes_opt: Option<&[u8]> = if pubkey.len() == 32 {
            // Standard Raw Key
            Some(pubkey)
        } else if pubkey.len() == 38 && pubkey.starts_with(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]) {
            // Libp2p PeerID Wrapper: [Identity(00), Len(24), Ed25519(0801), Bytes(1220)]
            // We strip the first 6 bytes to get the raw 32-byte key
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
        
        // Log failure only if strict debugging is needed, otherwise fail silently for security
        // println!("Sig Verify Failed. PubKey Len: {}", pubkey.len()); 
        false
    }

    pub fn to_libp2p_keypair(&self) -> libp2p::identity::Keypair {
        let mut bytes = self.keypair.to_bytes();
        libp2p::identity::Keypair::ed25519_from_bytes(&mut bytes).unwrap()
    }

    pub fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let bytes = self.keypair.to_bytes();
        fs::write(path, bytes)
    }

    pub fn load_from_disk<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let bytes = fs::read(path)?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "Key file must be 32 bytes"));
        }
        let arr: [u8; 32] = bytes.try_into().unwrap();
        let key = SigningKey::from_bytes(&arr);
        Ok(Self::from_key(key))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation_and_did() {
        let (identity, _) = PhalanxIdentity::generate();
        // FIX: Expect raw PeerID string (starts with 1 for Ed25519 identity multihash)
        assert!(!identity.did.0.starts_with("did:key:"));
        assert!(identity.did.0.len() > 40);
    }

    #[test]
    fn test_signing_and_verification() {
        let (identity, _) = PhalanxIdentity::generate();
        let message = b"evidence_shard_001";
        let signature = identity.sign(message);
        let pubkey = identity.keypair.verifying_key().to_bytes();
        
        assert!(PhalanxIdentity::verify(&pubkey, message, &signature.to_bytes()));
    }

    #[test]
    fn test_mnemonic_recovery() {
        let (original, phrase) = PhalanxIdentity::generate();
        let original_did = original.did.clone();

        let recovered = PhalanxIdentity::restore(&phrase).expect("Failed to restore");

        assert_eq!(original_did, recovered.did);
        assert_eq!(original.keypair.to_bytes(), recovered.keypair.to_bytes());
    }
}