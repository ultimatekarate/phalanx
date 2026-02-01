use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Signature, Verifier};
// Re-exported traits ensure ed25519-dalek is happy with the RNG version
use dalek_rand::{OsRng}; 
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;
use bs58;

#[derive(Serialize, Deserialize, Clone)]
pub struct PhalanxIdentity {
    pub did: String,             
    pub signing_key: SigningKey,
}

impl PhalanxIdentity {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        // This call requires the CryptoRngCore trait to be in scope
        let signing_key = SigningKey::generate(&mut rng);
        
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        let did = format!("did:phlx:{}", hex::encode(verifying_key.as_bytes()));
        
        Self { did, signing_key }
    }

    pub fn load_from_disk<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let bytes = fs::read(path)?;
        let signing_key = SigningKey::from_bytes(bytes.as_slice().try_into().map_err(|_| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid key length")
        })?);
        
        let verifying_key = signing_key.verifying_key();
        let did = format!("did:key:z{}", bs58::encode(verifying_key.as_bytes()).into_string());

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
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_generation_and_did() {
        let identity = PhalanxIdentity::generate();
        assert!(identity.did.starts_with("did:key:z"));
        // Ed25519 Public keys are 32 bytes; bs58 encoding will be longer
        assert!(identity.did.len() > 40);
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
}