use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
// Re-exported traits ensure ed25519-dalek is happy with the RNG version
use dalek_rand::{OsRng}; 
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone)]
pub struct PhalanxIdentity {
    pub did: String,             
    pub signing_key: Vec<u8>,    
}

impl PhalanxIdentity {
    pub fn generate<P: AsRef<Path>>(save_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = OsRng;
        // This call requires the CryptoRngCore trait to be in scope
        let signing_key = SigningKey::generate(&mut rng);
        
        let verifying_key: VerifyingKey = signing_key.verifying_key();
        
        let did = format!("did:phlx:{}", hex::encode(verifying_key.as_bytes()));
        
        let identity = Self {
            did,
            signing_key: signing_key.to_bytes().to_vec(),
        };

        let encoded = postcard::to_stdvec(&identity)?;
        fs::write(save_path, encoded)?;
        
        Ok(identity)
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&self.signing_key[..32]);
        let key = SigningKey::from_bytes(&bytes);
        
        let signature = key.sign(data);
        signature.to_bytes().to_vec()
    }
}