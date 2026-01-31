use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Signature};
use serde::{Serialize, Deserialize};
use std::fs;
use std::path::Path;

#[derive(Serialize, Deserialize, Clone)]
pub struct PhalanxIdentity {
    pub did: String,             // e.g., "did:phlx:z6Mkq..."
    pub signing_key: Vec<u8>,    // Secret key bytes
}

impl PhalanxIdentity {
    /// Create a new identity and save it to a local file
    pub fn generate<P: AsRef<Path>>(save_path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng);
        let verifying_key: VerifyingKey = (&signing_key).into();
        
        // Use the public key bytes to create a deterministic DID
        let did = format!("did:phlx:{}", hex::encode(verifying_key.as_bytes()));
        
        let identity = Self {
            did,
            signing_key: signing_key.to_bytes().to_vec(),
        };

        let encoded = postcard::to_stdvec(&identity)?;
        fs::write(save_path, encoded)?;
        
        Ok(identity)
    }

    /// Load an existing identity from disk
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let bytes = fs::read(path)?;
        let identity: PhalanxIdentity = postcard::from_bytes(&bytes)?;
        Ok(identity)
    }

    /// Sign a data buffer (e.g., a VideoShard)
    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        let key = SigningKey::from_bytes(
            &self.signing_key.clone().try_into().expect("Invalid key length")
        );
        let signature = key.sign(data);
        signature.to_bytes().to_vec()
    }
}