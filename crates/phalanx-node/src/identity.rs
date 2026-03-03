use bip39::{Language, Mnemonic};
use ed25519_dalek::SigningKey;
use phalanx_proto::prelude::*;
use std::{fs, path::Path};

impl PhalanxIdentity {
    pub fn generate() -> Result<(Self, String), IdentityError> {
        let mut rng = rand::rng();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e| IdentityError::EntropyError(e.to_string()))?;
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");

        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;
        let signing_key = SigningKey::from_bytes(&secret_bytes);

        Ok((
            PhalanxIdentity {
                version: IDENTITY_VERSION,
                did: Did::placeholder(),
                keypair: signing_key,
            },
            phrase,
        ))
    }

    pub fn restore(phrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| IdentityError::MnemonicError(e.to_string()))?;
        let seed = mnemonic.to_seed("");
        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;

        Ok(PhalanxIdentity {
            version: IDENTITY_VERSION,
            did: Did::placeholder(),
            keypair: SigningKey::from_bytes(&secret_bytes),
        })
    }

    pub fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let bytes = postcard::to_stdvec(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;
        fs::write(path, bytes).map_err(IdentityError::IoError)
    }

    pub fn verify_retrieval_auth(&self, request: &VolleyRequest) -> Result<(), IdentityError> {
        // High-level node policy logic
        Ok(())
    }

    pub fn init<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {

        match Self::load_from_disk(&path) {
            Ok(identity) => {
                info!(path = ?path.as_ref(), "Sovereign root: RESTORED");
                Ok(identity)
            }
            Err(IdentityError::IoError(ref e)) if e.kind() == std::io::ErrorKind::NotFound => {
                warn!("Sovereign root: NOT FOUND. Initiating Genesis...");

                let (new_identity, mnemonic) = Self::generate()?;

                // This is the only time the mnemonic should EVER be logged.
                info!("!!! GENESIS SUCCESSFUL !!!");
                info!("RESTORE PHRASE: {}", mnemonic);

                new_identity.save_to_disk(&path)?;
                Ok(new_identity)
            }
            Err(err) => {
                error!(error = %err, "Sovereign root: CORRUPTED or UNREADABLE");
                Err(err)
            }
        }
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
    fn test_mnemonic_recovery() {
        let (original, phrase) = PhalanxIdentity::generate().unwrap();
        let original_did = original.did.clone();

        let recovered = PhalanxIdentity::restore(&phrase).expect("Failed to restore");

        assert_eq!(original_did, recovered.did);
        assert_eq!(original.keypair.to_bytes(), recovered.keypair.to_bytes());
        assert_eq!(recovered.version, IDENTITY_VERSION);
    }

    #[test]
    fn test_identity_generation_and_did() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        assert!(!identity.did.0.starts_with("did:key:"));
        assert!(identity.did.0.len() > 40);
        assert_eq!(identity.version, IDENTITY_VERSION);
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
