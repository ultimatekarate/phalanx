use bip39::Mnemonic;
use ed25519_dalek::SigningKey;

use phalanx_proto::identity::PhalanxLocator;
use phalanx_proto::prelude::Did;
use phalanx_proto::prelude::IdentityError;
use phalanx_proto::prelude::NetworkId;
use phalanx_proto::prelude::PhalanxIdentity;
use phalanx_proto::VolleyRequest;
use rand::Rng;
use std::fs;
use std::path::Path;
pub const IDENTITY_VERSION: u32 = 1;

pub trait PhalanxNodeIdentityExt: Sized {
    fn generate() -> Result<(Self, String), IdentityError>;
    fn restore(phrase: &str) -> Result<Self, IdentityError>;
    fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError>;
    fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError>;
    fn verify_retrieval_auth(&self, request: &VolleyRequest) -> Result<(), IdentityError>;
    fn init<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError>;
}

impl PhalanxNodeIdentityExt for PhalanxIdentity {
    fn generate() -> Result<(Self, String), IdentityError> {
        let mut rng = rand::rng();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e: bip39::Error| IdentityError::EntropyError(e.to_string()))?;
        let phrase = mnemonic.to_string();
        let seed = mnemonic.to_seed("");

        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        Ok((
            PhalanxIdentity {
                network_id: NetworkId::random(),
                version: IDENTITY_VERSION,
                did: Did::derive_did_key(&public_key_bytes),
                keypair: signing_key,
            },
            phrase,
        ))
    }

    fn restore(phrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse(phrase)
            .map_err(|e: bip39::Error| IdentityError::MnemonicError(e.to_string()))?;
        let seed = mnemonic.to_seed("");
        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        Ok(PhalanxIdentity {
            network_id: NetworkId::random(),
            version: IDENTITY_VERSION,
            did: Did::derive_did_key(&public_key_bytes),
            keypair: signing_key,
        })
    }

    fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let bytes = postcard::to_allocvec(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;
        fs::write(path, bytes).map_err(|e| IdentityError::Corruption(e.to_string()))
    }

    fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let bytes = fs::read(path).map_err(|e| IdentityError::Corruption(e.to_string()))?;
        postcard::from_bytes(&bytes).map_err(|e| IdentityError::SerializationError(e.to_string()))
    }

    fn verify_retrieval_auth(&self, request: &VolleyRequest) -> Result<(), IdentityError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // 1. Resolve the public key of the claimed recipient (the requester)
        let pk_bytes =
            phalanx_forensics::identity::resolve_did_public_key(&request.locator.recipient)
                .map_err(|_| IdentityError::CryptoError("DID Resolution Failed".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Public Key: {}", e)))?;

        // 2. Reconstruct the signed message payload
        let signed_data = (&request.target_did, &request.volley_id, &request.locator);
        let msg = postcard::to_allocvec(&signed_data)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // 3. Verify the signature
        let signature = Signature::from_slice(&request.signature)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Signature: {}", e)))?;

        verifying_key
            .verify(&msg, &signature)
            .map_err(|_| IdentityError::CryptoError("Signature Verification Failed".into()))
    }

    fn init<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        // FIX: Replaced IoError match with an explicit path check
        if !path.as_ref().exists() {
            tracing::warn!("Sovereign root: NOT FOUND. Initiating Genesis...");

            let (new_identity, mnemonic) = Self::generate()?;
            tracing::info!("!!! GENESIS SUCCESSFUL !!!");
            tracing::info!("RESTORE PHRASE: {}", mnemonic);

            new_identity.save_to_disk(&path)?;
            return Ok(new_identity);
        }

        match Self::load_from_disk(&path) {
            Ok(identity) => {
                tracing::info!(path = ?path.as_ref(), "Sovereign root: RESTORED");
                Ok(identity)
            }
            Err(err) => {
                tracing::error!(error = %err, "Sovereign root: CORRUPTED or UNREADABLE");
                Err(err)
            }
        }
    }
}

pub trait PhalanxLocatorExt {
    fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError>;
    fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError>
    where
        Self: Sized;
}

impl PhalanxLocatorExt for PhalanxLocator {
    fn save_to_disk<P: AsRef<Path>>(&self, path: P) -> Result<(), IdentityError> {
        let bytes = postcard::to_allocvec(self)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;
        fs::write(path, bytes).map_err(|e| IdentityError::Corruption(e.to_string()))
    }

    fn load_from_disk<P: AsRef<Path>>(path: P) -> Result<Self, IdentityError> {
        let bytes = fs::read(path).map_err(|e| IdentityError::Corruption(e.to_string()))?;
        postcard::from_bytes(&bytes).map_err(|e| IdentityError::SerializationError(e.to_string()))
    }
}
