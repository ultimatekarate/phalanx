use bip39::Mnemonic;
use ed25519_dalek::SigningKey;

use anyhow::Result;
use argon2::{self, Argon2};
use phalanx_forensics::cryptography::{decrypt_bytes, encrypt_bytes};
use phalanx_proto::crypto::SymmetricKey;
use rand_core::OsRng;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

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

/// M6 FIX: Private struct used exclusively for encrypted disk persistence.
/// This is the only path through which private keypair bytes are serialized,
/// and it is always encrypted with Argon2-derived AEAD before touching disk.
#[derive(Serialize, Deserialize)]
struct IdentityDiskFormat {
    version: u32,
    did: Did,
    network_id: NetworkId,
    keypair_bytes: [u8; 32],
}

impl IdentityDiskFormat {
    fn from_identity(identity: &PhalanxIdentity) -> Self {
        Self {
            version: identity.version,
            did: identity.did.clone(),
            network_id: identity.network_id.clone(),
            keypair_bytes: identity.keypair.to_bytes(),
        }
    }

    fn into_identity(self) -> PhalanxIdentity {
        PhalanxIdentity {
            version: self.version,
            did: self.did,
            network_id: self.network_id,
            keypair: SigningKey::from_bytes(&self.keypair_bytes),
        }
    }
}

pub trait PhalanxNodeIdentityExt: Sized {
    fn generate() -> Result<(Self, String), IdentityError>;
    fn restore(phrase: &str) -> Result<Self, IdentityError>;
    fn save_to_disk<P: AsRef<Path>>(&self, path: P, passphrase: &str) -> Result<(), IdentityError>;
    fn load_from_disk<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, IdentityError>;
    fn verify_retrieval_auth(&self, request: &VolleyRequest) -> Result<(), IdentityError>;
    fn init<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, IdentityError>;
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

    /// Saves the identity to disk, encrypted with a passphrase.
    ///
    /// The on-disk format is:
    /// - 16-byte Argon2 salt
    /// - 24-byte AEAD nonce (for a cipher like XChaCha20-Poly1305)
    /// - Encrypted postcard-serialized identity data
    fn save_to_disk<P: AsRef<Path>>(&self, path: P, passphrase: &str) -> Result<(), IdentityError> {
        // M6 FIX: Serialize via IdentityDiskFormat, not PhalanxIdentity directly.
        let disk_format = IdentityDiskFormat::from_identity(self);
        let plaintext = postcard::to_allocvec(&disk_format)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // Generate a random 16-byte salt for Argon2.
        // A new salt is generated for each save to prevent rainbow table attacks.
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);

        // Derive a 32-byte encryption key from the passphrase and salt using Argon2.
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| {
                IdentityError::CryptoError(format!("Argon2 key derivation failed: {}", e))
            })?;
        let key = SymmetricKey(key_bytes);

        // Generate a random 24-byte nonce for the AEAD cipher.
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);

        // Encrypt the serialized data using the derived key and nonce.
        // This assumes `encrypt_bytes` is an AEAD function like XChaCha20-Poly1305.
        let ciphertext_wrapper = encrypt_bytes(&key, &plaintext)
            .map_err(|e| IdentityError::CryptoError(format!("Encryption failed: {}", e)))?;

        // Assemble the final file content: [salt][nonce][ciphertext]
        let mut file_bytes =
            Vec::with_capacity(salt.len() + nonce.len() + ciphertext_wrapper.0.len());
        file_bytes.extend_from_slice(&salt);
        file_bytes.extend_from_slice(&nonce);
        file_bytes.extend_from_slice(&ciphertext_wrapper.0);

        // Write the encrypted bundle to disk.
        fs::write(path.as_ref(), file_bytes).map_err(|e| {
            IdentityError::Corruption(format!(
                "Failed to write encrypted identity to {:?}: {}",
                path.as_ref(),
                e
            ))
        })?;

        // Securely erase the derived key from memory.
        key_bytes.zeroize();

        Ok(())
    }

    /// Loads an identity from an encrypted file on disk using a passphrase.
    fn load_from_disk<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, IdentityError> {
        // Read the entire encrypted file.
        let file_bytes = fs::read(path.as_ref()).map_err(|e| {
            IdentityError::Corruption(format!(
                "Failed to read encrypted identity from {:?}: {}",
                path.as_ref(),
                e
            ))
        })?;

        // Deconstruct the file content: [salt][nonce][ciphertext]
        if file_bytes.len() < (16 + 24) {
            return Err(IdentityError::Corruption(
                "Invalid or corrupt identity file: too short".to_string(),
            ));
        }
        let (salt_slice, rest) = file_bytes.split_at(16);
        let (nonce_slice, ciphertext) = rest.split_at(24);

        let salt: [u8; 16] = salt_slice.try_into().unwrap(); // Should not fail
        let nonce: [u8; 24] = nonce_slice.try_into().unwrap(); // Should not fail

        // Re-derive the same encryption key using the passphrase and the extracted salt.
        let argon2 = Argon2::default();
        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)
            .map_err(|e| {
                IdentityError::CryptoError(format!("Argon2 key derivation failed: {}", e))
            })?;
        let key = SymmetricKey(key_bytes);

        // Decrypt the ciphertext. If the passphrase is wrong or the file is corrupt,
        // the AEAD authentication tag will not match, and this will fail.
        let plaintext = decrypt_bytes(&key, &nonce, ciphertext).map_err(|_| {
            IdentityError::CryptoError(
                "Failed to decrypt identity. Incorrect passphrase or corrupt file.".to_string(),
            )
        })?;

        // M6 FIX: Deserialize via IdentityDiskFormat, not PhalanxIdentity directly.
        let disk_format: IdentityDiskFormat = postcard::from_bytes(&plaintext).map_err(|e| {
            IdentityError::SerializationError(format!(
                "Failed to deserialize decrypted identity. File may be corrupt: {}",
                e
            ))
        })?;

        // Securely erase the derived key from memory.
        key_bytes.zeroize();

        Ok(disk_format.into_identity())
    }

    fn verify_retrieval_auth(&self, request: &VolleyRequest) -> Result<(), IdentityError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Resolve the public key of the claimed recipient (the requester)
        let pk_bytes =
            phalanx_forensics::identity::resolve_did_public_key(&request.locator.recipient)
                .map_err(|_| IdentityError::CryptoError("DID Resolution Failed".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Public Key: {}", e)))?;

        // Reconstruct the signed message payload
        let signed_data = (&request.target_did, &request.volley_id, &request.locator);
        let msg = postcard::to_allocvec(&signed_data)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // Verify the signature
        let signature = Signature::from_slice(&request.signature)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Signature: {}", e)))?;

        verifying_key
            .verify(&msg, &signature)
            .map_err(|_| IdentityError::CryptoError("Signature Verification Failed".into()))
    }

    fn init<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, IdentityError> {
        // FIX: Replaced IoError match with an explicit path check
        if !path.as_ref().exists() {
            tracing::warn!("Sovereign root: NOT FOUND. Initiating Genesis...");

            let (new_identity, mnemonic) = Self::generate()?;
            tracing::info!("!!! GENESIS SUCCESSFUL !!!");
            tracing::info!("RESTORE PHRASE: {}", mnemonic);

            new_identity.save_to_disk(&path, passphrase)?;
            return Ok(new_identity);
        }

        match Self::load_from_disk(&path, passphrase) {
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
