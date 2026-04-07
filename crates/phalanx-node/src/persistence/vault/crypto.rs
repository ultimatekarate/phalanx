// crates/phalanx-node/src/persistence/vault/crypto.rs
//
// Vault cryptography utilities: key derivation, encrypted file I/O.

use phalanx_forensics::cryptography::{decrypt_bytes, encrypt_bytes};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::storage::GuardianError;
use std::path::Path;
use tokio::fs;
use zeroize::Zeroizing;

/// XChaCha20-Poly1305 nonce length (24 bytes).
pub(crate) const AEAD_NONCE_LEN: usize = 24;

/// M7 FIX: Vault key derivation now includes a random 32-byte salt.
/// This ensures that identity key compromise does not directly yield the vault key.
/// The salt is stored unencrypted in a `.vault_salt` file next to the vault directory.
#[allow(clippy::arithmetic_side_effects)] // Buffer capacity arithmetic — sum of known-size fields.
pub fn derive_vault_key(identity: &PhalanxIdentity, salt: &[u8; 32]) -> SymmetricKey {
    let key_bytes = Zeroizing::new(identity.keypair.to_bytes());
    // Concatenate domain separator with salt for the BLAKE3 derivation context
    let mut context_input = Vec::with_capacity(key_bytes.len() + salt.len());
    context_input.extend_from_slice(&*key_bytes);
    context_input.extend_from_slice(salt);
    SymmetricKey::from_bytes(blake3::derive_key(
        "phalanx.vault.v1.disk-encryption",
        &context_input,
    ))
}

/// Load or create the vault salt file. Generated once with OsRng on first vault creation.
pub fn load_or_create_vault_salt(vault_path: &str) -> std::io::Result<[u8; 32]> {
    let salt_path = std::path::Path::new(vault_path).join(".vault_salt");
    if salt_path.exists() {
        let bytes = std::fs::read(&salt_path)?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Vault salt file is not 32 bytes",
            ));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(salt)
    } else {
        use rand_core::{OsRng, RngCore};
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        // Ensure parent directory exists
        if let Some(parent) = salt_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&salt_path, salt)?;
        Ok(salt)
    }
}

/// Encrypt and atomically write to disk (write .tmp → rename to final path).
#[allow(clippy::arithmetic_side_effects)] // Buffer capacity — sum of nonce and ciphertext lengths.
pub(crate) async fn atomic_encrypted_write(
    path: &Path,
    plaintext: &[u8],
    key: &SymmetricKey,
) -> Result<(), GuardianError> {
    let (nonce, ciphertext) = encrypt_bytes(key, plaintext)
        .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

    // On-disk format: [24-byte nonce][ciphertext + poly1305 tag]
    let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &sealed)
        .await
        .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;

    fs::rename(&tmp_path, path)
        .await
        .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))
}

/// Read and decrypt a file written by `atomic_encrypted_write`.
pub async fn read_encrypted_file(
    path: &Path,
    key: &SymmetricKey,
) -> Result<Vec<u8>, GuardianError> {
    let sealed = fs::read(path)
        .await
        .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

    if sealed.len() < AEAD_NONCE_LEN {
        return Err(GuardianError::StorageFailure(
            "File too small for AEAD frame".to_string(),
        ));
    }

    let (nonce, ciphertext) = sealed.split_at(AEAD_NONCE_LEN);
    decrypt_bytes(key, nonce, ciphertext)
        .map_err(|_| GuardianError::StorageFailure("AEAD authentication failed".to_string()))
}
