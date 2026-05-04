// crates/phalanx-forensics/src/cryptography/identity.rs
//
// Shared identity persistence: seal and unseal PhalanxIdentity for disk storage.
//
// Laboratory layer — pure crypto verbs. No IO, no file system.
// Callers (phalanx-node, phalanx-stronghold) handle the actual read/write.

use argon2::{Algorithm, Argon2, Params, Version};
use phalanx_proto::crypto::{CryptoError, SymmetricKey};
use phalanx_proto::error::IdentityError;
use phalanx_proto::identity::{IdentityDiskFormat, PhalanxIdentity};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use super::{decrypt_bytes, encrypt_bytes};

/// Pinned Argon2id parameters — shared between node and Stronghold.
///
/// m=19 MiB, t=2 iterations, p=1 lane, 32-byte output.
/// Mobile-appropriate. Compile-time constants prevent silent changes
/// on dependency updates from making existing identity files unreadable.
///
/// At these parameters, a GPU attacker can test ~thousands of passphrases/sec.
/// This protects local disk against casual access, not targeted seizure with
/// a weak PIN. The identity file assumes a high-entropy passphrase (6+ random
/// words or equivalent). If the mobile UX enforces a short PIN, the real
/// protection is device-level encryption (iOS/Android FDE), not this layer.
pub fn identity_argon2() -> Argon2<'static> {
    // These are compile-time-known constants; Params::new cannot fail for these values.
    #[allow(clippy::expect_used)]
    let params = Params::new(19 * 1024, 2, 1, Some(32)).expect("hardcoded Argon2 params are valid");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Encrypt a PhalanxIdentity into bytes ready for disk persistence.
///
/// Returns: `[16-byte salt][24-byte nonce][ciphertext]`
///
/// Pure crypto — caller handles file IO.
#[allow(clippy::arithmetic_side_effects)] // Buffer capacity arithmetic — sum of known constant-size fields.
pub fn seal_identity(identity: &PhalanxIdentity, passphrase: &str) -> Result<Vec<u8>, CryptoError> {
    // Serialize via IdentityDiskFormat — the only authorized serialization path for keypairs.
    let disk_format = IdentityDiskFormat::from_identity(identity);
    let plaintext =
        postcard::to_allocvec(&disk_format).map_err(|_| CryptoError::EncryptionFailure)?;

    // Generate fresh 16-byte salt for Argon2.
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);

    // Derive 32-byte encryption key from passphrase + salt.
    let argon2 = identity_argon2();
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), &salt, &mut key_bytes)
        .map_err(|_| CryptoError::EncryptionFailure)?;
    let key = SymmetricKey::from_bytes(key_bytes);

    // Encrypt. encrypt_bytes returns (nonce_vec, ciphertext_vec).
    let (nonce, ciphertext) =
        encrypt_bytes(&key, &plaintext).map_err(|_| CryptoError::EncryptionFailure)?;

    // Defense-in-depth: wipes the stack copy of the key bytes. The
    // SymmetricKey wrapper wipes its own copy via ZeroizeOnDrop. Both
    // are intentional — two copies exist briefly on the stack.
    key_bytes.zeroize();

    // Assemble: [salt][nonce][ciphertext]
    let mut file_bytes = Vec::with_capacity(salt.len() + nonce.len() + ciphertext.len());
    file_bytes.extend_from_slice(&salt);
    file_bytes.extend_from_slice(&nonce);
    file_bytes.extend_from_slice(&ciphertext);

    Ok(file_bytes)
}

/// Decrypt bytes from disk back into a PhalanxIdentity.
///
/// Expects: `[16-byte salt][24-byte nonce][ciphertext]`
///
/// Pure crypto — caller handles file IO.
///
/// Returns `IdentityError::CryptoError` on decryption failure (wrong
/// passphrase, corrupt file). Returns `IdentityError::SchemaUpgradeRequired`
/// when the file decrypts cleanly but predates the v2 schema; the caller
/// should prompt for a BIP39 phrase re-restore. Returns
/// `IdentityError::UnknownVersion` for forward-incompatible files.
pub fn unseal_identity(
    file_bytes: &[u8],
    passphrase: &str,
) -> Result<PhalanxIdentity, IdentityError> {
    // Minimum: 16 (salt) + 24 (nonce) + at least 1 byte ciphertext.
    if file_bytes.len() < 41 {
        return Err(IdentityError::CryptoError(
            "Identity file too short to contain salt + nonce + ciphertext".into(),
        ));
    }

    let (salt, rest) = file_bytes.split_at(16);
    let (nonce, ciphertext) = rest.split_at(24);

    // Re-derive the encryption key.
    let argon2 = identity_argon2();
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key_bytes)
        .map_err(|e| IdentityError::CryptoError(format!("Argon2 derive failed: {e}")))?;
    let key = SymmetricKey::from_bytes(key_bytes);

    // Decrypt. AEAD tag validation catches wrong passphrases and corrupt files.
    let plaintext = decrypt_bytes(&key, nonce, ciphertext)
        .map_err(|e: CryptoError| IdentityError::CryptoError(e.to_string()))?;

    // Defense-in-depth: wipes the stack copy of the key bytes. The
    // SymmetricKey wrapper wipes its own copy via ZeroizeOnDrop. Both
    // are intentional — two copies exist briefly on the stack.
    key_bytes.zeroize();

    // Deserialize.
    let disk_format: IdentityDiskFormat = postcard::from_bytes(&plaintext)
        .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

    // Typed schema-version errors flow through.
    disk_format.into_identity()
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_round_trip() {
        let identity = PhalanxIdentity::new_ephemeral();
        let sealed = seal_identity(&identity, "test-passphrase").unwrap();
        let restored = unseal_identity(&sealed, "test-passphrase").unwrap();

        assert_eq!(identity.did, restored.did);
        assert_eq!(identity.witness_id, restored.witness_id);
        assert_eq!(identity.version, restored.version);
        assert_eq!(identity.keypair.to_bytes(), restored.keypair.to_bytes());
    }

    #[test]
    fn wrong_passphrase_fails() {
        let identity = PhalanxIdentity::new_ephemeral();
        let sealed = seal_identity(&identity, "correct").unwrap();
        assert!(unseal_identity(&sealed, "wrong").is_err());
    }

    #[test]
    fn truncated_file_fails() {
        assert!(unseal_identity(&[0u8; 10], "passphrase").is_err());
    }

    #[test]
    fn empty_file_fails() {
        assert!(unseal_identity(&[], "passphrase").is_err());
    }

    #[test]
    fn deterministic_identity_preserved() {
        // Verify that DID and WitnessId survive the round trip exactly.
        let identity = PhalanxIdentity::new_ephemeral();
        let original_did = identity.did.clone();
        let original_witness_id = identity.witness_id.clone();

        let sealed = seal_identity(&identity, "p").unwrap();
        let restored = unseal_identity(&sealed, "p").unwrap();

        assert_eq!(restored.did, original_did);
        assert_eq!(restored.witness_id, original_witness_id);
    }
}
