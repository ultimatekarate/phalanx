use bip39::Mnemonic;
use ed25519_dalek::SigningKey;
use phalanx_forensics::cryptography::identity::{seal_identity, unseal_identity};
use phalanx_forensics::derive_dek_master;
use phalanx_proto::identity::PhalanxLocator;
use phalanx_proto::identity::IDENTITY_VERSION;
use phalanx_proto::prelude::{Did, IdentityError, PhalanxIdentity};
use phalanx_proto::revocation::RevocationKey;
use phalanx_proto::RecordingRequest;
use rand::Rng;
use std::fs;
use std::path::Path;
use zeroize::Zeroize;

/// BIP39 passphrase choice, pinned as a versioned constant.
///
/// We currently support only the empty-passphrase ("25th word disabled")
/// branch of BIP39. Pinning it as a constant prevents accidental changes
/// (which would silently fork all derivations — keypair, revocation key,
/// dek_master). A future identity v3 could offer a non-empty passphrase
/// flow under a distinct constant.
pub const BIP39_PASSPHRASE_V1: &str = "";

pub trait PhalanxNodeIdentityExt: Sized {
    fn generate() -> Result<(Self, String), IdentityError>;
    fn restore(phrase: &str) -> Result<Self, IdentityError>;
    fn save_to_disk<P: AsRef<Path>>(&self, path: P, passphrase: &str) -> Result<(), IdentityError>;
    /// All-or-nothing persistence. Writes to `path.tmp`, fsyncs, then
    /// atomically renames to `path`. Used by the restore-from-mnemonic path,
    /// which cannot leave a half-state on disk: an in-memory-only identity
    /// would lock the user out on next launch ("no identity found, please
    /// restore" again — but the previous restore "succeeded"). On Windows,
    /// `std::fs::rename` is implemented via `MoveFileExW` with
    /// `MOVEFILE_REPLACE_EXISTING` and is atomic; on Unix, `rename(2)` is
    /// atomic within a single filesystem.
    fn save_to_disk_atomic<P: AsRef<Path>>(
        &self,
        path: P,
        passphrase: &str,
    ) -> Result<(), IdentityError>;
    fn load_from_disk<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, IdentityError>;
    fn verify_retrieval_auth(&self, request: &RecordingRequest) -> Result<(), IdentityError>;
    fn init<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
    ) -> Result<(Self, Option<String>), IdentityError>;
    /// Derive the revocation signing key from the BIP39 mnemonic.
    /// This is the ONLY way to obtain the private half — it is never stored on disk.
    fn revocation_signing_key(phrase: &str) -> Result<SigningKey, IdentityError>;
}

impl PhalanxNodeIdentityExt for PhalanxIdentity {
    fn generate() -> Result<(Self, String), IdentityError> {
        let mut rng = rand::rng();
        let mut entropy = [0u8; 16];
        rng.fill_bytes(&mut entropy);

        let mnemonic = Mnemonic::from_entropy(&entropy)
            .map_err(|e: bip39::Error| IdentityError::EntropyError(e.to_string()))?;
        let phrase = mnemonic.to_string();
        let mut seed = mnemonic.to_seed(BIP39_PASSPHRASE_V1);

        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        // Derive revocation public key from seed[32..64]
        let revocation_bytes: [u8; 32] = seed[32..64]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Revocation seed fail".into()))?;
        let revocation_signing = SigningKey::from_bytes(&revocation_bytes);
        let revocation_key = RevocationKey(revocation_signing.verifying_key().to_bytes());

        // Derive dek_master from the entire seed via HKDF, domain-separated
        // from the keypair/revocation slice derivations.
        let dek_master = derive_dek_master(&seed);

        let did = Did::derive_did_key(&public_key_bytes);
        let witness_id = did.to_witness_id();

        // Wipe the seed before returning. Defense in depth — the BIP39 seed
        // is the universal recovery secret; nothing downstream should hold
        // it. Local stack copies in `secret_bytes`/`revocation_bytes` go out
        // of scope at function end without zeroize but are short-lived.
        seed.zeroize();

        Ok((
            PhalanxIdentity {
                witness_id,
                version: IDENTITY_VERSION,
                did,
                keypair: signing_key,
                revocation_key,
                dek_master,
            },
            phrase,
        ))
    }

    fn restore(phrase: &str) -> Result<Self, IdentityError> {
        let mnemonic = Mnemonic::parse(phrase)
            .map_err(|e: bip39::Error| IdentityError::MnemonicError(e.to_string()))?;
        let mut seed = mnemonic.to_seed(BIP39_PASSPHRASE_V1);
        let secret_bytes: [u8; 32] = seed[0..32]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Seed fail".into()))?;

        let signing_key = SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = verifying_key.to_bytes();

        // Derive revocation public key from seed[32..64]
        let revocation_bytes: [u8; 32] = seed[32..64]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Revocation seed fail".into()))?;
        let revocation_signing = SigningKey::from_bytes(&revocation_bytes);
        let revocation_key = RevocationKey(revocation_signing.verifying_key().to_bytes());

        // Derive dek_master from the entire seed.
        let dek_master = derive_dek_master(&seed);

        let did = Did::derive_did_key(&public_key_bytes);
        let witness_id = did.to_witness_id();

        seed.zeroize();

        Ok(PhalanxIdentity {
            witness_id,
            version: IDENTITY_VERSION,
            did,
            keypair: signing_key,
            revocation_key,
            dek_master,
        })
    }

    /// Saves the identity to disk, encrypted with a passphrase.
    ///
    /// Delegates to shared `seal_identity()` for crypto (Laboratory),
    /// handles only the file write (Hands).
    fn save_to_disk<P: AsRef<Path>>(&self, path: P, passphrase: &str) -> Result<(), IdentityError> {
        let file_bytes = seal_identity(self, passphrase)
            .map_err(|e| IdentityError::CryptoError(format!("Seal failed: {}", e)))?;

        fs::write(path.as_ref(), file_bytes).map_err(|e| {
            IdentityError::Corruption(format!(
                "Failed to write encrypted identity to {:?}: {}",
                path.as_ref(),
                e
            ))
        })
    }

    fn save_to_disk_atomic<P: AsRef<Path>>(
        &self,
        path: P,
        passphrase: &str,
    ) -> Result<(), IdentityError> {
        let target = path.as_ref();
        let file_bytes = seal_identity(self, passphrase)
            .map_err(|e| IdentityError::CryptoError(format!("Seal failed: {}", e)))?;

        // Sibling tmp path. Same parent directory so the final rename is
        // intra-filesystem (a cross-fs rename would be a copy, not atomic).
        let mut tmp = target.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp_path = std::path::PathBuf::from(tmp);

        // Write + fsync the tmp file. We use a fresh File handle (not
        // fs::write) so we can call sync_all() before close.
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp_path).map_err(|e| {
                IdentityError::Corruption(format!(
                    "Failed to create tmp identity at {:?}: {}",
                    tmp_path, e
                ))
            })?;
            f.write_all(&file_bytes).map_err(|e| {
                IdentityError::Corruption(format!(
                    "Failed to write tmp identity at {:?}: {}",
                    tmp_path, e
                ))
            })?;
            f.sync_all().map_err(|e| {
                IdentityError::Corruption(format!(
                    "Failed to fsync tmp identity at {:?}: {}",
                    tmp_path, e
                ))
            })?;
        }

        // Atomic rename. On Unix, rename(2) is atomic intra-fs. On Windows,
        // std::fs::rename uses MoveFileExW with MOVEFILE_REPLACE_EXISTING,
        // which is atomic for files on the same volume.
        fs::rename(&tmp_path, target).map_err(|e| {
            // Best-effort cleanup; if rename failed the tmp file is stale.
            let _ = fs::remove_file(&tmp_path);
            IdentityError::Corruption(format!(
                "Failed to atomically rename {:?} to {:?}: {}",
                tmp_path, target, e
            ))
        })
    }

    /// Loads an identity from an encrypted file on disk using a passphrase.
    ///
    /// Delegates to shared `unseal_identity()` for crypto (Laboratory),
    /// handles only the file read (Hands).
    fn load_from_disk<P: AsRef<Path>>(path: P, passphrase: &str) -> Result<Self, IdentityError> {
        let file_bytes = fs::read(path.as_ref()).map_err(|e| {
            IdentityError::Corruption(format!(
                "Failed to read encrypted identity from {:?}: {}",
                path.as_ref(),
                e
            ))
        })?;

        // Schema-version errors (SchemaUpgradeRequired, UnknownVersion)
        // propagate verbatim so the caller can prompt for re-restore.
        // Crypto errors get a clearer "wrong passphrase or corrupt file"
        // message than the underlying CryptoError detail.
        match unseal_identity(&file_bytes, passphrase) {
            Ok(identity) => Ok(identity),
            Err(IdentityError::CryptoError(_)) => Err(IdentityError::CryptoError(
                "Failed to decrypt identity. Incorrect passphrase or corrupt file.".to_string(),
            )),
            Err(other) => Err(other),
        }
    }

    fn verify_retrieval_auth(&self, request: &RecordingRequest) -> Result<(), IdentityError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Resolve the public key of the claimed recipient (the requester)
        let pk_bytes =
            phalanx_forensics::identity::resolve_did_public_key(&request.locator.recipient)
                .map_err(|_| IdentityError::CryptoError("DID Resolution Failed".into()))?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Public Key: {}", e)))?;

        // Reconstruct the signed message payload
        let signed_data = (&request.target_did, &request.recording_id, &request.locator);
        let msg = postcard::to_allocvec(&signed_data)
            .map_err(|e| IdentityError::SerializationError(e.to_string()))?;

        // Verify the signature
        let signature = Signature::from_slice(&request.signature)
            .map_err(|e| IdentityError::CryptoError(format!("Invalid Signature: {}", e)))?;

        verifying_key
            .verify(&msg, &signature)
            .map_err(|_| IdentityError::CryptoError("Signature Verification Failed".into()))
    }

    fn init<P: AsRef<Path>>(
        path: P,
        passphrase: &str,
    ) -> Result<(Self, Option<String>), IdentityError> {
        // FIX: Replaced IoError match with an explicit path check
        if !path.as_ref().exists() {
            tracing::warn!("Sovereign root: NOT FOUND. Initiating Genesis...");

            let (new_identity, mnemonic) = Self::generate()?;
            tracing::info!("!!! GENESIS SUCCESSFUL !!!");
            // Mnemonic is returned to caller for UI display — no longer logged.

            new_identity.save_to_disk(&path, passphrase)?;
            return Ok((new_identity, Some(mnemonic)));
        }

        match Self::load_from_disk(&path, passphrase) {
            Ok(identity) => {
                tracing::info!(path = ?path.as_ref(), "Sovereign root: RESTORED");
                Ok((identity, None))
            }
            Err(err) => {
                tracing::error!(error = %err, "Sovereign root: CORRUPTED or UNREADABLE");
                Err(err)
            }
        }
    }

    fn revocation_signing_key(phrase: &str) -> Result<SigningKey, IdentityError> {
        let mnemonic = Mnemonic::parse(phrase)
            .map_err(|e: bip39::Error| IdentityError::MnemonicError(e.to_string()))?;
        let mut seed = mnemonic.to_seed(BIP39_PASSPHRASE_V1);
        let revocation_bytes: [u8; 32] = seed[32..64]
            .try_into()
            .map_err(|_| IdentityError::CryptoError("Revocation seed fail".into()))?;
        let key = SigningKey::from_bytes(&revocation_bytes);
        seed.zeroize();
        Ok(key)
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// End-to-end restore loop: generate identity at path A, restore from the
    /// returned phrase at a *fresh* path B, assert the same DID is produced.
    /// Exercises both `save_to_disk_atomic` (the restore-path persistence) and
    /// the determinism of `PhalanxIdentity::restore`.
    #[test]
    fn restore_loop_yields_same_did() {
        let dir_a = TempDir::new().expect("tempdir A");
        let dir_b = TempDir::new().expect("tempdir B");
        let path_a = dir_a.path().join("identity.bin");
        let path_b = dir_b.path().join("identity.bin");
        let passphrase = "test-passphrase";

        let (gen_id, phrase) = PhalanxIdentity::generate().expect("generate");
        gen_id.save_to_disk(&path_a, passphrase).expect("save A");
        let did_a = gen_id.did.as_str().to_string();

        // Fresh path B (no identity present), restore from the phrase, atomic save.
        assert!(!path_b.exists(), "tempdir B should be empty");
        let restored = PhalanxIdentity::restore(&phrase).expect("restore");
        restored
            .save_to_disk_atomic(&path_b, passphrase)
            .expect("atomic save B");
        assert!(path_b.exists(), "atomic save produced no file");

        let did_b = restored.did.as_str().to_string();
        assert_eq!(did_a, did_b, "DID must match after restore");

        // Loading from B yields the same identity (round-trip).
        let loaded = PhalanxIdentity::load_from_disk(&path_b, passphrase).expect("load B");
        assert_eq!(
            loaded.did.as_str(),
            did_a,
            "DID must survive atomic-save → load round-trip"
        );
    }

    /// Atomic save leaves no `.tmp` sibling behind on success.
    #[test]
    fn atomic_save_cleans_up_tmp() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("identity.bin");
        let tmp_path = dir.path().join("identity.bin.tmp");

        let (identity, _) = PhalanxIdentity::generate().expect("generate");
        identity
            .save_to_disk_atomic(&path, "pw")
            .expect("atomic save");

        assert!(path.exists(), "final file should exist");
        assert!(!tmp_path.exists(), ".tmp sibling should have been renamed");
    }
}
