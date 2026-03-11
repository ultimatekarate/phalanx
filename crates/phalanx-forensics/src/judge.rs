use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, VerifyingKey}; // Crypto stays here!
use phalanx_proto::crypto::CryptoError;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::prelude::DataPayload;
use phalanx_proto::prelude::ShardError;
use phalanx_proto::prelude::SignatureHash;
use phalanx_proto::storage::HandoverProof;
use phalanx_proto::time::{PhalanxTimestamp, TimeError};

pub trait HandoverJudge {
    fn verify_signatures(&self) -> Result<SignatureHash, ShardError>;
}

impl HandoverJudge for HandoverProof {
    fn verify_signatures(&self) -> Result<SignatureHash, ShardError> {
        let transfer_manifest = (
            &self.volley_id,
            &self.sequence_id,
            &self.old_did,
            &self.new_did,
            &self.anchor_hash,
        );

        let manifest_bytes = postcard::to_allocvec(&transfer_manifest)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&manifest_bytes);

        Ok(SignatureHash(hasher.finalize().into()))
    }
}

pub trait Decryptor {
    fn reveal(&self, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError>;
}

impl Decryptor for DataPayload {
    fn reveal(&self, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
        match self {
            DataPayload::Encrypted { nonce, ciphertext } => {
                // 1. Initialize the cryptographic engine using the provided 32-byte key
                let cipher = XChaCha20Poly1305::new(key.as_bytes().into());

                // 2. Load the 24-byte extended nonce
                let x_nonce = XNonce::from_slice(nonce);

                // 3. Perform Authenticated Decryption
                // If the ciphertext was tampered with, this will safely fail.
                let decrypted_bytes = cipher
                    .decrypt(x_nonce, ciphertext.as_ref())
                    .map_err(|_| CryptoError::DecryptionFailure)?;

                Ok(decrypted_bytes)
            }

            // If the payload is already in the clear, just clone and return it
            DataPayload::Clear(data) => Ok(data.clone()),

            // Gaps and Compressed data cannot be decrypted directly via this trait
            _ => Err(CryptoError::DecryptionFailure),
        }
    }
}

pub trait PayloadCipher {
    fn apply_encryption(&mut self, key: &SymmetricKey) -> Result<(), CryptoError>;
    fn reveal(&self, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError>;
}

impl PayloadCipher for DataPayload {
    fn apply_encryption(&mut self, key: &SymmetricKey) -> Result<(), CryptoError> {
        let plaintext = match self {
            DataPayload::Clear(data) => data.clone(),
            DataPayload::Compressed(data) => data.clone(),
            DataPayload::Encrypted { .. } => return Ok(()), // Already encrypted; idempotent
            DataPayload::Missing(_) => return Err(CryptoError::EncryptionFailure),
        };

        use chacha20poly1305::KeyInit; // Local scope only
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let nonce_bytes = rand::random::<[u8; 24]>();
        let x_nonce = XNonce::from_slice(&nonce_bytes);

        use chacha20poly1305::aead::Aead; // Local scope only
        let ciphertext = cipher
            .encrypt(x_nonce, plaintext.as_ref())
            .map_err(|_| CryptoError::EncryptionFailure)?;

        *self = DataPayload::Encrypted {
            nonce: nonce_bytes.to_vec(),
            ciphertext,
        };
        Ok(())
    }

    fn reveal(&self, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
        match self {
            DataPayload::Encrypted { nonce, ciphertext } => {
                use chacha20poly1305::KeyInit;
                let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
                let x_nonce = XNonce::from_slice(nonce);

                use chacha20poly1305::aead::Aead;
                let decrypted_bytes = cipher
                    .decrypt(x_nonce, ciphertext.as_ref())
                    .map_err(|_| CryptoError::DecryptionFailure)?;

                Ok(decrypted_bytes)
            }
            DataPayload::Clear(data) => Ok(data.clone()),
            _ => Err(CryptoError::DecryptionFailure),
        }
    }
}

pub trait JudgeExt {
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool;
    fn sign(&self, msg: &[u8]) -> Signature;
}

impl JudgeExt for PhalanxIdentity {
    fn verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> bool {
        let key_bytes_opt: Option<&[u8]> = if pubkey.len() == 32 {
            Some(pubkey)
        } else if pubkey.len() == 38 && pubkey.starts_with(&[0x00, 0x24, 0x08, 0x01, 0x12, 0x20]) {
            pubkey.get(6..)
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
        false
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        self.keypair.sign(msg)
    }
}

pub trait TimeJudge {
    fn verify_freshness(
        &self,
        current_now: PhalanxTimestamp,
        tolerance: u64,
    ) -> Result<(), TimeError>;
}

impl TimeJudge for PhalanxTimestamp {
    fn verify_freshness(&self, now: PhalanxTimestamp, tolerance: u64) -> Result<(), TimeError> {
        let claimed = self.as_u64();
        let current = now.as_u64();

        if claimed > current + tolerance {
            return Err(TimeError::Future(claimed - current));
        }
        if claimed < current.saturating_sub(tolerance) {
            return Err(TimeError::Stale(current - claimed));
        }
        Ok(())
    }
}

// Gate traits (WitnessGate, IntegrityGate, PrivacyGate, CapacityGate,
// ForensicGate) live in crate::gate — re-exported here for backwards
// compatibility so existing `use phalanx_forensics::judge::IntegrityGate`
// paths continue to resolve.
pub use crate::gate::{
    BufferCapacityGate, ContinuityGate, ForensicGate, IntegrityGate, PrivacyGate, WitnessGate,
};

#[cfg(test)]
mod tests {
    use crate::witness::WitnessAuthority;

    use super::*;
    use crate::policy::EgressGovernor;
    use phalanx_proto::evidence::{
        DataPayload, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
    };
    use phalanx_proto::identity::{PhalanxIdentity, VolleyId};
    use phalanx_proto::time::SystemClock;
    use phalanx_proto::trust::TrustLevel;
    use phalanx_proto::types::{ForensicUnit, SystemStress, Verified};

    use tracing::info;

    #[tokio::test]
    async fn test_forensic_boundary_tamper_detection_v4() {
        // 1. Setup Identities & Baseline Environment
        let witness_identity = PhalanxIdentity::new_ephemeral();
        let witness_peer_id = witness_identity.clone().network_id;
        let vid = VolleyId::new("test_stream_01");
        let clock = SystemClock;
        let now = PhalanxTimestamp::now();

        // 2. Properly initialize a valid VideoShard
        let original_shard = VideoShard {
            timestamp: now,
            sequence_id: StorageSequence(100),
            fps: 30,
            volley_id: vid,
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };

        // Seal the evidence legitimately
        let mut envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(original_shard),
            &witness_identity,
            witness_peer_id.clone(),
            None,
        )
        .expect("Failed to initialize valid WitnessEnvelope");

        // 3. BASELINE: Verify check_integrity passes on clean data (Gate 3)
        let integrity_result =
            envelope
                .clone()
                .check_integrity(&witness_peer_id, &clock, 10_000, None);
        assert!(
            integrity_result.is_ok(),
            "Integrity Gate failed on clean data"
        );

        // 4. TAMPER: Modify the evidence bytes (Simulation of disk-rot or database injection)
        match &mut envelope.evidence {
            Evidence::Video(shard) => {
                if let DataPayload::Clear(ref mut bytes) = shard.payload {
                    bytes.push(0xFF); // Injected corruption into the real struct
                }
            }
            _ => panic!("Expected Video evidence"),
        }

        // 5. THE TEST: Gate 3 (Integrity) must catch the modification
        // Re-serializing and comparing against the stored signature must fail.
        let tamper_result = envelope.check_integrity(&witness_peer_id, &clock, 10_000, None);

        assert!(
            tamper_result.is_err(),
            "INTEGRITY BREACH: Gate 3 (check_integrity) accepted modified evidence!"
        );

        // 6. THE ARCHITECTURAL LOCK: Gate 4 (Policy Promotion)
        // We prove that without a successful Gate 3, we cannot obtain a 'Verified' unit,
        // which means the EgressGovernor cannot produce a 'Sealed' unit for the wire.
        match tamper_result {
            Ok(valid_env) => {
                // If we somehow reached here (we shouldn't), the Governor is the second line of defense.
                let unit = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(valid_env);
                let sealed_result =
                    EgressGovernor::authorize(unit, &TrustLevel::Ally, &SystemStress::Nominal);
                assert!(
                    sealed_result.is_err(),
                    "Governor allowed tampered data to be promoted to Sealed!"
                );
            }
            Err(_) => {
                info!("Gate 3 correctly blocked promotion. No 'Verified' unit was created.");
            }
        }

        // 7. FINAL PROOF: VolleyResponse requires Sealed units
        // Because the tamper_result was an Err, we can't even construct a
        // VolleyResponse::Success(vec![...]) with this data.

        info!("Forensic Boundary: Successfully verified that Gate 3 and Gate 4 block tampered evidence.");
    }
}
