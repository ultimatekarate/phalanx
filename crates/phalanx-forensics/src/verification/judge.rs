use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use chacha20poly1305::aead::Aead;
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

use rand_core::OsRng;
use rand_core::RngCore;
pub trait HandoverJudge {
    fn verify_signatures(&self) -> Result<SignatureHash, ShardError>;
}

impl HandoverJudge for HandoverProof {
    fn verify_signatures(&self) -> Result<SignatureHash, ShardError> {
        let transfer_manifest = (
            &self.recording_id,
            &self.sequence_id,
            &self.old_did,
            &self.new_did,
            &self.anchor_hash,
        );

        let manifest_bytes = postcard::to_allocvec(&transfer_manifest)?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&manifest_bytes);

        Ok(SignatureHash(hasher.finalize().into()))
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
            DataPayload::Missing => return Err(CryptoError::EncryptionFailure),
        };

        use chacha20poly1305::KeyInit; // Local scope only
        let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
        let mut nonce_bytes = [0u8; 24];
        OsRng.fill_bytes(&mut nonce_bytes);
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

/// Decode a `DataPayload` into cleartext bytes (consuming).
///
/// This is the single canonical decode path for end-to-end consumers.
/// Takes ownership of the payload — zero-copy on `Clear`, no clone.
///
/// - `Clear` → returned as-is (moved out)
/// - `Encrypted` → XChaCha20-Poly1305 decrypt, then LZ4 decompress
/// - `Compressed` → LZ4 decompress
/// - `Missing` → error
///
/// The production pipeline is compress → encrypt, so encrypted payloads
/// are always decompressed after decryption.
///
/// For borrow-based decryption without decompression (e.g., stronghold
/// export which writes decrypted envelopes to disk), use `PayloadCipher::reveal()`.
pub fn decode_payload(
    payload: DataPayload,
    key: Option<&SymmetricKey>,
) -> Result<Vec<u8>, CryptoError> {
    match payload {
        DataPayload::Clear(data) => Ok(data),
        DataPayload::Encrypted { nonce, ciphertext } => {
            let key = key.ok_or(CryptoError::DecryptionFailure)?;
            let cipher = XChaCha20Poly1305::new(key.as_bytes().into());
            let x_nonce = XNonce::from_slice(&nonce);

            let decrypted = cipher
                .decrypt(x_nonce, ciphertext.as_ref())
                .map_err(|_| CryptoError::DecryptionFailure)?;

            crate::reassembler::decompress_payload(&decrypted)
                .map_err(|_| CryptoError::DecompressionFailure)
        }
        DataPayload::Compressed(data) => crate::reassembler::decompress_payload(&data)
            .map_err(|_| CryptoError::DecompressionFailure),
        DataPayload::Missing => Err(CryptoError::DecryptionFailure),
    }
}

pub trait JudgeExt {
    fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool;
    fn sign(&self, msg: &[u8]) -> Signature;
}

impl JudgeExt for PhalanxIdentity {
    fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
        let Ok(vk) = VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let Ok(sig) = Signature::from_slice(sig) else {
            return false;
        };
        vk.verify_strict(msg, &sig).is_ok()
    }

    fn sign(&self, msg: &[u8]) -> Signature {
        self.keypair.sign(msg)
    }
}

/// This eliminates unit confusion (seconds vs milliseconds) that previously
/// allowed attackers to exploit misconfigured tolerance values.
pub trait TimeJudge {
    fn verify_freshness(
        &self,
        current_now: PhalanxTimestamp,
        tolerance: std::time::Duration,
    ) -> Result<(), TimeError>;
}

impl TimeJudge for PhalanxTimestamp {
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Timestamp arithmetic and millis→u64 — epoch millis fit in u64 for centuries.
    fn verify_freshness(
        &self,
        now: PhalanxTimestamp,
        tolerance: std::time::Duration,
    ) -> Result<(), TimeError> {
        let claimed = self.as_u64();
        let current = now.as_u64();

        // PhalanxTimestamp values are in milliseconds, so tolerance must match.
        let tolerance_ms = tolerance.as_millis() as u64;

        if claimed > current + tolerance_ms {
            return Err(TimeError::Future(claimed - current));
        }
        if claimed < current.saturating_sub(tolerance_ms) {
            return Err(TimeError::Stale(current - claimed));
        }
        Ok(())
    }
}

// Gate traits (WitnessGate, IntegrityGate, PrivacyGate, ContinuityGate)
// live in crate::gate — re-exported here for backwards compatibility so
// existing `use phalanx_forensics::judge::IntegrityGate` paths continue
// to resolve.
pub use crate::gate::{ContinuityGate, IntegrityGate, PrivacyGate, WitnessGate};

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use crate::witness::WitnessAuthority;

    use super::*;
    use crate::policy::EgressGovernor;
    use crate::unit::ForensicUnit;
    use phalanx_proto::evidence::{
        DataPayload, Evidence, ForensicMetrics, StorageSequence, VideoShard, WitnessEnvelope,
    };
    use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
    use phalanx_proto::time::{SystemClock, TrustedClock};
    use phalanx_proto::trust::TrustLevel;
    use phalanx_proto::types::{Fps, SystemStress};

    use tracing::info;

    #[tokio::test]
    async fn test_forensic_boundary_tamper_detection_v4() {
        // Setup Identities & Baseline Environment
        let witness_identity = PhalanxIdentity::new_ephemeral();
        let witness_peer_id = witness_identity.clone().witness_id;
        let vid = RecordingId::new("test_stream_01");
        let clock = SystemClock;
        let now = clock.now();

        // Properly initialize a valid VideoShard
        let original_shard = VideoShard {
            timestamp: now,
            sequence_id: StorageSequence(100),
            fps: Fps::new(30),
            recording_id: vid,
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
            lens_metrics: ForensicMetrics::default(),
        };

        // Seal the evidence legitimately
        let mut envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(original_shard),
            &witness_identity,
            witness_peer_id.clone(),
            None,
        )
        .expect("Failed to initialize valid WitnessEnvelope");

        // BASELINE: Verify check_integrity passes on clean data (Gate 3)
        let integrity_result = envelope.clone().check_integrity(
            &witness_peer_id,
            &clock,
            std::time::Duration::from_millis(10_000),
            None,
        );
        assert!(
            integrity_result.is_ok(),
            "Integrity Gate failed on clean data"
        );

        // TAMPER: Modify the evidence bytes (Simulation of disk-rot or database injection)
        match &mut envelope.evidence {
            Evidence::Video(shard) => {
                if let DataPayload::Clear(ref mut bytes) = shard.payload {
                    bytes.push(0xFF); // Injected corruption into the real struct
                }
            }
            _ => panic!("Expected Video evidence"),
        }

        // THE TEST: Gate 3 (Integrity) must catch the modification
        // Re-serializing and comparing against the stored signature must fail.
        let tamper_result = envelope.check_integrity(
            &witness_peer_id,
            &clock,
            std::time::Duration::from_millis(10_000),
            None,
        );

        assert!(
            tamper_result.is_err(),
            "INTEGRITY BREACH: Gate 3 (check_integrity) accepted modified evidence!"
        );

        // THE ARCHITECTURAL LOCK: Gate 4 (Policy Promotion)
        // We prove that without a successful Gate 3, we cannot obtain a 'Verified' unit,
        // which means the EgressGovernor cannot produce a 'Sealed' unit for the wire.
        match tamper_result {
            Ok(valid_env) => {
                // If we somehow reached here (we shouldn't), the Governor is the second line of defense.
                let unit = ForensicUnit::new_verified_unchecked(valid_env);
                let sealed_result = EgressGovernor::authorize(
                    unit,
                    &TrustLevel::Ally,
                    &SystemStress::Nominal,
                    &SymmetricKey::from_bytes([0u8; 32]),
                );
                assert!(
                    sealed_result.is_err(),
                    "Governor allowed tampered data to be promoted to Sealed!"
                );
            }
            Err(_) => {
                info!("Gate 3 correctly blocked promotion. No 'Verified' unit was created.");
            }
        }

        // FINAL PROOF: RecordingResponse requires Sealed units
        // Because the tamper_result was an Err, we can't even construct a
        // RecordingResponse::Success(vec![...]) with this data.

        info!(
            "Forensic Boundary: Successfully verified that Gate 3 and Gate 4 block tampered evidence."
        );
    }

    // ── PayloadCipher: encryption state machine ─────────────────────────

    use phalanx_proto::crypto::SymmetricKey as TestSymKey;

    fn test_key() -> TestSymKey {
        TestSymKey::from_bytes([0x5Au8; 32])
    }

    #[test]
    fn payload_cipher_clear_to_encrypt_then_reveal_roundtrips() {
        // Round-trip: Clear → apply_encryption → reveal must return original bytes.
        // If the cipher or nonce handling drifted, decryption would produce junk.
        let plaintext = b"evidence-bytes-under-test".to_vec();
        let mut payload = DataPayload::Clear(plaintext.clone());
        payload
            .apply_encryption(&test_key())
            .expect("clear-path encryption must succeed");

        assert!(
            matches!(payload, DataPayload::Encrypted { .. }),
            "apply_encryption must promote Clear to Encrypted"
        );
        let revealed = payload.reveal(&test_key()).expect("reveal must succeed");
        assert_eq!(revealed, plaintext);
    }

    #[test]
    fn payload_cipher_apply_encryption_is_idempotent_on_already_encrypted() {
        // The explicit idempotence guard (judge.rs line 51) — re-encrypting an
        // already-encrypted payload must be a no-op, not a double-encrypt.
        // Without this, a buggy pipeline re-run would corrupt evidence.
        let mut payload = DataPayload::Clear(b"once-only".to_vec());
        payload
            .apply_encryption(&test_key())
            .expect("first encrypt");

        // Snapshot the encrypted payload's ciphertext.
        let first_ciphertext = match &payload {
            DataPayload::Encrypted { ciphertext, .. } => ciphertext.clone(),
            other => panic!("expected Encrypted, got {other:?}"),
        };

        // Re-apply encryption — must be a no-op.
        payload
            .apply_encryption(&test_key())
            .expect("idempotent second encrypt");
        let second_ciphertext = match &payload {
            DataPayload::Encrypted { ciphertext, .. } => ciphertext.clone(),
            other => panic!("expected Encrypted after second call, got {other:?}"),
        };
        assert_eq!(
            first_ciphertext, second_ciphertext,
            "second apply_encryption must leave Encrypted variant untouched"
        );
    }

    #[test]
    fn payload_cipher_rejects_missing_variant() {
        // A `Missing` payload has no plaintext to encrypt — must fail cleanly
        // rather than silently producing an Encrypted(empty) value.
        let mut payload = DataPayload::Missing;
        let err = payload
            .apply_encryption(&test_key())
            .expect_err("Missing payload must not encrypt");
        let _ = err; // variant shape is the only guarantee we rely on here.
    }

    #[test]
    fn payload_cipher_reveal_with_wrong_key_fails() {
        // AEAD tag verification must catch a wrong decryption key.
        let mut payload = DataPayload::Clear(b"secret".to_vec());
        payload.apply_encryption(&test_key()).expect("encrypt ok");

        let wrong_key = TestSymKey::from_bytes([0xA5u8; 32]);
        let result = payload.reveal(&wrong_key);
        assert!(
            result.is_err(),
            "reveal with wrong key must fail, got {result:?}"
        );
    }

    #[test]
    fn payload_cipher_reveal_on_clear_returns_underlying_bytes() {
        // Reveal on a Clear payload is zero-op pass-through. If this path
        // drifts, end-to-end consumers would silently receive empty bytes.
        let bytes = b"already-clear".to_vec();
        let payload = DataPayload::Clear(bytes.clone());
        let revealed = payload.reveal(&test_key()).expect("reveal on Clear");
        assert_eq!(revealed, bytes);
    }
}
