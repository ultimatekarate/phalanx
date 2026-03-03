use crate::crucible::EvidenceExt;
use crate::witness::WitnessAuthority;
use chacha20poly1305::aead::Aead;
use chacha20poly1305::KeyInit;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::XNonce;
use ed25519_dalek::Signer;
use ed25519_dalek::{Signature, VerifyingKey}; // Crypto stays here!
use phalanx_proto::crypto::CryptoError;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::PhalanxIdentity;
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

use phalanx_proto::prelude::*;
use tracing::{error, warn};

/// Gate 1: The Witnessing Gate
pub trait WitnessGate {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError>;
}

impl WitnessGate for Evidence {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError> {
        phalanx_proto::evidence::WitnessEnvelope::sign_envelope(self, identity, peer_id, prev_hash)
            .map_err(|_| {
                error!(
                    event = "signing_failure",
                    "Witness Gate: Failed to seal unit"
                );
                ShardError::SigningError("Failed to seal".into())
            })
    }
}

/// Gate 3: The Integrity Gate (Reception Side)
pub trait IntegrityGate {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        now: PhalanxTimestamp, // Pass timestamp directly to decouple from Clock impl
        tolerance: u64,
    ) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl IntegrityGate for WitnessEnvelope {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        now: PhalanxTimestamp,
        tolerance: u64,
    ) -> Result<Self, ShardError> {
        if !phalanx_proto::evidence::WitnessEnvelope::verify_envelope(&self) {
            error!(event = "integrity_failure", node = %node_id, peer = %self.did, "SIGNATURE_INVALID");
            return Err(ShardError::SigningError(
                "Signature verification failed".into(),
            ));
        }

        match self.evidence.timestamp().verify_freshness(now, tolerance) {
            Ok(_) => Ok(self),
            Err(e) => {
                error!(event = "temporal_failure", node = %node_id, peer = %self.did, "TIME_INVALID");
                // FIX: Map to String to bypass the TimeError module collision
                Err(ShardError::InvalidConfiguration(e.to_string()))
            }
        }
    }
}

/// Gate 4: The Privacy Gate (Egress)
pub trait PrivacyGate {
    fn safeguard(self, key: &SymmetricKey) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl PrivacyGate for Evidence {
    fn safeguard(mut self, key: &SymmetricKey) -> Result<Self, ShardError> {
        let res = match &mut self {
            Evidence::Video(s) => s.payload.apply_encryption(key),
            Evidence::Audio(s) => s.payload.apply_encryption(key),
            _ => Ok(()),
        };

        res.map(|_| self).map_err(|e| {
            tracing::error!(event = "privacy_failure", error = %e, "Safeguarding failed");
            ShardError::Encryption(e.to_string())
        })
    }
}

/// Gate 5: The Capacity Gate (Ingress)
pub trait CapacityGate {
    fn check_capacity(
        self,
        peer: &NetworkId,
        pending: usize,
        limit: usize,
    ) -> Result<Self, ShardError>
    where
        Self: Sized;
}

impl CapacityGate for WitnessEnvelope {
    fn check_capacity(
        self,
        peer: &NetworkId,
        pending: usize,
        limit: usize,
    ) -> Result<Self, ShardError> {
        if pending > limit {
            warn!(event = "capacity_shedding", peer = %peer, "Node saturated");
            return Err(ShardError::CapacityExceeded(pending as u64));
        }
        Ok(self)
    }
}

/// Monadic Observation Extension
pub trait ForensicGate<T, E> {
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E>;
}

impl<T, E: std::fmt::Display> ForensicGate<T, E> for Result<T, E> {
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E> {
        if let Err(ref e) = self {
            error!(event = event, node = %node, error = %e, "{msg}");
        }
        self
    }
}
