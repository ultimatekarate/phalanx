
use phalanx_proto::HandoverProof;
use ed25519_dalek::{Verifier, Signature, VerifyingKey}; // Crypto stays here!

pub trait HandoverJudge {
    fn verify_signatures(&self) -> Result<(), String>;
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

        let manifest_bytes = postcard::to_stdvec(&transfer_manifest)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        let mut hasher = blake3::Hasher::new();
        hasher.update(&manifest_bytes);

        Ok(SignatureHash(hasher.finalize().into()))
    }

}

pub trait Decryptor {
    fn reveal(&self, key: &SymmetricKey) -> Result<Vec<u8>, ForensicError>;
}

impl Decryptor for DataPayload {
    fn reveal(&self, key: &SymmetricKey) -> Result<Vec<u8>, ForensicError> {
        match self {
            DataPayload::Encrypted { data, .. } => {
                // Actual decryption math lives here
                Ok(decrypted_bytes)
            },
            DataPayload::Clear(data) => Ok(data.clone()),
            _ => Err(ForensicError::Validation("Payload not decryptable".into())),
        }
}

use phalanx_proto::identity::PhalanxIdentity;
use ed25519_dalek::{Signature, Signer, VerifyingKey};

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

// crates/phalanx-forensics/src/judge.rs
use phalanx_proto::time::{PhalanxTimestamp, TimeError};

pub trait TimeJudge {
    fn verify_freshness(&self, current_now: PhalanxTimestamp, tolerance: u64) -> Result<(), TimeError>;
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
        WitnessEnvelope::new(self, identity, peer_id, prev_hash).map_err(|e| {
            error!(event = "signing_failure", error = %e, "Witness Gate: Failed to seal unit");
            e
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
        if !self.verify() {
            error!(event = "integrity_failure", node = %node_id, peer = %self.did, "SIGNATURE_INVALID");
            return Err(ShardError::SigningError("Signature verification failed".into()));
        }

        match self.evidence.timestamp().verify_freshness(now, tolerance) {
            Ok(_) => Ok(self),
            Err(e) => {
                error!(event = "temporal_failure", node = %node_id, peer = %self.did, error = %e, "TIME_INVALID");
                Err(ShardError::TimeSource(e))
            }
        }
    }
}

/// Gate 4: The Privacy Gate (Egress)
pub trait PrivacyGate {
    fn safeguard(self, key: &SymmetricKey) -> Result<Self, ShardError> where Self: Sized;
}

impl PrivacyGate for Evidence {
    fn safeguard(mut self, key: &SymmetricKey) -> Result<Self, ShardError> {
        let res = match &mut self {
            Evidence::Video(s) => s.encrypt(key),
            Evidence::Audio(s) => s.encrypt(key),
            _ => Ok(()),
        };

        res.map(|_| self).map_err(|e| {
            error!(event = "privacy_failure", error = %e, "Safeguarding failed");
            ShardError::Encryption(e)
        })
    }
}

/// Gate 5: The Capacity Gate (Ingress)
pub trait CapacityGate {
    fn check_capacity(self, peer: &NetworkId, pending: usize, limit: usize) -> Result<Self, ShardError>
    where Self: Sized;
}

impl CapacityGate for WitnessEnvelope {
    fn check_capacity(self, peer: &NetworkId, pending: usize, limit: usize) -> Result<Self, ShardError> {
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

// crates/phalanx-forensics/src/judge.rs
