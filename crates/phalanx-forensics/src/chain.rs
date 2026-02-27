use phalanx_proto::prelude::*;
use crate::crucible::Mold;

const VOLLEY_SIZE_THRESHOLD: usize = 50;
const VOLLEY_TIME_THRESHOLD: Duration = Duration::from_secs(1);

// --- STRATEGY 1: SHARD REASSEMBLY (Chunks -> Envelope) --

// --- STRATEGY 2: VOLLEY ASSEMBLY (Envelopes -> Volley) ---
#[derive(Debug, Serialize, Deserialize)]
pub struct VolleyAmalgam;

impl Mold for VolleyAmalgam {
    type Input = WitnessEnvelope;
    type Output = Volley;
    type Key = VolleyId;
    type Accumulator = VolleyBuffer;

    fn get_key(item: &Self::Input) -> Self::Key {
        item.evidence.volley_id().clone()
    }

    fn init_accumulator(item: &Self::Input) -> Self::Accumulator {
        let mut artifacts = BTreeMap::new();
        artifacts.insert(item.evidence.sequence_id(), item.clone());

        VolleyBuffer {
            artifacts,
            volley_id: item.evidence.volley_id().clone(),
            owner_did: item.did.clone(),
        }
    }

    fn ingest(acc: &mut Self::Accumulator, item: Self::Input) {
        let seq = item.evidence.sequence_id();

        match &item.evidence {
            Evidence::Handover(proof) => {
                // 1. Verify the bridge connects to the CURRENT legal owner
                if proof.old_did == acc.owner_did {
                    tracing::info!(
                        volley = %acc.volley_id,
                        "Crucible: Advancing stream ownership via HandoverProof"
                    );

                    // Transfer legal ownership of the active buffer
                    acc.owner_did = proof.new_did.clone();
                    acc.artifacts.insert(seq, item);
                } else {
                    tracing::warn!(
                        volley = %acc.volley_id,
                        "Crucible rejected HandoverProof: Unauthorized origin"
                    );
                }
            }
            _ => {
                // 2. Standard Frame Verification
                if item.did == acc.owner_did {
                    acc.artifacts.insert(seq, item);
                } else {
                    // ZERO-TRUST DROP: Prevent buffer bloat from malicious peers
                    tracing::warn!(
                        volley = %acc.volley_id,
                        seq = %seq.0,
                        "Crucible dropped illegal frame: Causality Breach (Identity Mismatch)"
                    );
                }
            }
        }
    }

    fn is_ready(acc: &Self::Accumulator, elapsed: Duration) -> bool {
        acc.artifacts.len() >= VOLLEY_SIZE_THRESHOLD || elapsed > VOLLEY_TIME_THRESHOLD
    }

    fn assemble(&self, key: VolleyId, acc: Self::Accumulator) -> Option<Self::Output> {
        if acc.artifacts.is_empty() {
            return None;
        }

        let mut sorted_envelopes: Vec<WitnessEnvelope> = Vec::with_capacity(acc.artifacts.len());
        let mut gaps = Vec::new();
        let clock = TrustedClock::new();
        let now = clock.forensic_now().ok()?;

        let mut expected_seq: Option<StorageSequence> = None;
        let mut last_signature_hash: Option<SignatureHash> = None;

        // BTreeMap guarantees we iterate by StorageSequence order
        for (seq, env) in acc.artifacts {
            let current_seq: StorageSequence = seq;

            // 1. SEQUENCE CONTINUITY CHECK
            if let Some(expected) = expected_seq {
                if current_seq > expected {
                    // Detected a sequence gap - create an attributed ForensicGap
                    gaps.push(ForensicGap {
                        volley_id: key.clone(), // FIX: Every gap belongs to the Volley
                        start_seq: expected,
                        end_seq: current_seq - 1,
                        detected_at: now,
                    });

                    // Note: A gap breaks the hash-link by definition.
                    // In a 'Healable' timeline, we reset the link anchor here.
                    last_signature_hash = None;
                }
            }

            // 2. CAUSALITY (HASH-LINK) VERIFICATION
            // Only verify link if there wasn't just a gap or if it's not the first unit
            if let (Some(expected_hash), Some(actual_link)) = (last_signature_hash, env.prev_hash) {
                if expected_hash != actual_link {
                    error!(
                        volley_id = %key,
                        seq = %current_seq,
                        "VolleyAmalgam: CAUSALITY BREACH - Hash link mismatch detected"
                    );
                    // In Zero-Trust, a breach means we discard the assembly to prevent corruption
                    return None;
                }
            }

            // Update state for next iteration
            expected_seq = Some(current_seq + 1);
            last_signature_hash = Some(env.signature_hash());
            sorted_envelopes.push(env);
        }

        info!(
            volley_id = %key,
            artifacts = %sorted_envelopes.len(),
            gaps = %gaps.len(),
            "VolleyAmalgam: Finalized chain with verified causality"
        );

        let gaps_2 = gaps.clone();

        Some(Volley {
            id: key.clone(),
            owner_did: acc.owner_did,
            artifacts: sorted_envelopes,
            gaps,
            is_complete: gaps_2.is_empty(),
        })
    }
}


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



#[cfg(test)]
mod security_tests {
    use super::*;
    use phalanx_proto::prelude::*;

    #[test]
    fn test_unauthorized_retrieval_rejection() {
        let author = PhalanxIdentity::generate();
        let authorized_investigator = PhalanxIdentity::generate();
        let malicious_attacker = PhalanxIdentity::generate();

        let volley_id = VolleyId::new("forensic-event-001");
        let locator = PhalanxLocator {
            id: volley_id.clone(),
            secret: "top-secret".to_string(),
            author: author.did.clone(),
            recipient_did: authorized_investigator.did.clone(),
        };

        // Attacker attempts to forge a request
        let malicious_signature = malicious_attacker.sign(volley_id.as_str().as_bytes());
        let malicious_request = VolleyRequest {
            target_did: author.did.clone(),
            volley_id,
            locator,
            signature: malicious_signature.to_bytes().to_vec(),
        };

        // THE JUDGMENT: Identity Gate must fail
        let result = authorized_investigator.verify_retrieval_auth(&malicious_request);
        assert!(result.is_err(), "Privacy Breach: Engine allowed attacker to pass Identity Gate.");
    }

    #[test]
    fn test_replay_attack_prevention() {
        let (author, _) = PhalanxIdentity::generate_with_seed();
        let (investigator, _) = PhalanxIdentity::generate_with_seed();

        let volley_a = VolleyId::new("video-alpha");
        let volley_b = VolleyId::new("video-beta");

        // Signature for Alpha...
        let signature_a = investigator.sign(volley_a.as_str().as_bytes());

        // ...replayed for Beta
        let replayed_request = VolleyRequest {
            target_did: author.did.clone(),
            volley_id: volley_b.clone(),
            locator: PhalanxLocator { id: volley_b, secret: "k".into(), author: author.did.clone(), recipient_did: investigator.did.clone() },
            signature: signature_a.to_bytes().to_vec(),
        };

        let result = author.verify_retrieval_auth(&replayed_request);
        assert!(result.is_err(), "Security Failure: Engine accepted replayed signature.");
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use phalanx_proto::time::{PhalanxTimestamp, TimeError};

    #[test]
    fn test_signing_and_verification() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let message = b"evidence_shard_001";
        let signature = identity.sign(message);
        let pubkey = identity.keypair.verifying_key().to_bytes();

        assert!(PhalanxIdentity::verify(
            &pubkey,
            message,
            &signature.to_bytes()
        ));
    }


    #[test]
    fn test_libp2p_key_format_handling() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let message = b"compatibility_check";
        let signature = identity.sign(message);
        let raw_key = identity.keypair.verifying_key().to_bytes();
        let mut peer_id_bytes = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
        peer_id_bytes.extend_from_slice(&raw_key);

        assert_eq!(peer_id_bytes.len(), 38);
        assert!(PhalanxIdentity::verify(
            &peer_id_bytes,
            message,
            &signature.to_bytes()
        ));
    }

    #[test]
    fn test_valid_timestamp_acceptance() {
        let now = PhalanxTimestamp::from_u64(1000);
        let tolerance = 5;

        // Perfect Match
        assert!(PhalanxTimestamp::from_u64(1000).verify_freshness(now, tolerance).is_ok());
        // Recent Past
        assert!(PhalanxTimestamp::from_u64(997).verify_freshness(now, tolerance).is_ok());
        // Near Future
        assert!(PhalanxTimestamp::from_u64(1003).verify_freshness(now, tolerance).is_ok());
    }

    #[test]
    fn test_attack_rejections() {
        let now = PhalanxTimestamp::from_u64(1000);
        let tolerance = 5;

        // Replay Attack (Old)
        let stale = PhalanxTimestamp::from_u64(900);
        assert!(matches!(stale.verify_freshness(now, tolerance), Err(TimeError::Stale(_))));

        // Time Traveler Attack (Future)
        let future = PhalanxTimestamp::from_u64(1100);
        assert!(matches!(future.verify_freshness(now, tolerance), Err(TimeError::Future(_))));
    }
}