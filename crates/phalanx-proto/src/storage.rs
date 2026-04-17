use crate::RecordingResponse;
// crates/phalanx-proto/src/storage.rs
use crate::evidence::{ShardChunk, SignatureHash, StorageSequence};
use crate::identity::{Did, RecordingId};
use crate::prelude::NetworkId;
use crate::prelude::PhalanxTimestamp;
use crate::prelude::ShardError;
use crate::revocation::RevocationToken;
use crate::types::ByteCapacity;
use async_trait::async_trait;
use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, thiserror::Error, Serialize, Deserialize)]
pub enum GuardianError {
    #[error("Quota exceeded: {0:?}")]
    QuotaExceeded(ByteCapacity),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Replay attack detected: Sequence {0} is too old")]
    ReplayDetected(u64),

    #[error("WAL write failed: {0}")]
    WalWriteFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Cryptographic verification failed: {0}")]
    VerificationFailed(String),

    #[error("Storage error: {0}")]
    StorageFailure(String),

    #[error("Chain Integrity Violation: {0}")]
    ChainIntegrityViolation(String),

    #[error("Policy Violation: {0}")]
    PolicyViolation(String),

    #[error("Ambiguous ownership: Multiple unproven identities claiming Recording")]
    AmbiguousOwnership,

    #[error("Crucible capacity exhausted: {0} active contexts at limit")]
    CapacityExhausted(usize),

    #[error("Sequence conflict: sequence {0} already exists with different content")]
    SequenceConflict(u64),

    #[error("Recording revoked: {0}")]
    RecordingRevoked(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandoverProof {
    pub recording_id: RecordingId,
    pub sequence_id: StorageSequence,
    pub old_did: Did,
    pub new_did: Did,
    pub anchor_hash: SignatureHash,
    pub old_signature: Signature,
    pub new_signature: Signature,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEgress {
    pub channel_id: String,
    pub response: RecordingResponse,
    pub attempt_count: u32,
    pub next_attempt: PhalanxTimestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageAck {
    Success(RecordingId, NetworkId),
    Failure(ShardError, NetworkId),
}

/// The Transient Journal: A high-speed, volatile storage contract.
/// Defines the shape of persistence for WAL (Write-Ahead Log) chunks,
/// egress salvage, and Crucible workbench state recovery.
///
/// This is a Noun (capability contract) — implementations live in
/// `phalanx-node` (FileJournal) and test doubles.
#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod handover_proof_tests {
    use super::*;

    fn sample_handover_proof(sequence: u32, anchor_first_byte: u8) -> HandoverProof {
        let mut anchor_bytes = [0u8; 32];
        anchor_bytes[0] = anchor_first_byte;
        HandoverProof {
            recording_id: RecordingId::new("rec-handover"),
            sequence_id: StorageSequence(sequence),
            old_did: Did("did:key:old".to_string()),
            new_did: Did("did:key:new".to_string()),
            anchor_hash: SignatureHash(anchor_bytes),
            old_signature: Signature::from_bytes(&[1u8; 64]),
            new_signature: Signature::from_bytes(&[2u8; 64]),
        }
    }

    #[test]
    fn handover_proof_postcard_roundtrip_preserves_all_fields() {
        let original = sample_handover_proof(42, 0xAB);
        let bytes = postcard::to_allocvec(&original).expect("serialize HandoverProof");
        let recovered: HandoverProof =
            postcard::from_bytes(&bytes).expect("deserialize HandoverProof");
        assert_eq!(recovered, original);
    }

    #[test]
    fn handover_proof_with_different_sequence_ids_serialize_distinctly() {
        // Ordering-sensitivity guard: two proofs identical except for sequence_id
        // must produce different wire bytes. If they collided, evidence chain
        // replay would be undetectable.
        let a = sample_handover_proof(1, 0xCD);
        let b = sample_handover_proof(2, 0xCD);
        let bytes_a = postcard::to_allocvec(&a).expect("serialize a");
        let bytes_b = postcard::to_allocvec(&b).expect("serialize b");
        assert_ne!(bytes_a, bytes_b);
    }
}

#[async_trait]
pub trait TransientJournal: Send + Sync + 'static {
    // --- WAL (Write-Ahead Log) Verbs ---
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;

    // --- Egress Salvage Verbs ---
    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError>;
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError>;

    // --- Workbench State Recovery ---
    async fn record_workbench_state(&mut self, state_bytes: &[u8]) -> Result<(), ShardError>;
    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError>;

    // --- Revocation Persistence ---
    async fn record_revocations(
        &mut self,
        _revocations: &[RevocationToken],
    ) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_revocations(&mut self) -> Result<Vec<RevocationToken>, ShardError> {
        Ok(vec![])
    }
}
