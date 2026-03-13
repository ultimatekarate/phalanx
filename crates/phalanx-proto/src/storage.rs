use crate::RecordingResponse;
// crates/phalanx-proto/src/storage.rs
use crate::evidence::{SignatureHash, StorageSequence};
use crate::identity::{Did, RecordingId};
use crate::prelude::NetworkId;
use crate::prelude::PhalanxTimestamp;
use crate::prelude::ShardError;
use crate::time::TimeError;
use crate::types::ByteCapacity;
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

    #[error("Time synchronization failure: {0}")]
    TimeSource(#[from] TimeError),

    #[error("Attack attempt blocked: Peer {0} is blacklisted")]
    BlacklistedPeer(String),

    #[error("Cryptographic verification failed: {0}")]
    VerificationFailed(String),

    #[error("Crucible commit failed: {0}")]
    CrucibleError(String),

    #[error("Storage error: {0}")]
    StorageFailure(String),

    #[error("Chain Integrity Violation: {0}")]
    ChainIntegrityViolation(String),

    #[error("Reassembly failure: {0}")]
    ReassemblyError(String),

    #[error("Policy Violation: {0}")]
    PolicyViolation(String),

    #[error("Identity Mismatch")]
    IdentityMismatch,

    #[error("Ambiguous ownership: Multiple unproven identities claiming Recording")]
    AmbiguousOwnership,

    #[error("Crucible capacity exhausted: {0} active contexts at limit")]
    CapacityExhausted(usize),

    #[error("Sequence conflict: sequence {0} already exists with different content")]
    SequenceConflict(u64),
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
