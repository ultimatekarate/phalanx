use crate::VolleyResponse;
// crates/phalanx-proto/src/storage.rs
use crate::evidence::{SignatureHash, StorageSequence};
use crate::identity::{Did, VolleyId};
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

    #[error("Ambiguous ownership: Multiple unproven identities claiming Volley")]
    AmbiguousOwnership,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HandoverProof {
    pub volley_id: VolleyId,
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
    pub response: VolleyResponse,
    pub attempt_count: u32,
    pub next_attempt: PhalanxTimestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StorageAck {
    Success(VolleyId, NetworkId),
    Failure(ShardError, NetworkId),
}
