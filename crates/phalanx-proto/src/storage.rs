// crates/phalanx-proto/src/storage.rs
use crate::time::TimeError;
use crate::types::ByteCapacity;
use serde::{Deserialize, Serialize};
#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
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

    #[error("Chain Integrity Violation")]
    ChainIntegrityViolation,
}
