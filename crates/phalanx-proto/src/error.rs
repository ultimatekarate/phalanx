// crates/phalanx-proto/src/storage.rs

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum ShardError {
    #[error("Dataset capacity exceeded: {0} exceeds u32 limit")]
    CapacityExceeded(u64),

    #[error("Invalid shard configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Serialization failed: {0}")]
    SerializationError(String),

    #[error("Time source error: {0}")]
    TimeSource(#[from] TimeError), // TimeError must now be serializable too!

    #[error("Cryptographic signing failed: {0}")]
    SigningError(String),

    #[error("Encryption error: {0}")]
    Encryption(String),

    // THE FIX: We store the string representation for serialization
    #[error("Disk I/O failed: {0}")]
    Io(String),

    #[error("Decompression Error: {0}")]
    DecompressionFailure(String),

    #[error("Invalid Signature: {0}")]
    InvalidSignature(String),

    #[error("Salvage operation failed: {0}")] // Fixed duplicate error message
    SalvageError(String),

    #[error("Not enough reputation")]
    Unauthorized(String),
}

// Manually implement From<io::Error> to handle the string conversion
impl From<std::io::Error> for ShardError {
    fn from(err: std::io::Error) -> Self {
        ShardError::Io(err.to_string())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, thiserror::Error)]
pub enum TimeError {
    #[error("Clock skew detected: timestamp is in the future")]
    FutureTimestamp,

    #[error("Resource expired")]
    Expired,

    #[error("Stale: {0}ms behind")]
    Stale(u64),

    #[error("Future: {0}ms ahead")]
    Future(u64),
}

// In phalanx-node or a local module
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Critical startup failure: {0}")]
    StartupFailure(String),

    #[error("Identity subsystem failure: {0}")]
    Identity(String),

    #[error("Forensic persistence error: {0}")]
    Io(#[from] std::io::Error), // This works now because we aren't serializing

    #[error("Time synchronization error: {0}")]
    Time(#[from] TimeError),

    #[error("Fatal simulator state: {0}")]
    Simulation(String),

    #[error("Security breach: {0}")]
    SecurityBreach(String),

    #[error("Critical storage failure: {0}")]
    StorageFailure(String),
}
