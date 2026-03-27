// crates/phalanx-proto/src/error.rs

use crate::crypto::CryptoError;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, thiserror::Error)]
pub enum ShardError {
    #[error("Dataset capacity exceeded: {0} exceeds u32 limit")]
    CapacityExceeded(u64),
    #[error("Invalid shard configuration: {0}")]
    InvalidConfiguration(String),
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Cryptographic signing failed: {0}")]
    SigningError(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Disk I/O failed: {0}")]
    Io(String),
    #[error("Not enough reputation")]
    Unauthorized(String),
    #[error("Size cannot be 0")]
    InvalidSize(String),
    #[error("Recording has been revoked")]
    RecordingRevoked,
}

impl From<postcard::Error> for ShardError {
    fn from(e: postcard::Error) -> Self {
        ShardError::SerializationError(e.to_string())
    }
}

impl From<CryptoError> for ShardError {
    fn from(e: CryptoError) -> Self {
        ShardError::Encryption(e.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("Entropy generation failed: {0}")]
    EntropyError(String),
    #[error("Mnemonic parsing failed: {0}")]
    MnemonicError(String),
    #[error("Cryptographic derivation failed: {0}")]
    CryptoError(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Identity data corruption: {0}")]
    Corruption(String),
}
