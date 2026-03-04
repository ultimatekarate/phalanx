// crates/phalanx-proto/src/storage.rs

pub use crate::time::TimeError;
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
    TimeSource(#[from] TimeError),
    #[error("Cryptographic signing failed: {0}")]
    SigningError(String),
    #[error("Encryption error: {0}")]
    Encryption(String),
    #[error("Disk I/O failed: {0}")]
    Io(String),
    #[error("Decompression Error: {0}")]
    DecompressionFailure(String),
    #[error("Invalid Signature: {0}")]
    InvalidSignature(String),
    #[error("Salvage operation failed: {0}")]
    SalvageError(String),
    #[error("Not enough reputation")]
    Unauthorized(String),
    #[error("Size cannot be 0")]
    InvalidSize(String),
    #[error("Shard verification failed")]
    VerificationFailed,
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

#[derive(Debug, thiserror::Error, Serialize, Deserialize)]
pub enum LocatorError {
    #[error("Locator input is malformed or incorrectly delimited")]
    MalformedInput,
    #[error("Locator is missing the required author/signer field")]
    MissingAuthor,
    #[error("Locator scheme is unsupported or invalid: {0}")]
    InvalidScheme(String),
    #[error("Locator payload exceeds maximum forensic length: {0}")]
    PayloadTooLarge(usize),
    #[error("Cryptographic signature in locator failed verification")]
    SignatureMismatch,
    #[error("Internal encoding error: {0}")]
    Encoding(String),
    #[error("Missing fragment (Decryption Key)")]
    MissingKey,
    #[error("Malformatted component")]
    ParseError,
    #[error("Locator is missing a recipient.")]
    MissingRecipient,
}
