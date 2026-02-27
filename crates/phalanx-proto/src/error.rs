#[derive(Debug, thiserror::Error)]
pub enum ShardError {
    #[error("Dataset capacity exceeded: calculated chunk count {0} exceeds u32 limit")]
    CapacityExceeded(u64),

    #[error("Invalid shard configuration: {0}")]
    InvalidConfiguration(String),

    #[error("Serialization failed: {0}")]
    SerializationError(String),

    #[error("Time source error.")]
    TimeSource(#[from] TimeError),

    #[error("Cryptographic signing failed: {0}")]
    SigningError(String),

    #[error("Encryption error: {0}")]
    Encryption(#[from] CryptoError),

    // NEW: Required for Write-Ahead Log disk operations
    #[error("Disk I/O failed: {0}")]
    Io(#[from] std::io::Error),

    #[error("Decompression Error: {0}")]
    DecompressionFailure(String),

    #[error("Invalid Signature: {0}")]
    InvalidSignature(String),

    #[error("Invalid Signature: {0}")]
    SalvageError(String),
}

#[derive(Debug, thiserror::Error)]
pub enum TimeError {
    #[error("Clock skew detected: timestamp is in the future")]
    FutureTimestamp,
    #[error("Resource expired")]
    Expired,
}


#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Critical startup failure: {0}")]
    StartupFailure(String),
    #[error("Identity subsystem failure: {0}")]
    Identity(#[from] IdentityError),
    #[error("Forensic persistence error: {0}")]
    Io(#[from] io::Error),
    #[error("Time synchronization error: {0}")]
    Time(#[from] TimeError),
    #[error("Fatal simulator state: {0}")]
    Simulation(String),
    #[error("Security breach: {0}")]
    SecurityBreach(String),
    #[error("Critical storage failure: {0}")]
    StorageFailure(String),
}
