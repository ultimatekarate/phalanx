use std::time::Duration;

// crates/phalanx-proto/src/constants.rs
pub const SERVICE_STORAGE: &[u8] = b"phalanx/service/storage/v1";
pub const STRONGHOLD_NAMESPACE: &[u8] = b"phalanx.stronghold.v1";
pub const RETRIEVAL_PROTOCOL_ID: &str = "/phalanx/retrieval/1.0.0";
pub const VOLLEY_SIZE_THRESHOLD: usize = 50;
pub const VOLLEY_TIME_THRESHOLD: Duration = Duration::from_secs(1);

#[derive(Debug, thiserror::Error)]
pub enum DiscoveryError {
    #[error("Failed to serialize provider record")]
    SerializationError,
    #[error("DHT store is full or unavailable")]
    StorageError,
}
