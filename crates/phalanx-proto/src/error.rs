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
    #[error(
        "Identity file is from an older schema (v{from}) and must be upgraded to v{to}; \
         re-restore from your BIP39 phrase to derive the DEK master"
    )]
    SchemaUpgradeRequired { from: u32, to: u32 },
    #[error("Identity file declares unsupported schema version: {0}")]
    UnknownVersion(u32),
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn shard_error_capacity_exceeded_display_includes_inner_value() {
        // Display strings show up in logs and audit records — the capacity
        // number is the only way an operator distinguishes a 10GB-overflow
        // from a u32-overflow. Regression guard against dropping the value.
        let err = ShardError::CapacityExceeded(u64::MAX);
        let rendered = err.to_string();
        assert!(
            rendered.contains(&u64::MAX.to_string()),
            "Display should include inner value, got: {rendered}"
        );
    }

    #[test]
    fn shard_error_from_postcard_preserves_variant() {
        // postcard errors must land in SerializationError — routing them elsewhere
        // would mask deserialization bugs as cryptographic or capacity failures.
        let postcard_err: postcard::Error =
            postcard::from_bytes::<u32>(&[]).expect_err("empty input must fail");
        let shard_err: ShardError = postcard_err.into();
        assert!(
            matches!(shard_err, ShardError::SerializationError(_)),
            "postcard::Error must convert to ShardError::SerializationError, got {shard_err:?}"
        );
    }

    #[test]
    fn shard_error_serde_roundtrip_preserves_variant_and_payload() {
        // ShardError crosses the wire in StorageAck::Failure. Confirm that
        // all variants with payloads survive a postcard roundtrip.
        let cases = [
            ShardError::CapacityExceeded(1_234_567),
            ShardError::InvalidConfiguration("bad".into()),
            ShardError::Unauthorized("no rep".into()),
            ShardError::RecordingRevoked,
        ];
        for original in cases {
            let bytes = postcard::to_allocvec(&original).expect("serialize");
            let recovered: ShardError = postcard::from_bytes(&bytes).expect("deserialize");
            assert_eq!(
                std::mem::discriminant(&original),
                std::mem::discriminant(&recovered),
                "variant tag drift for {original:?}"
            );
            assert_eq!(original.to_string(), recovered.to_string());
        }
    }

    #[test]
    fn identity_error_display_includes_reason() {
        // IdentityError is not Serialize (it wraps io-ish reasons), but its
        // Display is load-bearing for the UI and CLI.
        let err = IdentityError::MnemonicError("word 13 invalid".into());
        let rendered = err.to_string();
        assert!(rendered.contains("word 13 invalid"), "got: {rendered}");
    }
}
