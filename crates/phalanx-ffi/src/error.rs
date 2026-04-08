// crates/phalanx-ffi/src/error.rs
//
// The Larynx's diagnostic vocabulary.
// Every FFI function returns an i32 status code. Zero is success; negative is failure.
// This is the C-ABI contract: no panics, no exceptions, no Result<T,E> across the boundary.

/// FFI error codes returned by all `extern "C"` functions.
///
/// Contract: every public FFI function returns `PhalanxError as i32`.
/// The Dart wrapper maps these to typed exceptions.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhalanxError {
    /// Operation completed successfully.
    Ok = 0,
    /// A null pointer was passed where a valid pointer was required.
    NullPointer = -1,
    /// The handle is in an invalid state for the requested operation.
    InvalidState = -2,
    /// A C-string argument contained invalid UTF-8.
    InvalidUtf8 = -3,
    /// Engine bootstrap failed (config, identity, vault, swarm, or sentinel).
    BootFailed = -4,
    /// The engine is already running; duplicate `phalanx_start` calls.
    AlreadyRunning = -5,
    /// The engine is not running; operation requires a running engine.
    NotRunning = -6,
    /// An internal mpsc/oneshot channel was closed unexpectedly.
    ChannelClosed = -7,
    /// A trust registry operation failed.
    TrustError = -8,
    /// A playback operation failed.
    PlaybackError = -9,
    /// Configuration loading or validation failed.
    ConfigError = -10,
    /// Recording is already active; duplicate `phalanx_start_recording` calls.
    AlreadyRecording = -11,
    /// No active recording to stop or push frames to.
    NotRecording = -12,
    /// Cryptographic Forgetting: revocation failed (bad mnemonic, key mismatch, or storage error).
    RevocationFailed = -13,
    /// Community ceremony failed (invalid vouch, quorum not met, expired, etc.).
    CeremonyFailed = -14,
}

impl PhalanxError {
    /// Convert to the raw i32 code returned across the C-ABI boundary.
    #[must_use]
    pub fn code(self) -> i32 {
        self as i32
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_are_stable() {
        // These values are part of the C-ABI contract.
        // Changing them breaks all Dart code.
        assert_eq!(PhalanxError::Ok.code(), 0);
        assert_eq!(PhalanxError::NullPointer.code(), -1);
        assert_eq!(PhalanxError::InvalidState.code(), -2);
        assert_eq!(PhalanxError::InvalidUtf8.code(), -3);
        assert_eq!(PhalanxError::BootFailed.code(), -4);
        assert_eq!(PhalanxError::AlreadyRunning.code(), -5);
        assert_eq!(PhalanxError::NotRunning.code(), -6);
        assert_eq!(PhalanxError::ChannelClosed.code(), -7);
        assert_eq!(PhalanxError::TrustError.code(), -8);
        assert_eq!(PhalanxError::PlaybackError.code(), -9);
        assert_eq!(PhalanxError::ConfigError.code(), -10);
        assert_eq!(PhalanxError::AlreadyRecording.code(), -11);
        assert_eq!(PhalanxError::NotRecording.code(), -12);
        assert_eq!(PhalanxError::RevocationFailed.code(), -13);
        assert_eq!(PhalanxError::CeremonyFailed.code(), -14);
    }

    #[test]
    fn error_codes_are_all_unique() {
        let codes: Vec<i32> = vec![
            PhalanxError::Ok.code(),
            PhalanxError::NullPointer.code(),
            PhalanxError::InvalidState.code(),
            PhalanxError::InvalidUtf8.code(),
            PhalanxError::BootFailed.code(),
            PhalanxError::AlreadyRunning.code(),
            PhalanxError::NotRunning.code(),
            PhalanxError::ChannelClosed.code(),
            PhalanxError::TrustError.code(),
            PhalanxError::PlaybackError.code(),
            PhalanxError::ConfigError.code(),
            PhalanxError::AlreadyRecording.code(),
            PhalanxError::NotRecording.code(),
            PhalanxError::RevocationFailed.code(),
            PhalanxError::CeremonyFailed.code(),
        ];

        let mut sorted = codes.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted.len(), codes.len(), "Duplicate error codes detected");
    }

    #[test]
    fn ok_is_zero_errors_are_negative() {
        assert_eq!(PhalanxError::Ok.code(), 0);

        let error_variants = [
            PhalanxError::NullPointer,
            PhalanxError::InvalidState,
            PhalanxError::InvalidUtf8,
            PhalanxError::BootFailed,
            PhalanxError::AlreadyRunning,
            PhalanxError::NotRunning,
            PhalanxError::ChannelClosed,
            PhalanxError::TrustError,
            PhalanxError::PlaybackError,
            PhalanxError::ConfigError,
            PhalanxError::AlreadyRecording,
            PhalanxError::NotRecording,
            PhalanxError::RevocationFailed,
            PhalanxError::CeremonyFailed,
        ];

        for variant in &error_variants {
            assert!(
                variant.code() < 0,
                "Error {variant:?} has non-negative code {}",
                variant.code()
            );
        }
    }
}
