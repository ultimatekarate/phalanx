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
    /// Caller-provided output buffer was too small. `*out_len` has been
    /// updated with the required size; retry with a larger buffer.
    /// Part of the two-call query protocol for community query functions.
    BufferTooSmall = -15,
    /// Postcard encoding of a response payload failed. Indicates a bug in
    /// the wire type, not caller error.
    SerializationFailure = -16,
    /// Recovery walk is already in progress; duplicate `phalanx_start_recovery`
    /// or attempt to start a recording / playback while recovery is mid-walk.
    /// Both producer (capture) and the playback path are gated so the
    /// single-tenant providers channel can't be reassigned mid-recovery.
    AlreadyRecovering = -17,
    /// An `extern "C"` body caught a panic from inside Rust code (typically a
    /// third-party crate like `c2pa` on malformed input). The panic was
    /// converted to this error code by an `ffi_body!` wrapper to avoid the
    /// process-abort that would otherwise occur when a panic unwinds across
    /// an `extern "C"` boundary.
    Panic = -18,
    /// BIP-39 mnemonic phrase failed to parse — wordlist or checksum violation.
    /// Split out of `RevocationFailed` so the UI can tell the user "this phrase
    /// isn't a valid BIP-39 phrase" rather than the conflated "phrase invalid
    /// or recording not found."
    MnemonicParseError = -19,
    /// BIP-39 phrase parsed and produced a revocation key, but that key does
    /// not match the revocation key embedded in the target recording. Usually
    /// means the user typed a different identity's phrase, or a typo that
    /// still passes checksum.
    RevocationKeyMismatch = -20,
    /// The recording_id is not present in the local vault and no shards were
    /// discoverable. Distinct from `RevocationKeyMismatch` so a recovering
    /// node can tell "I don't have this yet" apart from "wrong phrase."
    RecordingNotFound = -21,
    /// `phalanx_restore` was called against a `storage_path` that already
    /// contains an `identity.bin`. The caller (UI) must explicitly confirm
    /// destruction of the existing on-device identity before retrying. We
    /// fail closed here rather than silently overwriting — losing the on-disk
    /// identity is destructive even though the mesh-side recordings are
    /// untouched.
    IdentityAlreadyExists = -22,
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
    #[allow(clippy::cognitive_complexity)]
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
        assert_eq!(PhalanxError::BufferTooSmall.code(), -15);
        assert_eq!(PhalanxError::SerializationFailure.code(), -16);
        assert_eq!(PhalanxError::AlreadyRecovering.code(), -17);
        assert_eq!(PhalanxError::Panic.code(), -18);
        assert_eq!(PhalanxError::MnemonicParseError.code(), -19);
        assert_eq!(PhalanxError::RevocationKeyMismatch.code(), -20);
        assert_eq!(PhalanxError::RecordingNotFound.code(), -21);
        assert_eq!(PhalanxError::IdentityAlreadyExists.code(), -22);
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
            PhalanxError::BufferTooSmall.code(),
            PhalanxError::SerializationFailure.code(),
            PhalanxError::AlreadyRecovering.code(),
            PhalanxError::Panic.code(),
            PhalanxError::MnemonicParseError.code(),
            PhalanxError::RevocationKeyMismatch.code(),
            PhalanxError::RecordingNotFound.code(),
            PhalanxError::IdentityAlreadyExists.code(),
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
            PhalanxError::BufferTooSmall,
            PhalanxError::SerializationFailure,
            PhalanxError::AlreadyRecovering,
            PhalanxError::Panic,
            PhalanxError::MnemonicParseError,
            PhalanxError::RevocationKeyMismatch,
            PhalanxError::RecordingNotFound,
            PhalanxError::IdentityAlreadyExists,
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
