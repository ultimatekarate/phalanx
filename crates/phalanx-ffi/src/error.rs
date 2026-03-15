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
}

impl PhalanxError {
    /// Convert to the raw i32 code returned across the C-ABI boundary.
    #[must_use]
    pub fn code(self) -> i32 {
        self as i32
    }
}
