// crates/phalanx-ffi/tests/ffi_roundtrip.rs
//
// Integration tests for the phalanx-ffi C-ABI boundary are in src/ modules
// as #[cfg(test)] unit tests.
//
// cdylib/staticlib crates cannot be imported by Rust integration tests
// (no rlib output). All FFI tests live as #[cfg(test)] modules within:
//   - src/error.rs   — error code stability
//   - src/memory.rs  — free function safety
//   - src/probe.rs   — atomics + HardwareProbe trait
//   - src/handle.rs  — null pointer safety on lifecycle functions
//   - src/status.rs  — null pointer safety on status queries
//   - src/capture.rs — null pointer safety on capture functions
//
// Run with: cargo test -p phalanx-ffi --lib
