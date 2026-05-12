#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
//! FFI-boundary panic-safety tests.
//!
//! The panic boundary in `phalanx_create` and `phalanx_export_c2pa`
//! exists to catch panics from third-party code (notably `c2pa` on
//! malformed manifest assertions, or `libp2p`/`postcard` on
//! corrupted persisted data) and convert them to status codes instead
//! of unwinding across the `extern "C"` boundary — which on modern
//! Rust would abort the process.
//!
//! Verification has three layers, none of which is sufficient alone:
//!
//! 1. **Helper unit tests** (`src/panic_safety.rs` `#[cfg(test)] mod
//!    tests`): prove `ffi_panic_safe` catches a deliberate panic and
//!    returns the fallback, for both `i32` and pointer return types.
//!    Direct, fast, but doesn't prove the helper is *applied* to the
//!    production functions.
//!
//! 2. **This file**: confirms the wrapped happy and early-reject paths
//!    still work as expected after wrapping — i.e. the panic boundary
//!    is transparent to non-panicking calls. A regression that
//!    accidentally broke marshalling inside the wrapper would surface
//!    here. Doesn't prove the boundary fires on a real panic.
//!
//! 3. **Code review** (or a `tests/ui/` trybuild check, future work):
//!    confirms the body of `phalanx_create` and `phalanx_export_c2pa`
//!    is wrapped in `ffi_panic_safe(...)`. Triggering a *real* panic
//!    in those bodies from outside the crate is infeasible without
//!    a test-only injection hook — the panic-prone code paths are
//!    deep inside `c2pa::Builder::sign` or `setup_transport` and
//!    require specific malformed-state inputs that the public FFI
//!    signature doesn't expose. This layer is therefore manual.
//!
//! Layers 1 and 2 give CI-level coverage. Layer 3 is part of the audit
//! commit message and the documentation in `panic_safety.rs`.

use phalanx_ffi::error::PhalanxError;
use phalanx_ffi::handle::{phalanx_create, phalanx_destroy};
use std::ffi::CString;

/// The wrapped `phalanx_create` still returns a usable handle on the
/// happy path. If the `ffi_panic_safe` wrapper accidentally swallowed a
/// successful return (e.g. wrong `Ok(v) => v` mapping), this would
/// regress.
#[test]
fn wrapped_phalanx_create_returns_non_null_on_happy_path() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let storage_cstr =
        CString::new(tempdir.path().to_string_lossy().as_ref()).expect("storage path");
    let passphrase_cstr = CString::new("panic-safety-happy-path").expect("passphrase");
    let mut genesis_phrase: *mut std::os::raw::c_char = std::ptr::null_mut();

    let handle = unsafe {
        phalanx_create(
            std::ptr::null(),
            storage_cstr.as_ptr(),
            passphrase_cstr.as_ptr(),
            &mut genesis_phrase as *mut *mut std::os::raw::c_char,
        )
    };
    assert!(
        !handle.is_null(),
        "wrapped phalanx_create must succeed on a healthy bootstrap"
    );

    unsafe {
        phalanx_destroy(handle);
        if !genesis_phrase.is_null() {
            phalanx_ffi::memory::phalanx_free_string(genesis_phrase);
        }
    }
}

/// Early-reject paths (null required pointers) still return the right
/// null sentinel. The panic-safety wrapper must not mask the
/// "return early on null arg" semantics — those checks happen *inside*
/// the wrapped body and propagate out through the `Ok(null_mut)` arm
/// of `ffi_panic_safe`.
#[test]
fn wrapped_phalanx_create_returns_null_for_null_storage_path() {
    let passphrase_cstr = CString::new("panic-safety-null-storage").expect("passphrase");
    let mut genesis_phrase: *mut std::os::raw::c_char = std::ptr::null_mut();

    let handle = unsafe {
        phalanx_create(
            std::ptr::null(),
            std::ptr::null(), // ← null storage path: must reject
            passphrase_cstr.as_ptr(),
            &mut genesis_phrase as *mut *mut std::os::raw::c_char,
        )
    };
    assert!(
        handle.is_null(),
        "wrapped phalanx_create must reject null storage_path with null return"
    );
}

#[test]
fn wrapped_phalanx_create_returns_null_for_null_passphrase() {
    let tempdir = tempfile::tempdir().expect("tempdir");
    let storage_cstr =
        CString::new(tempdir.path().to_string_lossy().as_ref()).expect("storage path");
    let mut genesis_phrase: *mut std::os::raw::c_char = std::ptr::null_mut();

    let handle = unsafe {
        phalanx_create(
            std::ptr::null(),
            storage_cstr.as_ptr(),
            std::ptr::null(), // ← null passphrase: must reject
            &mut genesis_phrase as *mut *mut std::os::raw::c_char,
        )
    };
    assert!(
        handle.is_null(),
        "wrapped phalanx_create must reject null passphrase with null return"
    );
}

/// Confirms `PhalanxError::Panic` has the expected stable code (-18).
/// The integration tests above can't trigger a real panic, but if the
/// helper *does* fire in production it must return this exact code so
/// the Dart wrapper can map it. Pin the constant here so a reorder of
/// the enum variants is caught by CI.
#[test]
fn panic_error_code_is_minus_eighteen() {
    assert_eq!(
        PhalanxError::Panic.code(),
        -18,
        "PhalanxError::Panic must be -18 (C-ABI contract; Dart side maps it)"
    );
}
