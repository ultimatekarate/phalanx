#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::undocumented_unsafe_blocks
)]
//! FFI-boundary lifecycle tests.
//!
//! Exercises the C-ABI surface end-to-end:
//! `phalanx_create → phalanx_start → phalanx_stop → phalanx_destroy`.
//!
//! These tests link against `phalanx-ffi` as an `rlib` (added to
//! `crate-type` for this purpose) so the actual `extern "C"` entry
//! points are invoked the same way a Flutter caller would invoke them
//! — through `unsafe` Rust calls instead of FFI marshalling, but the
//! function bodies and the bootstrap path are identical.
//!
//! Each test creates a fresh tempdir for the vault and identity, runs
//! the lifecycle under a `tokio::time::timeout`, and asserts the call
//! returns rather than hanging.

use phalanx_ffi::error::PhalanxError;
use phalanx_ffi::handle::{phalanx_create, phalanx_destroy, phalanx_start, phalanx_stop};
use std::ffi::CString;
use std::path::PathBuf;
use std::time::Duration;

/// Set up a tempdir + CString paths for `phalanx_create`. Returns the
/// dir guard (must outlive the handle) and the passphrase CString.
struct TestEnv {
    _tempdir: tempfile::TempDir,
    storage_cstr: CString,
    passphrase_cstr: CString,
}

impl TestEnv {
    fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let storage_path: PathBuf = tempdir.path().to_path_buf();
        let storage_cstr = CString::new(storage_path.to_string_lossy().as_ref())
            .expect("storage path has no NULs");
        let passphrase_cstr =
            CString::new("ffi-lifecycle-test-passphrase").expect("passphrase has no NULs");
        Self {
            _tempdir: tempdir,
            storage_cstr,
            passphrase_cstr,
        }
    }
}

/// Run a body under a hard timeout — the whole point of these tests is
/// to catch deadlocks, so blocking forever must fail loudly rather than
/// hang CI. Runs the body on a dedicated thread so the test can join
/// with a timeout (block_on can't be timed out from sync code).
fn under_timeout<F>(timeout: Duration, body: F)
where
    F: FnOnce() + Send + 'static,
{
    let handle = std::thread::spawn(body);
    let start = std::time::Instant::now();
    while !handle.is_finished() {
        if start.elapsed() > timeout {
            panic!(
                "FFI call exceeded {:?} — likely deadlocked. Aborting test.",
                timeout
            );
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    handle.join().expect("test body panicked");
}

#[test]
fn phalanx_create_then_destroy_completes_quickly() {
    // The shortest possible lifecycle: bootstrap the engine and tear it
    // down without ever calling `phalanx_start`. Exercises identity
    // init, vault salt, journal, trust registry, MobileProbe, and
    // libp2p transport setup — but not the orchestrator run loop.
    under_timeout(Duration::from_secs(30), || {
        let env = TestEnv::new();
        let mut genesis_phrase: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = unsafe {
            phalanx_create(
                std::ptr::null(), // config_path
                env.storage_cstr.as_ptr(),
                env.passphrase_cstr.as_ptr(),
                &mut genesis_phrase as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(!handle.is_null(), "phalanx_create must succeed");
        unsafe {
            phalanx_destroy(handle);
            // Free the genesis phrase too (returned for first-boot).
            if !genesis_phrase.is_null() {
                phalanx_ffi::memory::phalanx_free_string(genesis_phrase);
            }
        }
    });
}

#[test]
fn phalanx_full_lifecycle_completes_quickly() {
    // Full lifecycle: create → start → stop → destroy. This is the
    // shape the audit's H2/H3 regression tests need — without
    // `phalanx_start`, the run loop never holds the borrow that used
    // to cause the deadlock, so this test must pass before deadlock
    // tests for `phalanx_set_recording_state` / `phalanx_start_recovery`
    // can run on top of it.
    under_timeout(Duration::from_secs(45), || {
        let env = TestEnv::new();
        let mut genesis_phrase: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = unsafe {
            phalanx_create(
                std::ptr::null(),
                env.storage_cstr.as_ptr(),
                env.passphrase_cstr.as_ptr(),
                &mut genesis_phrase as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(!handle.is_null(), "phalanx_create must succeed");

        let started = unsafe { phalanx_start(handle) };
        assert_eq!(
            started,
            PhalanxError::Ok.code(),
            "phalanx_start must succeed; got {started}"
        );

        // Give the engine a beat to enter its run loop before stopping.
        // Without this, stop runs before run() actually starts, which
        // still works but doesn't exercise the steady-state shutdown
        // path we're trying to test.
        std::thread::sleep(Duration::from_millis(200));

        let stopped = unsafe { phalanx_stop(handle) };
        assert_eq!(
            stopped,
            PhalanxError::Ok.code(),
            "phalanx_stop must succeed; got {stopped}"
        );

        unsafe {
            phalanx_destroy(handle);
            if !genesis_phrase.is_null() {
                phalanx_ffi::memory::phalanx_free_string(genesis_phrase);
            }
        }
    });
}

#[test]
fn phalanx_destroy_without_stop_drains_cleanly() {
    // M2 regression: `phalanx_destroy` on a still-Running handle must
    // drive the equivalent of `phalanx_stop` first (with its 10s drain
    // deadline) before dropping the runtime. Before the audit-driven
    // fix, `phalanx_destroy` would just `Box::from_raw` and the runtime
    // drop would force-cancel any in-flight shard writes.
    //
    // This test doesn't push frames (no `phalanx_start_recording`); it
    // just confirms the create → start → destroy path completes without
    // hanging. A direct "frame lands on disk" assertion is a follow-up
    // — would need to wire `phalanx_start_recording` and observe the
    // vault.
    under_timeout(Duration::from_secs(45), || {
        let env = TestEnv::new();
        let mut genesis_phrase: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = unsafe {
            phalanx_create(
                std::ptr::null(),
                env.storage_cstr.as_ptr(),
                env.passphrase_cstr.as_ptr(),
                &mut genesis_phrase as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(!handle.is_null());
        let started = unsafe { phalanx_start(handle) };
        assert_eq!(started, PhalanxError::Ok.code());

        std::thread::sleep(Duration::from_millis(200));

        // Skip phalanx_stop entirely — destroy must handle the Running
        // state itself.
        unsafe {
            phalanx_destroy(handle);
            if !genesis_phrase.is_null() {
                phalanx_ffi::memory::phalanx_free_string(genesis_phrase);
            }
        }
    });
}
