#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::undocumented_unsafe_blocks
)]
//! FFI-boundary regression tests for the H1/H2/H3 deadlock class.
//!
//! Each function exercises one FFI entry point that used to deadlock
//! against `engine.run()`'s long-held borrow on the sentinel:
//!
//! * **H2** — `phalanx_set_recording_state` (was: `sentinel_ref.lock().await`
//!   inside a `block_on`). Fixed by dispatching
//!   `SentinelCommand::SetRecordingState` through the sentinel mailbox.
//! * **H3** — `phalanx_start_recovery` (same lock pattern, but inside a
//!   `tokio::spawn` so the function returned 0 immediately and the
//!   recovery silently stalled in `Idle`). Fixed by
//!   `SentinelCommand::SpawnRecovery`. The test must therefore assert
//!   *progress*, not just return code.
//!
//! (H1 covered `phalanx_sign_ble_challenge`, removed with the BLE/local-mesh
//! excision; H2/H3 still guard the same FFI-vs-engine deadlock class.)
//!
//! Both tests run under a hard timeout: deadlocks must fail loudly
//! rather than hang CI.

use phalanx_ffi::error::PhalanxError;
use phalanx_ffi::handle::{phalanx_create, phalanx_destroy, phalanx_start, phalanx_stop};
use std::ffi::CString;
use std::time::Duration;

struct TestEnv {
    _tempdir: tempfile::TempDir,
    storage_cstr: CString,
    passphrase_cstr: CString,
}

impl TestEnv {
    fn new() -> Self {
        let tempdir = tempfile::tempdir().expect("tempdir");
        let storage_cstr =
            CString::new(tempdir.path().to_string_lossy().as_ref()).expect("storage path");
        let passphrase_cstr = CString::new("ffi-deadlock-regression-test").expect("passphrase");
        Self {
            _tempdir: tempdir,
            storage_cstr,
            passphrase_cstr,
        }
    }
}

/// Spawn `body` on a thread and join with a hard timeout. Used to catch
/// deadlocks: any FFI call that should return in <1s but blocks forever
/// will exceed the budget and fail the test loudly rather than hanging
/// CI indefinitely.
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

/// Bootstrap a full engine and start it. Returns the raw handle pointer.
/// Caller must `phalanx_destroy` it (and free `genesis_phrase` if not null).
unsafe fn create_and_start(
    env: &TestEnv,
) -> (
    *mut phalanx_ffi::handle::PhalanxHandle,
    *mut std::os::raw::c_char,
) {
    unsafe {
        let mut genesis: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = phalanx_create(
            std::ptr::null(),
            env.storage_cstr.as_ptr(),
            env.passphrase_cstr.as_ptr(),
            &mut genesis as *mut *mut std::os::raw::c_char,
        );
        assert!(!handle.is_null(), "phalanx_create must succeed");
        let started = phalanx_start(handle);
        assert_eq!(
            started,
            PhalanxError::Ok.code(),
            "phalanx_start must succeed"
        );
        // Let the engine's run loop tick into steady state before driving it.
        std::thread::sleep(Duration::from_millis(200));
        (handle, genesis)
    }
}

unsafe fn cleanup(
    handle: *mut phalanx_ffi::handle::PhalanxHandle,
    genesis: *mut std::os::raw::c_char,
) {
    unsafe {
        let _ = phalanx_stop(handle);
        phalanx_destroy(handle);
        if !genesis.is_null() {
            phalanx_ffi::memory::phalanx_free_string(genesis);
        }
    }
}

/// **H2 regression**: setting the recording state while the engine is
/// running must complete in milliseconds. Pre-Phase-3b this hung
/// forever via `sentinel.lock().await`. Verifies the SentinelCommand
/// round-trip across the FFI marshalling layer.
#[test]
fn h2_set_recording_state_does_not_deadlock_against_engine_run() {
    under_timeout(Duration::from_secs(60), || {
        let env = TestEnv::new();
        let (handle, genesis) = unsafe { create_and_start(&env) };

        // Start a recording.
        let rec_id = CString::new("h2-regression-recording").expect("rec id");
        let set_start = std::time::Instant::now();
        let code =
            unsafe { phalanx_ffi::community::phalanx_set_recording_state(handle, rec_id.as_ptr()) };
        let elapsed = set_start.elapsed();
        assert_eq!(code, 0, "phalanx_set_recording_state(Some) must succeed");
        assert!(
            elapsed < Duration::from_secs(1),
            "phalanx_set_recording_state took {elapsed:?}; expected <1s"
        );

        // And stop it. Same deadline applies.
        let stop_start = std::time::Instant::now();
        let code = unsafe {
            phalanx_ffi::community::phalanx_set_recording_state(handle, std::ptr::null())
        };
        let elapsed = stop_start.elapsed();
        assert_eq!(code, 0, "phalanx_set_recording_state(None) must succeed");
        assert!(
            elapsed < Duration::from_secs(1),
            "phalanx_set_recording_state(None) took {elapsed:?}; expected <1s"
        );

        unsafe { cleanup(handle, genesis) }
    });
}

/// **H3 regression — silent-stall detection**: the recovery deadlock
/// pre-Phase-3c was particularly nasty because `phalanx_start_recovery`
/// returned 0 immediately (the deadlock was inside a `tokio::spawn`).
/// Status stayed at `Idle` forever. The UI saw "recovery succeeded but
/// found nothing", not "engine deadlocked."
///
/// A return-code test would NOT have caught it. This test must poll
/// `phalanx_recovery_status` and assert the state *advances* past
/// `Idle` within a reasonable window. With no manifest on disk (fresh
/// tempdir) the recovery should walk `Idle → FetchingManifest →
/// NoManifestFound` — but the critical assertion is that *something*
/// happens, not that the walk succeeds.
#[test]
fn h3_start_recovery_advances_past_idle_no_silent_stall() {
    under_timeout(Duration::from_secs(60), || {
        let env = TestEnv::new();
        let (handle, genesis) = unsafe { create_and_start(&env) };

        // Kick off the recovery. Return code is uninformative here.
        let code = unsafe { phalanx_ffi::recovery::phalanx_start_recovery(handle) };
        assert_eq!(
            code,
            PhalanxError::Ok.code(),
            "phalanx_start_recovery must return Ok"
        );

        // Poll status until the state field is no longer Idle, OR the
        // 5-second budget runs out. Pre-Phase-3c this loop would never
        // observe a transition — the engine task is blocked waiting on
        // `sentinel.lock().await`, the orchestrator never starts, and
        // status stays at the freshly-reset Idle.
        let poll_deadline = std::time::Instant::now() + Duration::from_secs(5);
        let (advanced, last_state) = loop {
            let mut out_ptr: *mut u8 = std::ptr::null_mut();
            let mut out_len: u32 = 0;
            let status_code = unsafe {
                phalanx_ffi::recovery::phalanx_recovery_status(
                    handle,
                    &mut out_ptr as *mut *mut u8,
                    &mut out_len as *mut u32,
                )
            };
            assert_eq!(status_code, PhalanxError::Ok.code());
            let snapshot: phalanx_proto::recovery::RecoveryStatus = unsafe {
                let slice = std::slice::from_raw_parts(out_ptr, out_len as usize);
                let decoded = postcard::from_bytes(slice).expect("postcard decode");
                phalanx_ffi::memory::phalanx_free_bytes(out_ptr, out_len);
                decoded
            };
            let is_idle = matches!(snapshot.state, phalanx_proto::recovery::RecoveryState::Idle);
            if !is_idle {
                break (true, snapshot.state);
            }
            if std::time::Instant::now() >= poll_deadline {
                break (false, snapshot.state);
            }
            std::thread::sleep(Duration::from_millis(100));
        };

        assert!(
            advanced,
            "recovery state stayed at Idle for 5s — silent stall regression. \
            last observed state: {last_state:?}"
        );

        // Cancellation is best-effort; we don't assert on it.
        let _ = unsafe { phalanx_ffi::recovery::phalanx_cancel_recovery(handle) };

        unsafe { cleanup(handle, genesis) }
    });
}
