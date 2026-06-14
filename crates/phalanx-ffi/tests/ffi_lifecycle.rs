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
use phalanx_ffi::handle::{
    phalanx_create, phalanx_create_with_profile, phalanx_destroy, phalanx_start, phalanx_stop,
};
use phalanx_ffi::profile::{phalanx_profile_flags, phalanx_validate_pairing};
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

/// **N1 regression — unified `recording_active` flag.**
///
/// Pre-cleanup, `PhalanxHandle::recording_active` was a standalone
/// `AtomicBool` that `capture.rs:phalanx_start_recording` wrote
/// directly, while the engine's `RecordingSessionState` had its own
/// flag flipped by `start_recording` / `stop_recording`. The two
/// could drift if any caller wrote one without the other.
///
/// Post-cleanup, the handle's field is an `Arc<AtomicBool>` cloned
/// from the engine at bootstrap; `phalanx_start_recording` dispatches
/// `SentinelCommand::SetRecordingState` which causes the *engine* to
/// flip the (shared) atomic. This test confirms the FFI-visible flag
/// reflects engine-side writes — i.e. that there's actually only one
/// flag now, not two.
/// **N1 regression — unified `recording_active` flag.**
///
/// Pre-cleanup, `PhalanxHandle::recording_active` was a standalone
/// `AtomicBool` that `capture.rs:phalanx_start_recording` wrote
/// directly, while the engine's `RecordingSessionState` had its own
/// flag flipped by `start_recording` / `stop_recording`. The two
/// could drift if any caller wrote one without the other.
///
/// Post-cleanup, the handle's field is an `Arc<AtomicBool>` cloned
/// from the engine at bootstrap; `phalanx_start_recording` dispatches
/// `SentinelCommand::SetRecordingState` which causes the *engine* to
/// flip the (shared) atomic. This test confirms the FFI-visible flag
/// reflects engine-side writes — observed via the public
/// `phalanx_is_recording` query — i.e. that there's actually only
/// one flag now, not two.
#[test]
fn phalanx_start_recording_flips_unified_recording_active_via_engine() {
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

        // Pre-condition: no recording active. Use the public query —
        // the test must not poke private fields, so any future change
        // that breaks the C-ABI signal here is caught.
        let pre = unsafe { phalanx_ffi::status::phalanx_is_recording(handle) };
        assert_eq!(pre, 0, "phalanx_is_recording starts at 0");

        // Drive phalanx_start_recording — routes through SentinelCommand.
        let mut out_id: *mut std::os::raw::c_char = std::ptr::null_mut();
        let code = unsafe {
            phalanx_ffi::capture::phalanx_start_recording(
                handle,
                &mut out_id as *mut *mut std::os::raw::c_char,
            )
        };
        assert_eq!(code, PhalanxError::Ok.code(), "phalanx_start_recording");

        // The engine processed SetRecordingState and flipped the shared atomic.
        let post_start = unsafe { phalanx_ffi::status::phalanx_is_recording(handle) };
        assert_eq!(
            post_start, 1,
            "phalanx_is_recording is 1 after phalanx_start_recording (engine is the writer)"
        );

        // And the inverse via phalanx_stop_recording.
        let code = unsafe { phalanx_ffi::capture::phalanx_stop_recording(handle) };
        assert_eq!(code, PhalanxError::Ok.code(), "phalanx_stop_recording");

        let post_stop = unsafe { phalanx_ffi::status::phalanx_is_recording(handle) };
        assert_eq!(
            post_stop, 0,
            "phalanx_is_recording back to 0 after phalanx_stop_recording"
        );

        unsafe {
            if !out_id.is_null() {
                phalanx_ffi::memory::phalanx_free_string(out_id);
            }
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

// ── Profile-picker entry points (the phone leg) ─────────────────────────────

/// Hold a `CString` alive while its raw pointer is passed across the boundary.
fn cstr(s: &str) -> CString {
    CString::new(s).expect("no interior NUL")
}

#[test]
fn profile_create_solo_then_destroy() {
    // SoloDevice needs no companion data: a null pairing boots on defaults.
    under_timeout(Duration::from_secs(30), || {
        let env = TestEnv::new();
        let profile = cstr("solo_device");
        let mut genesis: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = unsafe {
            phalanx_create_with_profile(
                profile.as_ptr(),
                std::ptr::null(), // stronghold_addr
                std::ptr::null(), // stronghold_did
                env.storage_cstr.as_ptr(),
                env.passphrase_cstr.as_ptr(),
                &mut genesis as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(!handle.is_null(), "solo_device must boot");
        unsafe {
            phalanx_destroy(handle);
            if !genesis.is_null() {
                phalanx_ffi::memory::phalanx_free_string(genesis);
            }
        }
    });
}

#[test]
fn profile_create_community_unpaired_boots() {
    // CommunityWithStronghold boots WITHOUT a pairing: the replica-count
    // shortfall is only a warn, so passive gossip works before pairing.
    under_timeout(Duration::from_secs(30), || {
        let env = TestEnv::new();
        let profile = cstr("community_with_stronghold");
        let mut genesis: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = unsafe {
            phalanx_create_with_profile(
                profile.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                env.storage_cstr.as_ptr(),
                env.passphrase_cstr.as_ptr(),
                &mut genesis as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(!handle.is_null(), "un-paired Community must still boot");
        unsafe {
            phalanx_destroy(handle);
            if !genesis.is_null() {
                phalanx_ffi::memory::phalanx_free_string(genesis);
            }
        }
    });
}

#[test]
fn profile_create_community_paired_boots() {
    // A well-formed, dialable (/p2p/-tailed) pairing boots — the dial itself is
    // best-effort, so an unreachable target does not block bootstrap.
    under_timeout(Duration::from_secs(45), || {
        let env = TestEnv::new();
        let profile = cstr("community_with_stronghold");
        let addr = cstr("/ip4/127.0.0.1/udp/4001/quic-v1/p2p/12D3KooWStronghold");
        let did = cstr("did:key:z6MkStronghold");
        let mut genesis: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = unsafe {
            phalanx_create_with_profile(
                profile.as_ptr(),
                addr.as_ptr(),
                did.as_ptr(),
                env.storage_cstr.as_ptr(),
                env.passphrase_cstr.as_ptr(),
                &mut genesis as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(!handle.is_null(), "paired Community must boot");
        unsafe {
            phalanx_destroy(handle);
            if !genesis.is_null() {
                phalanx_ffi::memory::phalanx_free_string(genesis);
            }
        }
    });
}

#[test]
fn profile_create_rejects_malformed_pairing_and_unknown_profile() {
    under_timeout(Duration::from_secs(30), || {
        // Community + an address with NO /p2p/ tail → hard UndialableArchivalPeer.
        let env = TestEnv::new();
        let profile = cstr("community_with_stronghold");
        let bad_addr = cstr("/ip4/1.2.3.4/udp/4001/quic-v1");
        let mut genesis: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle = unsafe {
            phalanx_create_with_profile(
                profile.as_ptr(),
                bad_addr.as_ptr(),
                std::ptr::null(),
                env.storage_cstr.as_ptr(),
                env.passphrase_cstr.as_ptr(),
                &mut genesis as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(handle.is_null(), "addr without /p2p/ tail must be rejected");

        // Unknown profile name → null (no silent default).
        let env2 = TestEnv::new();
        let nonsense = cstr("nonsense");
        let mut genesis2: *mut std::os::raw::c_char = std::ptr::null_mut();
        let handle2 = unsafe {
            phalanx_create_with_profile(
                nonsense.as_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                env2.storage_cstr.as_ptr(),
                env2.passphrase_cstr.as_ptr(),
                &mut genesis2 as *mut *mut std::os::raw::c_char,
            )
        };
        assert!(handle2.is_null(), "unknown profile must be rejected");
    });
}

#[test]
fn validate_pairing_verdicts() {
    // Well-formed dialable address → Ok.
    let good = cstr("/ip4/10.0.0.5/udp/4001/quic-v1/p2p/12D3KooWStronghold");
    assert_eq!(
        unsafe { phalanx_validate_pairing(good.as_ptr(), std::ptr::null()) },
        PhalanxError::Ok.code()
    );
    // No /p2p/ tail → ConfigError (the same verdict `create` reaches at assemble).
    let bad = cstr("/ip4/10.0.0.5/udp/4001/quic-v1");
    assert_eq!(
        unsafe { phalanx_validate_pairing(bad.as_ptr(), std::ptr::null()) },
        PhalanxError::ConfigError.code()
    );
    // Null address → NullPointer.
    assert_eq!(
        unsafe { phalanx_validate_pairing(std::ptr::null(), std::ptr::null()) },
        PhalanxError::NullPointer.code()
    );
}

#[test]
fn profile_flags_match_capability() {
    let flag = |name: &str| {
        let c = cstr(name);
        unsafe { phalanx_profile_flags(c.as_ptr()) }
    };
    // bit0=known(1), bit1=needs_stronghold(2), bit2=requires_psk(4).
    assert_eq!(flag("solo_device"), 1);
    assert_eq!(flag("community_with_stronghold"), 3);
    assert_eq!(flag("affinity_group_lan"), 5);
    assert_eq!(flag("high_risk_cross_border"), 7);
    // Internal / unknown names are not addressable → negative (ConfigError).
    assert_eq!(flag("simulation"), PhalanxError::ConfigError.code());
    assert!(flag("nonsense") < 0);
}
