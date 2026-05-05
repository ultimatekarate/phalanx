// crates/phalanx-ffi/src/recovery.rs
//
// Recovery FFI — drives the manifest-walk recovery flow from Flutter.
//
// Flow:
// 1. Flutter calls `phalanx_start_recovery(handle)` — kicks off the
//    orchestrator on a background task, returns immediately.
// 2. Flutter polls `phalanx_recovery_status(handle, out_ptr, out_len)`
//    every ~500ms — receives a postcard-encoded `RecoveryStatus` snapshot
//    that the UI renders as a progress bar / state label.
// 3. Optional: Flutter calls `phalanx_cancel_recovery(handle)` to abort
//    the walk. Idempotent.
//
// The recovery task itself lives on the engine's tokio runtime. Cancellation
// is via a oneshot sender stored on the handle. The polled snapshot lives
// behind a `Mutex<RecoveryStatus>` shared between the orchestrator and the
// FFI read side.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;
use crate::logcat::phalanx_log;

use phalanx_proto::recovery::{RecoveryState, RecoveryStatus};

use std::sync::atomic::Ordering;

/// Start a recovery walk: locate the per-identity manifest on the mesh,
/// walk it, and pull every cataloged child recording into the local vault.
///
/// Returns:
/// * `0` on success — the walk has been spawned. Poll
///   `phalanx_recovery_status` to track progress.
/// * `PhalanxError::NullPointer` if `handle` is null.
/// * `PhalanxError::NotRunning` if the engine isn't running.
/// * `PhalanxError::AlreadyRecording` if a recording is currently active.
/// * `PhalanxError::AlreadyRecovering` if a previous recovery is still
///   running.
/// * `PhalanxError::InvalidState` if the engine state is otherwise wrong.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_start_recovery(handle: *const PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if !h.is_running() {
        return PhalanxError::NotRunning.code();
    }

    if h.recording_active.load(Ordering::Relaxed) {
        return PhalanxError::AlreadyRecording.code();
    }

    // Reject a duplicate start while a previous recovery is mid-walk.
    {
        let s = h.recovery_status.lock().unwrap_or_else(|e| e.into_inner());
        if matches!(
            s.state,
            RecoveryState::FetchingManifest
                | RecoveryState::WalkingManifest
                | RecoveryState::FetchingChildren
        ) {
            return PhalanxError::AlreadyRecovering.code();
        }
    }

    // Reset the status snapshot to an Idle baseline so the next poll sees
    // a fresh walk and not the residual `Complete` / `NoManifestFound` /
    // `Cancelled` of the previous run.
    {
        let mut s = h.recovery_status.lock().unwrap_or_else(|e| e.into_inner());
        *s = RecoveryStatus::default();
    }

    let sentinel_arc = {
        let Ok(guard) = h.sentinel.lock() else {
            return PhalanxError::InvalidState.code();
        };
        match guard.as_ref() {
            Some(s) => s.clone(),
            None => return PhalanxError::InvalidState.code(),
        }
    };

    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
    let status = h.recovery_status.clone();

    // Spawn off the runtime, lock the sentinel, call spawn_recovery
    // (which itself spawns on the runtime), and store the resulting
    // JoinHandle. The intermediate task exists because spawn_recovery
    // takes `&mut self` — we need to hold the tokio Mutex on the
    // sentinel to call it. The sentinel run loop holds the Mutex across
    // its main `tokio::select!`; spawn_recovery is called from a separate
    // FFI request path that takes the lock briefly via
    // `Arc<tokio::sync::Mutex<_>>`. That's the same pattern other FFI
    // entry points (e.g. trust commands) use.
    //
    // NOTE: this design path is the one PlaybackCoordinator's callsite
    // already establishes. A future cleanup could expose
    // `spawn_recovery` through a one-shot command on the sentinel
    // mailbox, but for v1 the lock-and-call pattern matches existing
    // playback scaffolding.
    let inner_status = status.clone();
    let join_handle = h.runtime.spawn(async move {
        let mut engine = sentinel_arc.lock().await;
        let recovery_handle = engine.spawn_recovery(inner_status, cancel_rx);
        drop(engine);
        // Await completion of the inner recovery so this outer task's
        // JoinHandle reflects the real recovery lifetime.
        let _ = recovery_handle.await;
    });

    // Replace any prior cancel/handle. Old task is already terminal
    // (we only get here past the `AlreadyRecovering` gate).
    {
        let mut c = h.recovery_cancel.lock().unwrap_or_else(|e| e.into_inner());
        *c = Some(cancel_tx);
    }
    {
        let mut j = h.recovery_handle.lock().unwrap_or_else(|e| e.into_inner());
        *j = Some(join_handle);
    }

    phalanx_log!("[Phalanx FFI] Recovery walk started");
    PhalanxError::Ok.code()
}

/// Postcard-encode a snapshot of the current recovery status. Caller frees
/// the returned bytes via `phalanx_free_bytes` (same lifetime contract as
/// `phalanx_sign_vouch`).
///
/// Returns:
/// * `0` on success — `*out_ptr` and `*out_len` describe a freshly-malloc'd
///   postcard buffer.
/// * `PhalanxError::NullPointer` if any pointer is null.
/// * `PhalanxError::SerializationFailure` if postcard fails (indicates a
///   bug in the wire type, not caller error).
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_ptr` and `out_len` must be writable pointers.
#[no_mangle]
pub unsafe extern "C" fn phalanx_recovery_status(
    handle: *const PhalanxHandle,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    if handle.is_null() || out_ptr.is_null() || out_len.is_null() {
        return PhalanxError::NullPointer.code();
    }
    let h = &*handle;

    let snapshot = {
        let s = h.recovery_status.lock().unwrap_or_else(|e| e.into_inner());
        s.clone()
    };

    let serialized = match postcard::to_allocvec(&snapshot) {
        Ok(bytes) => bytes,
        Err(_) => return PhalanxError::SerializationFailure.code(),
    };

    #[allow(clippy::cast_possible_truncation)]
    let len = serialized.len() as u32;
    let mut boxed = serialized.into_boxed_slice();
    let ptr = boxed.as_mut_ptr();
    std::mem::forget(boxed);

    *out_ptr = ptr;
    *out_len = len;

    PhalanxError::Ok.code()
}

/// Cancel an in-progress recovery walk. Idempotent: calling twice or
/// calling when no recovery is active is a no-op that returns `0`.
///
/// The orchestrator observes the cancel on its next poll iteration
/// (within ~1s) and exits with `state = Cancelled`. Partial state on disk
/// is preserved — a subsequent `phalanx_start_recovery` resumes from
/// where this one left off.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_cancel_recovery(handle: *const PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    let cancel_tx = {
        let mut c = h.recovery_cancel.lock().unwrap_or_else(|e| e.into_inner());
        c.take()
    };

    if let Some(tx) = cancel_tx {
        // `send` returns Err if the receiver was already dropped (recovery
        // already completed naturally). Either outcome is fine — caller
        // sees a no-op return.
        let _ = tx.send(());
    }

    PhalanxError::Ok.code()
}
