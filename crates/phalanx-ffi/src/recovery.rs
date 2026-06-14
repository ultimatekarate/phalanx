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

use phalanx_node::actors::meshsentinel::SentinelCommand;
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_start_recovery(handle: *const PhalanxHandle) -> i32 {
    unsafe {
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

        let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel();
        let status = h.recovery_status.clone();

        // Dispatch SpawnRecovery to the engine via the SentinelCommand
        // mailbox. The engine services the command inside its `select!` arm
        // — `&mut MeshSentinel` is available there without any external
        // lock — and returns the inner `JoinHandle` via the reply oneshot.
        // No FFI-side `sentinel.lock().await`, no silent stall on the
        // engine.run() borrow. (Fixes audit finding H3.)
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if h.sentinel_cmd_tx
            .blocking_send(SentinelCommand::SpawnRecovery {
                status,
                cancel_rx,
                reply_to: reply_tx,
            })
            .is_err()
        {
            return PhalanxError::ChannelClosed.code();
        }
        let join_handle = match reply_rx.blocking_recv() {
            Ok(jh) => jh,
            Err(_) => return PhalanxError::ChannelClosed.code(),
        };

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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_recovery_status(
    handle: *const PhalanxHandle,
    out_ptr: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    unsafe {
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

        crate::memory::leak_bytes_to_c(serialized.into_boxed_slice(), out_ptr, out_len);

        PhalanxError::Ok.code()
    }
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
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_cancel_recovery(handle: *const PhalanxHandle) -> i32 {
    unsafe {
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
}
