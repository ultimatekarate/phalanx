// crates/phalanx-ffi/src/playback.rs
//
// Playback FFI — drives the existing `MeshSentinel::spawn_playback()` from Flutter.
//
// Flow:
// 1. Flutter calls `phalanx_start_playback(recording_id)` → Rust spawns PlaybackCoordinator
// 2. Flutter polls `phalanx_poll_playback_frame()` → returns decoded frame bytes or null
// 3. Flutter calls `phalanx_stop_playback()` → tears down the coordinator
//
// The playback channel uses `VideoPlayerSink` → mpsc → poll from FFI.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use phalanx_node::VideoPlayerSink;
use phalanx_proto::prelude::RecordingId;

use std::ffi::CStr;
use std::os::raw::c_char;

use tokio::sync::mpsc;

/// Starts playback of a recording by ID.
///
/// Spawns a `PlaybackCoordinator` that retrieves shards from storage,
/// decrypts them, and feeds decoded frames to an internal mpsc channel.
/// Flutter polls this channel via `phalanx_poll_playback_frame`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_start_playback(
    handle: *mut PhalanxHandle,
    recording_id: *const c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if recording_id.is_null() {
        return PhalanxError::NullPointer.code();
    }

    if !h.is_running() {
        return PhalanxError::NotRunning.code();
    }

    let id_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let rec_id = RecordingId::new(id_str);

    // Create the playback channel: VideoPlayerSink → mpsc → FFI poll
    let (ui_tx, ui_rx) = mpsc::channel(64);
    let sink = VideoPlayerSink::new(ui_tx);

    // Store the receiver for polling
    if let Ok(mut guard) = h.playback_rx.lock() {
        *guard = Some(ui_rx);
    } else {
        return PhalanxError::InvalidState.code();
    }

    // Spawn playback via MeshSentinel
    let sentinel_ref = match h.sentinel.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(s) => s.clone(),
            None => return PhalanxError::InvalidState.code(),
        },
        Err(_) => return PhalanxError::InvalidState.code(),
    };

    h.runtime.spawn(async move {
        let mut engine = sentinel_ref.lock().await;
        let _task = engine.spawn_playback(rec_id, sink);
        // The JoinHandle is dropped — playback runs independently.
        // It self-terminates when the recording is fully played or the channel closes.
    });

    PhalanxError::Ok.code()
}

/// Polls for the next decoded playback frame.
///
/// Returns the frame data through `out_data` and `out_len`.
/// If no frame is available yet, `*out_data` is set to null and returns Ok.
/// Caller must free the returned bytes with `phalanx_free_bytes`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_data` and `out_len` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn phalanx_poll_playback_frame(
    handle: *mut PhalanxHandle,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if out_data.is_null() || out_len.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let Ok(mut guard) = h.playback_rx.lock() else {
        return PhalanxError::InvalidState.code();
    };

    let rx = match guard.as_mut() {
        Some(rx) => rx,
        None => return PhalanxError::PlaybackError.code(),
    };

    // Non-blocking poll — try_recv returns immediately
    match rx.try_recv() {
        Ok(frame) => {
            // Frame size will never exceed u32::MAX on mobile devices
            #[allow(clippy::cast_possible_truncation)]
            let len = frame.len() as u32;
            let mut boxed = frame.into_boxed_slice();
            *out_data = boxed.as_mut_ptr();
            *out_len = len;
            // Leak the allocation — caller frees via phalanx_free_bytes
            std::mem::forget(boxed);
            PhalanxError::Ok.code()
        }
        Err(mpsc::error::TryRecvError::Empty) => {
            // No frame available yet — not an error
            *out_data = std::ptr::null_mut();
            *out_len = 0;
            PhalanxError::Ok.code()
        }
        Err(mpsc::error::TryRecvError::Disconnected) => {
            // Playback complete — channel closed by the coordinator
            *out_data = std::ptr::null_mut();
            *out_len = 0;
            // Clean up the receiver
            *guard = None;
            PhalanxError::PlaybackError.code()
        }
    }
}

/// Stops active playback by dropping the receiver channel.
///
/// The `PlaybackCoordinator` will detect the closed channel and terminate.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_stop_playback(handle: *mut PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if let Ok(mut guard) = h.playback_rx.lock() {
        *guard = None; // Dropping the Receiver closes the channel
    }

    PhalanxError::Ok.code()
}
