// crates/phalanx-ffi/src/playback.rs
//
// Playback FFI — drives the existing `MeshSentinel::spawn_playback()` from Flutter.
//
// Flow:
// 1. Flutter calls `phalanx_start_playback(recording_id)` → returns opaque PlaybackSession*
// 2. Flutter polls `phalanx_poll_video_frame(session)` → returns decoded frame bytes or null
// 3. Flutter polls `phalanx_poll_audio_frame(session)` → returns decoded audio bytes or null
// 4. Flutter calls `phalanx_stop_playback(session)` → drops the session, closing receivers
//
// The PlaybackSession owns the video + audio receivers. No Mutex on PhalanxHandle.
// Each poll is a pure `try_recv()` — stateless from the caller's perspective.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use phalanx_node::VideoPlayerSink;
use phalanx_proto::prelude::RecordingId;

use std::ffi::CStr;
use std::os::raw::c_char;

use tokio::sync::mpsc;

// =====================================================================
// PLAYBACK SESSION — opaque handle returned to Flutter
// =====================================================================

/// Opaque playback session — owns the video + audio receivers.
///
/// Flutter holds a `Pointer<Void>` to this. Each poll is a pure `try_recv()`
/// on the session's receiver. No Mutex. Single-owner (Flutter's main isolate).
pub struct PlaybackSession {
    video_rx: mpsc::Receiver<Vec<u8>>,
    audio_rx: mpsc::Receiver<Vec<u8>>,
}

// =====================================================================
// FFI FUNCTIONS
// =====================================================================

/// Starts playback of a recording by ID. Returns an opaque PlaybackSession pointer.
///
/// Spawns a `PlaybackCoordinator` that retrieves shards from storage,
/// decrypts them, and feeds decoded frames to internal mpsc channels.
/// Flutter polls these channels via `phalanx_poll_video_frame` / `phalanx_poll_audio_frame`.
///
/// Returns null on failure.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_start_playback(
    handle: *mut PhalanxHandle,
    recording_id: *const c_char,
) -> *mut PlaybackSession {
    let Some(h) = handle.as_ref() else {
        return std::ptr::null_mut();
    };

    if recording_id.is_null() {
        return std::ptr::null_mut();
    }

    if !h.is_running() {
        return std::ptr::null_mut();
    }

    let id_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let rec_id = RecordingId::new(id_str);

    // Channel buffer size = 1: lock-step with Flutter's poll rate.
    // Minimal buffered state — the coordinator blocks until Flutter consumes.
    let (video_tx, video_rx) = mpsc::channel(1);
    let (audio_tx, audio_rx) = mpsc::channel(1);

    let video_sink = VideoPlayerSink::new(video_tx);
    let _audio_sink = VideoPlayerSink::new(audio_tx); // Same type — just a channel wrapper

    // Spawn playback via MeshSentinel
    let sentinel_ref = match h.sentinel.lock() {
        Ok(guard) => match guard.as_ref() {
            Some(s) => s.clone(),
            None => return std::ptr::null_mut(),
        },
        Err(_) => return std::ptr::null_mut(),
    };

    h.runtime.spawn(async move {
        let mut engine = sentinel_ref.lock().await;
        let _task = engine.spawn_playback(rec_id, video_sink);
        // TODO: pass audio_sink once PlaybackCoordinator supports dual sinks (Part C1)
        // The JoinHandle is dropped — playback runs independently.
        // It self-terminates when the recording is fully played or the channel closes.
    });

    // Return opaque session pointer — caller owns this
    Box::into_raw(Box::new(PlaybackSession { video_rx, audio_rx }))
}

/// Polls for the next decoded video frame from a playback session.
///
/// Returns the frame data through `out_data` and `out_len`.
/// If no frame is available yet, `*out_data` is set to null and returns Ok.
/// Caller must free the returned bytes with `phalanx_free_bytes`.
///
/// # Safety
/// * `session` must be a valid pointer from `phalanx_start_playback`.
/// * `out_data` and `out_len` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn phalanx_poll_video_frame(
    session: *mut PlaybackSession,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    let Some(s) = session.as_mut() else {
        return PhalanxError::NullPointer.code();
    };

    if out_data.is_null() || out_len.is_null() {
        return PhalanxError::NullPointer.code();
    }

    poll_channel(&mut s.video_rx, out_data, out_len)
}

/// Polls for the next decoded audio frame from a playback session.
///
/// Returns the audio data through `out_data` and `out_len`.
/// If no audio is available yet, `*out_data` is set to null and returns Ok.
/// Caller must free the returned bytes with `phalanx_free_bytes`.
///
/// # Safety
/// * `session` must be a valid pointer from `phalanx_start_playback`.
/// * `out_data` and `out_len` must be valid pointers.
#[no_mangle]
pub unsafe extern "C" fn phalanx_poll_audio_frame(
    session: *mut PlaybackSession,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    let Some(s) = session.as_mut() else {
        return PhalanxError::NullPointer.code();
    };

    if out_data.is_null() || out_len.is_null() {
        return PhalanxError::NullPointer.code();
    }

    poll_channel(&mut s.audio_rx, out_data, out_len)
}

/// Stops playback by destroying the session.
///
/// Dropping the session closes both receivers, which signals the
/// `PlaybackCoordinator` to terminate.
///
/// # Safety
/// * `session` must be a valid pointer from `phalanx_start_playback`.
/// * Must be called exactly once per session. Null is a safe no-op.
#[no_mangle]
pub unsafe extern "C" fn phalanx_stop_playback(session: *mut PlaybackSession) {
    if !session.is_null() {
        let _ = Box::from_raw(session);
    }
}

// =====================================================================
// INTERNAL
// =====================================================================

/// Non-blocking poll on an mpsc receiver. Shared by video and audio poll functions.
unsafe fn poll_channel(
    rx: &mut mpsc::Receiver<Vec<u8>>,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
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
            PhalanxError::PlaybackError.code()
        }
    }
}
