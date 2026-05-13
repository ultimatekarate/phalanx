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
use crate::logcat::phalanx_log;

use phalanx_node::actors::meshsentinel::SentinelCommand;
use phalanx_node::VideoPlayerSink;
use phalanx_proto::playback::PlaybackSink;
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
    /// DIAGNOSTIC: counts poll_video_frame calls to confirm Flutter is polling
    video_poll_count: u32,
    /// DIAGNOSTIC: counts how many video frames were delivered
    video_hit_count: u32,
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

    // Single-tenant providers channel: refuse playback while a recovery
    // walk is in progress. Mirror gate in capture.rs.
    {
        let s = h.recovery_status.lock().unwrap_or_else(|e| e.into_inner());
        use phalanx_proto::recovery::RecoveryState::{
            FetchingChildren, FetchingManifest, WalkingManifest,
        };
        if matches!(
            s.state,
            FetchingManifest | WalkingManifest | FetchingChildren
        ) {
            return std::ptr::null_mut();
        }
    }

    let id_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return std::ptr::null_mut(),
    };

    let rec_id = RecordingId::new(id_str);

    // Channel buffer = ceil(max_consumer_stall / frame_interval).
    // Flutter polls at ~33ms (30fps). Worst-case Android UI stall (old-space GC +
    // layout in same frame) ≈ 80ms → ceil(80/33) = 3. Small enough that
    // backpressure keeps the coordinator from prefetching the whole recording.
    // Buffer = 8 frames: enough headroom for Android GC pauses (~300ms at
    // 15fps = ~5 frames) while providing backpressure to pace the coordinator.
    let (video_tx, video_rx) = mpsc::channel(8);
    let (audio_tx, audio_rx) = mpsc::channel(8);

    // Construct the playback sinks here; the PlaybackCoordinator and its
    // providers/discovery channels live inside the sentinel and are reached
    // via SentinelCommand::SpawnPlayback. This wires mesh fallback through
    // the sentinel's real discovery_rx, replacing the prior dummy channels
    // (which silently disabled mesh discovery). The sentinel's playback_slot
    // enforces at-most-one-playback by type; we receive Err(AlreadyPlaying)
    // if a prior session is still live.
    let video_sink: Box<dyn PlaybackSink + Send + Sync + 'static> =
        Box::new(VideoPlayerSink::new(video_tx));
    let audio_sink: Box<dyn PlaybackSink + Send + Sync + 'static> =
        Box::new(VideoPlayerSink::new(audio_tx));

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    if h.runtime
        .block_on(h.sentinel_cmd_tx.send(SentinelCommand::SpawnPlayback {
            recording_id: rec_id.clone(),
            video_sink,
            audio_sink,
            reply_to: reply_tx,
        }))
        .is_err()
    {
        phalanx_log!(
            "[Phalanx FFI] phalanx_start_playback: sentinel command channel closed for {}",
            rec_id.as_str()
        );
        return std::ptr::null_mut();
    }

    match h.runtime.block_on(reply_rx) {
        Ok(Ok(())) => {
            phalanx_log!(
                "[Phalanx FFI] phalanx_start_playback: dispatched for {}",
                rec_id.as_str()
            );
        }
        Ok(Err(_already_playing)) => {
            phalanx_log!(
                "[Phalanx FFI] phalanx_start_playback: rejected ({}): a playback session is already active",
                rec_id.as_str()
            );
            return std::ptr::null_mut();
        }
        Err(_) => {
            phalanx_log!(
                "[Phalanx FFI] phalanx_start_playback: reply channel dropped for {}",
                rec_id.as_str()
            );
            return std::ptr::null_mut();
        }
    }

    // Return opaque session pointer — caller owns this. Dropping the session
    // closes video_rx/audio_rx, which makes the sentinel-spawned coordinator's
    // sink writes fail and the run loop exit cleanly. No JoinHandle stored
    // here — the sentinel owns the task lifecycle via its playback_slot.
    Box::into_raw(Box::new(PlaybackSession {
        video_rx,
        audio_rx,
        video_poll_count: 0,
        video_hit_count: 0,
    }))
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

    s.video_poll_count = s.video_poll_count.saturating_add(1);

    // Log first poll to confirm Flutter is calling us
    if s.video_poll_count == 1 {
        phalanx_log!("[Phalanx FFI] poll_video_frame: FIRST POLL");
    }

    let result = poll_channel(&mut s.video_rx, out_data, out_len);
    if !(*out_data).is_null() {
        s.video_hit_count = s.video_hit_count.saturating_add(1);
        phalanx_log!(
            "[Phalanx FFI] poll_video_frame: got {} bytes (hit {}/poll {})",
            *out_len,
            s.video_hit_count,
            s.video_poll_count
        );
    } else if s.video_poll_count % 100 == 0 {
        // Periodic heartbeat to confirm we're still polling
        phalanx_log!(
            "[Phalanx FFI] poll_video_frame: {} polls, {} hits so far",
            s.video_poll_count,
            s.video_hit_count
        );
    }
    result
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
            crate::memory::leak_bytes_to_c(frame.into_boxed_slice(), out_data, out_len);
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
