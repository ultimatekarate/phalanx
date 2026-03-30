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

use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::{PlaybackCoordinator, VideoPlayerSink};
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

    // Channel buffer = ceil(max_consumer_stall / frame_interval).
    // Flutter polls at ~33ms (30fps). Worst-case Android UI stall (old-space GC +
    // layout in same frame) ≈ 80ms → ceil(80/33) = 3. Small enough that
    // backpressure keeps the coordinator from prefetching the whole recording.
    let (video_tx, video_rx) = mpsc::channel(3);
    let (audio_tx, audio_rx) = mpsc::channel(3);

    let video_sink = VideoPlayerSink::new(video_tx);
    let audio_sink = VideoPlayerSink::new(audio_tx); // Same type — just a channel wrapper

    // Construct PlaybackCoordinator directly from handle channels.
    // DO NOT lock the sentinel — engine.run() holds that tokio::sync::Mutex
    // for its entire lifetime, so sentinel_ref.lock().await would deadlock.
    let storage_tx = h.storage_tx.clone();
    let egress_tx = h.egress_tx.clone();
    let identity = h.identity.clone();
    let vault_key = h.vault_key.clone();

    // Dummy discovery/providers channels — local playback doesn't need DHT.
    // When a shard is missing locally the coordinator will try_send to
    // discovery_tx (silently dropped) and poll providers_rx (always empty).
    // Remote retrieval requires wiring these through the sentinel, but for
    // the local-capture demo path this is correct.
    let (discovery_tx, _discovery_rx) = mpsc::channel(1);
    let (_providers_tx, providers_rx) = mpsc::channel(1);

    h.runtime.spawn(async move {
        eprintln!("[Phalanx FFI] Starting playback for {}", rec_id.as_str());

        // Resolve per-recording content key for decryption.
        // Falls back to vault_key for legacy recordings without content keys.
        let decryption_key = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let _ = storage_tx
                .send(StorageCommand::GetContentKey {
                    recording_id: rec_id.clone(),
                    reply_to: tx,
                })
                .await;
            match rx.await {
                Ok(Some(key_bytes)) => {
                    eprintln!("[Phalanx FFI] Got content key ({} bytes) for {}", key_bytes.len(), rec_id.as_str());
                    Some(phalanx_proto::crypto::SymmetricKey(key_bytes))
                }
                Ok(None) => {
                    eprintln!("[Phalanx FFI] No content key found, falling back to vault_key");
                    Some((*vault_key).clone())
                }
                Err(e) => {
                    eprintln!("[Phalanx FFI] GetContentKey channel error: {e:?}, falling back to vault_key");
                    Some((*vault_key).clone())
                }
            }
        };

        let mut coordinator = PlaybackCoordinator::new(
            storage_tx,
            egress_tx,
            decryption_key,
            video_sink,
            audio_sink,
            discovery_tx,
            providers_rx,
            identity,
        );

        eprintln!("[Phalanx FFI] PlaybackCoordinator starting run loop");
        match coordinator.run(rec_id).await {
            Ok(()) => eprintln!("[Phalanx FFI] PlaybackCoordinator finished normally"),
            Err(e) => eprintln!("[Phalanx FFI] PlaybackCoordinator FAILED: {e:?}"),
        }
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
