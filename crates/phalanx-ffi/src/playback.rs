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

    // Clone tx handles before moving into sinks — we need them later for capacity diagnostics
    let video_tx_diag = video_tx.clone();
    let audio_tx_diag = audio_tx.clone();

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
        phalanx_log!("[Phalanx FFI] Starting playback for {}", rec_id.as_str());

        // Resolve per-recording content key for decryption.
        //
        // Under the v2 deterministic-DEK regime (PR A), `GetContentKey`
        // always returns `Some` — the storage actor's `resolve_encryption_key`
        // chain is `keyring → derive(dek_master, recording_id)` and never
        // returns `None`. The `Ok(None)` branch is therefore unreachable in
        // production; it's retained only as a defensive bridge for any
        // future callers that choose to emit `None` again. The `Err` arm
        // covers the genuine failure mode: the storage actor died before
        // replying. In that case the vault_key is the only key still in
        // scope here — decryption will almost certainly fail downstream
        // (it's the wrong key for v2 recordings), but logging the storage
        // failure is the correct first signal.
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
                    phalanx_log!("[Phalanx FFI] Got content key ({} bytes) for {}", key_bytes.len(), rec_id.as_str());
                    Some(phalanx_proto::crypto::SymmetricKey::from_bytes(key_bytes))
                }
                Ok(None) => {
                    // Defensive: not emitted by the post-PR-A storage actor.
                    phalanx_log!("[Phalanx FFI] GetContentKey returned None (unexpected under v2); falling back to vault_key");
                    Some((*vault_key).clone())
                }
                Err(e) => {
                    phalanx_log!("[Phalanx FFI] GetContentKey channel error (storage actor down?): {e:?}; falling back to vault_key");
                    Some((*vault_key).clone())
                }
            }
        };

        // Diagnostic: probe storage for shard 1 before starting coordinator
        {
            let (probe_tx, probe_rx) = tokio::sync::oneshot::channel();
            let _ = storage_tx
                .send(StorageCommand::GetShard {
                    recording_id: rec_id.clone(),
                    sequence_id: phalanx_proto::evidence::StorageSequence(1),
                    reply_to: probe_tx,
                })
                .await;
            match probe_rx.await {
                Ok(Some(env)) => {
                    let (etype, payload) = match &env.evidence {
                        phalanx_proto::evidence::Evidence::Video(v) => ("Video", Some(v.payload.clone())),
                        phalanx_proto::evidence::Evidence::Audio(a) => ("Audio", Some(a.payload.clone())),
                        _ => ("Other", None),
                    };
                    phalanx_log!("[Phalanx FFI] Probe: shard 1 EXISTS ({})", etype);

                    // Try to decode the payload to verify the full pipeline
                    if let Some(p) = payload {
                        let payload_desc = match &p {
                            phalanx_proto::evidence::DataPayload::Missing => "Missing",
                            phalanx_proto::evidence::DataPayload::Clear(_) => "Clear",
                            phalanx_proto::evidence::DataPayload::Compressed(_) => "Compressed",
                            phalanx_proto::evidence::DataPayload::Encrypted { .. } => "Encrypted",
                        };
                        phalanx_log!("[Phalanx FFI] Probe: shard 1 payload = {}", payload_desc);

                        match phalanx_forensics::decode_payload(p, decryption_key.as_ref()) {
                            Ok(decoded) => {
                                phalanx_log!("[Phalanx FFI] Probe: decode_payload OK, {} bytes", decoded.len());
                                if etype == "Video" {
                                    match postcard::from_bytes::<Vec<Vec<u8>>>(&decoded) {
                                        Ok(frames) => phalanx_log!("[Phalanx FFI] Probe: postcard deser OK, {} JPEG frames", frames.len()),
                                        Err(e) => phalanx_log!("[Phalanx FFI] Probe: postcard deser FAILED: {e:?}"),
                                    }
                                }
                            }
                            Err(e) => phalanx_log!("[Phalanx FFI] Probe: decode_payload FAILED: {e:?}"),
                        }
                    }
                }
                Ok(None) => phalanx_log!("[Phalanx FFI] Probe: shard 1 NOT FOUND"),
                Err(e) => phalanx_log!("[Phalanx FFI] Probe: GetShard failed: {e:?}"),
            }

            // Also probe ListRecordings to see how many the storage actor knows about
            let (list_tx, list_rx) = tokio::sync::oneshot::channel();
            let _ = storage_tx
                .send(StorageCommand::ListRecordings { reply_to: list_tx })
                .await;
            match list_rx.await {
                Ok(ids) => {
                    phalanx_log!("[Phalanx FFI] Probe: {} recordings known to storage", ids.len());
                    for id in &ids {
                        phalanx_log!("[Phalanx FFI] Probe:   recording = {}", id.as_str());
                    }
                }
                Err(e) => phalanx_log!("[Phalanx FFI] Probe: ListRecordings failed: {e:?}"),
            }

            // Query shard count for this specific recording
            let (info_tx, info_rx) = tokio::sync::oneshot::channel();
            let _ = storage_tx
                .send(StorageCommand::DebugRecordingInfo {
                    recording_id: rec_id.clone(),
                    reply_to: info_tx,
                })
                .await;
            match info_rx.await {
                Ok((shard_count, has_key)) => {
                    phalanx_log!(
                        "[Phalanx FFI] Probe: recording {} has {} shards, has_key={}",
                        rec_id.as_str(), shard_count, has_key
                    );
                }
                Err(e) => phalanx_log!("[Phalanx FFI] Probe: DebugRecordingInfo failed: {e:?}"),
            }

            // List vault directory contents to see if .recording files exist on disk
            let (vault_tx, vault_rx) = tokio::sync::oneshot::channel();
            let _ = storage_tx
                .send(StorageCommand::DebugVaultListing {
                    reply_to: vault_tx,
                })
                .await;
            match vault_rx.await {
                Ok((vault_path, entries)) => {
                    phalanx_log!("[Phalanx FFI] Probe: vault_path = {}", vault_path);
                    if entries.is_empty() {
                        phalanx_log!("[Phalanx FFI] Probe: vault directory is EMPTY");
                    }
                    for entry in &entries {
                        phalanx_log!("[Phalanx FFI] Probe:   {}", entry);
                    }
                }
                Err(e) => phalanx_log!("[Phalanx FFI] Probe: DebugVaultListing failed: {e:?}"),
            }
        }

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

        phalanx_log!("[Phalanx FFI] PlaybackCoordinator starting run loop");
        match coordinator.run(rec_id).await {
            Ok(stats) => {
                // Channel capacity is bounded at 8, well within u32 range.
                #[allow(clippy::cast_possible_truncation)]
                let video_buffered = 8u32.saturating_sub(video_tx_diag.capacity() as u32);
                #[allow(clippy::cast_possible_truncation)]
                let audio_buffered = 8u32.saturating_sub(audio_tx_diag.capacity() as u32);
                phalanx_log!(
                    "[Phalanx FFI] PlaybackStats: found={}, missing={}, video_sent={}, audio_sent={}, decode_fail={}",
                    stats.shards_found, stats.shards_missing, stats.video_sent, stats.audio_sent, stats.decode_failures
                );
                phalanx_log!(
                    "[Phalanx FFI] PlaybackCoordinator finished. video_buffered={}, audio_buffered={}",
                    video_buffered, audio_buffered
                );
            }
            Err(e) => phalanx_log!("[Phalanx FFI] PlaybackCoordinator FAILED: {e:?}"),
        }
    });

    // Return opaque session pointer — caller owns this
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
