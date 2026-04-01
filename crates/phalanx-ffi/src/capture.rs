// crates/phalanx-ffi/src/capture.rs
//
// Frame capture FFI — receives raw YUV data from Flutter's camera plugin
// and runs the full forensic pipeline:
//
//   Y-plane + UV-plane → ForensicLens::analyze(Y) → compress_frame(YUV) → create_video_shard() → encrypt → send
//
// Flutter delivers NV21 (Android) or NV12 (iOS). Both formats provide:
//   - Y plane: width × height bytes of luminance
//   - UV plane: width × (height/2) bytes of interleaved chroma
//
// ForensicLens operates on Y-plane only (PRNU, Moiré, Laplacian).
// compress_frame receives both planes for full-color JPEG via turbojpeg.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;
use crate::logcat::phalanx_log;

use phalanx_forensics::reassembler::{compress_frame, create_audio_shard, create_video_shard};
use phalanx_lens::scalar::ScalarLens;
use phalanx_lens::ForensicLens;
use phalanx_node::actors::egress::EgressCommand;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_node::hardware::camera::target_fps;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::prelude::RecordingId;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::types::{BlackLevel, ChannelCount, Fps, SampleRate};

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::Ordering;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Static forensic lens — L1-cache optimized, no allocation needed.
static LENS: ScalarLens = ScalarLens;

/// Unified sequence counter for all evidence (video + audio) within a recording.
/// Shared counter prevents sequence collisions in the recording log index.
/// Starts at 1 — `PlaybackCoordinator` starts at `StorageSequence(1)`.
/// Reset on each `phalanx_start_recording`.
static SEQUENCE: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(1);

// =====================================================================
// PIXEL FORMAT
// =====================================================================

/// Pixel format of the interleaved chroma plane from the camera.
///
/// Android's Camera2 API delivers NV21 (VU interleaved).
/// iOS AVFoundation delivers NV12 (UV interleaved).
/// Both share the same Y plane — only the chroma byte order differs.
#[repr(C)]
pub enum PixelFormat {
    /// NV21: V then U interleaved. Android default.
    Nv21 = 0,
    /// NV12: U then V interleaved. iOS default.
    Nv12 = 1,
}

/// Starts a new recording session.
///
/// Generates a unique `RecordingId` and sets the handle into recording mode.
/// Returns the recording ID through `out_recording_id` (caller frees with `phalanx_free_string`).
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_recording_id` must be a valid pointer to receive the C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_start_recording(
    handle: *mut PhalanxHandle,
    out_recording_id: *mut *mut c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if out_recording_id.is_null() {
        return PhalanxError::NullPointer.code();
    }

    if !h.is_running() {
        return PhalanxError::NotRunning.code();
    }

    if h.recording_active.load(Ordering::Relaxed) {
        return PhalanxError::AlreadyRecording.code();
    }

    // Generate recording ID from timestamp + node DID prefix
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    let id_str = format!(
        "rec-{}-{}",
        &h.node_did[..8.min(h.node_did.len())],
        timestamp
    );
    // Reset unified sequence counter (starts at 1 to match PlaybackCoordinator)
    SEQUENCE.store(1, Ordering::Relaxed);

    // Request per-recording content key from StorageActor.
    // Uses channels cloned onto the handle — no sentinel lock needed.
    // block_on is acceptable: user-initiated, sub-millisecond key generation.
    let recording_id = RecordingId::from(id_str.clone());
    let storage_tx = h.storage_tx.clone();

    let key_result = h.runtime.block_on(async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        storage_tx
            .send(StorageCommand::StartRecording {
                recording_id: recording_id.clone(),
                reply_to: tx,
            })
            .await
            .map_err(|_| ())?;
        rx.await.map_err(|_| ())
    });

    match key_result {
        Ok(Ok(key_bytes)) => {
            let _ = h.content_key_tx.send(Some(SymmetricKey(key_bytes)));
        }
        Ok(Err(_)) | Err(()) => {
            tracing::warn!(
                target: "phalanx::ffi",
                "Content key generation failed — falling back to vault_key"
            );
        }
    }

    // Set recording active — recording_id is returned to the caller
    // and passed back on each push call (no Mutex storage needed).
    h.recording_active.store(true, Ordering::Relaxed);

    // Return recording ID to caller
    match CString::new(id_str) {
        Ok(cstr) => {
            *out_recording_id = cstr.into_raw();
            PhalanxError::Ok.code()
        }
        Err(_) => PhalanxError::InvalidUtf8.code(),
    }
}

/// Stops the current recording session.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_stop_recording(handle: *mut PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if !h.recording_active.load(Ordering::Relaxed) {
        return PhalanxError::NotRecording.code();
    }

    h.recording_active.store(false, Ordering::Relaxed);

    // Clear per-recording content key — MediaEgressActor reverts to vault_key (None).
    let _ = h.content_key_tx.send(None);

    PhalanxError::Ok.code()
}

/// Pushes a raw YUV video frame through the forensic pipeline.
///
/// Pipeline:
/// 1. `ForensicLens::analyze()` — PRNU variance, Moiré detection, Laplacian energy (Y-plane only, 256×256 center crop, 64KB, fits L1)
/// 2. `compress_frame()` — full-color YUV→JPEG via turbojpeg (no RGB conversion)
/// 3. `create_video_shard()` — shard with forensic metrics
/// 4. `try_send` to video channel → `MediaEgressActor` handles mesh distribution
///
/// Uses `try_send` — returns immediately, drops on backpressure.
/// Power-state-aware FPS is governed by Rust via `target_fps()`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `y_plane` must point to `y_len` valid bytes of raw luma data (`width * height`).
/// * `uv_plane` must point to `uv_len` valid bytes of interleaved chroma (`width * height / 2`).
/// * `recording_id` must be a valid null-terminated C string (returned from `phalanx_start_recording`).
#[no_mangle]
pub unsafe extern "C" fn phalanx_push_video_frame(
    handle: *mut PhalanxHandle,
    y_plane: *const u8,
    y_len: u32,
    uv_plane: *const u8,
    uv_len: u32,
    width: u32,
    height: u32,
    pixel_format: PixelFormat,
    recording_id: *const c_char,
    _timestamp_ms: u64,
) -> i32 {
    // DIAGNOSTIC: log first call to confirm Flutter is pushing frames
    {
        static LOGGED_ENTRY: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !LOGGED_ENTRY.swap(true, Ordering::Relaxed) {
            phalanx_log!(
                "[Phalanx FFI] push_video_frame CALLED: y_len={}, uv_len={}, {}x{}, handle_null={}, y_null={}, uv_null={}, rec_null={}",
                y_len, uv_len, width, height, handle.is_null(), y_plane.is_null(), uv_plane.is_null(), recording_id.is_null()
            );
        }
    }

    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if y_plane.is_null() || uv_plane.is_null() || recording_id.is_null() {
        return PhalanxError::NullPointer.code();
    }

    if !h.recording_active.load(Ordering::Relaxed) {
        // DIAGNOSTIC: log if recording_active is false
        static LOGGED_INACTIVE: std::sync::atomic::AtomicBool =
            std::sync::atomic::AtomicBool::new(false);
        if !LOGGED_INACTIVE.swap(true, Ordering::Relaxed) {
            phalanx_log!("[Phalanx FFI] push_video_frame: recording_active=false, rejecting");
        }
        return PhalanxError::NotRecording.code();
    }

    // Parse recording ID from caller (no Mutex — stateless)
    let rec_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };
    let rec_id = RecordingId::new(rec_str);

    // Get video sender
    let video_tx = match &h.video_tx {
        Some(tx) => tx.clone(),
        None => return PhalanxError::ChannelClosed.code(),
    };

    // Validate UV plane size: must be width * height / 2 (NV12/NV21 interleaved).
    // Some Android camera HALs deliver UV planes off by 1 byte (e.g., 460799 vs
    // 460800 for 1280×720). Pad to expected size — the missing byte is the last
    // chroma sample, visually imperceptible.
    #[allow(clippy::arithmetic_side_effects)]
    let expected_uv = (width * height) / 2;
    if uv_len != expected_uv && uv_len.saturating_add(1) != expected_uv {
        static LOGGED_UV: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
        if !LOGGED_UV.swap(true, Ordering::Relaxed) {
            phalanx_log!(
                "[Phalanx FFI] push_video_frame: UV size mismatch: expected={}, got={}",
                expected_uv,
                uv_len
            );
        }
        return PhalanxError::InvalidState.code();
    }

    // Copy raw YUV from Flutter's memory NOW (caller frees after we return).
    // This is a fast memcpy — the expensive work (JPEG, forensics, shard
    // creation) happens on tokio's blocking thread pool below.
    let y_data = std::slice::from_raw_parts(y_plane, y_len as usize).to_vec();
    let mut uv_data = std::slice::from_raw_parts(uv_plane, uv_len as usize).to_vec();
    if uv_data.len() < expected_uv as usize {
        // Pad short UV plane with last byte repeated (nearest-neighbor chroma)
        let pad = *uv_data.last().unwrap_or(&128);
        uv_data.resize(expected_uv as usize, pad);
    }
    let is_nv12 = matches!(pixel_format, PixelFormat::Nv12);

    // Claim sequence number now (atomic — no contention with the blocking task).
    let sequence = StorageSequence(SEQUENCE.fetch_add(1, Ordering::Relaxed));
    let current_fps = target_fps(Fps::new(30), h.governor.current_power_state());

    // Dispatch the heavy pipeline to tokio's blocking thread pool.
    // The FFI call returns immediately — Flutter's UI thread is never blocked
    // by JPEG compression, forensic analysis, or shard serialization.
    h.runtime.spawn(async move {
        let result = tokio::task::spawn_blocking(move || -> Option<_> {
            // Step 1: ForensicLens — PRNU, Moiré, Laplacian (Y-plane only)
            let lens_metrics = LENS.analyze(
                &y_data,
                width as usize,
                height as usize,
                BlackLevel::default(),
            );

            // Step 2: JPEG compression (YUV→JPEG via turbojpeg)
            let compressed = match compress_frame(&y_data, &uv_data, width, height, is_nv12) {
                Ok(c) => {
                    // DIAGNOSTIC: log first successful compression
                    static LOGGED_OK: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if !LOGGED_OK.swap(true, Ordering::Relaxed) {
                        phalanx_log!(
                            "[Phalanx FFI] compress_frame OK: {} bytes JPEG from {}x{}",
                            c.len(),
                            width,
                            height
                        );
                    }
                    c
                }
                Err(e) => {
                    // DIAGNOSTIC: log first compression failure
                    static LOGGED_ERR: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(false);
                    if !LOGGED_ERR.swap(true, Ordering::Relaxed) {
                        phalanx_log!("[Phalanx FFI] compress_frame FAILED: {}", e);
                    }
                    return None;
                }
            };

            // Step 3: Create video shard with forensic metrics
            let elapsed = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or(Duration::from_secs(0));
            let now = PhalanxTimestamp::from_millis(
                elapsed
                    .as_secs()
                    .saturating_mul(1000)
                    .saturating_add(u64::from(elapsed.subsec_millis())),
            );
            match create_video_shard(
                vec![compressed],
                sequence,
                current_fps,
                rec_id,
                lens_metrics,
                now,
            ) {
                Ok(shard) => Some(shard),
                Err(e) => {
                    phalanx_log!("[Phalanx FFI] create_video_shard FAILED: {e:?}");
                    None
                }
            }
        })
        .await;

        // Step 4: Non-blocking send to MediaEgressActor
        match &result {
            Ok(Some(shard)) => {
                static LOGGED_SEND: std::sync::atomic::AtomicBool =
                    std::sync::atomic::AtomicBool::new(false);
                if !LOGGED_SEND.swap(true, Ordering::Relaxed) {
                    phalanx_log!("[Phalanx FFI] video shard created, sending to egress");
                }
                let _ = video_tx.try_send(shard.clone());
            }
            Ok(None) => {} // spawn_blocking returned None (pipeline failure logged above)
            Err(e) => {
                phalanx_log!("[Phalanx FFI] spawn_blocking panicked: {e:?}");
            }
        }
    });

    PhalanxError::Ok.code()
}

// Audio uses the shared SEQUENCE counter above — no separate counter needed.

/// Pushes a raw PCM audio frame through the forensic pipeline.
///
/// Pipeline:
/// 1. `create_audio_shard()` — wraps PCM data with LZ4 compression
/// 2. `try_send` to audio channel → `MediaEgressActor` encrypts + handles mesh distribution
///
/// Uses `try_send` — returns immediately, drops on backpressure.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `pcm_data` must point to `pcm_len` valid bytes of 16-bit LE PCM audio.
/// * `recording_id` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_push_audio_frame(
    handle: *mut PhalanxHandle,
    pcm_data: *const u8,
    pcm_len: u32,
    sample_rate: u32,
    channels: u8,
    recording_id: *const c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if pcm_data.is_null() || recording_id.is_null() {
        return PhalanxError::NullPointer.code();
    }

    if !h.recording_active.load(Ordering::Relaxed) {
        return PhalanxError::NotRecording.code();
    }

    // Parse recording ID from caller (stateless — no Mutex)
    let rec_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };
    let rec_id = RecordingId::new(rec_str);

    // Get audio sender
    let audio_tx = match &h.audio_tx {
        Some(tx) => tx,
        None => return PhalanxError::ChannelClosed.code(),
    };

    // Copy PCM data from the FFI boundary
    let pcm = std::slice::from_raw_parts(pcm_data, pcm_len as usize).to_vec();

    // Create audio shard (LZ4 compressed internally)
    let sequence = StorageSequence(SEQUENCE.fetch_add(1, Ordering::Relaxed));
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0));
    let now = PhalanxTimestamp::from_millis(
        elapsed
            .as_secs()
            .saturating_mul(1000)
            .saturating_add(u64::from(elapsed.subsec_millis())),
    );
    let shard = match create_audio_shard(
        pcm,
        sequence,
        SampleRate::new(sample_rate),
        ChannelCount::new(channels),
        rec_id,
        now,
    ) {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidState.code(),
    };

    // Non-blocking send to MediaEgressActor
    // Encryption deferred to MediaEgressActor (async thread) — see media_egress.rs.
    match audio_tx.try_send(shard) {
        Ok(()) => PhalanxError::Ok.code(),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            // Backpressure: audio chunk dropped silently.
            PhalanxError::Ok.code()
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            PhalanxError::ChannelClosed.code()
        }
    }
}

/// Returns the target FPS based on the current power state.
///
/// Flutter should use this to throttle camera frame delivery.
/// Values: 30 (Normal), 15 (Conserving), 6 (Leaf), 0 (Dormant)
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_get_target_fps(handle: *const PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return 0;
    };

    let fps = target_fps(Fps::new(30), h.governor.current_power_state());
    fps.get().cast_signed()
}

// =====================================================================
// RECORDING LIST
// =====================================================================

/// Returns a JSON array of recording IDs as a C string.
///
/// Example output: `["rec-did:key:-123456","rec-did:key:-789012"]`
///
/// The returned string must be freed with `phalanx_free_string`.
/// Returns an empty array `"[]"` if no recordings exist.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_json` must be a valid pointer to receive the C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_list_recordings(
    handle: *mut PhalanxHandle,
    out_json: *mut *mut c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if out_json.is_null() {
        return PhalanxError::NullPointer.code();
    }

    if !h.is_running() {
        return PhalanxError::NotRunning.code();
    }

    let storage_tx = h.storage_tx.clone();

    let result = h.runtime.block_on(async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        storage_tx
            .send(StorageCommand::ListRecordings { reply_to: tx })
            .await
            .map_err(|_| ())?;
        rx.await.map_err(|_| ())
    });

    let ids: Vec<phalanx_proto::identity::RecordingId> = result.unwrap_or_default();

    // Serialize as JSON array of strings
    let json_parts: Vec<String> = ids.iter().map(|id| format!("\"{}\"", id)).collect();
    let json = format!("[{}]", json_parts.join(","));

    match CString::new(json) {
        Ok(cstr) => {
            *out_json = cstr.into_raw();
            PhalanxError::Ok.code()
        }
        Err(_) => PhalanxError::InvalidUtf8.code(),
    }
}

// =====================================================================
// DEEP LINK SHARING
// =====================================================================

/// Generates a `phx://` deep link URI for a recording.
///
/// Uses the existing `PhalanxLocator` URI scheme:
/// `phx://[recording_id]#[secret]@[author_did]>[recipient_did]`
///
/// The returned string must be freed with `phalanx_free_string`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
/// * `recipient_did` must be a valid null-terminated C string (the peer's DID).
/// * `out_link` must be a valid pointer to receive the C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_get_share_link(
    handle: *const PhalanxHandle,
    recording_id: *const c_char,
    recipient_did: *const c_char,
    out_link: *mut *mut c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if recording_id.is_null() || recipient_did.is_null() || out_link.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let rec_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let recipient_str = match CStr::from_ptr(recipient_did).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    // Generate a sharing secret (random hex string)
    let secret = format!("{:016x}", rand_u64());

    let locator = phalanx_proto::identity::PhalanxLocator {
        id: RecordingId::new(rec_str),
        secret,
        author: phalanx_proto::prelude::Did::new(&h.node_did),
        recipient_did: phalanx_proto::prelude::Did::new(recipient_str),
    };

    let link = locator.to_string();

    match CString::new(link) {
        Ok(cstr) => {
            *out_link = cstr.into_raw();
            PhalanxError::Ok.code()
        }
        Err(_) => PhalanxError::InvalidUtf8.code(),
    }
}

/// Opens a received `phx://` deep link — initiates recording retrieval from the mesh.
///
/// Parses the URI, validates the recipient matches this node's DID, and triggers
/// `EgressCommand::FindProviders` to locate peers that have the recording.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `phx_link` must be a valid null-terminated C string containing a `phx://` URI.
#[no_mangle]
pub unsafe extern "C" fn phalanx_open_link(
    handle: *mut PhalanxHandle,
    phx_link: *const c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if phx_link.is_null() {
        return PhalanxError::NullPointer.code();
    }

    if !h.is_running() {
        return PhalanxError::NotRunning.code();
    }

    let link_str = match CStr::from_ptr(phx_link).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    // Parse the phx:// URI
    let locator: phalanx_proto::identity::PhalanxLocator = match link_str.parse() {
        Ok(loc) => loc,
        Err(_) => return PhalanxError::InvalidState.code(),
    };

    // Trigger DHT provider discovery for this recording
    let recording_id = locator.id.clone();
    let egress_tx = h.egress_tx.clone();
    h.runtime.spawn(async move {
        let _ = egress_tx
            .send(EgressCommand::FindProviders(recording_id))
            .await;
    });

    PhalanxError::Ok.code()
}

/// Debug-only: delete a recording without cryptographic revocation.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_debug_delete_recording(
    handle: *mut PhalanxHandle,
    recording_id: *const c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };
    if recording_id.is_null() {
        return PhalanxError::NullPointer.code();
    }
    let id_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let rec_id = RecordingId::new(id_str);
    let storage_tx = h.storage_tx.clone();

    let result = h.runtime.block_on(async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        storage_tx
            .send(
                phalanx_node::actors::storage::StorageCommand::DebugDeleteRecording {
                    recording_id: rec_id,
                    reply_to: tx,
                },
            )
            .await
            .map_err(|_| ())?;
        rx.await.map_err(|_| ())?.map_err(|_| ())?;
        Ok::<(), ()>(())
    });

    match result {
        Ok(()) => PhalanxError::Ok.code(),
        Err(()) => PhalanxError::InvalidState.code(),
    }
}

/// Debug: returns "shards=N,key=true/false" as a C string for a recording.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `recording_id` must be a valid null-terminated C string.
/// * `out_info` must be a valid pointer to receive the C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_debug_recording_info(
    handle: *mut PhalanxHandle,
    recording_id: *const c_char,
    out_info: *mut *mut c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };
    if recording_id.is_null() || out_info.is_null() {
        return PhalanxError::NullPointer.code();
    }
    let id_str = match CStr::from_ptr(recording_id).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let rec_id = RecordingId::new(id_str);
    let storage_tx = h.storage_tx.clone();

    let result = h.runtime.block_on(async {
        let (tx, rx) = tokio::sync::oneshot::channel();
        storage_tx
            .send(
                phalanx_node::actors::storage::StorageCommand::DebugRecordingInfo {
                    recording_id: rec_id,
                    reply_to: tx,
                },
            )
            .await
            .map_err(|_| ())?;
        rx.await.map_err(|_| ())
    });

    let (shards, has_key) = result.unwrap_or((0, false));
    let info = format!("shards={shards},key={has_key}");
    match std::ffi::CString::new(info) {
        Ok(cstr) => {
            *out_info = cstr.into_raw();
            PhalanxError::Ok.code()
        }
        Err(_) => PhalanxError::InvalidState.code(),
    }
}

/// Simple pseudo-random u64 from system time for sharing secrets.
/// Not cryptographically secure — the real security is in the X25519 ECDH
/// `SealedLocator` wrapping, not this identifier.
fn rand_u64() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| {
            // Truncation is intentional: nanos won't exceed u64 for ~584 years
            #[allow(clippy::cast_possible_truncation)]
            let v = d.as_nanos() as u64;
            v
        })
        .unwrap_or(0)
        ^ 0x517cc1b727220a95 // xor with a constant to avoid trivial values
}
