// crates/phalanx-ffi/src/local_mesh.rs
//
// Local mesh FFI — bridges Flutter's BLE/WiFi Direct platform code into Rust.
//
// Flutter owns the transport (CoreBluetooth, Android BLE GATT, WiFi Direct).
// These C-ABI functions push inbound events into the LocalMeshAdapter's channel
// and poll outbound packets for Flutter to transmit.
//
// Follows the same patterns as capture.rs (try_send) and playback.rs (try_recv).

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use phalanx_proto::identity::MeshAddress;
use phalanx_proto::network::{BleChallenge, BleResponse, NetworkEvent};
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::topology::{SubnetBucket, TransportClass};

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::Ordering;

/// Current wall-clock time in milliseconds since the Unix epoch, for the BLE
/// challenge freshness window. The verifier IS the challenger (it answers its
/// own challenge), so this shares the local-time basis the challenge's
/// `issued_at` was stamped with — the comparison holds even with no NTP.
fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Rolling window (ms) for the LocalMesh admission rate cap.
const LOCAL_MESH_ADMIT_WINDOW_MS: u64 = 60_000;
/// Max authenticated LocalMesh peers admitted per window — the anti-sybil
/// throttle. A co-located attacker who mints `did:key`s and completes valid
/// handshakes is still bounded to this many new LocalMesh admissions per
/// window, so it cannot flood the privileged LocalMesh admission lane or inflate
/// the corroboration proximity count. A policy-layer threshold at the admission
/// boundary (not on the integral path), like `target_fps(PowerState)`.
const LOCAL_MESH_ADMIT_MAX_PER_WINDOW: usize = 8;

/// Drop admission timestamps older than `window` (front of the deque is oldest)
/// and return how many remain within the window. Pure, so the cap is
/// unit-testable without a live handle.
fn prune_and_count(times: &mut std::collections::VecDeque<u64>, now: u64, window: u64) -> usize {
    while let Some(&front) = times.front() {
        if now.saturating_sub(front) > window {
            times.pop_front();
        } else {
            break;
        }
    }
    times.len()
}

/// Verify a BLE auth response and, only on success, admit the peer as an
/// authenticated LocalMesh discovery. This is the Rust-side trust boundary for
/// proximity corroboration.
///
/// A `PeerDiscovered{LocalMesh}` event — and therefore a `ProximityWitness` —
/// is emitted ONLY when all four hold:
///   1. the responder's Ed25519 signature verifies over the recording/time-bound
///      message (`verify_ble_response`),
///   2. the challenge is fresh — within `BLE_CHALLENGE_MAX_AGE` of now,
///   3. the per-window LocalMesh admission cap is not yet reached — the
///      anti-sybil throttle for a co-located attacker minting valid handshakes,
///   4. the challenge nonce has not already been admitted (single-use).
///
/// There is deliberately NO bare "push a discovered peer" entry point: the
/// platform plugin cannot mint an unauthenticated LocalMesh peer, because the
/// only path that emits the discovery runs this verification first. The DID the
/// witness binds is the one whose signature just verified — not an
/// FFI-supplied string the engine would otherwise trust blindly.
///
/// `challenge` and `response` are opaque postcard blobs the plugin relays over
/// BLE; it never constructs or parses them.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `challenge_ptr`/`response_ptr` must point to the declared number of
///   readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_ble_verify_and_admit(
    handle: *mut PhalanxHandle,
    challenge_ptr: *const u8,
    challenge_len: usize,
    response_ptr: *const u8,
    response_len: usize,
) -> i32 {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. `handle` is null-checked via `as_ref`;
    // `challenge_ptr`/`response_ptr` are null-checked before being read via
    // `from_raw_parts` for the caller-declared lengths.
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };
        if challenge_ptr.is_null() || response_ptr.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let challenge_bytes = std::slice::from_raw_parts(challenge_ptr, challenge_len);
        let response_bytes = std::slice::from_raw_parts(response_ptr, response_len);

        let challenge: BleChallenge = match postcard::from_bytes(challenge_bytes) {
            Ok(c) => c,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };
        let response: BleResponse = match postcard::from_bytes(response_bytes) {
            Ok(r) => r,
            Err(_) => return PhalanxError::SerializationFailure.code(),
        };

        // (1) Signature over the recording/time-bound message.
        if phalanx_forensics::identity::verify_ble_response(&challenge, &response).is_err() {
            tracing::warn!(
                target: "phalanx::ffi",
                peer = %response.responder_did,
                "BLE admit rejected: signature did not verify"
            );
            return PhalanxError::InvalidState.code();
        }

        // (2) Freshness — reject stale or far-future challenges (later replay).
        let now_ms = now_millis();
        if !phalanx_forensics::identity::ble_challenge_is_fresh(
            challenge.issued_at,
            PhalanxTimestamp::from_u64(now_ms),
            phalanx_forensics::identity::BLE_CHALLENGE_MAX_AGE,
        ) {
            tracing::warn!(
                target: "phalanx::ffi",
                peer = %response.responder_did,
                "BLE admit rejected: stale challenge"
            );
            return PhalanxError::InvalidState.code();
        }

        // (3) Per-window admission cap — throttle co-located sybil floods even
        // when each handshake individually verifies. Checked before the nonce is
        // consumed so a rate-limited honest peer can retry the same challenge in
        // a later window.
        {
            let mut times = h.ble_admit_times.lock().unwrap_or_else(|e| e.into_inner());
            let in_window = prune_and_count(&mut times, now_ms, LOCAL_MESH_ADMIT_WINDOW_MS);
            if in_window >= LOCAL_MESH_ADMIT_MAX_PER_WINDOW {
                tracing::warn!(
                    target: "phalanx::ffi",
                    peer = %response.responder_did,
                    in_window,
                    "BLE admit rejected: per-window LocalMesh cap reached"
                );
                return PhalanxError::InvalidState.code();
            }
        }

        // (4) Single-use nonce — reject immediate replay of a valid pair.
        {
            let mut seen = h
                .ble_admitted_nonces
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let max_age = phalanx_forensics::identity::BLE_CHALLENGE_MAX_AGE.as_u64();
            // Prune entries outside the freshness window so the set stays bounded.
            seen.retain(|_, &mut admitted_at| now_ms.saturating_sub(admitted_at) <= max_age);
            if seen.contains_key(&challenge.nonce) {
                tracing::warn!(
                    target: "phalanx::ffi",
                    peer = %response.responder_did,
                    "BLE admit rejected: replayed nonce"
                );
                return PhalanxError::InvalidState.code();
            }
            seen.insert(challenge.nonce, now_ms);
        }

        // All checks passed — record this admission in the rate window before
        // emitting. Recorded here (not at the cap check) so a replay-rejected
        // attempt does not count against the window.
        h.ble_admit_times
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push_back(now_ms);

        // Admit: emit an authenticated LocalMesh discovery. The engine binds the
        // witness's `remote_did` to this now-verified DID.
        let tx = match &h.local_mesh_tx {
            Some(tx) => tx,
            None => return PhalanxError::ChannelClosed.code(),
        };
        let event = NetworkEvent::PeerDiscovered {
            peer: MeshAddress::new(response.responder_did.as_str()),
            source: DiscoverySource::LocalMesh,
            bucket: SubnetBucket::local_mesh(),
            transport: TransportClass::LocalMesh,
        };
        match tx.try_send(event) {
            Ok(()) => PhalanxError::Ok.code(),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                // Backpressure: drop silently, same as video frames.
                PhalanxError::Ok.code()
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                PhalanxError::ChannelClosed.code()
            }
        }
    }
}

/// Pushes received data from a local mesh peer into the channel.
///
/// Called when BLE/WiFi Direct receives data from a nearby device.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `peer_id` must be a valid null-terminated C string.
/// * `topic` must be a valid null-terminated C string.
/// * `data` must point to `data_len` valid bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_local_mesh_push_data_received(
    handle: *mut PhalanxHandle,
    peer_id: *const c_char,
    topic: *const c_char,
    data: *const u8,
    data_len: u32,
) -> i32 {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. `handle` is null-checked via `as_ref`;
    // `peer_id`/`topic`/`data` are null-checked before `peer_id`/`topic`
    // are read as NUL-terminated C strings and `data` via `from_raw_parts`
    // for the caller-declared `data_len`.
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        if peer_id.is_null() || topic.is_null() || data.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let peer_str = match CStr::from_ptr(peer_id).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        let topic_str = match CStr::from_ptr(topic).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        let payload = std::slice::from_raw_parts(data, data_len as usize).to_vec();

        let tx = match &h.local_mesh_tx {
            Some(tx) => tx,
            None => return PhalanxError::ChannelClosed.code(),
        };

        let event = NetworkEvent::DataReceived {
            origin: MeshAddress::new(peer_str.to_string()),
            topic: phalanx_proto::prelude::MeshTopic::from(topic_str),
            data: payload,
        };

        match tx.try_send(event) {
            Ok(()) => PhalanxError::Ok.code(),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => PhalanxError::Ok.code(),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                PhalanxError::ChannelClosed.code()
            }
        }
    }
}

/// Pushes a peer disconnection event from Flutter into the local mesh channel.
///
/// Called when a BLE/WiFi Direct peer goes out of range or disconnects.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `peer_id` must be a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_local_mesh_push_peer_disconnected(
    handle: *mut PhalanxHandle,
    peer_id: *const c_char,
) -> i32 {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. `handle` is null-checked via `as_ref`;
    // `peer_id` is null-checked before being read as a caller-guaranteed
    // NUL-terminated C string.
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        if peer_id.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let peer_str = match CStr::from_ptr(peer_id).to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };

        let tx = match &h.local_mesh_tx {
            Some(tx) => tx,
            None => return PhalanxError::ChannelClosed.code(),
        };

        let event = NetworkEvent::PeerDisconnected {
            peer: MeshAddress::new(peer_str.to_string()),
        };

        match tx.try_send(event) {
            Ok(()) => PhalanxError::Ok.code(),
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => PhalanxError::Ok.code(),
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                PhalanxError::ChannelClosed.code()
            }
        }
    }
}

/// Polls for the next outbound local mesh packet.
///
/// Flutter calls this to retrieve data that Rust wants to send to a local peer.
/// Returns the target peer ID, data, and data length through output parameters.
/// If no packet is available, `*out_data` is set to null and returns Ok.
///
/// Caller must free `*out_peer` with `phalanx_free_string` and `*out_data`
/// with `phalanx_free_bytes`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_peer`, `out_data`, and `out_len` must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_local_mesh_poll_outbound(
    handle: *mut PhalanxHandle,
    out_peer: *mut *mut c_char,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. `handle` is null-checked via `as_ref`;
    // `out_peer`/`out_data`/`out_len` are null-checked before the leaked
    // string and byte-buffer pointers and length are written through them,
    // and the caller guarantees each is a writable pointer of the matching
    // pointee type.
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        if out_peer.is_null() || out_data.is_null() || out_len.is_null() {
            return PhalanxError::NullPointer.code();
        }

        let Ok(mut guard) = h.local_mesh_outbound_rx.lock() else {
            return PhalanxError::InvalidState.code();
        };

        let rx = match guard.as_mut() {
            Some(rx) => rx,
            None => {
                *out_data = std::ptr::null_mut();
                *out_len = 0;
                *out_peer = std::ptr::null_mut();
                return PhalanxError::Ok.code();
            }
        };

        match rx.try_recv() {
            Ok(packet) => {
                // Peer ID → C string (caller frees with phalanx_free_string).
                // libp2p peer IDs are base58 and contain no NULs, so the
                // CString conversion realistically cannot fail. If it ever
                // does, the packet is dropped on the floor (already dequeued)
                // and the caller sees `InvalidUtf8`. Trace the impossible
                // path so it surfaces if invariants change upstream.
                match std::ffi::CString::new(packet.target.0.clone()) {
                    Ok(cstr) => {
                        *out_peer = cstr.into_raw();
                    }
                    Err(_) => {
                        tracing::warn!(
                            target: "phalanx::ffi",
                            peer = %packet.target.0,
                            bytes = packet.data.len(),
                            "outbound local-mesh packet dropped: peer ID contained interior NUL (unreachable path)"
                        );
                        *out_data = std::ptr::null_mut();
                        *out_len = 0;
                        *out_peer = std::ptr::null_mut();
                        return PhalanxError::InvalidUtf8.code();
                    }
                }

                // Data → leaked allocation (caller frees with phalanx_free_bytes)
                crate::memory::leak_bytes_to_c(packet.data.into_boxed_slice(), out_data, out_len);

                PhalanxError::Ok.code()
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Empty) => {
                *out_data = std::ptr::null_mut();
                *out_len = 0;
                *out_peer = std::ptr::null_mut();
                PhalanxError::Ok.code()
            }
            Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                *out_data = std::ptr::null_mut();
                *out_len = 0;
                *out_peer = std::ptr::null_mut();
                *guard = None;
                PhalanxError::ChannelClosed.code()
            }
        }
    }
}

/// Sets the local mesh transport availability flag.
///
/// Flutter calls this when BLE/WiFi Direct becomes available or unavailable.
/// The MeshSentinel's select! loop checks `is_available()` to decide whether
/// to poll the local mesh adapter.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_local_mesh_set_available(
    handle: *mut PhalanxHandle,
    available: bool,
) -> i32 {
    // SAFETY: caller upholds the # Safety contract on the parent
    // `unsafe extern "C" fn`. `handle.as_ref()` null-checks the pointer and
    // otherwise yields a `&PhalanxHandle` whose validity the caller
    // guarantees; no other raw pointer is dereferenced.
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        h.local_mesh_available.store(available, Ordering::Relaxed);
        PhalanxError::Ok.code()
    }
}

#[cfg(test)]
mod tests {
    use super::{LOCAL_MESH_ADMIT_MAX_PER_WINDOW, LOCAL_MESH_ADMIT_WINDOW_MS, prune_and_count};
    use std::collections::VecDeque;

    #[test]
    fn empty_window_counts_zero() {
        let mut times = VecDeque::new();
        assert_eq!(
            prune_and_count(&mut times, 1_000, LOCAL_MESH_ADMIT_WINDOW_MS),
            0
        );
    }

    #[test]
    fn in_window_admissions_are_retained() {
        // Three admissions, all within a 60s window ending at now = 60_000.
        let mut times = VecDeque::from([10_000_u64, 30_000, 60_000]);
        assert_eq!(
            prune_and_count(&mut times, 60_000, LOCAL_MESH_ADMIT_WINDOW_MS),
            3
        );
        assert_eq!(times.len(), 3);
    }

    #[test]
    fn expired_admissions_are_pruned() {
        // now = 100_000, window = 60_000 → anything stamped before 40_000 expires.
        let mut times = VecDeque::from([5_000_u64, 39_999, 40_000, 70_000]);
        assert_eq!(
            prune_and_count(&mut times, 100_000, LOCAL_MESH_ADMIT_WINDOW_MS),
            2
        );
        // The boundary entry (exactly `window` old) survives; older ones are gone.
        assert_eq!(times.front().copied(), Some(40_000));
    }

    #[test]
    fn window_boundary_is_inclusive() {
        // Exactly `window` old → retained; pruning drops only strictly-older.
        let mut times = VecDeque::from([40_000_u64]);
        assert_eq!(
            prune_and_count(&mut times, 100_000, LOCAL_MESH_ADMIT_WINDOW_MS),
            1
        );
    }

    #[test]
    fn count_reaches_cap_after_a_burst() {
        // `cap` admissions all inside one window → the window reads as full, so
        // the next verify_and_admit sees `in_window >= cap` and is throttled.
        let mut times: VecDeque<u64> = VecDeque::new();
        for _ in 0..LOCAL_MESH_ADMIT_MAX_PER_WINDOW {
            times.push_back(1_000);
        }
        let in_window = prune_and_count(&mut times, 2_000, LOCAL_MESH_ADMIT_WINDOW_MS);
        assert_eq!(in_window, LOCAL_MESH_ADMIT_MAX_PER_WINDOW);
    }
}
