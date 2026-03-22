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

use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topology::{SubnetBucket, TransportClass};

use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::atomic::Ordering;

/// Pushes a peer discovery event from Flutter into the local mesh channel.
///
/// Called when BLE/WiFi Direct discovers a nearby device.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `peer_id` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_local_mesh_push_peer_discovered(
    handle: *mut PhalanxHandle,
    peer_id: *const c_char,
) -> i32 {
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

    let event = NetworkEvent::PeerDiscovered {
        peer: NetworkId(peer_str.to_string()),
        source: DiscoverySource::LocalMesh,
        bucket: SubnetBucket::local_mesh(),
        transport: TransportClass::LocalMesh,
    };

    match tx.try_send(event) {
        Ok(()) => PhalanxError::Ok.code(),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            // Backpressure: drop silently, same as video frames
            PhalanxError::Ok.code()
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            PhalanxError::ChannelClosed.code()
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
#[no_mangle]
pub unsafe extern "C" fn phalanx_local_mesh_push_data_received(
    handle: *mut PhalanxHandle,
    peer_id: *const c_char,
    topic: *const c_char,
    data: *const u8,
    data_len: u32,
) -> i32 {
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
        origin: NetworkId(peer_str.to_string()),
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

/// Pushes a peer disconnection event from Flutter into the local mesh channel.
///
/// Called when a BLE/WiFi Direct peer goes out of range or disconnects.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `peer_id` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_local_mesh_push_peer_disconnected(
    handle: *mut PhalanxHandle,
    peer_id: *const c_char,
) -> i32 {
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
        peer: NetworkId(peer_str.to_string()),
    };

    match tx.try_send(event) {
        Ok(()) => PhalanxError::Ok.code(),
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => PhalanxError::Ok.code(),
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            PhalanxError::ChannelClosed.code()
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
#[no_mangle]
pub unsafe extern "C" fn phalanx_local_mesh_poll_outbound(
    handle: *mut PhalanxHandle,
    out_peer: *mut *mut c_char,
    out_data: *mut *mut u8,
    out_len: *mut u32,
) -> i32 {
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
            // Peer ID → C string (caller frees with phalanx_free_string)
            match std::ffi::CString::new(packet.target.0) {
                Ok(cstr) => {
                    *out_peer = cstr.into_raw();
                }
                Err(_) => {
                    *out_data = std::ptr::null_mut();
                    *out_len = 0;
                    *out_peer = std::ptr::null_mut();
                    return PhalanxError::InvalidUtf8.code();
                }
            }

            // Data → leaked allocation (caller frees with phalanx_free_bytes)
            #[allow(clippy::cast_possible_truncation)]
            let len = packet.data.len() as u32;
            let mut boxed = packet.data.into_boxed_slice();
            *out_data = boxed.as_mut_ptr();
            *out_len = len;
            std::mem::forget(boxed);

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

/// Sets the local mesh transport availability flag.
///
/// Flutter calls this when BLE/WiFi Direct becomes available or unavailable.
/// The MeshSentinel's select! loop checks `is_available()` to decide whether
/// to poll the local mesh adapter.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_local_mesh_set_available(
    handle: *mut PhalanxHandle,
    available: bool,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    h.local_mesh_available.store(available, Ordering::Relaxed);
    PhalanxError::Ok.code()
}
