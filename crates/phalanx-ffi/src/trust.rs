// crates/phalanx-ffi/src/trust.rs
//
// Trust + peer management FFI — the social graph interface.
//
// Exposes peer listing, trust level management, pet name assignment, and
// peer removal through the TrustCommand channel to the TrustActor.
//
// All operations are async internally but presented as synchronous to the
// C-ABI caller via `blocking_send`/`blocking_recv`. This is acceptable because
// trust operations are infrequent (user-initiated, not per-frame).

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use phalanx_node::actors::trust_actor::TrustCommand;
use phalanx_proto::prelude::Did;
use phalanx_proto::trust::{PetName, TrustLevel};

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use tokio::sync::oneshot;

/// Returns the peer list as a JSON array string.
///
/// The returned string must be freed with `phalanx_free_string`.
/// Format: `[{"did":"did:key:...","pet_name":"Alice","level":"Verified","score":100,"is_blacklisted":false}, ...]`
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_json` must be a valid pointer to receive the C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_get_peers(
    handle: *const PhalanxHandle,
    out_json: *mut *mut c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if out_json.is_null() {
        return PhalanxError::NullPointer.code();
    }

    // Send ListPeers command and await response
    let (reply_tx, reply_rx) = oneshot::channel();
    let cmd = TrustCommand::ListPeers { reply_to: reply_tx };

    if h.trust_tx.blocking_send(cmd).is_err() {
        return PhalanxError::ChannelClosed.code();
    }

    match reply_rx.blocking_recv() {
        Ok(peers) => {
            let json = match serde_json::to_string(&peers) {
                Ok(j) => j,
                Err(_) => return PhalanxError::InvalidState.code(),
            };
            match CString::new(json) {
                Ok(cstr) => {
                    *out_json = cstr.into_raw();
                    PhalanxError::Ok.code()
                }
                Err(_) => PhalanxError::InvalidUtf8.code(),
            }
        }
        Err(_) => PhalanxError::ChannelClosed.code(),
    }
}

/// Sets the trust level for a peer.
///
/// Trust levels: 0 = Blocked, 1 = Ignored, 2 = Verified, 3 = Ally
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `did` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_set_trust_level(
    handle: *mut PhalanxHandle,
    did: *const c_char,
    level: i32,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if did.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let did_str = match CStr::from_ptr(did).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let trust_level = match level {
        0 => TrustLevel::Blocked,
        1 => TrustLevel::Ignored,
        2 => TrustLevel::Verified,
        3 => TrustLevel::Ally,
        _ => return PhalanxError::TrustError.code(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    let cmd = TrustCommand::SetTrustLevel {
        did: Did::new(did_str),
        level: trust_level,
        reply_to: reply_tx,
    };

    if h.trust_tx.blocking_send(cmd).is_err() {
        return PhalanxError::ChannelClosed.code();
    }

    match reply_rx.blocking_recv() {
        Ok(Ok(())) => PhalanxError::Ok.code(),
        Ok(Err(_)) => PhalanxError::TrustError.code(),
        Err(_) => PhalanxError::ChannelClosed.code(),
    }
}

/// Assigns a pet name to a peer.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `did` and `name` must be valid null-terminated C strings.
#[no_mangle]
pub unsafe extern "C" fn phalanx_assign_pet_name(
    handle: *mut PhalanxHandle,
    did: *const c_char,
    name: *const c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if did.is_null() || name.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let did_str = match CStr::from_ptr(did).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let name_str = match CStr::from_ptr(name).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let pet_name = match PetName::new(name_str) {
        Ok(pn) => pn,
        Err(_) => return PhalanxError::TrustError.code(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    let cmd = TrustCommand::AssignPetName {
        did: Did::new(did_str),
        name: pet_name,
        reply_to: reply_tx,
    };

    if h.trust_tx.blocking_send(cmd).is_err() {
        return PhalanxError::ChannelClosed.code();
    }

    match reply_rx.blocking_recv() {
        Ok(Ok(())) => PhalanxError::Ok.code(),
        Ok(Err(_)) => PhalanxError::TrustError.code(),
        Err(_) => PhalanxError::ChannelClosed.code(),
    }
}

/// Removes a peer from the trust registry.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `did` must be a valid null-terminated C string.
#[no_mangle]
pub unsafe extern "C" fn phalanx_remove_peer(
    handle: *mut PhalanxHandle,
    did: *const c_char,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if did.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let did_str = match CStr::from_ptr(did).to_str() {
        Ok(s) => s,
        Err(_) => return PhalanxError::InvalidUtf8.code(),
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    let cmd = TrustCommand::RemovePeer {
        did: Did::new(did_str),
        reply_to: reply_tx,
    };

    if h.trust_tx.blocking_send(cmd).is_err() {
        return PhalanxError::ChannelClosed.code();
    }

    match reply_rx.blocking_recv() {
        Ok(Ok(())) => PhalanxError::Ok.code(),
        Ok(Err(_)) => PhalanxError::TrustError.code(),
        Err(_) => PhalanxError::ChannelClosed.code(),
    }
}
