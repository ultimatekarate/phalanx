// crates/phalanx-ffi/src/profile.rs
//
// Profile-selection helpers for the mobile picker. Both functions are pure
// (no engine handle), mirroring `phalanx_validate_mnemonic`: the UI calls them
// before `phalanx_create_with_profile` to pre-screen a pairing and to gate the
// picker from Rust truth instead of a hardcoded Dart list.

use crate::error::PhalanxError;
use phalanx_node::config::ArchivalPeer;
use phalanx_proto::network::deployment::DeploymentProfile;
use std::ffi::CStr;
use std::os::raw::c_char;

/// Validate a Stronghold pairing (address + optional DID) before it is handed to
/// [`phalanx_create_with_profile`](crate::handle::phalanx_create_with_profile).
/// Stateless — no engine required.
///
/// Returns `PhalanxError::Ok` (0) iff `stronghold_addr` is a dialable multiaddr
/// carrying a `/p2p/<peer-id>` tail — the same hard check `NodeConfig::assemble`
/// enforces, so a green result here guarantees create will not reject the
/// address. A typo'd or tail-less address returns `ConfigError`, letting the UI
/// say "that address looks malformed" rather than surfacing a blank boot failure
/// later. `stronghold_did` is optional (null ⇒ custody-only push); when present
/// it must be valid UTF-8.
///
/// # Safety
/// `stronghold_addr` must be null or a valid null-terminated C string;
/// `stronghold_did` must be null or a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_validate_pairing(
    stronghold_addr: *const c_char,
    stronghold_did: *const c_char,
) -> i32 {
    crate::panic_safety::ffi_panic_safe(PhalanxError::Panic.code(), || {
        if stronghold_addr.is_null() {
            return PhalanxError::NullPointer.code();
        }
        // SAFETY: caller upholds the # Safety contract on the parent
        // `unsafe extern "C" fn`; `stronghold_addr` is non-null here and the
        // caller guarantees it points to a valid NUL-terminated C string.
        let addr = match unsafe { CStr::from_ptr(stronghold_addr) }.to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };
        // A present DID must at least be valid UTF-8 (`Did::new` is total, so
        // there is nothing further to reject structurally).
        if !stronghold_did.is_null() {
            // SAFETY: non-null checked; caller guarantees a valid C string.
            if unsafe { CStr::from_ptr(stronghold_did) }.to_str().is_err() {
                return PhalanxError::InvalidUtf8.code();
            }
        }
        let peer = ArchivalPeer {
            address: addr.to_string(),
            stronghold_did: None,
        };
        if peer.peer_id().is_some() {
            PhalanxError::Ok.code()
        } else {
            PhalanxError::ConfigError.code()
        }
    })
}

/// Capability flags for a profile name, so the Dart picker is driven by Rust
/// truth rather than a hardcoded list. Returns a non-negative bitfield for a
/// known public archetype, or a negative `PhalanxError` code (`NullPointer`,
/// `InvalidUtf8`, or `ConfigError` for an unknown name) otherwise.
///
/// Bitfield: `bit0 (1)` = known; `bit1 (2)` = needs a Stronghold pairing;
/// `bit2 (4)` = requires a PSK (not yet supplied on mobile, so the UI disables
/// those profiles). Thus `solo_device` → 1, `community_with_stronghold` → 3,
/// `affinity_group_lan` → 5, `high_risk_cross_border` → 7.
///
/// # Safety
/// `profile_name` must be null or a valid null-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_profile_flags(profile_name: *const c_char) -> i32 {
    crate::panic_safety::ffi_panic_safe(PhalanxError::Panic.code(), || {
        if profile_name.is_null() {
            return PhalanxError::NullPointer.code();
        }
        // SAFETY: non-null checked; caller guarantees a valid C string.
        let name = match unsafe { CStr::from_ptr(profile_name) }.to_str() {
            Ok(s) => s,
            Err(_) => return PhalanxError::InvalidUtf8.code(),
        };
        match DeploymentProfile::from_name(name) {
            Some(profile) => {
                let mut flags = 1i32; // bit0: known
                if profile.has_stronghold_role() {
                    flags |= 2; // bit1: needs a Stronghold pairing
                }
                if profile.psk_posture().require_psk() {
                    flags |= 4; // bit2: requires a PSK (disabled on mobile)
                }
                flags
            }
            None => PhalanxError::ConfigError.code(),
        }
    })
}
