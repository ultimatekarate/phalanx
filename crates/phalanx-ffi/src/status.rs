// crates/phalanx-ffi/src/status.rs
//
// Minimal query functions for the Flutter UI.
// Only what the UI actually needs — no dashboards, no spectral analysis displays.
// This is an emergency tool, not a monitoring console.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use std::ffi::CString;
use std::os::raw::c_char;

/// Returns the current power state as an integer.
///
/// Values: 0 = Normal, 1 = Conserving, 2 = Leaf, 3 = Dormant
/// Returns -1 on null pointer or error.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_get_power_state(handle: *const PhalanxHandle) -> i32 {
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        h.governor.current_power_state() as i32
    }
}

/// Returns whether a recording is currently active.
///
/// Returns: 1 = recording, 0 = not recording, negative = error
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_is_recording(handle: *const PhalanxHandle) -> i32 {
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        i32::from(
            h.recording_active
                .load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

/// Returns the node's DID (Decentralized Identifier) as a C string.
///
/// The returned string must be freed with `phalanx_free_string`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out` must be a valid pointer to a `*mut c_char` that will receive the result.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_get_node_did(
    handle: *const PhalanxHandle,
    out: *mut *mut c_char,
) -> i32 {
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        if out.is_null() {
            return PhalanxError::NullPointer.code();
        }

        match CString::new(h.node_did.clone()) {
            Ok(cstr) => {
                *out = cstr.into_raw();
                PhalanxError::Ok.code()
            }
            Err(_) => PhalanxError::InvalidUtf8.code(),
        }
    }
}

// =====================================================================
// HARDWARE PROBE UPDATES (Flutter → Rust atomics)
// =====================================================================

/// Updates battery level and charging state.
///
/// Called by Flutter every ~10 seconds via `battery_plus` package.
/// Drives the homeostatic integrals for power-state-aware duty cycling.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_update_battery(
    handle: *mut PhalanxHandle,
    level: u8,
    charging: bool,
) -> i32 {
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        h.probe.set_battery(level, charging);
        PhalanxError::Ok.code()
    }
}

/// Updates thermal reading in degrees Celsius.
///
/// Called by Flutter every ~10 seconds.
/// Thermal state drives power conservation transitions.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_update_thermal(handle: *mut PhalanxHandle, celsius: i32) -> i32 {
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        h.probe.set_thermal(celsius);
        PhalanxError::Ok.code()
    }
}

/// Updates foreground/background lifecycle state.
///
/// Called by Flutter's `WidgetsBindingObserver` on lifecycle transitions.
/// `is_foreground = true` → Normal power state.
/// `is_foreground = false` → Dormant power state (no capture on iOS).
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_update_lifecycle(
    handle: *mut PhalanxHandle,
    is_foreground: bool,
) -> i32 {
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        h.probe.set_lifecycle(is_foreground);
        PhalanxError::Ok.code()
    }
}

/// Updates total device RAM in bytes.
///
/// Called once by Flutter shortly after `phalanx_create`/`phalanx_restore`,
/// using the platform's physical-memory API. RAM sizes the homeostatic
/// memory-pressure integrals; passing 0 leaves the reference-device fallback
/// in place. Additive setter — avoids an ABI change to `phalanx_create`.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn phalanx_update_device_ram(
    handle: *mut PhalanxHandle,
    total_ram_bytes: u64,
) -> i32 {
    unsafe {
        let Some(h) = handle.as_ref() else {
            return PhalanxError::NullPointer.code();
        };

        h.probe.set_device_ram(total_ram_bytes);
        PhalanxError::Ok.code()
    }
}
