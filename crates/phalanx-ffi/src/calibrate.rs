// crates/phalanx-ffi/src/calibrate.rs
//
// PRNU calibration FFI — three-step pipeline for Flutter:
//
//   1. phalanx_calibration_start(handle) — enter calibration mode
//   2. phalanx_calibration_push_frame(handle, y_plane, ...) — analyze a frame
//   3. phalanx_calibration_finish(handle, out_prnu_floor) — compute + store result
//
// The calibration binds the PRNU detection threshold to the physical sensor.
// Friction is a feature — an honest user does the calibration; a synthetic
// source cannot replicate the noise profile of a real camera.

use crate::error::PhalanxError;
use crate::handle::PhalanxHandle;

use phalanx_forensics::calibrate::{calibrate_prnu, posterior_from_batch, MAX_CALIBRATION_FRAMES};
use phalanx_lens::scalar::ScalarLens;
use phalanx_lens::ForensicLens;
use phalanx_node::actors::storage::StorageCommand;
use phalanx_proto::types::BlackLevel;

/// Static forensic lens — same instance used in capture.rs.
static LENS: ScalarLens = ScalarLens;

/// Starts PRNU calibration. Allocates the frame buffer.
///
/// Call this before pushing calibration frames. Returns error if calibration
/// is already in progress.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
#[no_mangle]
pub unsafe extern "C" fn phalanx_calibration_start(handle: *const PhalanxHandle) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    let Ok(mut guard) = h.calibration_metrics.lock() else {
        return PhalanxError::InvalidState.code();
    };

    if guard.is_some() {
        return PhalanxError::AlreadyRunning.code();
    }

    *guard = Some(Vec::new());
    PhalanxError::Ok.code()
}

/// Pushes a calibration frame. Runs ForensicLens on the Y-plane and stores
/// the resulting metrics.
///
/// Call this for each calibration frame (minimum 10, maximum 100).
/// Returns error if calibration is not in progress or buffer is full.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `y_plane` must point to `y_len` valid bytes of Y-plane data.
#[no_mangle]
pub unsafe extern "C" fn phalanx_calibration_push_frame(
    handle: *const PhalanxHandle,
    y_plane: *const u8,
    y_len: u32,
    width: u32,
    height: u32,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if y_plane.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let y_slice = std::slice::from_raw_parts(y_plane, y_len as usize);

    let Ok(mut guard) = h.calibration_metrics.lock() else {
        return PhalanxError::InvalidState.code();
    };

    let Some(ref mut metrics) = *guard else {
        // Calibration not started
        return PhalanxError::InvalidState.code();
    };

    if metrics.len() >= MAX_CALIBRATION_FRAMES {
        return PhalanxError::InvalidState.code();
    }

    let result = LENS.analyze(
        y_slice,
        width as usize,
        height as usize,
        BlackLevel::default(),
    );

    metrics.push(result);
    PhalanxError::Ok.code()
}

/// Finishes calibration, computes the PRNU floor, and writes it to `out_prnu_floor`.
///
/// Clears the calibration buffer regardless of success/failure.
/// On success, the calibrated floor is stored — the caller (Flutter) should
/// persist it to the device config.
///
/// # Safety
/// * `handle` must be a valid pointer from `phalanx_create`.
/// * `out_prnu_floor` must be a valid pointer to receive the f32 result.
#[no_mangle]
pub unsafe extern "C" fn phalanx_calibration_finish(
    handle: *const PhalanxHandle,
    out_prnu_floor: *mut f32,
) -> i32 {
    let Some(h) = handle.as_ref() else {
        return PhalanxError::NullPointer.code();
    };

    if out_prnu_floor.is_null() {
        return PhalanxError::NullPointer.code();
    }

    let Ok(mut guard) = h.calibration_metrics.lock() else {
        return PhalanxError::InvalidState.code();
    };

    // Take the metrics buffer (clears calibration state)
    let Some(metrics) = guard.take() else {
        return PhalanxError::InvalidState.code();
    };

    // Build Bayesian posterior from the calibration batch (warm-start).
    // This replaces whatever the online path has accumulated so far with
    // a posterior built from controlled calibration frames.
    let batch_posterior = posterior_from_batch(&metrics);
    if let Ok(mut post) = h.prnu_posterior.lock() {
        *post = batch_posterior;
    }
    // Persist the warm-started posterior through the actor channel.
    let _ = h
        .storage_tx
        .try_send(StorageCommand::PersistPosterior(batch_posterior));

    match calibrate_prnu(&metrics) {
        Ok(calibration) => {
            *out_prnu_floor = calibration.prnu_floor;
            PhalanxError::Ok.code()
        }
        Err(_) => PhalanxError::InvalidState.code(),
    }
}
