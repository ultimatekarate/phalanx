// crates/phalanx-forensics/src/calibrate.rs
//
// PRNU calibration pipeline: the Verb "To Calibrate."
//
// Pure function, no IO. Takes ForensicMetrics from N test frames captured
// during explicit device setup and derives a per-sensor PRNU floor threshold.
//
// The calibration binds the detection threshold to the physical sensor's noise
// profile. A stolen identity cannot replicate the PRNU of a different camera.

use phalanx_proto::evidence::{ForensicMetrics, SensorCalibration};
use phalanx_proto::prelude::ShardError;

/// Minimum number of valid frames required for calibration.
/// Fewer frames produce unreliable statistics — reject the calibration.
pub const MIN_CALIBRATION_FRAMES: usize = 10;

/// Maximum calibration frames accepted from FFI. Prevents unbounded
/// allocation from rogue FFI calls.
pub const MAX_CALIBRATION_FRAMES: usize = 100;

/// Minimum prnu_floor value. Prevents degenerate threshold from
/// pathological calibration (e.g., all frames nearly identical).
/// A floor below this would weaken LensGate to the point of accepting
/// synthetic content.
pub const PRNU_FLOOR_MINIMUM: f32 = 0.1;

/// Confidence margin in standard deviations below the mean ratio.
/// 3σ means <0.3% of legitimate frames will fall below the floor,
/// assuming approximately Gaussian distribution of prnu_var/luminance ratios.
const PRNU_CONFIDENCE_SIGMA: f32 = 3.0;

/// Minimum mean luminance for a frame to be usable in calibration.
/// Below this, the threshold formula `T × luminance` degenerates to ~0,
/// producing unreliable ratios.
const MIN_CALIBRATION_LUMINANCE: f32 = 1.0;

/// Derive a per-sensor PRNU floor from calibration frames.
///
/// Algorithm:
/// 1. Filter frames with `mean_luminance < 1.0` (too dark for reliable ratio)
/// 2. Require ≥ `MIN_CALIBRATION_FRAMES` valid frames after filtering
/// 3. For each valid frame: `r_i = prnu_var / mean_luminance`
/// 4. Compute `mean_r` and `std_r`
/// 5. `prnu_floor = max(mean_r − 3σ, PRNU_FLOOR_MINIMUM)`
///
/// Returns `SensorCalibration` with the derived floor and valid frame count.
#[allow(clippy::arithmetic_side_effects)] // Statistical arithmetic — subtraction for variance, division for mean.
pub fn calibrate_prnu(metrics: &[ForensicMetrics]) -> Result<SensorCalibration, ShardError> {
    // Filter out dark frames — unreliable ratios
    let ratios: Vec<f32> = metrics
        .iter()
        .filter(|m| m.mean_luminance >= MIN_CALIBRATION_LUMINANCE)
        .map(|m| m.prnu_var / m.mean_luminance)
        .collect();

    let valid_count = ratios.len();

    if valid_count < MIN_CALIBRATION_FRAMES {
        return Err(ShardError::InvalidConfiguration(format!(
            "Calibration requires at least {} valid frames, got {} \
             ({} total, {} filtered as too dark)",
            MIN_CALIBRATION_FRAMES,
            valid_count,
            metrics.len(),
            metrics.len() - valid_count,
        )));
    }

    let n = valid_count as f32;
    let mean_r: f32 = ratios.iter().sum::<f32>() / n;

    let variance: f32 = ratios.iter().map(|r| (r - mean_r).powi(2)).sum::<f32>() / n;
    let std_r = variance.sqrt();

    // Reject inconsistent sensor data — std > mean suggests mixed sources
    // or a malfunctioning sensor (RT-5 mitigation).
    if std_r > mean_r {
        return Err(ShardError::InvalidConfiguration(format!(
            "Calibration data too inconsistent: std ({:.4}) > mean ({:.4}). \
             Possible mixed lighting or sensor malfunction.",
            std_r, mean_r,
        )));
    }

    let prnu_floor = (mean_r - PRNU_CONFIDENCE_SIGMA * std_r).max(PRNU_FLOOR_MINIMUM);

    #[allow(clippy::cast_possible_truncation)]
    let frame_count = valid_count as u16;

    Ok(SensorCalibration {
        prnu_floor,
        frame_count,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::float_cmp,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use phalanx_test_fixtures::metrics::forensic_metrics_with_prnu;

    fn make_metrics(prnu_var: f32, mean_luminance: f32) -> ForensicMetrics {
        forensic_metrics_with_prnu(prnu_var, mean_luminance)
    }

    #[test]
    fn calibration_rejects_too_few_frames() {
        let metrics: Vec<ForensicMetrics> = (0..5).map(|_| make_metrics(2.0, 128.0)).collect();
        let result = calibrate_prnu(&metrics);
        assert!(result.is_err());
    }

    #[test]
    fn calibration_filters_dark_frames() {
        // 5 valid frames + 10 dark frames = only 5 valid → should fail
        let mut metrics: Vec<ForensicMetrics> = (0..5).map(|_| make_metrics(2.0, 128.0)).collect();
        metrics.extend((0..10).map(|_| make_metrics(0.001, 0.5)));

        let result = calibrate_prnu(&metrics);
        assert!(result.is_err());
    }

    #[test]
    fn calibration_succeeds_with_enough_valid_frames() {
        let metrics: Vec<ForensicMetrics> = (0..20).map(|_| make_metrics(2.0, 128.0)).collect();

        let cal = calibrate_prnu(&metrics).unwrap();
        assert_eq!(cal.frame_count, 20);
        // With uniform data, std = 0, so floor = mean_r = 2.0/128.0 ≈ 0.0156
        // But floor is clamped to PRNU_FLOOR_MINIMUM = 0.1
        assert!(
            cal.prnu_floor >= PRNU_FLOOR_MINIMUM,
            "Floor should be at least PRNU_FLOOR_MINIMUM, got {}",
            cal.prnu_floor
        );
    }

    #[test]
    fn calibration_floor_clamps_to_minimum() {
        // Very low PRNU/luminance ratio → floor would be below minimum
        let metrics: Vec<ForensicMetrics> = (0..20).map(|_| make_metrics(0.01, 128.0)).collect();

        let cal = calibrate_prnu(&metrics).unwrap();
        assert_eq!(
            cal.prnu_floor, PRNU_FLOOR_MINIMUM,
            "Floor should clamp to PRNU_FLOOR_MINIMUM"
        );
    }

    #[test]
    fn calibration_with_realistic_variance() {
        // Simulate realistic sensor with some variance in PRNU readings
        let metrics: Vec<ForensicMetrics> = (0..20)
            .map(|i| {
                let prnu = 1.5 + (i as f32 % 5.0) * 0.1; // 1.5, 1.6, 1.7, 1.8, 1.9 cycling
                make_metrics(prnu, 100.0)
            })
            .collect();

        let cal = calibrate_prnu(&metrics).unwrap();
        assert_eq!(cal.frame_count, 20);
        // mean_r ≈ 1.7/100 = 0.017, std_r small → floor near 0.017 → clamped to 0.1
        assert!(cal.prnu_floor >= PRNU_FLOOR_MINIMUM);
    }

    #[test]
    fn calibration_with_high_prnu_sensor() {
        // High-PRNU sensor (old/noisy camera) — floor should be above minimum
        let metrics: Vec<ForensicMetrics> = (0..20)
            .map(|i| {
                let prnu = 50.0 + (i as f32) * 2.0; // 50–88 range
                make_metrics(prnu, 100.0)
            })
            .collect();

        let cal = calibrate_prnu(&metrics).unwrap();
        // mean_r ≈ 0.69, std_r ≈ 0.116
        // floor ≈ 0.69 - 3*0.116 ≈ 0.34
        assert!(
            cal.prnu_floor > PRNU_FLOOR_MINIMUM,
            "High-PRNU sensor should produce floor above minimum, got {}",
            cal.prnu_floor
        );
    }

    #[test]
    fn calibration_rejects_inconsistent_data() {
        // std > mean → inconsistent (RT-5: possible mixed sources)
        // Asymmetric bimodal: many near-zero ratios + few very high ratios
        let mut metrics: Vec<ForensicMetrics> = Vec::new();
        for _ in 0..18 {
            metrics.push(make_metrics(0.1, 100.0)); // ratio = 0.001
        }
        for _ in 0..2 {
            metrics.push(make_metrics(2000.0, 100.0)); // ratio = 20.0
        }

        let result = calibrate_prnu(&metrics);
        assert!(result.is_err());
    }

    #[test]
    fn calibration_bounds_test() {
        // Verify derived ceiling is within expected bounds (RT-1)
        let derived = MOIRE_NATURAL_UPPER_BOUND * MOIRE_SAFETY_FACTOR;
        assert!(
            derived > MOIRE_NATURAL_UPPER_BOUND * 2.0,
            "Derived ceiling should be > 2× natural upper bound"
        );
        assert!(
            derived < RECAPTURE_LOWER_BOUND / 100.0,
            "Derived ceiling should be < recapture floor / 100"
        );
    }
}

// Constants used in the bounds test — mirrors values from gate.rs
#[cfg(test)]
use crate::gate::{MOIRE_NATURAL_UPPER_BOUND, MOIRE_SAFETY_FACTOR};

/// Lower bound of Moiré energy for screen recapture, used in bounds tests.
#[cfg(test)]
const RECAPTURE_LOWER_BOUND: f32 = 40_000.0;
