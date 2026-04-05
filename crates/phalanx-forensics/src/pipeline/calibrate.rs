// crates/phalanx-forensics/src/calibrate.rs
//
// PRNU calibration pipeline: the Verb "To Calibrate."
//
// Pure functions, no IO. Two calibration modes:
//
// 1. **Batch (legacy):** `calibrate_prnu()` takes N test frames from explicit
//    device setup and derives a fixed PRNU floor threshold (mean − 3σ).
//
// 2. **Online Bayesian:** `update_prnu_posterior()` accumulates sufficient
//    statistics for a linear regression `prnu_var = α·luminance + β + ε`.
//    Every frame is a calibration frame. No explicit setup step required.
//    `posterior_prnu_floor()` derives a luminance-conditioned threshold from
//    the posterior predictive interval.
//
// The calibration binds the detection threshold to the physical sensor's noise
// profile. A stolen identity cannot replicate the PRNU of a different camera.

use phalanx_proto::evidence::{ForensicMetrics, PrnuPosterior, SensorCalibration};
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
pub const PRNU_CONFIDENCE_SIGMA: f32 = 3.0;

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

// =====================================================================
// ONLINE BAYESIAN CALIBRATION
// =====================================================================

/// Minimum PRNU variance for a frame to contribute to calibration.
/// Below this, the frame carries no meaningful sensor noise information
/// (e.g., overexposed/constant region). Would bias the regression intercept
/// toward zero without adding signal.
const MIN_PRNU_VAR: f32 = 0.001;

/// Minimum S_xx (luminance spread) for regression to be meaningful.
/// If all frames have near-identical luminance, the slope is undefined.
/// Fall back to intercept-only model.
const MIN_SXX: f64 = 1.0;

/// Online Bayesian update of the PRNU posterior from a single frame's metrics.
///
/// Accumulates sufficient statistics for the linear regression model
/// `prnu_var = α · luminance + β + ε`. Each valid frame contributes six
/// f64 additions — O(1), no allocation.
///
/// **Filters:**
/// - Dark frames (`mean_luminance < 1.0`): ratio degenerates, skip.
/// - Degenerate frames (`prnu_var < 0.001`): no sensor signal, skip.
///
/// Returns the updated posterior. If filtered, returns `prior` unchanged.
#[allow(clippy::arithmetic_side_effects)] // Statistical accumulation.
pub fn update_prnu_posterior(prior: &PrnuPosterior, metrics: &ForensicMetrics) -> PrnuPosterior {
    // Guard: dark frames produce unreliable ratios.
    if metrics.mean_luminance < MIN_CALIBRATION_LUMINANCE {
        return *prior;
    }
    // Guard: zero-variance frames carry no sensor information.
    if metrics.prnu_var < MIN_PRNU_VAR {
        return *prior;
    }

    let x = f64::from(metrics.mean_luminance);
    let y = f64::from(metrics.prnu_var);

    PrnuPosterior {
        n: prior.n.saturating_add(1),
        sum_x: prior.sum_x + x,
        sum_y: prior.sum_y + y,
        sum_xx: prior.sum_xx + x * x,
        sum_xy: prior.sum_xy + x * y,
        sum_yy: prior.sum_yy + y * y,
    }
}

/// Compute the PRNU floor threshold conditioned on the current frame's luminance.
///
/// Uses the posterior predictive interval from Bayesian linear regression:
/// ```text
/// ŷ(L) = α̂·L + β̂
/// s²   = SSR / (n − 2)
/// se²  = s² · (1 + 1/n + (L − x̄)² / S_xx)
/// floor = ŷ − z · √se²
/// ```
///
/// The floor is naturally wider at luminance values far from the observed mean
/// (extrapolation) and tighter near the center of observed data.
///
/// **Fallbacks:**
/// - `n < 3`: regression underdetermined → `PRNU_FLOOR_MINIMUM × luminance`
/// - `S_xx < 1.0`: all frames at same luminance → intercept-only model
/// - `s² ≤ 0`: numerical edge case → `PRNU_FLOOR_MINIMUM × luminance`
///
/// Result is always clamped above `PRNU_FLOOR_MINIMUM × luminance`.
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
pub fn posterior_prnu_floor(
    posterior: &PrnuPosterior,
    luminance: f32,
    confidence_sigma: f32,
) -> f32 {
    let l = f64::from(luminance);
    let min_floor = f64::from(PRNU_FLOOR_MINIMUM) * l;
    let n = posterior.n;

    // Regression needs at least 3 data points (2 coefficients + 1 dof for variance).
    if n < 3 {
        #[allow(clippy::cast_possible_truncation)]
        return min_floor as f32;
    }

    let nf = f64::from(n);
    let x_bar = posterior.sum_x / nf;
    let y_bar = posterior.sum_y / nf;
    let s_xx = posterior.sum_xx - nf * x_bar * x_bar;

    // If all frames have the same luminance, slope is undefined.
    // Fall back to intercept-only model: floor = ȳ − z·s.
    if s_xx < MIN_SXX {
        let s_yy = posterior.sum_yy - nf * y_bar * y_bar;
        let variance = s_yy / (nf - 1.0);
        if variance <= 0.0 {
            return min_floor as f32;
        }
        let floor = y_bar - f64::from(confidence_sigma) * variance.sqrt();
        return floor.max(min_floor) as f32;
    }

    // OLS regression coefficients.
    let s_xy = posterior.sum_xy - nf * x_bar * y_bar;
    let alpha_hat = s_xy / s_xx; // slope (shot noise coefficient)
    let beta_hat = y_bar - alpha_hat * x_bar; // intercept (read noise floor)

    // Predicted prnu_var at this luminance.
    let y_hat = alpha_hat * l + beta_hat;

    // Residual sum of squares: SSR = Σyy − β̂·Σy − α̂·Σxy
    let ssr = posterior.sum_yy - beta_hat * posterior.sum_y - alpha_hat * posterior.sum_xy;

    // Residual variance estimate (n − 2 degrees of freedom for 2 coefficients).
    let s_sq = ssr / (nf - 2.0);
    if s_sq <= 0.0 {
        return min_floor as f32;
    }

    // Prediction interval variance at luminance L.
    let deviation = l - x_bar;
    let se_sq = s_sq * (1.0 + 1.0 / nf + (deviation * deviation) / s_xx);

    let z = f64::from(confidence_sigma);
    let floor = y_hat - z * se_sq.sqrt();

    floor.max(min_floor) as f32
}

/// Build a `PrnuPosterior` from a batch of calibration frames.
///
/// Equivalent to calling `update_prnu_posterior()` sequentially on each frame.
/// Used as a warm-start bridge from the explicit calibration FFI path.
pub fn posterior_from_batch(metrics: &[ForensicMetrics]) -> PrnuPosterior {
    let mut posterior = PrnuPosterior::new_uninformed();
    for m in metrics {
        posterior = update_prnu_posterior(&posterior, m);
    }
    posterior
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

    // =================================================================
    // ONLINE BAYESIAN CALIBRATION TESTS
    // =================================================================

    #[test]
    fn uninformed_posterior_floor_uses_fallback() {
        let post = PrnuPosterior::new_uninformed();
        // n < 3 → fallback to PRNU_FLOOR_MINIMUM × luminance
        let floor_at_100 = posterior_prnu_floor(&post, 100.0, PRNU_CONFIDENCE_SIGMA);
        let expected = PRNU_FLOOR_MINIMUM * 100.0;
        assert!(
            (floor_at_100 - expected).abs() < 0.01,
            "Uninformed posterior should use fallback floor, got {floor_at_100} expected {expected}"
        );
    }

    #[test]
    fn single_frame_update_accumulates() {
        let post = PrnuPosterior::new_uninformed();
        let m = make_metrics(50.0, 100.0);
        let updated = update_prnu_posterior(&post, &m);

        assert_eq!(updated.n, 1);
        assert!((updated.sum_x - 100.0).abs() < 1e-10);
        assert!((updated.sum_y - 50.0).abs() < 1e-10);
        assert!((updated.sum_xx - 10_000.0).abs() < 1e-10);
        assert!((updated.sum_xy - 5_000.0).abs() < 1e-10);
        assert!((updated.sum_yy - 2_500.0).abs() < 1e-10);
    }

    #[test]
    fn regression_recovers_known_line() {
        // True model: prnu_var = 0.5 * luminance + 2.0
        // Feed 50 frames with varied luminance, verify slope and intercept recovery.
        let mut post = PrnuPosterior::new_uninformed();
        for i in 0..50 {
            let luminance = 20.0 + (i as f32) * 4.0; // 20 to 216
            let prnu_var = 0.5 * luminance + 2.0;
            post = update_prnu_posterior(&post, &make_metrics(prnu_var, luminance));
        }

        assert_eq!(post.n, 50);
        // Recover OLS coefficients from sufficient statistics.
        let nf = f64::from(post.n);
        let x_bar = post.sum_x / nf;
        let s_xx = post.sum_xx - nf * x_bar * x_bar;
        let s_xy = post.sum_xy - nf * x_bar * (post.sum_y / nf);
        let alpha_hat = s_xy / s_xx;
        let beta_hat = (post.sum_y / nf) - alpha_hat * x_bar;

        assert!(
            (alpha_hat - 0.5).abs() < 0.01,
            "Slope should be ≈0.5, got {alpha_hat}"
        );
        assert!(
            (beta_hat - 2.0).abs() < 0.1,
            "Intercept should be ≈2.0, got {beta_hat}"
        );
    }

    #[test]
    fn floor_conditioned_on_luminance() {
        // Build posterior from varied-luminance data.
        let mut post = PrnuPosterior::new_uninformed();
        for i in 0..30 {
            let luminance = 20.0 + (i as f32) * 6.0;
            let prnu_var = 0.3 * luminance + 5.0 + (i as f32 % 3.0) * 0.5;
            post = update_prnu_posterior(&post, &make_metrics(prnu_var, luminance));
        }

        let floor_dim = posterior_prnu_floor(&post, 30.0, PRNU_CONFIDENCE_SIGMA);
        let floor_bright = posterior_prnu_floor(&post, 200.0, PRNU_CONFIDENCE_SIGMA);

        assert!(
            floor_bright > floor_dim,
            "Floor at L=200 ({floor_bright}) should be higher than at L=30 ({floor_dim})"
        );
    }

    #[test]
    fn dark_frame_filtered() {
        let post = PrnuPosterior::new_uninformed();
        let dark = make_metrics(5.0, 0.5); // mean_luminance < 1.0
        let updated = update_prnu_posterior(&post, &dark);
        assert_eq!(updated.n, 0, "Dark frame should not update posterior");
    }

    #[test]
    fn zero_variance_frame_filtered() {
        let post = PrnuPosterior::new_uninformed();
        let degenerate = make_metrics(0.0005, 128.0); // prnu_var < 0.001
        let updated = update_prnu_posterior(&post, &degenerate);
        assert_eq!(
            updated.n, 0,
            "Zero-variance frame should not update posterior"
        );
    }

    #[test]
    fn batch_and_online_agree() {
        let frames: Vec<ForensicMetrics> = (0..20)
            .map(|i| {
                let luminance = 30.0 + (i as f32) * 10.0;
                let prnu_var = 0.4 * luminance + 3.0;
                make_metrics(prnu_var, luminance)
            })
            .collect();

        // Online: update one at a time.
        let mut online = PrnuPosterior::new_uninformed();
        for m in &frames {
            online = update_prnu_posterior(&online, m);
        }

        // Batch: use posterior_from_batch.
        let batch = posterior_from_batch(&frames);

        assert_eq!(online.n, batch.n);
        assert!((online.sum_x - batch.sum_x).abs() < 1e-10);
        assert!((online.sum_y - batch.sum_y).abs() < 1e-10);
        assert!((online.sum_xx - batch.sum_xx).abs() < 1e-10);
        assert!((online.sum_xy - batch.sum_xy).abs() < 1e-10);
        assert!((online.sum_yy - batch.sum_yy).abs() < 1e-10);
    }

    #[test]
    fn prediction_interval_widens_at_extremes() {
        // Build posterior centered around L=100.
        let mut post = PrnuPosterior::new_uninformed();
        for i in 0..30 {
            let luminance = 80.0 + (i as f32) * 1.5; // 80 to 123.5
            let prnu_var = 0.3 * luminance + 4.0 + (i as f32 % 4.0) * 0.3;
            post = update_prnu_posterior(&post, &make_metrics(prnu_var, luminance));
        }

        let floor_center = posterior_prnu_floor(&post, 100.0, PRNU_CONFIDENCE_SIGMA);
        let floor_extreme = posterior_prnu_floor(&post, 5.0, PRNU_CONFIDENCE_SIGMA);

        // The floor at the extreme should be lower (wider interval → more lenient).
        // Because ŷ(5) < ŷ(100) AND the prediction interval is wider at L=5.
        assert!(
            floor_extreme < floor_center,
            "Floor at extreme L=5 ({floor_extreme}) should be lower than at center L=100 ({floor_center})"
        );
    }

    #[test]
    fn same_luminance_fallback() {
        // All frames at L=128 → S_xx ≈ 0 → intercept-only fallback.
        let mut post = PrnuPosterior::new_uninformed();
        for i in 0..20 {
            let prnu_var = 10.0 + (i as f32 % 5.0) * 0.5;
            post = update_prnu_posterior(&post, &make_metrics(prnu_var, 128.0));
        }

        // Should not panic or return NaN/Inf.
        let floor = posterior_prnu_floor(&post, 128.0, PRNU_CONFIDENCE_SIGMA);
        assert!(floor.is_finite(), "Floor should be finite, got {floor}");
        assert!(floor >= 0.0, "Floor should be non-negative, got {floor}");
    }

    #[test]
    fn bimodal_luminance_data() {
        // Frames from dim (L=20) and bright (L=200) conditions.
        // The regression should capture the slope across both clusters.
        let mut post = PrnuPosterior::new_uninformed();
        for i in 0..15 {
            let prnu_var_dim = 0.4 * 20.0 + 3.0 + (i as f32 % 3.0) * 0.2;
            post = update_prnu_posterior(&post, &make_metrics(prnu_var_dim, 20.0));

            let prnu_var_bright = 0.4 * 200.0 + 3.0 + (i as f32 % 3.0) * 0.2;
            post = update_prnu_posterior(&post, &make_metrics(prnu_var_bright, 200.0));
        }

        assert_eq!(post.n, 30);
        // Floor at bright should be much higher than at dim.
        let floor_dim = posterior_prnu_floor(&post, 20.0, PRNU_CONFIDENCE_SIGMA);
        let floor_bright = posterior_prnu_floor(&post, 200.0, PRNU_CONFIDENCE_SIGMA);
        assert!(
            floor_bright > floor_dim * 2.0,
            "Bright floor ({floor_bright}) should be >> dim floor ({floor_dim})"
        );
    }
}

// Constants used in the bounds test — mirrors values from gate.rs
#[cfg(test)]
use crate::gate::{MOIRE_NATURAL_UPPER_BOUND, MOIRE_SAFETY_FACTOR};

/// Lower bound of Moiré energy for screen recapture, used in bounds tests.
#[cfg(test)]
const RECAPTURE_LOWER_BOUND: f32 = 40_000.0;
