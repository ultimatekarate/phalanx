// crates/phalanx-lens/src/scalar.rs
//
// Pure-Rust scalar fallback for ForensicLens.
// Computes the same three metrics as the NEON kernel via standard f32 arithmetic
// on a 256×256 center crop. Used on x86_64 dev/test and as ground truth for
// cross-validation against SIMD implementations.

use crate::{ForensicLens, ANALYSIS_CROP_SIZE};
use phalanx_proto::evidence::ForensicMetrics;
use phalanx_proto::types::BlackLevel;

/// Pure-Rust scalar implementation of ForensicLens.
pub struct ScalarLens;

impl ForensicLens for ScalarLens {
    // SAFETY: All arithmetic in this kernel is bounded by the early-return guard
    // (width ≥ crop, height ≥ crop, y_plane.len() ≥ width×height). Loop indices
    // stay within [1, crop-2] so ±1 offsets never underflow/overflow. Counters
    // (lap_count, prnu_count) max at crop² = 65,536, well within u32.
    // The f64→f32 casts are intentional: we accumulate in f64 for numerical
    // stability and truncate to f32 for the output metrics (matching NEON kernel).
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    fn analyze(
        &self,
        y_plane: &[u8],
        width: usize,
        height: usize,
        black_level: BlackLevel,
    ) -> ForensicMetrics {
        let crop = ANALYSIS_CROP_SIZE;

        // Guard: if the frame is too small or the y_plane buffer is undersized,
        // return zero metrics. All-zero is itself a forensic signal — the LensGate
        // can flag it as a possible bypass attempt.
        if width < crop || height < crop || y_plane.len() < width * height {
            return ForensicMetrics::default();
        }

        // Center crop offsets
        let x_off = (width - crop) / 2;
        let y_off = (height - crop) / 2;

        // Safe pixel accessor — returns black_level for out-of-bounds (should never
        // happen after the guard above, but satisfies `indexing_slicing = "deny"`).
        let bl = black_level.0;
        let pixel = |cx: usize, cy: usize| -> f32 {
            let idx = (y_off + cy) * width + (x_off + cx);
            y_plane.get(idx).copied().unwrap_or(0) as f32
        };

        // 1. Laplacian energy (horizontal + vertical) on interior pixels.
        // Interior: skip 1-pixel border of the crop to avoid reaching outside.
        let mut h_sum: f64 = 0.0;
        let mut v_sum: f64 = 0.0;
        let mut lap_count: u32 = 0;

        for cy in 1..crop - 1 {
            for cx in 1..crop - 1 {
                let center = pixel(cx, cy);

                // Horizontal Laplacian: left − 2·center + right
                let h_lap = pixel(cx - 1, cy) - 2.0 * center + pixel(cx + 1, cy);
                // Vertical Laplacian: top − 2·center + bottom
                let v_lap = pixel(cx, cy - 1) - 2.0 * center + pixel(cx, cy + 1);

                h_sum += (h_lap * h_lap) as f64;
                v_sum += (v_lap * v_lap) as f64;
                lap_count += 1;
            }
        }

        let h_energy = if lap_count > 0 {
            (h_sum / lap_count as f64) as f32
        } else {
            0.0
        };
        let v_energy = if lap_count > 0 {
            (v_sum / lap_count as f64) as f32
        } else {
            0.0
        };

        // 2. PRNU variance: Var(pixel − black_level) over the full crop.
        // Raw (non-normalized) — the LensGate scales thresholds by mean luminance.
        // Also compute mean luminance for auto-exposure threshold scaling.
        let mut sum: f64 = 0.0;
        let mut sum_sq: f64 = 0.0;
        let mut luma_sum: f64 = 0.0;
        let mut prnu_count: u32 = 0;

        for cy in 0..crop {
            for cx in 0..crop {
                let raw = pixel(cx, cy);
                let val = raw - bl;
                sum += val as f64;
                sum_sq += (val as f64) * (val as f64);
                luma_sum += raw as f64;
                prnu_count += 1;
            }
        }

        let prnu_var = if prnu_count > 0 {
            let mean = sum / prnu_count as f64;
            (sum_sq / prnu_count as f64 - mean * mean) as f32
        } else {
            0.0
        };

        let mean_luminance = if prnu_count > 0 {
            (luma_sum / prnu_count as f64) as f32
        } else {
            0.0
        };

        ForensicMetrics {
            h_energy,
            v_energy,
            prnu_var,
            mean_luminance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_black_frame() {
        // All-black (value = 0) with black_level = 16.
        // Every pixel − BL = −16. Laplacian of constant = 0. PRNU variance = 0.
        let width = 640;
        let height = 480;
        let y_plane = vec![0u8; width * height];

        let metrics = ScalarLens.analyze(&y_plane, width, height, BlackLevel(16.0));

        // Laplacian of a constant plane is zero
        assert!(
            metrics.h_energy < f32::EPSILON,
            "h_energy should be ~0 for constant plane, got {}",
            metrics.h_energy
        );
        assert!(
            metrics.v_energy < f32::EPSILON,
            "v_energy should be ~0 for constant plane, got {}",
            metrics.v_energy
        );
        // PRNU variance of constant plane is zero (all pixels have same value)
        assert!(
            metrics.prnu_var < f32::EPSILON,
            "prnu_var should be ~0 for constant plane, got {}",
            metrics.prnu_var
        );
    }

    #[test]
    fn test_all_white_frame() {
        // All-white (value = 255) with black_level = 16.
        // Laplacian of constant = 0. PRNU variance = 0 (all same value after BL sub).
        let width = 640;
        let height = 480;
        let y_plane = vec![255u8; width * height];

        let metrics = ScalarLens.analyze(&y_plane, width, height, BlackLevel(16.0));

        assert!(
            metrics.h_energy < f32::EPSILON,
            "h_energy should be ~0 for constant plane"
        );
        assert!(
            metrics.v_energy < f32::EPSILON,
            "v_energy should be ~0 for constant plane"
        );
        assert!(
            metrics.prnu_var < f32::EPSILON,
            "prnu_var should be ~0 for constant plane"
        );
    }

    #[test]
    fn test_horizontal_gradient() {
        // Horizontal gradient: pixel value = x * 255 / (width-1), never wrapping.
        // A true linear gradient has zero second derivative → Laplacian ≈ 0.
        // PRNU variance should be non-zero because pixel values vary.
        let width = 640;
        let height = 480;
        let mut y_plane = vec![0u8; width * height];
        for y in 0..height {
            for x in 0..width {
                // True linear gradient: 0 at x=0, 255 at x=639, no wrap
                y_plane[y * width + x] = (x * 255 / (width - 1)) as u8;
            }
        }

        let metrics = ScalarLens.analyze(&y_plane, width, height, BlackLevel(0.0));

        // Linear gradient has zero second derivative → Laplacian ≈ 0.
        // Quantization noise (integer rounding) introduces tiny residual.
        assert!(
            metrics.h_energy < 1.0,
            "h_energy should be near-zero for linear gradient, got {}",
            metrics.h_energy
        );
        // Vertical: constant along y → zero
        assert!(
            metrics.v_energy < f32::EPSILON,
            "v_energy should be ~0 for horizontal gradient"
        );
        // PRNU variance should be positive (pixel values vary)
        assert!(
            metrics.prnu_var > 0.0,
            "prnu_var should be >0 for gradient, got {}",
            metrics.prnu_var
        );
    }

    #[test]
    fn test_noise_pattern() {
        // Noise pattern: alternating 0 and 255 in a checkerboard.
        // Maximum Laplacian energy (high-frequency content).
        let width = 640;
        let height = 480;
        let mut y_plane = vec![0u8; width * height];
        for y in 0..height {
            for x in 0..width {
                y_plane[y * width + x] = if (x + y) % 2 == 0 { 0 } else { 255 };
            }
        }

        let metrics = ScalarLens.analyze(&y_plane, width, height, BlackLevel(0.0));

        // High-frequency noise should produce large Laplacian energy
        assert!(
            metrics.h_energy > 100.0,
            "h_energy should be large for noise, got {}",
            metrics.h_energy
        );
        assert!(
            metrics.v_energy > 100.0,
            "v_energy should be large for noise, got {}",
            metrics.v_energy
        );
        // Variance of bimodal distribution (0 and 255)
        assert!(
            metrics.prnu_var > 1000.0,
            "prnu_var should be large for bimodal noise, got {}",
            metrics.prnu_var
        );
    }

    #[test]
    fn test_undersized_frame_returns_default() {
        // Frame smaller than the analysis crop window
        let width = 128;
        let height = 128;
        let y_plane = vec![128u8; width * height];

        let metrics = ScalarLens.analyze(&y_plane, width, height, BlackLevel(16.0));

        assert_eq!(metrics, ForensicMetrics::default());
    }

    #[test]
    fn test_empty_buffer_returns_default() {
        let metrics = ScalarLens.analyze(&[], 640, 480, BlackLevel(16.0));
        assert_eq!(metrics, ForensicMetrics::default());
    }

    #[test]
    fn test_black_level_shifts_prnu() {
        // Same data, different black levels → different PRNU variance.
        let width = 640;
        let height = 480;
        let mut y_plane = vec![0u8; width * height];
        // Fill with a moderate value
        for pixel in &mut y_plane {
            *pixel = 128;
        }

        let metrics_bl0 = ScalarLens.analyze(&y_plane, width, height, BlackLevel(0.0));
        let metrics_bl128 = ScalarLens.analyze(&y_plane, width, height, BlackLevel(128.0));

        // With BL=0: all values are 128 → variance = 0
        assert!(
            metrics_bl0.prnu_var < f32::EPSILON,
            "Constant plane should have zero variance"
        );
        // With BL=128: all values are (128-128)=0 → variance = 0
        assert!(
            metrics_bl128.prnu_var < f32::EPSILON,
            "Constant plane should have zero variance regardless of BL"
        );

        // Laplacian should be zero for both (constant plane)
        assert!(metrics_bl0.h_energy < f32::EPSILON);
        assert!(metrics_bl128.h_energy < f32::EPSILON);
    }
}
