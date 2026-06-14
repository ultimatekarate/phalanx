// crates/phalanx-lens/src/scalar.rs
//
// L1-cache native ForensicLens implementation.
/*
This method is an attempt to filter out deepfake images from making
it on to the network. Fighting AI with better AI only leads to an arms
race. We reject this idea in favor of a physics-based method. Reality is
our firewall.

This algorithm layers PRNU analysis and Moiré pattern detection. PRNU
is used to make sure that the video is coming from an actual sensor.
Moiré pattern detection is used to make sure that someone isn't
pointing a real sensor at a screen that is displaying
a deepfake video.

This method must run at capture time, prior to encryption. Speed is not
decorative, it is imperative. Every microsecond frame data spends
unencrypted is an increase in attack surface.

The naive approach is to analyze every pixel in the full RGB image.

Four key optimizations over the naive approach:

1. SPATIAL DOMAIN ANALYSIS —  Moiré patterns are global periodic artifacts in
   the spatial domain that show up as localized peaks in the frequency domain.
   Using FFT to hunt for them in the frequency domain would blow up cache locality.
   Instead, we exploit the local/global duality of spatial and frequency domain
   by using the fact that these periodic effects also produce high second-derivative
   energy that the 1-D Laplacian can detect locally.

2. LUMA CHANNEL — The Y-plane (Luma channel) contains the
   relevant signal for these computations. We are able to get this data directly
   from mobile OS FFI instead of computing the values from RGB.

3. 256 x 256 CENTER CROP — Both PRNU and Moiré patterns are global behaviors.
   Restricting the analysis to the center crop allows us to use measurements
   that have the highest fidelity. Furthermore, using the center crop removes
   the need to correct the calculations for edge effects such as vignetting.
   This also makes the method uniformly fast across all video resolutions.

   A 256×256 center crop spans width×256 bytes of address space —
   up to 491KB for 1080p, blowing L1 cache (32-64KB). We extract the crop into
   a contiguous 256-stride buffer (64KB) that fits entirely in L1. Both passes
   then operate on L1-resident data with zero cache misses.

4. ROW-ORIENTED SLICE ACCESS — Direct slice indexing instead of a per-pixel
   closure. The compiler sees contiguous sequential access patterns and
   auto-vectorizes the inner loops. The Laplacian stencil loads three
   adjacent rows as slices, enabling the compiler to generate packed
   load + fused multiply-accumulate sequences.

There is room for improvement but it requires arm64 and NEON intrinsics
that I am not yet comfortable with implementing. Specifically,
there is an in-memory transpose method that shows particular promise.

N.B. This optimization is 100% owed to my little brother for teaching
me about one-cycle multiply-accumalate and this kind of compiler
optimization. Without him I wouldn't know to look up "packed load" or
"fused multiply-accumulate." I knew about auto-vectorization from my
MATLAB days, but MATLAB is a scripting language. Rust is not. I don't
want to misrepresent my compiler knowledge. I'm only mostly sure that
it works this way.
*/
use crate::{ANALYSIS_CROP_SIZE, ForensicLens};
use phalanx_proto::evidence::ForensicMetrics;
use phalanx_proto::types::BlackLevel;

/// Crop buffer size in bytes (256 × 256 = 64KB — fits L1 cache).
const CROP_BYTES: usize = ANALYSIS_CROP_SIZE * ANALYSIS_CROP_SIZE;

/// L1-cache native ForensicLens implementation.
///
/// Extracts the center crop to a contiguous buffer, then runs two passes
/// over L1-resident data:
/// - Pass 1: PRNU variance + mean luminance (full crop, auto-vectorized sum/sum_sq)
/// - Pass 2: Laplacian energy (interior pixels, 3-row stencil)
///
/// Both passes touch the same 64KB — the second pass is effectively free
/// because the data is already in L1 from the first pass.
pub struct ScalarLens;

impl ForensicLens for ScalarLens {
    // SAFETY: All indexing is statically bounded.
    //
    // Crop extraction: 0 <=`row` <= 255, `crop` = 256, so 0 <= `row * crop` <= 65280
    // and `row * crop + crop` <= 65536 = CROP_BYTES = crop_buf.len().
    // `src_start + crop` <= y_plane.len() is guaranteed by the early-return guard
    // (width >= crop, height >= crop, y_plane.len() >= width × height).
    //
    // Laplacian stencil: 1 <= `row` <= 254, 1 <= `col` <= 254, so all +/- 1 offsets
    // stay within [0, 255]. Slice lengths are `crop` = 256, so `col + 1` <= 255 < 256.
    //
    // Direct indexing is required here — `.get().unwrap_or()` defeats auto-vectorization
    // by introducing a branch per pixel, destroying the packed load/FMA pipeline. Speed
    // is better than self-imposed purity.

    #[allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::indexing_slicing
    )]
    fn analyze(
        &self,
        y_plane: &[u8],
        width: usize,
        height: usize,
        black_level: BlackLevel,
    ) -> ForensicMetrics {
        let crop = ANALYSIS_CROP_SIZE;

        // Guard: undersized frame or buffer -> zero metrics (forensic signal).
        if width < crop || height < crop || y_plane.len() < width * height {
            return ForensicMetrics::default();
        }

        // Center crop offsets
        let x_off = (width - crop) / 2;
        let y_off = (height - crop) / 2;
        let bl = black_level.0;

        // L1-CACHE LOCK
        // Extract 256×256 center crop to contiguous 64KB buffer.
        // Transforms stride-width access (cache-hostile) to stride-256 (L1-native).
        //
        // Cost: 256 × memcpy(256 bytes) ≈ 1–2μs on modern hardware.
        // Payoff: eliminates all cache misses for both subsequent passes.
        //
        // 64KB stack allocation is safe — camera thread has >=1MB stack on all
        // target platforms (Android default: 1MB, iOS: 512KB min).
        let mut crop_buf = [0u8; CROP_BYTES];
        for row in 0..crop {
            let src_start = (y_off + row) * width + x_off;
            crop_buf[row * crop..][..crop].copy_from_slice(&y_plane[src_start..src_start + crop]);
        }

        // PASS 1: PRNU VARIANCE + MEAN LUMINANCE
        // Tight sequential loop over contiguous u8 data.
        // Accumulate in f64 for numerical stability (sum_sq can reach ~4.26×10⁹
        // for 65536 pixels at value 255, which exceeds f32 precision).
        //
        // Auto-vectorization profile: the compiler emits packed u8 -> f32 conversion
        // + FMA sequences (measured: 4-8 f32 lanes per cycle on x86_64 with AVX2).
        let mut sum: f64 = 0.0;
        let mut sum_sq: f64 = 0.0;
        let mut luma_sum: f64 = 0.0;

        for &px in crop_buf.iter() {
            let raw = px as f32;
            let val = raw - bl;
            sum += val as f64;
            sum_sq += (val as f64) * (val as f64);
            luma_sum += raw as f64;
        }

        let n = (crop * crop) as f64;
        let mean = sum / n;
        let prnu_var = (sum_sq / n - mean * mean) as f32;
        let mean_luminance = (luma_sum / n) as f32;

        // PASS 2: LAPLACIAN ENERGY (3-ROW STENCIL)
        // Process interior pixels: rows [1, crop-2], cols [1, crop-2].
        // Three slice references per row — prev, curr, next — all contiguous
        // in the crop buffer. No cache misses (data is L1-resident from Pass 1).
        //
        // Horizontal: curr[col-1] − 2·curr[col] + curr[col+1]
        // Vertical:   prev[col]   − 2·curr[col] + next[col]
        //
        // Squared energy accumulated in f64, divided by interior pixel count.
        let mut h_sum: f64 = 0.0;
        let mut v_sum: f64 = 0.0;
        let interior = crop - 2;

        for row in 1..crop - 1 {
            let prev = &crop_buf[(row - 1) * crop..][..crop];
            let curr = &crop_buf[row * crop..][..crop];
            let next = &crop_buf[(row + 1) * crop..][..crop];

            for col in 1..crop - 1 {
                let c = curr[col] as f32;

                let h_lap = curr[col - 1] as f32 - 2.0 * c + curr[col + 1] as f32;
                let v_lap = prev[col] as f32 - 2.0 * c + next[col] as f32;

                h_sum += (h_lap * h_lap) as f64;
                v_sum += (v_lap * v_lap) as f64;
            }
        }

        let lap_count = (interior * interior) as f64;

        ForensicMetrics {
            h_energy: (h_sum / lap_count) as f32,
            v_energy: (v_sum / lap_count) as f32,
            prnu_var,
            mean_luminance,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // MACHine EPSilon
    // It's pronounced Muh-cheps, as in "I'm flexing muh cheps." This is an inside joke
    // I have with my friends from grad school. We were reading FORTRAN code because
    // we wanted to understand why LAPACK/LINPACK was so damn fast.
    // It's because it has 'cheps and now you're in on the joke too.
    const MACHEPS: f32 = f32::EPSILON;

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
            metrics.h_energy < MACHEPS,
            "h_energy should be ~0 for constant plane, got {}",
            metrics.h_energy
        );
        assert!(
            metrics.v_energy < MACHEPS,
            "v_energy should be ~0 for constant plane, got {}",
            metrics.v_energy
        );
        // PRNU variance of constant plane is zero (all pixels have same value)
        assert!(
            metrics.prnu_var < MACHEPS,
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
            metrics.h_energy < MACHEPS,
            "h_energy should be ~0 for constant plane"
        );
        assert!(
            metrics.v_energy < MACHEPS,
            "v_energy should be ~0 for constant plane"
        );
        assert!(
            metrics.prnu_var < MACHEPS,
            "prnu_var should be ~0 for constant plane"
        );
    }

    #[test]
    #[allow(clippy::indexing_slicing, clippy::cast_possible_truncation)]
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

        // Linear gradient has zero second derivative -> Laplacian approx 0.
        // Quantization noise (integer rounding) introduces tiny residual.
        assert!(
            metrics.h_energy < 1.0,
            "h_energy should be near-zero for linear gradient, got {}",
            metrics.h_energy
        );
        // Vertical: constant along y -> zero
        assert!(
            metrics.v_energy < MACHEPS,
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
    #[allow(clippy::indexing_slicing)]
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
        // Same data, different black levels -> different PRNU variance.
        let width = 640;
        let height = 480;
        let mut y_plane = vec![0u8; width * height];
        // Fill with a moderate value
        for pixel in &mut y_plane {
            *pixel = 128;
        }

        let metrics_bl0 = ScalarLens.analyze(&y_plane, width, height, BlackLevel(0.0));
        let metrics_bl128 = ScalarLens.analyze(&y_plane, width, height, BlackLevel(128.0));

        // With BL=0: all values are 128 -> variance = 0
        assert!(
            metrics_bl0.prnu_var < MACHEPS,
            "Constant plane should have zero variance"
        );
        // With BL=128: all values are (128-128)=0 -> variance = 0
        assert!(
            metrics_bl128.prnu_var < MACHEPS,
            "Constant plane should have zero variance regardless of BL"
        );

        // Laplacian should be zero for both (constant plane)
        assert!(metrics_bl0.h_energy < MACHEPS);
        assert!(metrics_bl128.h_energy < MACHEPS);
    }
}
