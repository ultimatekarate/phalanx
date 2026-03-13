// crates/phalanx-lens/src/lib.rs
//
// The Forensic Eye: Examines raw sensor data before it enters the evidence pipeline.
// Every VideoShard carries a ForensicMetrics fingerprint computed by this crate.

pub mod scalar;

#[cfg(all(target_arch = "aarch64", feature = "neon"))]
pub mod neon;

use phalanx_proto::evidence::ForensicMetrics;
use phalanx_proto::types::BlackLevel;

/// The crop window size for forensic analysis.
/// Center crop of the Y-plane: highest lens fidelity, no edge effects,
/// representative of global PRNU/Moiré patterns.
pub const ANALYSIS_CROP_SIZE: usize = 256;

/// The core trait for forensic sensor fingerprinting.
///
/// Implementations analyze the Y (luma) plane of a camera frame and produce
/// three metrics:
/// - `h_energy`: Horizontal Moiré energy via Laplacian
/// - `v_energy`: Vertical Moiré energy via Laplacian
/// - `prnu_var`: Photo Response Non-Uniformity variance (sensor fingerprint)
///
/// Metrics are RAW (non-normalized). The LensGate compensates for auto-exposure
/// by scaling thresholds by mean luminance at comparison time.
pub trait ForensicLens: Send + Sync {
    fn analyze(
        &self,
        y_plane: &[u8],
        width: usize,
        height: usize,
        black_level: BlackLevel,
    ) -> ForensicMetrics;
}
