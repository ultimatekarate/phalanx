//! ForensicMetrics fixtures.
//!
//! Encapsulates the knowledge of which metric values satisfy LensGate
//! validation, so that tests outside phalanx-forensics never need to
//! know about PRNU floors or Moiré ceilings.

use phalanx_proto::evidence::ForensicMetrics;

/// ForensicMetrics that passes LensGate with default thresholds.
///
/// Encapsulates: `prnu_var` must exceed `floor × luminance`, and
/// `h_energy`/`v_energy` must stay below `moire_ceiling × luminance`.
pub fn forensic_metrics_synthetic() -> ForensicMetrics {
    ForensicMetrics {
        h_energy: 10.0,
        v_energy: 10.0,
        prnu_var: 200.0,
        mean_luminance: 128.0,
    }
}

/// ForensicMetrics with specified PRNU variance and luminance.
///
/// Used by calibration tests that need to control these two values
/// while keeping Moiré energy in the natural range.
pub fn forensic_metrics_with_prnu(prnu_var: f32, mean_luminance: f32) -> ForensicMetrics {
    ForensicMetrics {
        h_energy: 10.0,
        v_energy: 10.0,
        prnu_var,
        mean_luminance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_forensics::gate::{LensGate, LensThresholds};

    /// Self-test: synthetic metrics must pass default LensGate.
    /// If this fails, the fixture values have decoupled from the
    /// actual validation thresholds — update them here.
    #[test]
    fn synthetic_metrics_pass_lens_gate() {
        let metrics = forensic_metrics_synthetic();
        let thresholds = LensThresholds::default();
        metrics
            .check_provenance(&thresholds)
            .expect("fixture metrics must pass default LensGate");
    }
}
