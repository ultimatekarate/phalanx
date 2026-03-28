use crate::vitals::HomeostaticConfig;
use nalgebra::{Complex, DMatrix};

use super::config::*;
use super::jacobian::build_jacobian;

// =====================================================================
// EIGENVALUE ANALYSIS
// =====================================================================

/// Results of the eigenvalue stability analysis.
#[derive(Debug, Clone)]
pub struct StabilityReport {
    /// The label for this analysis scenario.
    pub scenario: String,
    /// Complex eigenvalues of the Jacobian.
    pub eigenvalues: Vec<Complex<f64>>,
    /// Maximum real part across all eigenvalues (must be < 0 for stability).
    pub max_real_part: f64,
    /// Spectral abscissa (same as max_real_part, standard control-theory term).
    pub spectral_abscissa: f64,
    /// True if and only if all eigenvalues have strictly negative real parts.
    pub is_stable: bool,
    /// Index of the dominant (least-damped) eigenvalue.
    pub dominant_mode_idx: usize,
    /// The Jacobian matrix itself, for inspection.
    pub jacobian: DMatrix<f64>,
    /// Whether the symmetric part (J+Jᵀ)/2 is negative definite.
    /// If true, the system is energy-dissipative in every direction —
    /// a stronger statement than eigenvalue stability alone.
    pub jsym_negative_definite: bool,
    /// Maximum eigenvalue of the symmetric part (J+Jᵀ)/2.
    pub jsym_max_eigenvalue: f64,
    /// Whether Q = PJ_n + J_nᵀP is negative definite under the Lyapunov
    /// matrix P, where J_n is the unit-normalized Jacobian.
    /// Contractivity implies global asymptotic stability and bounded
    /// transient overshoots — the strongest stability guarantee.
    pub is_contractive: bool,
    /// Contractivity margin: -λ_max(Q).  Positive means contractive.
    pub contractivity_margin: f64,
}

/// Compute eigenvalues and stability properties from a Jacobian matrix.
///
/// The `norm_scales` parameter provides the normalization constants for the
/// contractivity check.  If `None`, contractivity fields default to false/0.
pub fn analyze_stability(
    scenario: &str,
    jacobian: &DMatrix<f64>,
    norm_scales: Option<&[f64; DIM]>,
) -> StabilityReport {
    let eigenvalues = jacobian.complex_eigenvalues();
    let eigs: Vec<Complex<f64>> = eigenvalues.iter().cloned().collect();

    let (dominant_idx, max_re) = eigs
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.re.partial_cmp(&b.re).unwrap_or(std::cmp::Ordering::Equal))
        .map(|(i, v)| (i, v.re))
        .unwrap_or((0, f64::NEG_INFINITY));

    // Symmetric part analysis: Jsym = (J + Jᵀ)/2
    let jsym = (jacobian + jacobian.transpose()) * 0.5;
    let jsym_eigs = jsym.symmetric_eigenvalues();
    let jsym_max = jsym_eigs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    // Contractivity analysis: Q = P·J_n + J_nᵀ·P where J_n is normalized.
    let (is_contractive, contractivity_margin) = if let Some(scales) = norm_scales {
        check_contractivity(jacobian, scales)
    } else {
        (false, 0.0)
    };

    StabilityReport {
        scenario: scenario.to_string(),
        eigenvalues: eigs,
        max_real_part: max_re,
        spectral_abscissa: max_re,
        is_stable: max_re < 0.0,
        dominant_mode_idx: dominant_idx,
        jacobian: jacobian.clone(),
        jsym_negative_definite: jsym_max < 0.0,
        jsym_max_eigenvalue: jsym_max,
        is_contractive,
        contractivity_margin,
    }
}

/// Check contractivity under the Lyapunov matrix P.
///
/// Normalizes the Jacobian: J_n[i,j] = J[i,j] · scales[j] / scales[i],
/// then computes Q = P·J_n + J_nᵀ·P and checks all eigenvalues < 0.
fn check_contractivity(jacobian: &DMatrix<f64>, scales: &[f64; DIM]) -> (bool, f64) {
    // Build the normalized Jacobian: J_n = D_n · J · D_n⁻¹
    // where D_n = diag(1/scales), so J_n[i,j] = J[i,j] * scales[j] / scales[i]
    let mut jn = DMatrix::zeros(DIM, DIM);
    for i in 0..DIM {
        for j in 0..DIM {
            jn[(i, j)] = jacobian[(i, j)] * scales[j] / scales[i];
        }
    }

    // Load P from the const array
    let p = DMatrix::from_fn(DIM, DIM, |i, j| LYAPUNOV_P[i][j]);

    // Q = P·J_n + J_nᵀ·P
    let q = &p * &jn + jn.transpose() * &p;
    // Symmetrize for numerical stability
    let q_sym = (&q + q.transpose()) * 0.5;

    let q_eigs = q_sym.symmetric_eigenvalues();
    let q_max = q_eigs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

    (q_max < 0.0, -q_max)
}

/// Run stability analysis across idle / half-critical / near-critical operating
/// points and light / moderate / heavy traffic regimes.
pub fn full_analysis(cfg: &HomeostaticConfig) -> Vec<StabilityReport> {
    let scenarios: Vec<(&str, BaseImpulseRates, OperatingPoint)> = vec![
        (
            "idle + light traffic",
            BaseImpulseRates::light(),
            OperatingPoint::idle(),
        ),
        (
            "idle + heavy traffic",
            BaseImpulseRates::heavy(),
            OperatingPoint::idle(),
        ),
        (
            "half-critical + light traffic",
            BaseImpulseRates::light(),
            OperatingPoint::half_critical(cfg),
        ),
        (
            "half-critical + moderate traffic",
            BaseImpulseRates::moderate(),
            OperatingPoint::half_critical(cfg),
        ),
        (
            "half-critical + heavy traffic",
            BaseImpulseRates::heavy(),
            OperatingPoint::half_critical(cfg),
        ),
        (
            "near-critical + moderate traffic",
            BaseImpulseRates::moderate(),
            OperatingPoint::near_critical(cfg),
        ),
        (
            "near-critical + heavy traffic",
            BaseImpulseRates::heavy(),
            OperatingPoint::near_critical(cfg),
        ),
    ];

    let scales = normalization_scales(cfg);

    scenarios
        .into_iter()
        .map(|(label, rates, op)| {
            let jac = build_jacobian(cfg, &rates, &op);
            analyze_stability(label, &jac, Some(&scales))
        })
        .collect()
}

// =====================================================================
// REPORTING
// =====================================================================

/// Format a full stability report as a string for display.
pub fn format_report(reports: &[StabilityReport]) -> String {
    let mut out = String::new();
    out.push_str("╔══════════════════════════════════════════════════════════════╗\n");
    out.push_str("║   PHALANX INTEGRAL SYSTEM — EIGENVALUE STABILITY REPORT    ║\n");
    out.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

    for report in reports {
        out.push_str(&format!("━━━ {} ━━━\n", report.scenario));

        // Print Jacobian matrix
        out.push_str("\n  Jacobian (coupling matrix):\n");
        out.push_str("         ");
        for name in &INTEGRAL_NAMES {
            out.push_str(&format!("{:>10}", name));
        }
        out.push('\n');
        for i in 0..DIM {
            out.push_str(&format!("    {}  [", INTEGRAL_NAMES[i]));
            for k in 0..DIM {
                let v = report.jacobian[(i, k)];
                if v.abs() < 1e-12 {
                    out.push_str("         .");
                } else {
                    out.push_str(&format!("{:>10.4}", v));
                }
            }
            out.push_str(" ]\n");
        }

        // Print eigenvalues
        out.push_str("\n  Eigenvalues:\n");
        for (i, eig) in report.eigenvalues.iter().enumerate() {
            let marker = if i == report.dominant_mode_idx {
                " ◄ dominant"
            } else {
                ""
            };
            if eig.im.abs() < 1e-10 {
                out.push_str(&format!(
                    "    λ_{} = {:>10.6} (real){}\n",
                    INTEGRAL_NAMES[i], eig.re, marker
                ));
            } else {
                out.push_str(&format!(
                    "    λ_{} = {:>10.6} {:+.6}i{}\n",
                    INTEGRAL_NAMES[i], eig.re, eig.im, marker
                ));
            }
        }

        out.push_str(&format!(
            "\n  Spectral abscissa:  {:.6}\n",
            report.spectral_abscissa
        ));
        out.push_str(&format!(
            "  Jsym max eigenvalue: {:.6}  {}\n",
            report.jsym_max_eigenvalue,
            if report.jsym_negative_definite {
                "(negative definite → energy-dissipative)"
            } else {
                "(NOT negative definite — transient growth possible)"
            }
        ));
        out.push_str(&format!(
            "  Contractivity:      {} (margin: {:.6})\n",
            if report.is_contractive {
                "CONTRACTIVE (PJ_n + J_nᵀP ≺ 0)"
            } else {
                "not contractive"
            },
            report.contractivity_margin,
        ));
        out.push_str(&format!(
            "  Stability verdict:  {}\n\n",
            if report.is_stable {
                "STABLE (all Re(λ) < 0)"
            } else {
                "UNSTABLE — positive eigenvalue detected!"
            }
        ));
    }

    // Summary
    let all_stable = reports.iter().all(|r| r.is_stable);
    let all_contractive = reports.iter().all(|r| r.is_contractive);
    let min_margin = reports
        .iter()
        .map(|r| r.contractivity_margin)
        .fold(f64::INFINITY, f64::min);
    out.push_str("═══════════════════════════════════════════════════════════════\n");
    out.push_str(&format!(
        "  Overall: {}\n",
        if all_stable {
            "ALL SCENARIOS STABLE"
        } else {
            "INSTABILITY DETECTED — review scenarios above"
        }
    ));
    if all_contractive {
        out.push_str(&format!(
            "  Contractivity: ALL SCENARIOS CONTRACTIVE (min margin: {:.6})\n",
            min_margin
        ));
    }
    out.push_str("═══════════════════════════════════════════════════════════════\n");

    out
}

// =====================================================================
// TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use crate::stability::*;
    use crate::vitals::HomeostaticConfig;
    use nalgebra::DMatrix;

    fn default_cfg() -> HomeostaticConfig {
        HomeostaticConfig::default()
    }

    #[test]
    fn test_default_config_stable_at_idle() {
        let cfg = default_cfg();
        let jac = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let report = analyze_stability("idle", &jac, None);
        assert!(
            report.is_stable,
            "System unstable at idle! Max Re(λ) = {}",
            report.max_real_part
        );
    }

    #[test]
    fn test_default_config_stable_at_half_critical() {
        let cfg = default_cfg();
        let jac = build_jacobian(
            &cfg,
            &BaseImpulseRates::moderate(),
            &OperatingPoint::half_critical(&cfg),
        );
        let report = analyze_stability("half-critical", &jac, None);
        assert!(
            report.is_stable,
            "System unstable at half-critical! Max Re(λ) = {}",
            report.max_real_part
        );
    }

    #[test]
    fn test_default_config_stable_near_critical() {
        let cfg = default_cfg();
        let jac = build_jacobian(
            &cfg,
            &BaseImpulseRates::heavy(),
            &OperatingPoint::near_critical(&cfg),
        );
        let report = analyze_stability("near-critical", &jac, None);
        assert!(
            report.is_stable,
            "System unstable near critical! Max Re(λ) = {}",
            report.max_real_part
        );
    }

    #[test]
    fn test_latency_feedback_bounded() {
        // Verify that the positive feedback term in l never dominates λ_lat
        // across all operating regimes.
        let cfg = default_cfg();
        for (label, rates, op) in [
            (
                "light/idle",
                BaseImpulseRates::light(),
                OperatingPoint::idle(),
            ),
            (
                "heavy/idle",
                BaseImpulseRates::heavy(),
                OperatingPoint::idle(),
            ),
            (
                "heavy/near-crit",
                BaseImpulseRates::heavy(),
                OperatingPoint::near_critical(&cfg),
            ),
        ] {
            let jac = build_jacobian(&cfg, &rates, &op);
            let j_ll = jac[(L, L)];
            assert!(
                j_ll < 0.0,
                "Latency self-coupling J[l,l] = {} is non-negative in scenario '{}'. \
                 Positive feedback exceeds decay rate λ_lat = {}!",
                j_ll,
                label,
                cfg.lambda_lat
            );
        }
    }

    #[test]
    fn test_eigenvalue_sensitivity() {
        // Perturb each λ by −50% and verify stability persists.
        let mut cfg = default_cfg();
        let rates = BaseImpulseRates::heavy();
        let op = OperatingPoint::half_critical(&cfg);

        let lambdas: Vec<(&str, Box<dyn Fn(&mut HomeostaticConfig, f64)>)> = vec![
            (
                "lambda_sys",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_sys = v),
            ),
            (
                "lambda_io",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_io = v),
            ),
            (
                "lambda_entry",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_entry = v),
            ),
            (
                "lambda_lat",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_lat = v),
            ),
            (
                "lambda_mem",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_mem = v),
            ),
            (
                "lambda_wal",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_wal = v),
            ),
            (
                "lambda_bw",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_bw = v),
            ),
            (
                "lambda_conn",
                Box::new(|c: &mut HomeostaticConfig, v| c.lambda_conn = v),
            ),
        ];

        let originals = [
            cfg.lambda_sys,
            cfg.lambda_io,
            cfg.lambda_entry,
            cfg.lambda_lat,
            cfg.lambda_mem,
            cfg.lambda_wal,
            cfg.lambda_bw,
            cfg.lambda_conn,
        ];

        for (i, (name, setter)) in lambdas.iter().enumerate() {
            let perturbed = originals[i] * 0.5;
            setter(&mut cfg, perturbed);

            let jac = build_jacobian(&cfg, &rates, &op);
            let report = analyze_stability(name, &jac, None);
            assert!(
                report.is_stable,
                "System became unstable when {} was halved to {}! Max Re(λ) = {}",
                name, perturbed, report.max_real_part
            );

            // Restore
            setter(&mut cfg, originals[i]);
        }
    }

    #[test]
    fn test_decoupled_integrals() {
        // d (I/O) and c (connection) should be essentially decoupled from
        // other integrals — their off-diagonal entries should be zero.
        let cfg = default_cfg();
        let jac = build_jacobian(
            &cfg,
            &BaseImpulseRates::moderate(),
            &OperatingPoint::half_critical(&cfg),
        );

        // Row D: only J[D,D] should be nonzero.
        for k in 0..DIM {
            if k != D {
                assert!(
                    jac[(D, k)].abs() < 1e-12,
                    "J[d,{}] = {} should be zero (d is self-coupled only)",
                    INTEGRAL_NAMES[k],
                    jac[(D, k)]
                );
            }
        }

        // Row C: only J[C,C] should be nonzero.
        for k in 0..DIM {
            if k != C {
                assert!(
                    jac[(C, k)].abs() < 1e-12,
                    "J[c,{}] = {} should be zero (c is decoupled)",
                    INTEGRAL_NAMES[k],
                    jac[(C, k)]
                );
            }
        }

        // Column D: only J[D,D] should be nonzero (nothing depends on d).
        for k in 0..DIM {
            if k != D {
                assert!(
                    jac[(k, D)].abs() < 1e-12,
                    "J[{},d] = {} should be zero (nothing couples from d)",
                    INTEGRAL_NAMES[k],
                    jac[(k, D)]
                );
            }
        }

        // Column C: only J[C,C] should be nonzero.
        for k in 0..DIM {
            if k != C {
                assert!(
                    jac[(k, C)].abs() < 1e-12,
                    "J[{},c] = {} should be zero (nothing couples from c)",
                    INTEGRAL_NAMES[k],
                    jac[(k, C)]
                );
            }
        }
    }

    #[test]
    fn test_full_analysis_all_stable() {
        let cfg = default_cfg();
        let reports = full_analysis(&cfg);
        let output = format_report(&reports);
        println!("{}", output);
        for report in &reports {
            assert!(
                report.is_stable,
                "Scenario '{}' is unstable! Max Re(λ) = {}",
                report.scenario, report.max_real_part
            );
        }
    }

    // Shout out to Dr. Varga- I'm still using Gershgorin's theorem all these years later.
    #[test]
    fn test_gershgorin_analysis() {
        // Diagonal dominance is a sufficient (not necessary) condition for
        // stability.  This test checks which rows satisfy it and reports the
        // Gershgorin disc radii.  Rows that are NOT diagonally dominant rely
        // on the coupling *structure* for stability — eigenvalue analysis
        // (tested separately) confirms the system is still stable.
        let cfg = default_cfg();
        let jac = build_jacobian(&cfg, &BaseImpulseRates::heavy(), &OperatingPoint::idle());

        let mut non_dominant_rows = Vec::new();
        for i in 0..DIM {
            let diag = jac[(i, i)];
            let off_diag_sum: f64 = (0..DIM)
                .filter(|&k| k != i)
                .map(|k| jac[(i, k)].abs())
                .sum();
            let margin = -(diag + off_diag_sum); // positive = diagonally dominant
            println!(
                "  Row {} ({}): diag={:.4}, off-diag Σ={:.4}, margin={:.4} {}",
                i,
                INTEGRAL_NAMES[i],
                diag,
                off_diag_sum,
                margin,
                if margin > 0.0 {
                    "✓"
                } else {
                    "← not dominant"
                }
            );
            if margin <= 0.0 {
                non_dominant_rows.push(INTEGRAL_NAMES[i]);
            }
        }

        // The system is stable regardless (eigenvalue tests confirm), but log
        // which rows are NOT diagonally dominant — these are the integrals
        // whose stability depends on coupling structure, not just decay rate.
        if !non_dominant_rows.is_empty() {
            println!(
                "\n  Note: rows {:?} are not diagonally dominant under heavy/idle.\n  \
                 Stability of these integrals relies on coupling structure,\n  \
                 not just decay rates.  Eigenvalue analysis confirms stability.",
                non_dominant_rows
            );
        }
    }
}
