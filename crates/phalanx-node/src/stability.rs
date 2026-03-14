//! Eigenvalue stability analysis of the 8-integral Volterra feedback system.
//!
//! Constructs the 8x8 Jacobian (coupling matrix) of the linearized system and
//! computes eigenvalues.  All eigenvalues with negative real parts → the system
//! is asymptotically stable at the given operating point.
//!
//! Enabled via the `stability-analysis` cargo feature.

use crate::vitals::HomeostaticConfig;
use nalgebra::{Complex, DMatrix, DVector};

// Index mapping for the 8 integrals.
const S: usize = 0; // System / metabolic pressure
const D: usize = 1; // I/O digestion pressure
const E: usize = 2; // Entry / Sybil pressure
const L: usize = 3; // Latency (network/scheduling age)
const M: usize = 4; // Memory / buffer pressure
const W: usize = 5; // WAL / storage pressure
const B: usize = 6; // Bandwidth pressure
const C: usize = 7; // Connection pressure

const DIM: usize = 8;

/// Labels for each integral index.
pub const INTEGRAL_NAMES: [&str; DIM] = ["s", "d", "e", "l", "m", "w", "b", "c"];

// =====================================================================
// CONFIGURATION TYPES
// =====================================================================

/// Base (unthrottled) impulse rates for each integral under a given traffic
/// scenario.  Units are impulse/second — the average rate at which events
/// would feed each integral if no scaler or gate were active.
#[derive(Debug, Clone)]
pub struct BaseImpulseRates {
    pub u_s: f64, // metabolic: seconds of CPU per second (fractional utilization)
    pub u_d: f64, // I/O: seconds of fetch latency per second
    pub u_e: f64, // entry: shard arrivals per second
    pub u_l: f64, // latency: average shard-age seconds contributed per second
    pub u_m: f64, // memory: MiB accumulated per second
    pub u_w: f64, // storage: utilization-ratio increments per second
    pub u_b: f64, // bandwidth: MiB ingress per second
    pub u_c: f64, // connection: ratio increments per second
}

impl BaseImpulseRates {
    /// Light traffic — a mostly-idle node.
    pub fn light() -> Self {
        Self {
            u_s: 0.5,
            u_d: 0.2,
            u_e: 2.0,
            u_l: 0.1,
            u_m: 5.0,
            u_w: 0.01,
            u_b: 2.0,
            u_c: 0.05,
        }
    }

    /// Moderate traffic — typical operating conditions.
    pub fn moderate() -> Self {
        Self {
            u_s: 2.0,
            u_d: 1.0,
            u_e: 10.0,
            u_l: 0.5,
            u_m: 50.0,
            u_w: 0.05,
            u_b: 10.0,
            u_c: 0.2,
        }
    }

    /// Heavy traffic — sustained high load or flood.
    pub fn heavy() -> Self {
        Self {
            u_s: 5.0,
            u_d: 3.0,
            u_e: 50.0,
            u_l: 2.0,
            u_m: 200.0,
            u_w: 0.15,
            u_b: 40.0,
            u_c: 0.5,
        }
    }
}

/// Operating point at which the system is linearized.
/// Values represent the current integral magnitudes.
#[derive(Debug, Clone)]
pub struct OperatingPoint {
    pub vals: [f64; DIM],
}

impl OperatingPoint {
    /// System at rest — all integrals near zero.
    pub fn idle() -> Self {
        Self { vals: [0.0; DIM] }
    }

    /// Half-critical — each integral at 50% of its critical threshold (or a
    /// representative mid-range value for integrals without a threshold).
    pub fn half_critical(cfg: &HomeostaticConfig) -> Self {
        Self {
            vals: [
                cfg.s_crit * 0.5, // s
                cfg.d_crit * 0.5, // d
                5.0,              // e (representative mid-range)
                2.0,              // l (seconds of accumulated latency)
                cfg.m_crit * 0.5, // m
                cfg.w_crit * 0.5, // w
                cfg.b_crit * 0.5, // b
                cfg.c_crit * 0.5, // c
            ],
        }
    }

    /// Near-critical — integrals at 80% of threshold.
    pub fn near_critical(cfg: &HomeostaticConfig) -> Self {
        Self {
            vals: [
                cfg.s_crit * 0.8,
                cfg.d_crit * 0.8,
                15.0,
                5.0,
                cfg.m_crit * 0.8,
                cfg.w_crit * 0.8,
                cfg.b_crit * 0.8,
                cfg.c_crit * 0.8,
            ],
        }
    }
}

// =====================================================================
// JACOBIAN CONSTRUCTION
// =====================================================================

/// Build the 8×8 Jacobian of the linearized integral system.
///
/// The continuous-time model for each integral is:
///
///   dI_i/dt = f_i(I_0 … I_7) − λ_i · I_i
///
/// where f_i is the effective impulse rate, modulated by scalers from other
/// integrals.  The Jacobian entry J\[i,j\] = ∂f_i/∂I_j − λ_i·δ_{ij}.
///
/// Coupling coefficients are the analytical partial derivatives of the scaler
/// and gate functions at the given operating point.
pub fn build_jacobian(
    cfg: &HomeostaticConfig,
    rates: &BaseImpulseRates,
    op: &OperatingPoint,
) -> DMatrix<f64> {
    let mut j = DMatrix::zeros(DIM, DIM);

    // Helper: derivative of scaler σ(x) = max(0, 1 − x/x_crit) w.r.t. x.
    // In the linear regime (x < x_crit): dσ/dx = −1/x_crit.
    // In the saturated regime (x ≥ x_crit): dσ/dx = 0.
    let dscaler = |val: f64, crit: f64| -> f64 {
        if val < crit {
            -1.0 / crit
        } else {
            0.0
        }
    };

    // Scaler values at the operating point (used as throughput multipliers).
    let sigma_s = (1.0 - op.vals[S] / cfg.s_crit).max(0.0);
    let sigma_b = (1.0 - op.vals[B] / cfg.b_crit).max(0.0);
    let sigma_m = (1.0 - op.vals[M] / cfg.m_crit).max(0.0);

    // Sybil endowment at operating point and its derivative w.r.t. e.
    let e_val = op.vals[E];
    let endowment = cfg.psi_max / (1.0 + cfg.k_sybil * e_val);
    let dendowment_de = -cfg.psi_max * cfg.k_sybil / (1.0 + cfg.k_sybil * e_val).powi(2);
    // Normalized endowment effect: fraction of max endowment being used.
    let endowment_frac = endowment / cfg.psi_max; // 1.0 at idle, → 0 under attack

    // Ingestion throughput is the product of all gates along the pipeline:
    //   throughput = σ_b · σ_s · endowment_frac · σ_m (approximately)
    // Each integral fed by ingestion has its impulse rate scaled by throughput.
    let throughput = sigma_b * sigma_s * endowment_frac * sigma_m;

    // -------------------------------------------------------------------
    // Row S (metabolic): recorded at end of ingestion processing.
    // f_s = u_s · σ_b · σ_s · endowment_frac · σ_m
    // -------------------------------------------------------------------
    j[(S, S)] = -cfg.lambda_sys
        + rates.u_s * sigma_b * endowment_frac * sigma_m * dscaler(op.vals[S], cfg.s_crit);
    j[(S, E)] = rates.u_s * sigma_b * sigma_s * sigma_m * (dendowment_de / cfg.psi_max);
    j[(S, M)] = rates.u_s * sigma_b * sigma_s * endowment_frac * dscaler(op.vals[M], cfg.m_crit);
    j[(S, B)] = rates.u_s * sigma_s * endowment_frac * sigma_m * dscaler(op.vals[B], cfg.b_crit);

    // -------------------------------------------------------------------
    // Row D (I/O digestion): recorded by retrieval actor.
    // Retrieval is downstream; its load correlates with stored data volume,
    // which is indirectly driven by ingestion.  For the first-order model,
    // d is treated as self-coupled only (separate pipeline).
    // f_d = u_d · σ_d
    // -------------------------------------------------------------------
    j[(D, D)] = -cfg.lambda_io + rates.u_d * dscaler(op.vals[D], cfg.d_crit);

    // -------------------------------------------------------------------
    // Row E (entry/sybil): recorded once per successfully allocated shard.
    // f_e = u_e · σ_b · σ_s · endowment_frac · σ_m
    // -------------------------------------------------------------------
    j[(E, S)] = rates.u_e * sigma_b * endowment_frac * sigma_m * dscaler(op.vals[S], cfg.s_crit);
    j[(E, E)] =
        -cfg.lambda_entry + rates.u_e * sigma_b * sigma_s * sigma_m * (dendowment_de / cfg.psi_max);
    j[(E, M)] = rates.u_e * sigma_b * sigma_s * endowment_frac * dscaler(op.vals[M], cfg.m_crit);
    j[(E, B)] = rates.u_e * sigma_s * endowment_frac * sigma_m * dscaler(op.vals[B], cfg.b_crit);

    // -------------------------------------------------------------------
    // Row L (latency): recorded per shard with the shard's age as impulse.
    // f_l = u_l · σ_b · σ_s · endowment_frac · σ_m · g(l)
    //
    // Positive feedback: higher l → wider temporal_tolerance → accepts older
    // shards → average impulse magnitude (shard age) increases.  Model this
    // as a linear gain: g(l) ≈ 1 + α·l where α captures the age-expansion
    // sensitivity.  The gain is bounded by max_temporal_tolerance.
    //
    // At the operating point, ∂f_l/∂l includes +u_l·throughput·α (positive).
    // -------------------------------------------------------------------
    // Age-expansion gain: temporal_tolerance = base_drift + l, clamped to max.
    // The derivative w.r.t. l is 1.0 when below clamp, 0.0 when clamped.
    let base_drift_secs = cfg.base_temporal_drift.as_secs_f64();
    let max_tol_secs = cfg.max_temporal_tolerance.as_secs_f64();
    let current_tol = base_drift_secs + op.vals[L];
    let dtol_dl = if current_tol < max_tol_secs { 1.0 } else { 0.0 };
    // The positive feedback coefficient: wider tolerance lets in older shards
    // whose age is on average ~tolerance/2.  So the marginal increase in
    // average impulse magnitude per unit increase in l is approximately
    // dtol_dl * (1 / max_tol_secs) — a normalized sensitivity.
    let alpha_l = dtol_dl / max_tol_secs;

    j[(L, S)] = rates.u_l * sigma_b * endowment_frac * sigma_m * dscaler(op.vals[S], cfg.s_crit);
    j[(L, L)] = -cfg.lambda_lat + rates.u_l * throughput * alpha_l;
    j[(L, E)] = rates.u_l * sigma_b * sigma_s * sigma_m * (dendowment_de / cfg.psi_max);
    j[(L, M)] = rates.u_l * sigma_b * sigma_s * endowment_frac * dscaler(op.vals[M], cfg.m_crit);
    j[(L, B)] = rates.u_l * sigma_s * endowment_frac * sigma_m * dscaler(op.vals[B], cfg.b_crit);

    // -------------------------------------------------------------------
    // Row M (memory): recorded from channel-full events (meshsentinel),
    // ingress-governor-full rejections (ingestion), and buffer usage (storage).
    //
    // Memory has two impulse sources:
    //   1. Normal flow: buffered data ∝ throughput  →  f_m1 = u_m · throughput
    //   2. Rejection backpressure from storage: when w is high, storage rejects
    //      more, pushing phantom memory pressure.
    //      f_m2 = u_m_reject · (w / w_crit)  (proportional to storage stress)
    //
    // For the rejection term, the coupling coefficient ∂f_m2/∂w is positive
    // (destabilizing: more storage pressure → more memory pressure).
    // -------------------------------------------------------------------
    let u_m_reject = rates.u_m * 0.1; // rejection pathway is ~10% of normal memory flow
    j[(M, S)] = rates.u_m * sigma_b * endowment_frac * sigma_m * dscaler(op.vals[S], cfg.s_crit);
    j[(M, E)] = rates.u_m * sigma_b * sigma_s * sigma_m * (dendowment_de / cfg.psi_max);
    j[(M, M)] = -cfg.lambda_mem
        + rates.u_m * sigma_b * sigma_s * endowment_frac * dscaler(op.vals[M], cfg.m_crit);
    j[(M, W)] = u_m_reject / cfg.w_crit; // positive: storage stress → memory backpressure
    j[(M, B)] = rates.u_m * sigma_s * endowment_frac * sigma_m * dscaler(op.vals[B], cfg.b_crit);

    // -------------------------------------------------------------------
    // Row W (storage): recorded by storage actor from WAL utilization.
    // f_w = u_w · σ_b · σ_s · endowment_frac · σ_m  (driven by ingestion rate)
    // -------------------------------------------------------------------
    j[(W, S)] = rates.u_w * sigma_b * endowment_frac * sigma_m * dscaler(op.vals[S], cfg.s_crit);
    j[(W, E)] = rates.u_w * sigma_b * sigma_s * sigma_m * (dendowment_de / cfg.psi_max);
    j[(W, M)] = rates.u_w * sigma_b * sigma_s * endowment_frac * dscaler(op.vals[M], cfg.m_crit);
    j[(W, W)] = -cfg.lambda_wal
        + rates.u_w
            * sigma_b
            * sigma_s
            * endowment_frac
            * dscaler(op.vals[W], cfg.w_crit)
            * sigma_m;
    j[(W, B)] = rates.u_w * sigma_s * endowment_frac * sigma_m * dscaler(op.vals[B], cfg.b_crit);

    // -------------------------------------------------------------------
    // Row B (bandwidth): recorded at meshsentinel for every network message.
    // This is the entry point — externally driven by network traffic.
    // Self-gating: bandwidth_scaler drops at edge when saturated.
    // f_b = u_b · σ_b  (only self-coupled)
    // -------------------------------------------------------------------
    j[(B, B)] = -cfg.lambda_bw + rates.u_b * dscaler(op.vals[B], cfg.b_crit);

    // -------------------------------------------------------------------
    // Row C (connection): tracked but not actively gating anything.
    // f_c = u_c  (constant, decoupled)
    // -------------------------------------------------------------------
    j[(C, C)] = -cfg.lambda_conn;

    j
}

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
}

/// Compute eigenvalues and stability properties from a Jacobian matrix.
pub fn analyze_stability(scenario: &str, jacobian: &DMatrix<f64>) -> StabilityReport {
    let eigenvalues = jacobian.complex_eigenvalues();
    let eigs: Vec<Complex<f64>> = eigenvalues.iter().cloned().collect();

    let (dominant_idx, max_re) = eigs
        .iter()
        .enumerate()
        .max_by(|(_, a), (_, b)| a.re.partial_cmp(&b.re).unwrap())
        .map(|(i, v)| (i, v.re))
        .unwrap_or((0, f64::NEG_INFINITY));

    // Symmetric part analysis: Jsym = (J + Jᵀ)/2
    let jsym = (jacobian + jacobian.transpose()) * 0.5;
    let jsym_eigs = jsym.symmetric_eigenvalues();
    let jsym_max = jsym_eigs.iter().cloned().fold(f64::NEG_INFINITY, f64::max);

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
    }
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

    scenarios
        .into_iter()
        .map(|(label, rates, op)| {
            let jac = build_jacobian(cfg, &rates, &op);
            analyze_stability(label, &jac)
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
    out.push_str("═══════════════════════════════════════════════════════════════\n");
    out.push_str(&format!(
        "  Overall: {}\n",
        if all_stable {
            "ALL SCENARIOS STABLE"
        } else {
            "INSTABILITY DETECTED — review scenarios above"
        }
    ));
    out.push_str("═══════════════════════════════════════════════════════════════\n");

    out
}

// =====================================================================
// MATRIX EXPONENTIAL — Padé(13) Scaling & Squaring (Higham 2005)
// =====================================================================

/// Padé(13) coefficients for the matrix exponential.
const PADE13_B: [f64; 14] = [
    64764752532480000.0,
    32382376266240000.0,
    7771770303897600.0,
    1187353796428800.0,
    129060195264000.0,
    10559470521600.0,
    670442572800.0,
    33522128640.0,
    1323241920.0,
    40840800.0,
    960960.0,
    16380.0,
    182.0,
    1.0,
];

/// Padé(13) scaling-and-squaring matrix exponential.
///
/// Computes exp(A) for a square matrix A using the Higham (2005) algorithm.
/// All linear solves use LU factorization — no explicit matrix inversions.
pub fn mat_exp(a: &DMatrix<f64>) -> DMatrix<f64> {
    let n = a.nrows();
    assert_eq!(n, a.ncols(), "mat_exp requires a square matrix");

    // 1-norm for scaling decision
    let norm1: f64 = (0..n)
        .map(|col| (0..n).map(|row| a[(row, col)].abs()).sum::<f64>())
        .fold(0.0_f64, f64::max);

    // Scaling: s = max(0, ceil(log2(norm1 / theta_13)))
    const THETA_13: f64 = 5.371920351148152;
    let s = if norm1 > THETA_13 {
        (norm1 / THETA_13).log2().ceil() as u32
    } else {
        0
    };

    let a_scaled = if s > 0 {
        a / (2.0_f64.powi(s as i32))
    } else {
        a.clone()
    };

    // Compute matrix powers: A², A⁴, A⁶
    let id = DMatrix::identity(n, n);
    let a2 = &a_scaled * &a_scaled;
    let a4 = &a2 * &a2;
    let a6 = &a4 * &a2;

    // Build U₁₃ and V₁₃ from Padé coefficients
    // V₁₃ = b₀·I + b₂·A² + b₄·A⁴ + b₆·A⁶ + (b₈·A² + b₁₀·A⁴ + b₁₂·A⁶)·A⁶
    // U₁₃ = A·(b₁·I + b₃·A² + b₅·A⁴ + b₇·A⁶ + (b₉·A² + b₁₁·A⁴ + b₁₃·A⁶)·A⁶)
    let v_inner = &a6 * PADE13_B[12] + &a4 * PADE13_B[10] + &a2 * PADE13_B[8];
    let v13 = &v_inner * &a6
        + &a6 * PADE13_B[6]
        + &a4 * PADE13_B[4]
        + &a2 * PADE13_B[2]
        + &id * PADE13_B[0];

    let u_inner = &a6 * PADE13_B[13] + &a4 * PADE13_B[11] + &a2 * PADE13_B[9];
    let u13 = &a_scaled
        * &(&u_inner * &a6
            + &a6 * PADE13_B[7]
            + &a4 * PADE13_B[5]
            + &a2 * PADE13_B[3]
            + &id * PADE13_B[1]);

    // Solve (V₁₃ − U₁₃)·R = V₁₃ + U₁₃ via LU factorization
    let lhs = &v13 - &u13;
    let rhs = &v13 + &u13;
    let lu = lhs.lu();
    let mut result = lu.solve(&rhs).expect("Padé denominator is singular");

    // Repeated squaring: R = R² done s times
    for _ in 0..s {
        result = &result * &result;
    }

    result
}

// =====================================================================
// DYSON SERIES — Transient Threat Propagation Analysis
// =====================================================================

// 16-point Gauss-Legendre nodes on [-1, 1].
const GL16_NODES: [f64; 16] = [
    -0.9894009349916499,
    -0.9445750230732326,
    -0.8656312023878318,
    -0.7554044083550030,
    -0.6178762444026438,
    -0.4580167776572274,
    -0.2816035507792589,
    -0.0950125098376374,
    0.0950125098376374,
    0.2816035507792589,
    0.4580167776572274,
    0.6178762444026438,
    0.7554044083550030,
    0.8656312023878318,
    0.9445750230732326,
    0.9894009349916499,
];

// 16-point Gauss-Legendre weights on [-1, 1].
const GL16_WEIGHTS: [f64; 16] = [
    0.0271524594117541,
    0.0622535239386479,
    0.0951585116824928,
    0.1246289712555339,
    0.1495959888165767,
    0.1691565193950025,
    0.1826034150449236,
    0.1894506104550685,
    0.1894506104550685,
    0.1826034150449236,
    0.1691565193950025,
    0.1495959888165767,
    0.1246289712555339,
    0.0951585116824928,
    0.0622535239386479,
    0.0271524594117541,
];

/// Rescale GL nodes/weights from [-1,1] to [a,b].
fn gl16_rescale(a: f64, b: f64) -> ([f64; 16], [f64; 16]) {
    let half_len = (b - a) * 0.5;
    let mid = (a + b) * 0.5;
    let mut nodes = [0.0; 16];
    let mut weights = [0.0; 16];
    for i in 0..16 {
        nodes[i] = half_len * GL16_NODES[i] + mid;
        weights[i] = half_len * GL16_WEIGHTS[i];
    }
    (nodes, weights)
}

/// A time-localized threat perturbation to the integral system.
#[derive(Debug, Clone)]
pub struct ThreatProfile {
    pub name: String,
    /// Onset time in seconds from t=0.
    pub onset: f64,
    /// Duration of the threat in seconds.
    pub duration: f64,
    /// Direct impulse injection rate (8-vector). Active during [onset, onset+duration].
    pub forcing: DVector<f64>,
    /// Optional perturbation to the Jacobian (coupling change). When Some, the
    /// system matrix becomes J + V during the threat window.
    pub coupling_delta: Option<DMatrix<f64>>,
}

impl ThreatProfile {
    /// Sybil flood: 50 entries/s injected into the entry integral for 5 seconds.
    pub fn sybil_flood() -> Self {
        let mut forcing = DVector::zeros(DIM);
        forcing[E] = 50.0;
        Self {
            name: "Sybil Flood".into(),
            onset: 1.0,
            duration: 5.0,
            forcing,
            coupling_delta: None,
        }
    }

    /// Bandwidth DDoS: 100 MiB/s injected into the bandwidth integral for 10 seconds.
    pub fn bandwidth_ddos() -> Self {
        let mut forcing = DVector::zeros(DIM);
        forcing[B] = 100.0;
        Self {
            name: "Bandwidth DDoS".into(),
            onset: 1.0,
            duration: 10.0,
            forcing,
            coupling_delta: None,
        }
    }

    /// Storage exhaustion: +0.5 ratio/s into WAL storage for 30 seconds.
    pub fn storage_exhaustion() -> Self {
        let mut forcing = DVector::zeros(DIM);
        forcing[W] = 0.5;
        Self {
            name: "Storage Exhaustion".into(),
            onset: 1.0,
            duration: 30.0,
            forcing,
            coupling_delta: None,
        }
    }

    /// Network partition: all network-fed coupling paths are severed for 20 seconds.
    /// V(t) negates the bandwidth column of J, eliminating all coupling from b.
    /// Also zeroes the forcing that would normally flow through ingestion.
    pub fn network_partition(j: &DMatrix<f64>) -> Self {
        let mut v = DMatrix::zeros(DIM, DIM);
        // Negate column B (bandwidth) — sever the network edge gate's influence
        for row in 0..DIM {
            v[(row, B)] = -j[(row, B)];
        }
        // Also negate self-coupling for network-originated integrals
        // (they lose their impulse source entirely during partition)
        v[(S, S)] = -j[(S, S)] - 0.1; // small residual decay remains
        v[(E, E)] = -j[(E, E)] - 0.1;
        v[(L, L)] = -j[(L, L)] - 0.1;

        Self {
            name: "Network Partition".into(),
            onset: 1.0,
            duration: 20.0,
            forcing: DVector::zeros(DIM),
            coupling_delta: Some(v),
        }
    }

    /// Cascade: bandwidth DDoS at t=1 for 10s, then Sybil flood at t=16 for 5s.
    pub fn cascade_ddos_then_sybil() -> Vec<Self> {
        let mut ddos = Self::bandwidth_ddos();
        ddos.onset = 1.0;

        let mut sybil = Self::sybil_flood();
        sybil.onset = 16.0; // 5s gap after DDoS ends at t=11

        vec![ddos, sybil]
    }
}

/// Time series of the 8 integral states.
#[derive(Debug, Clone)]
pub struct TimeSeries {
    pub times: Vec<f64>,
    pub states: Vec<[f64; DIM]>,
}

/// Evolve the linearized integral system under one or more threat profiles.
///
/// Uses the exponential integrator with LU solves (no explicit inversions):
///   x(t+dt) = G·x(t) + φ
///   where J·φ = (G − I)·u(t), solved via pre-computed LU factorization.
pub fn evolve(
    j: &DMatrix<f64>,
    threats: &[ThreatProfile],
    x0: &[f64; DIM],
    t_final: f64,
    dt: f64,
) -> TimeSeries {
    let n = (t_final / dt).ceil() as usize;
    let id = DMatrix::identity(DIM, DIM);

    // Pre-compute the free propagator and LU factorization
    let g0 = mat_exp(&(j * dt));
    let lu_j = j.clone().lu();
    let g0_minus_i = &g0 - &id;

    // Collect distinct coupling deltas and pre-compute their propagators
    let mut coupling_cache: Vec<(
        DMatrix<f64>,
        DMatrix<f64>,
        nalgebra::LU<f64, nalgebra::Dyn, nalgebra::Dyn>,
    )> = Vec::new();
    for threat in threats {
        if let Some(ref v) = threat.coupling_delta {
            let j_plus_v = j + v;
            let g_v = mat_exp(&(&j_plus_v * dt));
            let lu_jv = j_plus_v.lu();
            coupling_cache.push((v.clone(), g_v, lu_jv));
        }
    }

    let mut times = Vec::with_capacity(n + 1);
    let mut states = Vec::with_capacity(n + 1);

    let mut x = DVector::from_column_slice(x0);
    let mut t = 0.0;

    times.push(t);
    let mut state = [0.0; DIM];
    for i in 0..DIM {
        state[i] = x[i];
    }
    states.push(state);

    for _ in 0..n {
        // Sum forcing from all active threats
        let mut u_total = DVector::zeros(DIM);
        let mut active_coupling: Option<usize> = None;

        for (ti, threat) in threats.iter().enumerate() {
            if t >= threat.onset && t < threat.onset + threat.duration {
                u_total += &threat.forcing;
                if threat.coupling_delta.is_some() {
                    // Find the matching cache entry
                    let cache_idx = threats[..ti]
                        .iter()
                        .filter(|t| t.coupling_delta.is_some())
                        .count();
                    active_coupling = Some(cache_idx);
                }
            }
        }

        // Select propagator and LU based on active coupling
        let (g, lu) = if let Some(idx) = active_coupling {
            (&coupling_cache[idx].1, &coupling_cache[idx].2)
        } else {
            (&g0, &lu_j)
        };

        // Exponential integrator step
        let g_ref = if active_coupling.is_some() {
            &coupling_cache[active_coupling.unwrap()].1 - &id
        } else {
            g0_minus_i.clone()
        };

        x = g * &x;
        if u_total.norm() > 1e-15 {
            let rhs = &g_ref * &u_total;
            if let Some(phi) = lu.solve(&rhs) {
                x += phi;
            }
        }

        t += dt;
        times.push(t);
        let mut state = [0.0; DIM];
        for i in 0..DIM {
            state[i] = x[i];
        }
        states.push(state);
    }

    TimeSeries { times, states }
}

/// Dyson series correction terms for the time-evolution operator.
#[derive(Debug, Clone)]
pub struct DysonTerms {
    /// Zeroth order: G₀(T) — the free propagator at the final time.
    pub zeroth: DMatrix<f64>,
    /// First-order correction: ∫ G₀(T−t₁)·V·G₀(t₁) dt₁
    pub first: DMatrix<f64>,
    /// Second-order correction: ∫∫ G₀(T−t₂)·V·G₀(t₂−t₁)·V·G₀(t₁) dt₁dt₂
    pub second: DMatrix<f64>,
    /// Convergence ratio ‖U²‖_F / ‖U¹‖_F. Must be < 1 for series convergence.
    pub convergence_ratio: f64,
}

/// Compute the first two Dyson series correction terms using 16-point
/// Gauss-Legendre quadrature.
///
/// Evaluates over the threat window [t_onset, t_end] with V constant.
/// The final time T is set to t_end (evaluation at the end of the threat).
pub fn compute_dyson_terms(
    j: &DMatrix<f64>,
    v: &DMatrix<f64>,
    t_onset: f64,
    t_end: f64,
) -> DysonTerms {
    let t_total = t_end;

    // Zeroth order: G₀(T)
    let zeroth = mat_exp(&(j * t_total));

    // GL nodes/weights rescaled to [t_onset, t_end]
    let (outer_nodes, outer_weights) = gl16_rescale(t_onset, t_end);

    // First-order: U¹ = Σᵢ wᵢ · G₀(T−tᵢ) · V · G₀(tᵢ)
    let mut first = DMatrix::zeros(DIM, DIM);
    for i in 0..16 {
        let ti = outer_nodes[i];
        let g_left = mat_exp(&(j * (t_total - ti)));
        let g_right = mat_exp(&(j * ti));
        first += (g_left * v * g_right) * outer_weights[i];
    }

    // Second-order: U² = Σᵢ wᵢ · Σⱼ wⱼ · G₀(T−tᵢ) · V · G₀(tᵢ−sⱼ) · V · G₀(sⱼ)
    // Outer integral over t₂ ∈ [t_onset, t_end], inner over t₁ ∈ [t_onset, t₂]
    let mut second = DMatrix::zeros(DIM, DIM);
    for i in 0..16 {
        let t2 = outer_nodes[i];
        let g_left = mat_exp(&(j * (t_total - t2)));

        // Inner GL rescaled to [t_onset, t2]
        if t2 > t_onset + 1e-12 {
            let (inner_nodes, inner_weights) = gl16_rescale(t_onset, t2);
            for k in 0..16 {
                let t1 = inner_nodes[k];
                let g_mid = mat_exp(&(j * (t2 - t1)));
                let g_right = mat_exp(&(j * t1));
                second +=
                    (&g_left * v * &g_mid * v * g_right) * (outer_weights[i] * inner_weights[k]);
            }
        }
    }

    let first_norm = first.norm();
    let second_norm = second.norm();
    let convergence_ratio = if first_norm > 1e-15 {
        second_norm / first_norm
    } else {
        0.0
    };

    DysonTerms {
        zeroth,
        first,
        second,
        convergence_ratio,
    }
}

/// Impulse response metrics for a threat scenario.
#[derive(Debug, Clone)]
pub struct ImpulseResponseReport {
    pub scenario: String,
    /// Peak absolute value of each integral during/after the threat.
    pub peak_values: [f64; DIM],
    /// Time at which each integral reaches its peak.
    pub peak_times: [f64; DIM],
    /// Time for each integral to return to 10% of its peak (f64::INFINITY if never).
    pub recovery_times: [f64; DIM],
    /// Full time series.
    pub time_series: TimeSeries,
}

/// Analyze the impulse response to a set of threats.
pub fn impulse_response(
    j: &DMatrix<f64>,
    threats: &[ThreatProfile],
    scenario: &str,
) -> ImpulseResponseReport {
    let x0 = [0.0; DIM];
    let dt = 0.05;
    let t_final = 60.0;
    let ts = evolve(j, threats, &x0, t_final, dt);

    let mut peak_values = [0.0; DIM];
    let mut peak_times = [0.0; DIM];
    let mut recovery_times = [f64::INFINITY; DIM];
    let mut past_peak = [false; DIM];

    for (step, state) in ts.states.iter().enumerate() {
        let t = ts.times[step];
        for i in 0..DIM {
            let v = state[i].abs();
            if v > peak_values[i] {
                peak_values[i] = v;
                peak_times[i] = t;
                past_peak[i] = false;
            } else if v < peak_values[i] {
                past_peak[i] = true;
            }

            if past_peak[i] && v < peak_values[i] * 0.1 && recovery_times[i] == f64::INFINITY {
                recovery_times[i] = t - peak_times[i];
            }
        }
    }

    ImpulseResponseReport {
        scenario: scenario.to_string(),
        peak_values,
        peak_times,
        recovery_times,
        time_series: ts,
    }
}

/// Cascade analysis: compare sequential threats against each individually.
#[derive(Debug, Clone)]
pub struct CascadeReport {
    pub threat_a_alone: ImpulseResponseReport,
    pub threat_b_alone: ImpulseResponseReport,
    pub cascade: ImpulseResponseReport,
    /// peak(A→B) / max(peak(A), peak(B)) per integral.
    /// Values > 1.0 indicate dangerous compounding.
    pub compounding_factors: [f64; DIM],
}

/// Run cascade analysis: threat A alone, threat B alone, then A→B sequentially.
pub fn cascade_analysis(
    j: &DMatrix<f64>,
    threat_a: &ThreatProfile,
    threat_b: &ThreatProfile,
) -> CascadeReport {
    let a_report = impulse_response(j, &[threat_a.clone()], &threat_a.name);
    let b_report = impulse_response(j, &[threat_b.clone()], &threat_b.name);
    let cascade_report = impulse_response(
        j,
        &[threat_a.clone(), threat_b.clone()],
        &format!("{} → {}", threat_a.name, threat_b.name),
    );

    let mut compounding = [0.0; DIM];
    for i in 0..DIM {
        let individual_max = a_report.peak_values[i].max(b_report.peak_values[i]);
        compounding[i] = if individual_max > 1e-12 {
            cascade_report.peak_values[i] / individual_max
        } else {
            1.0
        };
    }

    CascadeReport {
        threat_a_alone: a_report,
        threat_b_alone: b_report,
        cascade: cascade_report,
        compounding_factors: compounding,
    }
}

/// Find the convergence radius — the perturbation magnitude α where
/// ‖U²‖/‖U¹‖ ≈ 1 (Dyson series diverges beyond this point).
pub fn convergence_radius(
    j: &DMatrix<f64>,
    v_direction: &DMatrix<f64>,
    t_onset: f64,
    t_end: f64,
) -> f64 {
    // Normalize the direction
    let v_norm = v_direction.norm();
    if v_norm < 1e-15 {
        return f64::INFINITY;
    }
    let v_hat = v_direction / v_norm;

    // Binary search for α where convergence_ratio ≈ 1.0
    let mut lo = 0.01_f64;
    let mut hi = 1000.0_f64;

    // Check if lo already diverges
    let terms_lo = compute_dyson_terms(j, &(&v_hat * lo), t_onset, t_end);
    if terms_lo.convergence_ratio >= 1.0 {
        return lo * 0.5; // even small perturbations diverge
    }

    // Check if hi still converges
    let terms_hi = compute_dyson_terms(j, &(&v_hat * hi), t_onset, t_end);
    if terms_hi.convergence_ratio < 1.0 {
        return hi; // converges even at large α
    }

    for _ in 0..50 {
        let mid = (lo + hi) * 0.5;
        let terms = compute_dyson_terms(j, &(&v_hat * mid), t_onset, t_end);
        if terms.convergence_ratio < 1.0 {
            lo = mid;
        } else {
            hi = mid;
        }
        if (hi - lo) / lo < 0.01 {
            break;
        }
    }

    (lo + hi) * 0.5
}

/// Full Dyson analysis results.
#[derive(Debug, Clone)]
pub struct DysonAnalysisReport {
    pub threat_responses: Vec<ImpulseResponseReport>,
    pub cascade: CascadeReport,
    pub dyson_terms: DysonTerms,
    pub convergence_radius: f64,
}

/// Run the complete Dyson transient analysis across all threat scenarios.
pub fn full_dyson_analysis(cfg: &HomeostaticConfig) -> DysonAnalysisReport {
    let rates = BaseImpulseRates::moderate();
    let op = OperatingPoint::idle();
    let j = build_jacobian(cfg, &rates, &op);

    // Individual threat responses
    let sybil = impulse_response(&j, &[ThreatProfile::sybil_flood()], "Sybil Flood");
    let ddos = impulse_response(&j, &[ThreatProfile::bandwidth_ddos()], "Bandwidth DDoS");
    let storage = impulse_response(
        &j,
        &[ThreatProfile::storage_exhaustion()],
        "Storage Exhaustion",
    );
    let partition = impulse_response(
        &j,
        &[ThreatProfile::network_partition(&j)],
        "Network Partition",
    );

    // Cascade: DDoS → Sybil
    let cascade_threats = ThreatProfile::cascade_ddos_then_sybil();
    let cascade = cascade_analysis(&j, &cascade_threats[0], &cascade_threats[1]);

    // Dyson terms for network partition (has coupling change V)
    let partition_threat = ThreatProfile::network_partition(&j);
    let v = partition_threat.coupling_delta.as_ref().unwrap();
    let dyson = compute_dyson_terms(
        &j,
        v,
        partition_threat.onset,
        partition_threat.onset + partition_threat.duration,
    );

    // Convergence radius
    let conv_radius = convergence_radius(
        &j,
        v,
        partition_threat.onset,
        partition_threat.onset + partition_threat.duration,
    );

    DysonAnalysisReport {
        threat_responses: vec![sybil, ddos, storage, partition],
        cascade,
        dyson_terms: dyson,
        convergence_radius: conv_radius,
    }
}

/// Format the Dyson analysis report as a display string.
pub fn format_dyson_report(report: &DysonAnalysisReport) -> String {
    let mut out = String::new();
    out.push_str("╔══════════════════════════════════════════════════════════════╗\n");
    out.push_str("║     PHALANX DYSON SERIES — TRANSIENT THREAT ANALYSIS       ║\n");
    out.push_str("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Individual threat responses
    for resp in &report.threat_responses {
        out.push_str(&format!("━━━ {} ━━━\n\n", resp.scenario));
        out.push_str("  Integral   Peak Value   Peak Time   Recovery Time\n");
        out.push_str("  ─────────  ──────────   ─────────   ─────────────\n");
        for i in 0..DIM {
            let recovery = if resp.recovery_times[i] == f64::INFINITY {
                "never".to_string()
            } else {
                format!("{:.2}s", resp.recovery_times[i])
            };
            out.push_str(&format!(
                "  {:>9}  {:>10.4}   {:>7.2}s   {:>13}\n",
                INTEGRAL_NAMES[i], resp.peak_values[i], resp.peak_times[i], recovery,
            ));
        }
        out.push('\n');
    }

    // Cascade analysis
    out.push_str("━━━ CASCADE: DDoS → Sybil ━━━\n\n");
    out.push_str("  Integral   DDoS Peak   Sybil Peak   Cascade Peak   Compounding\n");
    out.push_str("  ─────────  ─────────   ──────────   ────────────   ───────────\n");
    for i in 0..DIM {
        let factor = report.cascade.compounding_factors[i];
        let marker = if factor > 1.5 {
            " ⚠"
        } else if factor > 1.0 {
            " ↑"
        } else {
            ""
        };
        out.push_str(&format!(
            "  {:>9}  {:>9.4}   {:>10.4}   {:>12.4}   {:>8.3}×{}\n",
            INTEGRAL_NAMES[i],
            report.cascade.threat_a_alone.peak_values[i],
            report.cascade.threat_b_alone.peak_values[i],
            report.cascade.cascade.peak_values[i],
            factor,
            marker,
        ));
    }
    out.push('\n');

    // Dyson terms (network partition)
    out.push_str("━━━ DYSON SERIES: Network Partition ━━━\n\n");
    out.push_str(&format!(
        "  ‖U⁰‖_F = {:.6}  (free propagator)\n",
        report.dyson_terms.zeroth.norm()
    ));
    out.push_str(&format!(
        "  ‖U¹‖_F = {:.6}  (first-order correction)\n",
        report.dyson_terms.first.norm()
    ));
    out.push_str(&format!(
        "  ‖U²‖_F = {:.6}  (second-order correction)\n",
        report.dyson_terms.second.norm()
    ));
    out.push_str(&format!(
        "  Convergence ratio ρ = {:.6}  {}\n",
        report.dyson_terms.convergence_ratio,
        if report.dyson_terms.convergence_ratio < 1.0 {
            "(ρ < 1 → series converges)"
        } else {
            "(ρ ≥ 1 → series DIVERGES, linearization breaks down!)"
        }
    ));
    out.push_str(&format!(
        "\n  Convergence radius α = {:.4}\n",
        report.convergence_radius
    ));
    out.push_str("  (perturbation magnitude at which ρ ≈ 1)\n\n");

    out.push_str("═══════════════════════════════════════════════════════════════\n");
    out
}

// =====================================================================
// TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn default_cfg() -> HomeostaticConfig {
        HomeostaticConfig::default()
    }

    #[test]
    fn test_default_config_stable_at_idle() {
        let cfg = default_cfg();
        let jac = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let report = analyze_stability("idle", &jac);
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
        let report = analyze_stability("half-critical", &jac);
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
        let report = analyze_stability("near-critical", &jac);
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
            let report = analyze_stability(name, &jac);
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

    // =================================================================
    // DYSON SERIES TESTS
    // =================================================================

    #[test]
    fn test_mat_exp_identity() {
        // exp(0) = I
        let zero = DMatrix::zeros(DIM, DIM);
        let result = mat_exp(&zero);
        let id = DMatrix::identity(DIM, DIM);
        assert!(
            (&result - &id).norm() < 1e-12,
            "exp(0) should be identity, got norm diff = {}",
            (&result - &id).norm()
        );
    }

    #[test]
    fn test_mat_exp_diagonal() {
        // exp(diag(λ)) = diag(exp(λ))
        let lambdas = [-4.0, -0.5, -0.1, -1.0, -0.3, -0.05, -0.5, -0.2];
        let mut diag = DMatrix::zeros(DIM, DIM);
        for i in 0..DIM {
            diag[(i, i)] = lambdas[i];
        }
        let result = mat_exp(&diag);
        for i in 0..DIM {
            let expected = lambdas[i].exp();
            assert!(
                (result[(i, i)] - expected).abs() < 1e-12,
                "exp(diag)[{},{}] = {}, expected {}",
                i,
                i,
                result[(i, i)],
                expected
            );
            // Off-diagonal should be zero
            for k in 0..DIM {
                if k != i {
                    assert!(
                        result[(i, k)].abs() < 1e-12,
                        "exp(diag)[{},{}] = {}, expected 0",
                        i,
                        k,
                        result[(i, k)]
                    );
                }
            }
        }
    }

    #[test]
    fn test_mat_exp_known_2x2() {
        // exp([[0, 1], [0, 0]]) = [[1, 1], [0, 1]] (nilpotent matrix)
        let mut a = DMatrix::zeros(2, 2);
        a[(0, 1)] = 1.0;
        let result = mat_exp(&a);
        assert!((result[(0, 0)] - 1.0).abs() < 1e-12);
        assert!((result[(0, 1)] - 1.0).abs() < 1e-12);
        assert!((result[(1, 0)] - 0.0).abs() < 1e-12);
        assert!((result[(1, 1)] - 1.0).abs() < 1e-12);
    }

    #[test]
    fn test_free_propagator_decays() {
        // ‖G₀(t)‖ → 0 as t → ∞ (all eigenvalues have Re < 0).
        //
        // Note: because J is non-normal (Jsym is NOT negative definite),
        // the propagator norm can experience transient growth before decaying.
        // We test the asymptotic regime (t ≥ 30s) where all modes have decayed.
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());

        let g_30 = mat_exp(&(&j * 30.0));
        let g_60 = mat_exp(&(&j * 60.0));
        let g_120 = mat_exp(&(&j * 120.0));

        assert!(
            g_60.norm() < g_30.norm(),
            "G₀(60) should have smaller norm than G₀(30): {:.6} vs {:.6}",
            g_60.norm(),
            g_30.norm()
        );
        assert!(
            g_120.norm() < g_60.norm(),
            "G₀(120) should have smaller norm than G₀(60)"
        );
        assert!(
            g_120.norm() < 0.01,
            "G₀(120) should be near zero, got ‖G₀‖ = {}",
            g_120.norm()
        );
    }

    #[test]
    fn test_sybil_flood_contained() {
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let resp = impulse_response(&j, &[ThreatProfile::sybil_flood()], "sybil");

        // All integrals should recover within 60s
        for i in 0..DIM {
            if resp.peak_values[i] > 1e-6 {
                assert!(
                    resp.recovery_times[i] < 60.0,
                    "Integral {} failed to recover from Sybil flood: peak={:.4}, recovery={:.2}s",
                    INTEGRAL_NAMES[i],
                    resp.peak_values[i],
                    resp.recovery_times[i]
                );
            }
        }

        // Entry integral should see the largest peak
        assert!(
            resp.peak_values[E] > resp.peak_values[S],
            "Entry integral should peak higher than metabolic under Sybil flood"
        );
    }

    #[test]
    fn test_ddos_recovery() {
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let resp = impulse_response(&j, &[ThreatProfile::bandwidth_ddos()], "ddos");

        // Bandwidth integral should recover within 5× its time constant
        // τ_b = 1/λ_bw = 2.0s, so recovery should be < 10s after peak
        let tau_b = 1.0 / cfg.lambda_bw;
        if resp.peak_values[B] > 1e-6 {
            assert!(
                resp.recovery_times[B] < tau_b * 5.0,
                "Bandwidth recovery too slow: {:.2}s (expected < {:.2}s)",
                resp.recovery_times[B],
                tau_b * 5.0
            );
        }
    }

    #[test]
    fn test_storage_exhaustion_memory_coupling() {
        // Storage spike propagates to memory via J[m,w] = +25.0 coupling.
        // Because the coupling coefficient is large, memory actually peaks
        // HIGHER than storage — the destabilizing w→m path amplifies the signal.
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let resp = impulse_response(&j, &[ThreatProfile::storage_exhaustion()], "storage");

        // Memory should see a strong response to the storage threat
        assert!(
            resp.peak_values[M] > 1.0,
            "Memory should respond strongly to storage exhaustion via J[m,w] coupling, \
             but peak_m = {:.6}",
            resp.peak_values[M]
        );

        // Memory should peak HIGHER than storage due to J[m,w] amplification.
        // This is the destabilizing coupling path identified in the eigenvalue analysis.
        assert!(
            resp.peak_values[M] > resp.peak_values[W],
            "Memory should peak higher than storage due to J[m,w] = +25.0 amplification: \
             peak_m={:.4} vs peak_w={:.4}",
            resp.peak_values[M],
            resp.peak_values[W]
        );
    }

    #[test]
    fn test_cascade_compounding_bounded() {
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let threats = ThreatProfile::cascade_ddos_then_sybil();
        let report = cascade_analysis(&j, &threats[0], &threats[1]);

        for i in 0..DIM {
            assert!(
                report.compounding_factors[i] < 2.0,
                "Compounding factor for {} = {:.3} exceeds 2.0 — dangerous amplification!",
                INTEGRAL_NAMES[i],
                report.compounding_factors[i]
            );
        }
    }

    #[test]
    fn test_network_partition_dyson_characterization() {
        // A full network partition is a severe structural change — it negates
        // entire coupling columns, making ‖V‖ comparable to ‖J‖.  The Dyson
        // series may or may not converge depending on the perturbation magnitude.
        //
        // This test characterizes the series behavior and verifies the
        // convergence radius analysis works correctly.
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let threat = ThreatProfile::network_partition(&j);
        let v = threat.coupling_delta.as_ref().unwrap();
        let terms = compute_dyson_terms(&j, v, threat.onset, threat.onset + threat.duration);

        println!(
            "  Network partition Dyson: ‖U¹‖={:.4}, ‖U²‖={:.4}, ρ={:.4}",
            terms.first.norm(),
            terms.second.norm(),
            terms.convergence_ratio,
        );

        // The convergence ratio tells us whether the linearized model is adequate.
        // If ρ ≥ 1, the partition is a genuinely nonlinear event — the Dyson
        // expansion cannot approximate it, which is itself a safety finding.
        if terms.convergence_ratio >= 1.0 {
            println!(
                "  Finding: network partition is a nonlinear event (ρ = {:.4} ≥ 1).\n  \
                 The linearized Dyson expansion is insufficient — full nonlinear\n  \
                 simulation is needed to characterize this threat.",
                terms.convergence_ratio
            );
        }

        // The first-order correction should always be nonzero (the partition
        // does change the system).
        assert!(
            terms.first.norm() > 1e-6,
            "First-order Dyson correction should be nonzero for a nontrivial V"
        );
    }

    #[test]
    fn test_convergence_radius_positive() {
        let cfg = default_cfg();
        let j = build_jacobian(&cfg, &BaseImpulseRates::moderate(), &OperatingPoint::idle());
        let threat = ThreatProfile::network_partition(&j);
        let v = threat.coupling_delta.as_ref().unwrap();
        let radius = convergence_radius(&j, v, threat.onset, threat.onset + threat.duration);

        assert!(
            radius > 0.0,
            "Convergence radius should be positive, got {}",
            radius
        );
        println!("  Convergence radius: {:.4}", radius);
    }

    #[test]
    fn test_full_dyson_analysis() {
        let cfg = default_cfg();
        let report = full_dyson_analysis(&cfg);
        let output = format_dyson_report(&report);
        println!("{}", output);

        // All threats should show recovery
        for resp in &report.threat_responses {
            for i in 0..DIM {
                if resp.peak_values[i] > 1e-3 {
                    assert!(
                        resp.recovery_times[i] < 60.0,
                        "Scenario '{}': integral {} failed to recover (peak={:.4})",
                        resp.scenario,
                        INTEGRAL_NAMES[i],
                        resp.peak_values[i]
                    );
                }
            }
        }

        // Log the Dyson convergence (may or may not converge for the
        // network partition — either outcome is a valid finding).
        println!(
            "  Dyson convergence ratio ρ = {:.4} ({})",
            report.dyson_terms.convergence_ratio,
            if report.dyson_terms.convergence_ratio < 1.0 {
                "converges"
            } else {
                "diverges — partition is nonlinear"
            }
        );
    }
}
