//! Eigenvalue stability analysis of the 8-integral Volterra feedback system.
//!
//! Constructs the 8x8 Jacobian (coupling matrix) of the linearized system and
//! computes eigenvalues.  All eigenvalues with negative real parts → the system
//! is asymptotically stable at the given operating point.
//!
//! Enabled via the `stability-analysis` cargo feature

// I had to pull out the rat glue for this one. This is 100% 'roach scholar' energy. Thank you Dr. Calvetti.

// This is what happens when a numerical analyst who doesn't know any better decides to
// design a distributed mesh.

// What you see here is a result of frustration. I am not a good programmer in the classical
// sense- or any sense really. I am a compulsive problem solver with a deep disdain for friction;
// not the physical concept of friction- that's supremely useful. I'm talking about design friction.
//
// The first pass at Phalanx started as many hobby projects do- a monolithic ball of mud. This was fine
// when the project was 5-10 files and didn't do much beyond send a jpeg still over gossipsub. As the project
// grew, so did the parameter count. Now, because I'm a bad programmer, who is always trying to become a
// better programmer, I was forcing myself to use test driven design because that is what the 'best'
// (for my particular definition of best) programmers do. And because I'm a bad programmer, who had a
// shit architecture to start, my tests would break every time I added a new feature. I found myself
// changing parameters to make one test work only to break another. It. fucking. sucked.
//
// There had to be a better way, so I set out to build one. My first idea was to derive a fundamental
// set of constants that every parameter in the code base would depend on. I forget what the initial ones
// were (they're in the git history so I guess I don't have to remember.), but I do remember network round trip
// time being the big one. I implemented it and it worked! For a while. Testing revealed that the mesh was still
// brittle which, in hindsight, makes so much sense because I didn't actually solve the real problem. I just
// reduced the number of parameters I was arbitrarily assigning values to. There had to be a better way.
//
// The insight came to me in the small hours of the morning while I was watching my parents very fancy
// coffee machine make my coffee. What if I just didn't use constants at all? What if I tried
// modeling this whole thing using a system of differential equations. So that's what I tried. And before
// my pencil hit the paper, I realized that that idea too would fail. Network signals are inherently
// non-differentiable; and even if they were, numerical differentiation is inherently unstable. It
// could never work. It would simply be a 'clever' trick that wasn't all that clever.
//
// And then I remembered my training- I could hear Dr. Somersalo (not unlike Yoda whispering to Luke,
// except with less magic) "Use the integral equations, Joe." And as this is all coming to me while
// staring at this coffee machine, I'm watching this machine force hot water through a brick of coffee
// grounds until the pressure accumulates to a point where it must pass through.
//
// Pressure. The whole system could be modeled by a system of coupled integral equations. Integral
// equations (for the most part) are inherently stable. I could model the pressure using Volterra
// integral equations of the second kind. So I did- and this time it really worked.
//
// I still had one last problem to solve. How would I know if it always worked? You see,
// I've never designed a distributed system before. How would I test this idea at scale?
// That would require programming an elaborate simulation harness, and what would that prove?
// That the system would work as intended simply because I the simulation long enough using
// similarly contrived parameters? No. Unacceptable. Once again, there had to be a better way.
//
// This time, it was Dr. Calvetti that whispered to me. "You're a roach scholar, Joe. This is the
// time for that rat glue. You glue yourself to the chair until the work is done." So I did- not
// literally, I'm not a psychopath. My plan of attack went something like this:
// 1. Show that a node is locally stable by looking at my freshly minted system Jacobian
// 2. Show that a failure in one node couldn't cascade into another.
// 3. Show that a node could survive under duress as t -> \infty
//
// What you see here is that plan in action. And oh, by they way, if you happen to model your
// distributed system this way you get Byzantine actor detection for roughly 100 FLOPS of
// additional work. You just have to look at the spectral gap between what the nodes claims
// they are doing and what they are actually doing. All nodes must live in the manifold
// defined by the integral equations that govern this system. A dishonest node has nowhere to
// hide- it cannot escape the math.

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
        .max_by(|(_, a), (_, b)| a.re.partial_cmp(&b.re).unwrap_or(std::cmp::Ordering::Equal))
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
        let (g, lu, g_ref) = if let Some(idx) = active_coupling {
            (
                &coupling_cache[idx].1,
                &coupling_cache[idx].2,
                &coupling_cache[idx].1 - &id,
            )
        } else {
            (&g0, &lu_j, g0_minus_i.clone())
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

    // Dyson terms for network partition (has coupling change V).
    // network_partition() always produces Some(coupling_delta) by construction.
    let partition_threat = ThreatProfile::network_partition(&j);
    let v = match partition_threat.coupling_delta.as_ref() {
        Some(v) => v,
        None => {
            // Structurally unreachable: network_partition always sets coupling_delta.
            // If we're here, someone broke the ThreatProfile constructor.
            return DysonAnalysisReport {
                threat_responses: vec![sybil, ddos, storage, partition],
                cascade,
                dyson_terms: DysonTerms {
                    zeroth: DMatrix::identity(DIM, DIM),
                    first: DMatrix::zeros(DIM, DIM),
                    second: DMatrix::zeros(DIM, DIM),
                    convergence_ratio: 0.0,
                },
                convergence_radius: f64::INFINITY,
            };
        }
    };
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
// NONLINEAR PARTITION ANALYSIS
// =====================================================================
//
// The Dyson series diverges (ρ = 1.30) for the network partition event,
// meaning the perturbation is too large for linearized analysis.  This
// section simulates the exact nonlinear dynamics via RK4 integration of
// the full 8-integral Volterra system, providing:
//   1. Direct nonlinear trajectory through partition + recovery
//   2. Linear vs nonlinear comparison (quantifies linearization error)
//   3. Maximal Lyapunov exponent (definitive stability certificate)
//   4. Partition duration sensitivity sweep

/// Configuration for the nonlinear partition simulation.
#[derive(Debug, Clone)]
pub struct PartitionConfig {
    /// Fraction of network-dependent traffic severed (0.0 = none, 1.0 = full).
    pub network_fraction: f64,
    /// Duration of the partition in seconds.
    pub partition_duration: f64,
    /// Time offset from end of warmup to partition onset.
    pub partition_onset: f64,
    /// Optional reconnection burst multiplier after partition heals.
    /// When Some(k), bandwidth impulse rate is multiplied by k for one
    /// bandwidth time constant (1/λ_bw) after reconnection.
    pub reconnection_burst: Option<f64>,
    /// Local camera capture rate during partition (fraction of normal, 0.0–1.0).
    pub local_capture_fraction: f64,
    /// Simulation time step in seconds.
    pub dt: f64,
    /// Warmup duration for steady-state convergence (seconds).
    pub warmup_duration: f64,
    /// Recovery observation period after partition heals (seconds).
    pub recovery_observation: f64,
}

impl Default for PartitionConfig {
    fn default() -> Self {
        Self {
            network_fraction: 1.0,
            partition_duration: 20.0,
            partition_onset: 0.0,
            reconnection_burst: None,
            local_capture_fraction: 0.0,
            dt: 0.05,
            warmup_duration: 120.0, // 6 × τ_wal = 6/0.05 = 120s
            recovery_observation: 120.0,
        }
    }
}

/// The full nonlinear 8-integral Volterra feedback system.
///
/// Evaluates the exact impulse rate functions f_j(x) at arbitrary states,
/// capturing all saturation nonlinearities, hard gates, the rational sybil
/// endowment, and the positive latency feedback loop.  Unlike the linearized
/// Jacobian (which gives ∂f/∂x at a single operating point), this struct
/// models the true dynamics across the entire state space.
pub struct NonlinearSystem {
    cfg: HomeostaticConfig,
    rates: BaseImpulseRates,
    /// When true, network-dependent throughput channels are severed.
    partition_active: bool,
    /// Fraction of network traffic removed during partition.
    network_fraction: f64,
    /// Local capture fraction during partition.
    local_capture_fraction: f64,
    /// Remaining burst duration in seconds (0.0 = no burst).
    burst_remaining: f64,
    /// Burst multiplier for bandwidth impulse rate.
    burst_multiplier: f64,
}

impl NonlinearSystem {
    pub fn new(
        cfg: &HomeostaticConfig,
        rates: &BaseImpulseRates,
        partition_cfg: &PartitionConfig,
    ) -> Self {
        Self {
            cfg: cfg.clone(),
            rates: rates.clone(),
            partition_active: false,
            network_fraction: partition_cfg.network_fraction,
            local_capture_fraction: partition_cfg.local_capture_fraction,
            burst_remaining: 0.0,
            burst_multiplier: 1.0,
        }
    }

    pub fn set_partition(&mut self, active: bool) {
        self.partition_active = active;
    }

    pub fn activate_burst(&mut self, duration: f64, multiplier: f64) {
        self.burst_remaining = duration;
        self.burst_multiplier = multiplier;
    }

    /// Scaler: σ(x) = max(0, 1 − x/x_crit).  Matches vitals.rs lines 831–899.
    #[inline]
    fn scaler(val: f64, crit: f64) -> f64 {
        (1.0 - val / crit).max(0.0)
    }

    /// Sybil endowment fraction: 1/(1 + k_sybil·x_e).  Matches vitals.rs line 841
    /// normalized to [0,1] (= endowment / ψ_max).
    #[inline]
    fn endowment_frac(&self, x_e: f64) -> f64 {
        1.0 / (1.0 + self.cfg.k_sybil * x_e)
    }

    /// Temporal tolerance factor: min(base + x_l, max_tol) / max_tol.
    /// Matches vitals.rs lines 822–828.
    #[inline]
    fn tol_factor(&self, x_l: f64) -> f64 {
        let base = self.cfg.base_temporal_drift.as_secs_f64();
        let max_tol = self.cfg.max_temporal_tolerance.as_secs_f64();
        (base + x_l).min(max_tol) / max_tol
    }

    /// Core throughput: T(x) = σ_s · E_frac · σ_m · σ_b_eff.
    /// During partition, σ_b_eff accounts for network severing.
    pub fn throughput(&self, x: &[f64; DIM]) -> f64 {
        let sigma_s = Self::scaler(x[S], self.cfg.s_crit);
        let e_frac = self.endowment_frac(x[E]);
        let sigma_m = Self::scaler(x[M], self.cfg.m_crit);

        let sigma_b_raw = Self::scaler(x[B], self.cfg.b_crit);
        let sigma_b_eff = if self.partition_active {
            // During partition: network fraction is severed, local may continue
            sigma_b_raw * (1.0 - self.network_fraction)
                + self.local_capture_fraction * self.network_fraction
        } else {
            sigma_b_raw
        };

        sigma_s * e_frac * sigma_m * sigma_b_eff
    }

    /// Compute all 8 impulse rate functions f_j(x).
    ///
    /// Uses smooth scaler functions throughout (matching the linearized Jacobian
    /// formulation), not hard gates.  This ensures the nonlinear model is the
    /// exact system whose linearization produces the Jacobian from build_jacobian().
    pub fn impulse_rates(&self, x: &[f64; DIM]) -> [f64; DIM] {
        let t = self.throughput(x);
        let tol = self.tol_factor(x[L]);

        // Rejection backpressure: memory phantom pressure proportional to storage
        // stress.  Matches linearized model: J[M,W] = u_m_reject / w_crit.
        let u_m_reject = self.rates.u_m * 0.1;
        let w_stress = (x[W] / self.cfg.w_crit).min(1.0);

        // Storage self-limiting: f_w includes σ_w factor (smooth, not hard gate).
        // Matches linearized model: J[W,W] includes dscaler(w, w_crit).
        let sigma_w = Self::scaler(x[W], self.cfg.w_crit);

        // Bandwidth: f_b = u_b · σ_b (smooth scaler).  During partition, zeroed.
        let sigma_b_raw = Self::scaler(x[B], self.cfg.b_crit);
        let bw_impulse = if self.partition_active && self.network_fraction >= 1.0 {
            0.0
        } else {
            let base = self.rates.u_b * sigma_b_raw;
            if self.burst_remaining > 0.0 {
                base * self.burst_multiplier
            } else {
                base
            }
        };

        [
            self.rates.u_s * t,                                   // f_s: metabolic
            self.rates.u_d * Self::scaler(x[D], self.cfg.d_crit), // f_d: I/O (self-coupled)
            self.rates.u_e * t,                                   // f_e: entry/sybil
            self.rates.u_l * t * tol, // f_l: latency (positive feedback)
            self.rates.u_m * t + u_m_reject * w_stress, // f_m: throughput + storage rejection
            self.rates.u_w * t * sigma_w, // f_w: includes σ_w self-limiting
            bw_impulse,               // f_b: bandwidth
            self.rates.u_c,           // f_c: connection
        ]
    }

    /// Full right-hand side: dI/dt = f(x) − Λ·x.
    pub fn rhs(&self, x: &[f64; DIM]) -> [f64; DIM] {
        let f = self.impulse_rates(x);
        let lambdas = [
            self.cfg.lambda_sys,
            self.cfg.lambda_io,
            self.cfg.lambda_entry,
            self.cfg.lambda_lat,
            self.cfg.lambda_mem,
            self.cfg.lambda_wal,
            self.cfg.lambda_bw,
            self.cfg.lambda_conn,
        ];
        let mut dx = [0.0; DIM];
        for j in 0..DIM {
            dx[j] = f[j] - lambdas[j] * x[j];
        }
        dx
    }

    /// Instantaneous Jacobian Df(x) via central finite differences.
    ///
    /// 16 evaluations of rhs() for DIM=8.  Central differences with h=1e-7
    /// give ~14 digits of accuracy — more than sufficient for the Lyapunov
    /// exponent computation.
    pub fn instantaneous_jacobian(&self, x: &[f64; DIM]) -> DMatrix<f64> {
        let h = 1e-7;
        let mut jac = DMatrix::zeros(DIM, DIM);
        for col in 0..DIM {
            let mut x_plus = *x;
            let mut x_minus = *x;
            x_plus[col] += h;
            x_minus[col] -= h;
            let f_plus = self.rhs(&x_plus);
            let f_minus = self.rhs(&x_minus);
            for row in 0..DIM {
                jac[(row, col)] = (f_plus[row] - f_minus[row]) / (2.0 * h);
            }
        }
        jac
    }
}

// ---------------------------------------------------------------------
// RK4 INTEGRATOR
// ---------------------------------------------------------------------

/// Fourth-order Runge-Kutta step for the nonlinear system.
///
/// dt·λ_max = 0.05 × 4.0 = 0.2, well within RK4 stability boundary (~2.785).
fn rk4_step(sys: &NonlinearSystem, x: &[f64; DIM], dt: f64) -> [f64; DIM] {
    let k1 = sys.rhs(x);

    let mut x2 = [0.0; DIM];
    for i in 0..DIM {
        x2[i] = x[i] + 0.5 * dt * k1[i];
    }
    let k2 = sys.rhs(&x2);

    let mut x3 = [0.0; DIM];
    for i in 0..DIM {
        x3[i] = x[i] + 0.5 * dt * k2[i];
    }
    let k3 = sys.rhs(&x3);

    let mut x4 = [0.0; DIM];
    for i in 0..DIM {
        x4[i] = x[i] + dt * k3[i];
    }
    let k4 = sys.rhs(&x4);

    let mut x_new = [0.0; DIM];
    for i in 0..DIM {
        x_new[i] = (x[i] + (dt / 6.0) * (k1[i] + 2.0 * k2[i] + 2.0 * k3[i] + k4[i])).max(0.0);
    }
    x_new
}

/// RK4 step for the variational equation dδ/dt = J(t)·δ.
/// The Jacobian is frozen at the current state for the duration of the step.
fn rk4_variational_step(jac: &DMatrix<f64>, delta: &[f64; DIM], dt: f64) -> [f64; DIM] {
    let dv = DVector::from_column_slice(delta);

    let k1 = jac * &dv;
    let k2 = jac * (&dv + &k1 * (0.5 * dt));
    let k3 = jac * (&dv + &k2 * (0.5 * dt));
    let k4 = jac * (&dv + &k3 * dt);

    let result = &dv + (&k1 + &k2 * 2.0 + &k3 * 2.0 + &k4) * (dt / 6.0);
    let mut out = [0.0; DIM];
    for i in 0..DIM {
        out[i] = result[i];
    }
    out
}

// ---------------------------------------------------------------------
// THREE-PHASE PARTITION SIMULATION
// ---------------------------------------------------------------------

/// Results from the nonlinear partition simulation.
#[derive(Debug, Clone)]
pub struct NonlinearSimulationResult {
    pub time_series: TimeSeries,
    /// Pre-partition equilibrium values.
    pub steady_state: [f64; DIM],
    /// Index in time_series where warmup ends / partition begins.
    pub warmup_end_idx: usize,
    /// Index where partition ends / recovery begins.
    pub partition_end_idx: usize,
}

/// Run the three-phase nonlinear partition simulation.
///
/// Phase 1 (warmup): forward-evolve from x₀ to reach steady state x*.
/// Phase 2 (partition): activate partition, evolve.
/// Phase 3 (recovery): deactivate partition, optional burst, evolve.
pub fn nonlinear_partition_simulation(
    cfg: &HomeostaticConfig,
    rates: &BaseImpulseRates,
    x0: &[f64; DIM],
    partition_cfg: &PartitionConfig,
) -> NonlinearSimulationResult {
    let mut sys = NonlinearSystem::new(cfg, rates, partition_cfg);
    let dt = partition_cfg.dt;

    let mut times = Vec::new();
    let mut states = Vec::new();
    let mut x = *x0;
    let mut t = 0.0;

    // Phase 1: Warmup — reach steady state
    let n_warmup = (partition_cfg.warmup_duration / dt).ceil() as usize;
    for _ in 0..n_warmup {
        times.push(t);
        states.push(x);
        x = rk4_step(&sys, &x, dt);
        t += dt;
    }

    // Allow partition_onset delay before activating partition
    let n_onset = (partition_cfg.partition_onset / dt).ceil() as usize;
    for _ in 0..n_onset {
        times.push(t);
        states.push(x);
        x = rk4_step(&sys, &x, dt);
        t += dt;
    }

    let steady_state = x;
    let warmup_end_idx = states.len();

    // Phase 2: Partition active
    sys.set_partition(true);
    let n_partition = (partition_cfg.partition_duration / dt).ceil() as usize;
    for _ in 0..n_partition {
        times.push(t);
        states.push(x);
        x = rk4_step(&sys, &x, dt);
        t += dt;
    }
    let partition_end_idx = states.len();

    // Phase 3: Recovery
    sys.set_partition(false);
    if let Some(burst_mult) = partition_cfg.reconnection_burst {
        let burst_dur = 1.0 / cfg.lambda_bw; // one bandwidth time constant
        sys.activate_burst(burst_dur, burst_mult);
    }
    let n_recovery = (partition_cfg.recovery_observation / dt).ceil() as usize;
    for _ in 0..n_recovery {
        times.push(t);
        states.push(x);
        // Tick down burst timer
        if sys.burst_remaining > 0.0 {
            sys.burst_remaining = (sys.burst_remaining - dt).max(0.0);
            if sys.burst_remaining <= 0.0 {
                sys.burst_multiplier = 1.0;
            }
        }
        x = rk4_step(&sys, &x, dt);
        t += dt;
    }
    times.push(t);
    states.push(x);

    NonlinearSimulationResult {
        time_series: TimeSeries { times, states },
        steady_state,
        warmup_end_idx,
        partition_end_idx,
    }
}

// ---------------------------------------------------------------------
// LINEAR vs NONLINEAR COMPARISON
// ---------------------------------------------------------------------

/// Comparison metrics between the linearized and nonlinear trajectories.
#[derive(Debug, Clone)]
pub struct LinearNonlinearComparison {
    /// Time points (partition + recovery only, not warmup).
    pub times: Vec<f64>,
    /// Trajectory error: ‖x_nl(t) − x_lin(t)‖₂ at each time step.
    pub trajectory_error: Vec<f64>,
    /// Per-integral peak absolute difference.
    pub per_integral_peak_error: [f64; DIM],
    /// Time of peak error per integral.
    pub per_integral_peak_error_time: [f64; DIM],
    /// Max trajectory error over all time steps.
    pub max_trajectory_error: f64,
    /// Mean trajectory error.
    pub mean_trajectory_error: f64,
}

/// Run both linearized evolve() and nonlinear simulation from the same
/// steady-state initial condition and compare their partition trajectories.
pub fn compare_linear_nonlinear(
    cfg: &HomeostaticConfig,
    rates: &BaseImpulseRates,
    partition_cfg: &PartitionConfig,
) -> LinearNonlinearComparison {
    // 1. Run nonlinear simulation to get steady state and trajectory
    let nl_result = nonlinear_partition_simulation(cfg, rates, &[0.0; DIM], partition_cfg);
    let ss = nl_result.steady_state;

    // 2. Build the linearized system at the steady-state operating point
    let op = OperatingPoint { vals: ss };
    let j = build_jacobian(cfg, rates, &op);
    let partition_threat = ThreatProfile::network_partition(&j);

    // 3. Run linearized evolution from the steady state for the partition + recovery period
    let lin_duration = partition_cfg.partition_duration + partition_cfg.recovery_observation;
    let lin_ts = evolve(&j, &[partition_threat], &ss, lin_duration, partition_cfg.dt);

    // 4. Extract nonlinear trajectory for the same time window (post-warmup)
    let wi = nl_result.warmup_end_idx;
    let nl_states = &nl_result.time_series.states[wi..];
    let nl_times = &nl_result.time_series.times[wi..];

    // 5. Compute comparison metrics
    let n = lin_ts.times.len().min(nl_states.len());
    let mut times = Vec::with_capacity(n);
    let mut trajectory_error = Vec::with_capacity(n);
    let mut per_integral_peak_error = [0.0f64; DIM];
    let mut per_integral_peak_error_time = [0.0f64; DIM];

    for i in 0..n {
        let t = nl_times[i] - nl_times[0]; // relative time
        times.push(t);

        let mut err_sq = 0.0;
        for j_idx in 0..DIM {
            let diff = (nl_states[i][j_idx] - lin_ts.states[i][j_idx]).abs();
            err_sq += diff * diff;
            if diff > per_integral_peak_error[j_idx] {
                per_integral_peak_error[j_idx] = diff;
                per_integral_peak_error_time[j_idx] = t;
            }
        }
        trajectory_error.push(err_sq.sqrt());
    }

    let max_trajectory_error = trajectory_error.iter().copied().fold(0.0f64, f64::max);
    let mean_trajectory_error = if trajectory_error.is_empty() {
        0.0
    } else {
        trajectory_error.iter().sum::<f64>() / trajectory_error.len() as f64
    };

    LinearNonlinearComparison {
        times,
        trajectory_error,
        per_integral_peak_error,
        per_integral_peak_error_time,
        max_trajectory_error,
        mean_trajectory_error,
    }
}

// ---------------------------------------------------------------------
// MAXIMAL LYAPUNOV EXPONENT (BENETTIN'S METHOD)
// ---------------------------------------------------------------------

/// Result of the finite-time Lyapunov exponent computation.
#[derive(Debug, Clone)]
pub struct LyapunovResult {
    /// Maximal Lyapunov exponent μ₁.  Negative → stable through the transient.
    pub mu1: f64,
    /// Running estimate of μ₁ at each renormalization event: (time, μ₁_running).
    pub running_estimate: Vec<(f64, f64)>,
    /// Number of renormalization events.
    pub renorm_count: usize,
}

/// Compute the maximal finite-time Lyapunov exponent through the partition event.
///
/// Co-evolves a perturbation vector δx alongside the state trajectory using
/// the variational equation dδ/dt = Df(x(t))·δ.  Renormalization every
/// `renorm_interval` steps prevents overflow (Benettin et al., 1980).
///
/// μ₁ < 0 is the definitive nonlinear stability certificate.
pub fn compute_lyapunov_exponent(
    cfg: &HomeostaticConfig,
    rates: &BaseImpulseRates,
    partition_cfg: &PartitionConfig,
) -> LyapunovResult {
    let mut sys = NonlinearSystem::new(cfg, rates, partition_cfg);
    let dt = partition_cfg.dt;
    let renorm_interval: usize = 50; // every 2.5s

    // Warmup to steady state
    let mut x = [0.0; DIM];
    let n_warmup = (partition_cfg.warmup_duration / dt).ceil() as usize;
    for _ in 0..n_warmup {
        x = rk4_step(&sys, &x, dt);
    }

    // Initialize perturbation as unit vector in the S direction.
    // The asymptotic Lyapunov exponent is independent of initial direction.
    let mut delta = [0.0; DIM];
    delta[S] = 1.0;

    let mut lyap_sum = 0.0;
    let mut renorm_count = 0;
    let mut t = 0.0;
    let mut running_estimate = Vec::new();
    let mut step_count: usize = 0;

    // Phase 2: Partition
    sys.set_partition(true);
    let n_partition = (partition_cfg.partition_duration / dt).ceil() as usize;
    for _ in 0..n_partition {
        let jac = sys.instantaneous_jacobian(&x);
        delta = rk4_variational_step(&jac, &delta, dt);
        x = rk4_step(&sys, &x, dt);
        t += dt;
        step_count += 1;

        if step_count % renorm_interval == 0 {
            let norm: f64 = delta.iter().map(|d| d * d).sum::<f64>().sqrt();
            if norm > 0.0 {
                lyap_sum += norm.ln();
                renorm_count += 1;
                for d in &mut delta {
                    *d /= norm;
                }
                running_estimate.push((t, lyap_sum / t));
            }
        }
    }

    // Phase 3: Recovery
    sys.set_partition(false);
    if let Some(burst_mult) = partition_cfg.reconnection_burst {
        sys.activate_burst(1.0 / cfg.lambda_bw, burst_mult);
    }
    let n_recovery = (partition_cfg.recovery_observation / dt).ceil() as usize;
    for _ in 0..n_recovery {
        let jac = sys.instantaneous_jacobian(&x);
        delta = rk4_variational_step(&jac, &delta, dt);
        x = rk4_step(&sys, &x, dt);
        t += dt;
        step_count += 1;

        if sys.burst_remaining > 0.0 {
            sys.burst_remaining = (sys.burst_remaining - dt).max(0.0);
            if sys.burst_remaining <= 0.0 {
                sys.burst_multiplier = 1.0;
            }
        }

        if step_count % renorm_interval == 0 {
            let norm: f64 = delta.iter().map(|d| d * d).sum::<f64>().sqrt();
            if norm > 0.0 {
                lyap_sum += norm.ln();
                renorm_count += 1;
                for d in &mut delta {
                    *d /= norm;
                }
                running_estimate.push((t, lyap_sum / t));
            }
        }
    }

    let mu1 = if t > 0.0 { lyap_sum / t } else { 0.0 };

    LyapunovResult {
        mu1,
        running_estimate,
        renorm_count,
    }
}

// ---------------------------------------------------------------------
// PARTITION DURATION SENSITIVITY SWEEP
// ---------------------------------------------------------------------

/// One point in the partition duration sensitivity sweep.
#[derive(Debug, Clone)]
pub struct SweepPoint {
    /// Partition duration in seconds.
    pub duration: f64,
    /// Peak L2-norm displacement from pre-partition steady state.
    pub peak_displacement: f64,
    /// Per-integral peak displacement from steady state.
    pub per_integral_peak: [f64; DIM],
    /// Recovery time to return to 10% of peak displacement (seconds).
    pub recovery_time: f64,
    /// Per-integral recovery times (seconds, f64::INFINITY if never).
    pub per_integral_recovery: [f64; DIM],
    /// Maximal Lyapunov exponent for this partition duration.
    pub lyapunov_mu1: f64,
}

/// Sweep partition duration and compute stability metrics for each.
pub fn partition_duration_sweep(
    cfg: &HomeostaticConfig,
    rates: &BaseImpulseRates,
    durations: &[f64],
) -> Vec<SweepPoint> {
    durations
        .iter()
        .map(|&dur| {
            let mut pcfg = PartitionConfig::default();
            pcfg.partition_duration = dur;

            let result = nonlinear_partition_simulation(cfg, rates, &[0.0; DIM], &pcfg);
            let ss = result.steady_state;
            let wi = result.warmup_end_idx;

            // Compute peak displacement and per-integral metrics
            let mut peak_displacement = 0.0f64;
            let mut per_integral_peak = [0.0f64; DIM];
            let mut per_integral_peak_time = [0.0f64; DIM];

            for (idx, state) in result.time_series.states[wi..].iter().enumerate() {
                let t = result.time_series.times[wi + idx] - result.time_series.times[wi];
                let mut disp_sq = 0.0;
                for j in 0..DIM {
                    let diff = (state[j] - ss[j]).abs();
                    disp_sq += diff * diff;
                    if diff > per_integral_peak[j] {
                        per_integral_peak[j] = diff;
                        per_integral_peak_time[j] = t;
                    }
                }
                let disp = disp_sq.sqrt();
                if disp > peak_displacement {
                    peak_displacement = disp;
                }
            }

            // Recovery times: first time after peak where displacement < 10% of peak
            let mut per_integral_recovery = [f64::INFINITY; DIM];
            for j in 0..DIM {
                if per_integral_peak[j] < 1e-12 {
                    per_integral_recovery[j] = 0.0;
                    continue;
                }
                let threshold = per_integral_peak[j] * 0.1;
                let mut past_peak = false;
                for (idx, state) in result.time_series.states[wi..].iter().enumerate() {
                    let t = result.time_series.times[wi + idx] - result.time_series.times[wi];
                    let diff = (state[j] - ss[j]).abs();
                    if t >= per_integral_peak_time[j] {
                        past_peak = true;
                    }
                    if past_peak && diff < threshold {
                        per_integral_recovery[j] = t;
                        break;
                    }
                }
            }

            let global_recovery = per_integral_recovery.iter().copied().fold(0.0f64, f64::max);

            // Lyapunov exponent for this duration
            let lyap = compute_lyapunov_exponent(cfg, rates, &pcfg);

            SweepPoint {
                duration: dur,
                peak_displacement,
                per_integral_peak,
                recovery_time: global_recovery,
                per_integral_recovery,
                lyapunov_mu1: lyap.mu1,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------
// FULL REPORT
// ---------------------------------------------------------------------

/// Complete results of the nonlinear partition analysis.
#[derive(Debug, Clone)]
pub struct NonlinearPartitionReport {
    /// Pre-partition steady-state integral values.
    pub steady_state: [f64; DIM],
    /// Full nonlinear simulation result.
    pub simulation: NonlinearSimulationResult,
    /// Linear vs nonlinear comparison.
    pub comparison: LinearNonlinearComparison,
    /// Maximal finite-time Lyapunov exponent.
    pub lyapunov: LyapunovResult,
    /// Partition duration sensitivity sweep.
    pub sensitivity_sweep: Vec<SweepPoint>,
    /// Dyson convergence ratio (cross-reference).
    pub dyson_rho: f64,
}

/// Run the complete nonlinear partition analysis.
pub fn full_nonlinear_partition_analysis(cfg: &HomeostaticConfig) -> NonlinearPartitionReport {
    let rates = BaseImpulseRates::moderate();
    let pcfg = PartitionConfig::default();

    // 1. Nonlinear simulation
    let simulation = nonlinear_partition_simulation(cfg, &rates, &[0.0; DIM], &pcfg);
    let steady_state = simulation.steady_state;

    // 2. Linear vs nonlinear comparison
    let comparison = compare_linear_nonlinear(cfg, &rates, &pcfg);

    // 3. Lyapunov exponent
    let lyapunov = compute_lyapunov_exponent(cfg, &rates, &pcfg);

    // 4. Sensitivity sweep
    let durations = vec![5.0, 10.0, 20.0, 30.0, 60.0, 120.0];
    let sensitivity_sweep = partition_duration_sweep(cfg, &rates, &durations);

    // 5. Dyson convergence ratio for cross-reference (at idle, matching
    //    the original Dyson analysis which found ρ ≈ 1.30).
    // network_partition() always produces Some(coupling_delta) by construction.
    let op = OperatingPoint::idle();
    let j = build_jacobian(cfg, &rates, &op);
    let partition_threat = ThreatProfile::network_partition(&j);
    let dyson_rho = match partition_threat.coupling_delta.as_ref() {
        Some(v) => {
            let dyson = compute_dyson_terms(
                &j,
                v,
                partition_threat.onset,
                partition_threat.onset + partition_threat.duration,
            );
            dyson.convergence_ratio
        }
        None => 0.0, // structurally unreachable
    };

    NonlinearPartitionReport {
        steady_state,
        simulation,
        comparison,
        lyapunov,
        sensitivity_sweep,
        dyson_rho,
    }
}

/// Format the nonlinear partition report.
pub fn format_nonlinear_partition_report(report: &NonlinearPartitionReport) -> String {
    let mut out = String::new();
    out.push_str("\n═══════════════════════════════════════════════════════════════\n");
    out.push_str("    PHALANX NONLINEAR PARTITION ANALYSIS\n");
    out.push_str("═══════════════════════════════════════════════════════════════\n\n");

    // Cross-reference: why we need this
    out.push_str(&format!(
        "  Dyson convergence ratio ρ = {:.4} → linearization {}.\n",
        report.dyson_rho,
        if report.dyson_rho < 1.0 {
            "valid"
        } else {
            "INVALID — nonlinear analysis required"
        }
    ));
    out.push_str("\n");

    // Steady state
    out.push_str("━━━ Pre-Partition Steady State ━━━\n\n");
    out.push_str("  Integral    Value\n");
    out.push_str("  ─────────   ──────────\n");
    for j in 0..DIM {
        out.push_str(&format!(
            "  {:>9}   {:>10.4}\n",
            INTEGRAL_NAMES[j], report.steady_state[j]
        ));
    }
    out.push_str("\n");

    // Partition trajectory (peak displacement from steady state)
    let sim = &report.simulation;
    let ss = sim.steady_state;
    let wi = sim.warmup_end_idx;
    let _pi = sim.partition_end_idx;

    // Compute per-integral peaks during partition+recovery
    let mut peak_vals = [0.0f64; DIM];
    let mut peak_times = [0.0f64; DIM];
    let mut recovery_times = [f64::INFINITY; DIM];
    let t_base = sim.time_series.times[wi];

    for (idx, state) in sim.time_series.states[wi..].iter().enumerate() {
        let t = sim.time_series.times[wi + idx] - t_base;
        for j in 0..DIM {
            let diff = (state[j] - ss[j]).abs();
            if diff > peak_vals[j] {
                peak_vals[j] = diff;
                peak_times[j] = t;
            }
        }
    }
    // Recovery: first time after peak where diff < 10% of peak
    for j in 0..DIM {
        if peak_vals[j] < 1e-12 {
            recovery_times[j] = 0.0;
            continue;
        }
        let threshold = peak_vals[j] * 0.1;
        let mut past_peak = false;
        for (idx, state) in sim.time_series.states[wi..].iter().enumerate() {
            let t = sim.time_series.times[wi + idx] - t_base;
            if t >= peak_times[j] {
                past_peak = true;
            }
            if past_peak && (state[j] - ss[j]).abs() < threshold {
                recovery_times[j] = t;
                break;
            }
        }
    }

    out.push_str("━━━ Nonlinear Partition Response (20s partition) ━━━\n\n");
    out.push_str("  Integral   Peak Δ from SS   Peak Time   Recovery Time\n");
    out.push_str("  ─────────  ──────────────   ─────────   ─────────────\n");
    for j in 0..DIM {
        let rec_str = if recovery_times[j].is_infinite() {
            "never".to_string()
        } else {
            format!("{:.2}s", recovery_times[j])
        };
        out.push_str(&format!(
            "  {:>9}  {:>14.4}   {:>9.2}s   {:>13}\n",
            INTEGRAL_NAMES[j], peak_vals[j], peak_times[j], rec_str
        ));
    }
    out.push_str("\n");

    // Linear vs nonlinear comparison
    let comp = &report.comparison;
    out.push_str("━━━ Linear vs Nonlinear Comparison ━━━\n\n");
    out.push_str(&format!(
        "  Max trajectory error:  {:.4}\n",
        comp.max_trajectory_error
    ));
    out.push_str(&format!(
        "  Mean trajectory error: {:.4}\n\n",
        comp.mean_trajectory_error
    ));
    out.push_str("  Integral   Peak |x_nl − x_lin|   Time\n");
    out.push_str("  ─────────  ───────────────────   ─────────\n");
    for j in 0..DIM {
        out.push_str(&format!(
            "  {:>9}  {:>19.4}   {:>9.2}s\n",
            INTEGRAL_NAMES[j],
            comp.per_integral_peak_error[j],
            comp.per_integral_peak_error_time[j]
        ));
    }
    out.push_str("\n");

    // Lyapunov exponent
    let lyap = &report.lyapunov;
    out.push_str("━━━ Maximal Lyapunov Exponent ━━━\n\n");
    out.push_str(&format!(
        "  μ₁ = {:.6}  →  {}\n",
        lyap.mu1,
        if lyap.mu1 < 0.0 {
            "STABLE (perturbations decay through the partition transient)"
        } else {
            "UNSTABLE (perturbations grow during the partition event)"
        }
    ));
    out.push_str(&format!(
        "  Renormalization events: {}\n\n",
        lyap.renorm_count
    ));

    // Sensitivity sweep
    out.push_str("━━━ Partition Duration Sensitivity ━━━\n\n");
    out.push_str("  Duration   Peak Δ‖x‖₂   Recovery     μ₁\n");
    out.push_str("  ────────   ──────────   ────────   ──────────\n");
    for pt in &report.sensitivity_sweep {
        let rec_str = if pt.recovery_time.is_infinite() {
            "never".to_string()
        } else {
            format!("{:.1}s", pt.recovery_time)
        };
        out.push_str(&format!(
            "  {:>6.0}s    {:>10.4}   {:>8}   {:>10.6}\n",
            pt.duration, pt.peak_displacement, rec_str, pt.lyapunov_mu1
        ));
    }
    out.push_str("\n");

    // Summary verdict
    out.push_str("━━━ Summary ━━━\n\n");
    let all_recover = recovery_times.iter().all(|r| r.is_finite());
    let stable = lyap.mu1 < 0.0;
    if all_recover && stable {
        out.push_str(
            "  VERDICT: The system is nonlinearly stable through the network partition.\n",
        );
        out.push_str(&format!(
            "  All 8 integrals recover to steady state.  μ₁ = {:.6} < 0.\n",
            lyap.mu1
        ));
        out.push_str("  The Dyson divergence (ρ > 1) reflects the breakdown of LINEARIZATION,\n");
        out.push_str("  not the breakdown of STABILITY.\n");
    } else if !all_recover {
        out.push_str("  WARNING: Not all integrals recovered from the partition.\n");
        for j in 0..DIM {
            if recovery_times[j].is_infinite() {
                out.push_str(&format!("    {} did not recover\n", INTEGRAL_NAMES[j]));
            }
        }
    } else {
        out.push_str(&format!(
            "  WARNING: μ₁ = {:.6} > 0 — perturbations grow during the partition.\n",
            lyap.mu1
        ));
    }

    out.push_str("\n═══════════════════════════════════════════════════════════════\n");
    out
}

// =====================================================================
// SPECTRAL GAP & EIGENVECTOR ORTHOGONALITY ANALYSIS
// =====================================================================
//
// Fourth layer of the stability proof.  The eigenvalue analysis tells us
// *that* the system is stable; the spectral gap and eigenvector geometry
// tell us *how robustly* stable it is.
//
//   γ₁  = |Re(λ_dominant)|        — distance from the instability boundary
//   κ(V) = σ_max(V)/σ_min(V)     — worst-case transient amplification bound
//   r(J) = min_ω σ_min(iωI − J)  — smallest perturbation that destabilizes
//   δ_H  = √(‖J‖²_F − Σ|λ|²)    — Henrici departure from normality
//
// Together with the Lyapunov exponent μ₁ < 0 from the nonlinear analysis,
// these quantities constitute a mathematically complete robustness certificate.

/// Per-scenario spectral gap and eigenvector analysis.
pub struct SpectralGapReport {
    /// Label for this analysis scenario.
    pub scenario: String,
    /// Eigenvalues sorted by |Re(λ)| ascending (dominant / slowest mode first).
    pub eigenvalues_sorted: Vec<Complex<f64>>,
    /// Absolute spectral gap: |Re(λ_dominant)|.  Distance from instability.
    pub spectral_gap_gamma1: f64,
    /// Modal gap: |Re(λ₂)| − |Re(λ₁)|.  Separation between two slowest modes.
    pub spectral_gap_gamma2: f64,
    /// Dimensionless spectral gap ratio γ₂/γ₁.
    pub spectral_gap_ratio: f64,
    /// Real eigenvector matrix V ∈ ℝ^{DIM×DIM}.
    /// For complex conjugate pairs the real part of the eigenvector is stored.
    pub eigenvector_matrix: DMatrix<f64>,
    /// Gram matrix Vᵀ V.  Identity iff eigenvectors are orthonormal.
    pub gram_matrix: DMatrix<f64>,
    /// Condition number κ(V) = σ_max(V)/σ_min(V).
    /// Bounds transient amplification: ‖e^{Jt}‖ ≤ κ(V)·e^{αt}.
    pub eigenvector_condition_number: f64,
    /// Henrici departure from normality √(‖J‖²_F − Σ|λ_k|²).
    /// Zero iff J is normal.
    pub henrici_departure: f64,
    /// Stability radius r(J) = min_ω σ_min(iωI − J).
    /// Smallest operator-norm perturbation that can destabilize.
    pub stability_radius: f64,
    /// Frequency ω* where the stability radius minimum is attained.
    pub stability_radius_omega: f64,
    /// Time after which exponential decay dominates transient growth:
    /// t_decay = ln(κ(V)) / γ₁.
    pub guaranteed_decay_time: f64,
    /// Frobenius norm of the Jacobian, for reference.
    pub jacobian_frobenius: f64,
}

/// Aggregate report across multiple operating scenarios.
pub struct FullSpectralReport {
    /// Per-scenario results.
    pub scenarios: Vec<SpectralGapReport>,
    /// Human-readable combined robustness certificate.
    pub combined_certificate: String,
    /// Worst (smallest) γ₁ across all scenarios.
    pub worst_gamma1: f64,
    /// Worst (smallest) stability radius across all scenarios.
    pub worst_stability_radius: f64,
    /// Worst (largest) eigenvector condition number across all scenarios.
    pub worst_condition_number: f64,
    /// Maximal Lyapunov exponent from nonlinear partition analysis, if computed.
    pub lyapunov_mu1: Option<f64>,
}

// ----- eigenvector computation via SVD null-space -----

/// Compute real eigenvectors for the DIM×DIM Jacobian.
///
/// nalgebra 0.33 does not expose eigenvectors for non-symmetric matrices.
/// For each eigenvalue λ_k we extract the null space of (J − λ_k I) via SVD:
///
///   Real λ:    v = right-singular vector of (J − λI) with smallest σ.
///   Complex λ: Compute (J − aI)² + b²I  where a = Re(λ), b = Im(λ).
///              The two right-singular vectors with smallest σ span the real
///              2-D invariant subspace.  We take the first for the eigenvalue
///              with Im(λ) > 0 and skip the conjugate.
///
/// Returns a DIM×DIM matrix whose columns are the (real) eigenvectors.
fn compute_eigenvectors(jacobian: &DMatrix<f64>, eigenvalues: &[Complex<f64>]) -> DMatrix<f64> {
    let n = jacobian.nrows();
    let identity = DMatrix::<f64>::identity(n, n);
    let mut vectors = DMatrix::<f64>::zeros(n, n);
    let mut col = 0;
    let mut skip_conjugate = false;

    for eig in eigenvalues.iter() {
        if skip_conjugate {
            skip_conjugate = false;
            // Still place a vector for this column — use the second invariant
            // subspace vector stored from the previous iteration.
            // (handled below via the copy from the complex branch)
            continue;
        }

        if eig.im.abs() < 1e-12 {
            // Real eigenvalue — null space of (J − λI).
            // For repeated eigenvalues the null space is ≥ 2-D; we pick the
            // direction most independent from already-placed columns (deflation).
            let shifted = jacobian - &identity * eig.re;
            let svd = shifted.svd(true, true);
            if let Some(ref v_t) = svd.v_t {
                let last = v_t.nrows() - 1;
                let svals = &svd.singular_values;
                let s_max = svals[0].max(1e-15);
                let threshold = s_max * 1e-6;

                // Scan from smallest σ upward to find all null-space rows
                let mut best_row = last;
                let mut best_independence = -1.0_f64;

                for k in (0..v_t.nrows()).rev() {
                    if svals[k] > threshold && k != last {
                        break;
                    }
                    // Measure independence from previously placed vectors
                    let mut min_indep = 1.0_f64;
                    for prev in 0..col {
                        let mut dot = 0.0_f64;
                        for r in 0..n {
                            dot += v_t[(k, r)] * vectors[(r, prev)];
                        }
                        min_indep = min_indep.min(1.0 - dot.abs());
                    }
                    if min_indep > best_independence {
                        best_independence = min_indep;
                        best_row = k;
                    }
                }

                for r in 0..n {
                    vectors[(r, col)] = v_t[(best_row, r)];
                }
            }
            col += 1;
        } else if eig.im > 0.0 {
            // Complex conjugate pair — real invariant subspace via
            // (J − aI)² + b²I whose null space is the 2-D real subspace.
            let a = eig.re;
            let b = eig.im;
            let shifted = jacobian - &identity * a;
            let kernel_mat = &shifted * &shifted + &identity * (b * b);
            let svd = kernel_mat.svd(true, true);
            if let Some(ref v_t) = svd.v_t {
                let last = v_t.nrows() - 1;
                // First vector of the 2-D subspace
                for r in 0..n {
                    vectors[(r, col)] = v_t[(last, r)];
                }
                // Second vector of the 2-D subspace
                if col + 1 < n && last >= 1 {
                    for r in 0..n {
                        vectors[(r, col + 1)] = v_t[(last - 1, r)];
                    }
                }
            }
            col += 2;
            skip_conjugate = true;
        }
        // Negative imaginary conjugate is skipped via the flag.
    }

    vectors
}

// ----- stability radius via real block-matrix trick -----

/// Compute the stability radius r(J) = min_ω σ_min(iωI − J).
///
/// Uses the real block-matrix equivalence:
///   σ_min(iωI − J) = σ_min( M(ω) )
/// where
///   M(ω) = [[ −J,  −ωI ],
///            [ ωI,  −J  ]]   ∈ ℝ^{2n × 2n}
///
/// Three-stage refinement:
///   1. Coarse:     ω ∈ [0, 10] step 0.5       (21 points)
///   2. Fine:       ±0.5 around best, step 0.05 (~20 points)
///   3. Ultra-fine: ±0.05 around best, step 0.005 (~20 points)
fn stability_radius(jacobian: &DMatrix<f64>) -> (f64, f64) {
    let n = jacobian.nrows();
    let neg_j = jacobian * -1.0;

    let sigma_min_at = |omega: f64| -> f64 {
        // Build 2n × 2n block matrix
        let mut block = DMatrix::<f64>::zeros(2 * n, 2 * n);
        // Top-left: −J
        for r in 0..n {
            for c in 0..n {
                block[(r, c)] = neg_j[(r, c)];
            }
        }
        // Top-right: −ωI
        for i in 0..n {
            block[(i, n + i)] = -omega;
        }
        // Bottom-left: ωI
        for i in 0..n {
            block[(n + i, i)] = omega;
        }
        // Bottom-right: −J
        for r in 0..n {
            for c in 0..n {
                block[(n + r, n + c)] = neg_j[(r, c)];
            }
        }
        let svd = block.svd(false, false);
        svd.singular_values
            .iter()
            .cloned()
            .fold(f64::INFINITY, f64::min)
    };

    // Stage 1: coarse scan
    let mut best_omega = 0.0_f64;
    let mut best_sigma = f64::INFINITY;
    let mut omega = 0.0_f64;
    while omega <= 10.0 {
        let s = sigma_min_at(omega);
        if s < best_sigma {
            best_sigma = s;
            best_omega = omega;
        }
        omega += 0.5;
    }

    // Stage 2: fine scan around best coarse
    let lo = (best_omega - 0.5).max(0.0);
    let hi = best_omega + 0.5;
    omega = lo;
    while omega <= hi {
        let s = sigma_min_at(omega);
        if s < best_sigma {
            best_sigma = s;
            best_omega = omega;
        }
        omega += 0.05;
    }

    // Stage 3: ultra-fine scan
    let lo = (best_omega - 0.05).max(0.0);
    let hi = best_omega + 0.05;
    omega = lo;
    while omega <= hi {
        let s = sigma_min_at(omega);
        if s < best_sigma {
            best_sigma = s;
            best_omega = omega;
        }
        omega += 0.005;
    }

    (best_sigma, best_omega)
}

// ----- main analysis entry point -----

/// analyze spectral gap, eigenvector orthogonality, and stability radius
/// for a single operating scenario.
pub fn analyze_spectral_gap(
    scenario: &str,
    cfg: &HomeostaticConfig,
    rates: &BaseImpulseRates,
    op: &OperatingPoint,
) -> SpectralGapReport {
    let jacobian = build_jacobian(cfg, rates, op);
    let raw_eigs = jacobian.complex_eigenvalues();
    let mut eigs: Vec<Complex<f64>> = raw_eigs.iter().cloned().collect();

    // Sort by |Re(λ)| ascending — dominant (slowest) mode first.
    eigs.sort_by(|a, b| {
        a.re.abs()
            .partial_cmp(&b.re.abs())
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    // Spectral gap
    let gamma1 = eigs[0].re.abs();
    let gamma2 = if eigs.len() > 1 {
        eigs[1].re.abs() - eigs[0].re.abs()
    } else {
        0.0
    };
    let gap_ratio = if gamma1 > 1e-15 { gamma2 / gamma1 } else { 0.0 };

    // Eigenvectors
    let eigvecs = compute_eigenvectors(&jacobian, &eigs);
    let gram = eigvecs.transpose() * &eigvecs;

    // Condition number of eigenvector matrix
    let svd_v = eigvecs.clone().svd(false, false);
    let svals = &svd_v.singular_values;
    let sigma_max = svals.iter().cloned().fold(0.0_f64, f64::max);
    let sigma_min = svals.iter().cloned().fold(f64::INFINITY, f64::min);
    let kappa = if sigma_min > 1e-15 {
        sigma_max / sigma_min
    } else {
        f64::INFINITY
    };

    // Henrici departure from normality: δ_H = √(‖J‖²_F − Σ|λ_k|²)
    let frob_sq: f64 = jacobian.iter().map(|x| x * x).sum();
    let eig_norm_sq: f64 = eigs
        .iter()
        .map(|lam| lam.re * lam.re + lam.im * lam.im)
        .sum();
    let henrici_raw = frob_sq - eig_norm_sq;
    // Clamp to zero — floating-point can produce tiny negatives for near-normal matrices
    let henrici = if henrici_raw > 0.0 {
        henrici_raw.sqrt()
    } else {
        0.0
    };

    // Stability radius
    let (stab_rad, stab_omega) = stability_radius(&jacobian);

    // Guaranteed decay time: ln(κ) / γ₁
    let decay_time = if gamma1 > 1e-15 {
        kappa.ln() / gamma1
    } else {
        f64::INFINITY
    };

    SpectralGapReport {
        scenario: scenario.to_string(),
        eigenvalues_sorted: eigs,
        spectral_gap_gamma1: gamma1,
        spectral_gap_gamma2: gamma2,
        spectral_gap_ratio: gap_ratio,
        eigenvector_matrix: eigvecs,
        gram_matrix: gram,
        eigenvector_condition_number: kappa,
        henrici_departure: henrici,
        stability_radius: stab_rad,
        stability_radius_omega: stab_omega,
        guaranteed_decay_time: decay_time,
        jacobian_frobenius: frob_sq.sqrt(),
    }
}

// ----- 7-scenario sweep -----

/// Run spectral gap analysis across seven operating scenarios that span the
/// full range from idle to near-critical under light to heavy load.
pub fn full_spectral_analysis(cfg: &HomeostaticConfig) -> FullSpectralReport {
    let scenarios: Vec<(&str, BaseImpulseRates, OperatingPoint)> = vec![
        (
            "idle + light traffic",
            BaseImpulseRates::light(),
            OperatingPoint::idle(),
        ),
        (
            "idle + moderate traffic",
            BaseImpulseRates::moderate(),
            OperatingPoint::idle(),
        ),
        (
            "idle + heavy traffic",
            BaseImpulseRates::heavy(),
            OperatingPoint::idle(),
        ),
        (
            "half-critical + moderate traffic",
            BaseImpulseRates::moderate(),
            OperatingPoint::half_critical(cfg),
        ),
        (
            "near-critical + moderate traffic",
            BaseImpulseRates::moderate(),
            OperatingPoint::near_critical(cfg),
        ),
        (
            "half-critical + heavy traffic",
            BaseImpulseRates::heavy(),
            OperatingPoint::half_critical(cfg),
        ),
        (
            "near-critical + heavy traffic",
            BaseImpulseRates::heavy(),
            OperatingPoint::near_critical(cfg),
        ),
    ];

    let results: Vec<SpectralGapReport> = scenarios
        .iter()
        .map(|(name, rates, op)| analyze_spectral_gap(name, cfg, rates, op))
        .collect();

    let worst_g1 = results
        .iter()
        .map(|r| r.spectral_gap_gamma1)
        .fold(f64::INFINITY, f64::min);
    let worst_rad = results
        .iter()
        .map(|r| r.stability_radius)
        .fold(f64::INFINITY, f64::min);
    let worst_kappa = results
        .iter()
        .map(|r| r.eigenvector_condition_number)
        .fold(0.0_f64, f64::max);

    // Compute the nonlinear Lyapunov exponent so the certificate is self-contained.
    let lyap = compute_lyapunov_exponent(
        cfg,
        &BaseImpulseRates::moderate(),
        &PartitionConfig::default(),
    );
    let mu1 = lyap.mu1;

    let cert = build_combined_certificate(&results, worst_g1, worst_rad, worst_kappa, Some(mu1));

    FullSpectralReport {
        scenarios: results,
        combined_certificate: cert,
        worst_gamma1: worst_g1,
        worst_stability_radius: worst_rad,
        worst_condition_number: worst_kappa,
        lyapunov_mu1: Some(mu1),
    }
}

fn build_combined_certificate(
    results: &[SpectralGapReport],
    worst_g1: f64,
    worst_rad: f64,
    worst_kappa: f64,
    lyapunov_mu1: Option<f64>,
) -> String {
    let mut out = String::new();
    out.push_str("COMBINED ROBUSTNESS CERTIFICATE\n");
    out.push_str("===============================\n\n");

    // Layer 1: eigenvalue stability
    let all_stable = results.iter().all(|r| r.spectral_gap_gamma1 > 0.0);
    out.push_str(&format!(
        "  [{}] Eigenvalue stability:  all Re(λ) < 0 across {} scenarios\n",
        if all_stable { "PASS" } else { "FAIL" },
        results.len()
    ));
    out.push_str(&format!("       worst spectral gap γ₁ = {:.6}\n", worst_g1));

    // Layer 2: spectral gap
    out.push_str(&format!(
        "  [{}] Spectral gap:  γ₁ = {:.6} — system is {:.1}× from instability boundary\n",
        if worst_g1 > 0.01 { "PASS" } else { "WARN" },
        worst_g1,
        worst_g1 / 0.01
    ));

    // Layer 3: stability radius
    out.push_str(&format!(
        "  [{}] Stability radius:  r(J) = {:.6}\n",
        if worst_rad > 0.0 { "PASS" } else { "FAIL" },
        worst_rad
    ));
    out.push_str(&format!(
        "       perturbation must exceed r(J) in operator norm to destabilize\n"
    ));

    // Layer 4: eigenvector conditioning
    let worst_decay = results
        .iter()
        .map(|r| r.guaranteed_decay_time)
        .fold(0.0_f64, f64::max);
    out.push_str(&format!(
        "  [{}] Eigenvector conditioning:  κ(V) = {:.4}\n",
        if worst_kappa < 1000.0 { "PASS" } else { "WARN" },
        worst_kappa
    ));
    out.push_str(&format!("       transient amplification bounded by κ(V)\n"));
    out.push_str(&format!(
        "       guaranteed decay dominance after t = {:.2}s\n",
        worst_decay
    ));

    // Layer 5: nonlinear certificate (computed, not hardcoded)
    match lyapunov_mu1 {
        Some(mu1) if mu1 < 0.0 => {
            out.push_str(&format!(
                "  [PASS] Nonlinear Lyapunov:  μ₁ = {:.6} < 0  (from partition analysis)\n",
                mu1
            ));
            out.push_str("         system is Lyapunov-stable through worst-case transient\n");
        }
        Some(mu1) => {
            out.push_str(&format!(
                "  [FAIL] Nonlinear Lyapunov:  μ₁ = {:.6} ≥ 0  (UNSTABLE through partition!)\n",
                mu1
            ));
        }
        None => {
            out.push_str("  [????] Nonlinear Lyapunov:  not computed\n");
        }
    }

    out.push_str("\n");
    let lyapunov_stable = lyapunov_mu1.map_or(false, |mu| mu < 0.0);
    if all_stable && worst_rad > 0.0 && worst_kappa < f64::INFINITY && lyapunov_stable {
        out.push_str("  VERDICT: The 8-integral Volterra feedback system possesses a\n");
        out.push_str("  mathematically complete stability certificate across all four layers.\n");
        out.push_str("  No perturbation within the stability radius can induce failure.\n");
    }

    out
}

// ----- report formatting -----

/// Format the full spectral analysis into a human-readable report.
pub fn format_spectral_report(report: &FullSpectralReport) -> String {
    let mut out = String::new();

    out.push_str("\n═══════════════════════════════════════════════════════════════\n");
    out.push_str("       SPECTRAL GAP & EIGENVECTOR ORTHOGONALITY ANALYSIS\n");
    out.push_str("═══════════════════════════════════════════════════════════════\n\n");

    // Per-scenario table
    out.push_str("┌─────────────────────────────────────┬────────┬────────┬──────────┬────────┬────────┬─────────┐\n");
    out.push_str("│ Scenario                            │   γ₁   │   γ₂   │   κ(V)   │  δ_H   │  r(J)  │ t_decay │\n");
    out.push_str("├─────────────────────────────────────┼────────┼────────┼──────────┼────────┼────────┼─────────┤\n");

    for s in &report.scenarios {
        out.push_str(&format!(
            "│ {:<35} │ {:6.4} │ {:6.4} │ {:8.2} │ {:6.4} │ {:6.4} │ {:5.2}s  │\n",
            s.scenario,
            s.spectral_gap_gamma1,
            s.spectral_gap_gamma2,
            s.eigenvector_condition_number,
            s.henrici_departure,
            s.stability_radius,
            s.guaranteed_decay_time,
        ));
    }

    out.push_str("└─────────────────────────────────────┴────────┴────────┴──────────┴────────┴────────┴─────────┘\n\n");

    // Worst-case summary
    out.push_str("Worst-case across all scenarios:\n");
    out.push_str(&format!(
        "  Smallest spectral gap:        γ₁ = {:.6}\n",
        report.worst_gamma1
    ));
    out.push_str(&format!(
        "  Smallest stability radius:    r(J) = {:.6}\n",
        report.worst_stability_radius
    ));
    out.push_str(&format!(
        "  Largest condition number:      κ(V) = {:.4}\n",
        report.worst_condition_number
    ));

    // Eigenvalue detail for first scenario (idle + light)
    if let Some(first) = report.scenarios.first() {
        out.push_str(&format!(
            "\nEigenvalue spectrum ({}), sorted by |Re(λ)|:\n",
            first.scenario
        ));
        for (i, lam) in first.eigenvalues_sorted.iter().enumerate() {
            let label = if i < INTEGRAL_NAMES.len() {
                INTEGRAL_NAMES[i]
            } else {
                "?"
            };
            if lam.im.abs() < 1e-12 {
                out.push_str(&format!(
                    "  λ_{} = {:.6}          (mode {})\n",
                    i, lam.re, label
                ));
            } else {
                out.push_str(&format!(
                    "  λ_{} = {:.6} ± {:.6}i  (mode {})\n",
                    i,
                    lam.re,
                    lam.im.abs(),
                    label
                ));
            }
        }

        out.push_str("\nGram matrix Vᵀ V (identity = perfect orthogonality):\n");
        let g = &first.gram_matrix;
        for r in 0..g.nrows() {
            out.push_str("  [");
            for c in 0..g.ncols() {
                if c > 0 {
                    out.push_str(", ");
                }
                out.push_str(&format!("{:7.4}", g[(r, c)]));
            }
            out.push_str("]\n");
        }
        out.push_str(&format!(
            "\n  Henrici departure δ_H = {:.6}  (0 = perfectly normal)\n",
            first.henrici_departure
        ));
        out.push_str(&format!("  ‖J‖_F = {:.6}\n", first.jacobian_frobenius));
    }

    out.push_str("\n───────────────────────────────────────────────────────────────\n");
    out.push_str(&report.combined_certificate);
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
        // Shout out to Dr. Turc for forcing me to learn this shit.
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

    // =================================================================
    // NONLINEAR PARTITION TESTS
    // =================================================================

    #[test]
    fn test_nonlinear_rhs_at_origin() {
        // At x = [0; 8], all scalers = 1.0, endowment_frac = 1.0.
        // All impulse rates should be positive, so rhs = f(0) ≥ 0.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let pcfg = PartitionConfig::default();
        let sys = NonlinearSystem::new(&cfg, &rates, &pcfg);
        let x = [0.0; DIM];
        let dx = sys.rhs(&x);
        println!("  rhs at origin:");
        for j in 0..DIM {
            println!("    {}: {:.6}", INTEGRAL_NAMES[j], dx[j]);
            assert!(
                dx[j] >= 0.0,
                "rhs[{}] = {} should be non-negative at origin",
                INTEGRAL_NAMES[j],
                dx[j]
            );
        }
    }

    #[test]
    fn test_nonlinear_steady_state_exists() {
        // Forward simulation from the origin should converge to a positive
        // steady state where ||rhs(x*)|| < threshold.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let pcfg = PartitionConfig::default();
        let sys = NonlinearSystem::new(&cfg, &rates, &pcfg);
        let dt = 0.05;
        let mut x = [0.0; DIM];
        for _ in 0..(120.0 / dt) as usize {
            x = rk4_step(&sys, &x, dt);
        }
        let dx = sys.rhs(&x);
        let norm: f64 = dx.iter().map(|d| d * d).sum::<f64>().sqrt();

        println!("  Steady state after 120s warmup:");
        for j in 0..DIM {
            println!(
                "    {}: {:.6}  (dI/dt = {:.2e})",
                INTEGRAL_NAMES[j], x[j], dx[j]
            );
        }
        println!("  ||rhs(x*)|| = {:.2e}", norm);

        assert!(
            norm < 1e-4,
            "Failed to reach steady state: ||rhs|| = {:.2e}",
            norm
        );
        for j in 0..DIM {
            assert!(
                x[j] >= 0.0,
                "Steady state x[{}] = {} is negative",
                INTEGRAL_NAMES[j],
                x[j]
            );
        }
    }

    #[test]
    fn test_nonlinear_matches_jacobian_at_operating_point() {
        // The finite-difference Jacobian should match the analytic build_jacobian()
        // at the same operating point (within tolerance of the FD approximation).
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let op = OperatingPoint::half_critical(&cfg);
        let pcfg = PartitionConfig::default();
        let sys = NonlinearSystem::new(&cfg, &rates, &pcfg);

        let j_analytic = build_jacobian(&cfg, &rates, &op);
        let j_numeric = sys.instantaneous_jacobian(&op.vals);

        let err = (&j_analytic - &j_numeric).norm();
        let rel_err = err / j_analytic.norm();

        println!("  Analytic vs numeric Jacobian at half-critical:");
        println!("    ||J_analytic - J_numeric|| = {:.2e}", err);
        println!("    Relative error = {:.2e}", rel_err);

        // Print the largest discrepancies
        let mut max_diff = 0.0f64;
        let mut max_i = 0;
        let mut max_j = 0;
        for i in 0..DIM {
            for j in 0..DIM {
                let diff = (j_analytic[(i, j)] - j_numeric[(i, j)]).abs();
                if diff > max_diff {
                    max_diff = diff;
                    max_i = i;
                    max_j = j;
                }
            }
        }
        println!(
            "    Max element diff at [{},{}]: analytic={:.6}, numeric={:.6}, diff={:.2e}",
            INTEGRAL_NAMES[max_i],
            INTEGRAL_NAMES[max_j],
            j_analytic[(max_i, max_j)],
            j_numeric[(max_i, max_j)],
            max_diff
        );

        // Use a generous tolerance because the analytic Jacobian linearizes
        // the throughput differently than the finite-difference approach
        // (the analytic version is a hand-derived partial derivative expansion;
        // the numeric version perturbs the full nonlinear rhs).  They should
        // agree closely but not exactly due to higher-order terms.
        assert!(
            rel_err < 0.05,
            "Numeric Jacobian disagrees with analytic: rel_err = {:.2e}",
            rel_err
        );
    }

    #[test]
    fn test_rk4_recovers_exponential_decay() {
        // For decoupled integrals with zero impulse, RK4 should match exp(-λ*t).
        // This is pure Dr. Somersalo here.
        let cfg = default_cfg();
        let mut rates = BaseImpulseRates::moderate();
        rates.u_d = 0.0; // zero I/O impulse for pure decay test
        rates.u_c = 0.0; // zero connection impulse
        let pcfg = PartitionConfig::default();
        let sys = NonlinearSystem::new(&cfg, &rates, &pcfg);
        let dt = 0.05;

        let mut x = [0.0; DIM];
        x[D] = 10.0;
        x[C] = 0.5;

        for step in 0..200 {
            x = rk4_step(&sys, &x, dt);
            let t = (step + 1) as f64 * dt;
            let expected_d = 10.0 * (-cfg.lambda_io * t).exp();
            let expected_c = 0.5 * (-cfg.lambda_conn * t).exp();
            assert!(
                (x[D] - expected_d).abs() < 1e-6,
                "RK4 d integral diverges at t={:.2}: got {:.6}, expected {:.6}",
                t,
                x[D],
                expected_d
            );
            assert!(
                (x[C] - expected_c).abs() < 1e-6,
                "RK4 c integral diverges at t={:.2}: got {:.6}, expected {:.6}",
                t,
                x[C],
                expected_c
            );
        }
        println!("  RK4 pure-decay accuracy verified over 200 steps (10s)");
    }

    #[test]
    fn test_partition_zeros_throughput() {
        // During full partition (network_fraction=1.0, local=0.0), T(x) = 0
        // at any state.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let mut pcfg = PartitionConfig::default();
        pcfg.network_fraction = 1.0;
        pcfg.local_capture_fraction = 0.0;
        let mut sys = NonlinearSystem::new(&cfg, &rates, &pcfg);
        sys.set_partition(true);

        // Test at origin (all scalers open)
        let x_origin = [0.0; DIM];
        assert!(
            sys.throughput(&x_origin).abs() < 1e-12,
            "Throughput should be 0 at origin during full partition, got {}",
            sys.throughput(&x_origin)
        );

        // Test at half-critical (scalers partially closed)
        let x_half = OperatingPoint::half_critical(&cfg).vals;
        assert!(
            sys.throughput(&x_half).abs() < 1e-12,
            "Throughput should be 0 at half-critical during full partition, got {}",
            sys.throughput(&x_half)
        );

        println!("  Full partition correctly zeros throughput at all states");
    }

    #[test]
    fn test_partition_recovery_nonlinear() {
        // The system should return to within 10% of steady state after
        // a 20s partition with 120s of recovery observation.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let pcfg = PartitionConfig::default();
        let result = nonlinear_partition_simulation(&cfg, &rates, &[0.0; DIM], &pcfg);

        let ss = result.steady_state;
        let final_state = result.time_series.states.last().unwrap();

        println!("  Partition recovery check (20s partition + 120s observation):");
        for j in 0..DIM {
            let diff = (final_state[j] - ss[j]).abs();
            let rel = if ss[j] > 1e-6 { diff / ss[j] } else { diff };
            println!(
                "    {}: ss={:.6}, final={:.6}, rel_err={:.4}",
                INTEGRAL_NAMES[j], ss[j], final_state[j], rel
            );
        }

        for j in 0..DIM {
            if ss[j] > 1e-6 {
                let rel_err = (final_state[j] - ss[j]).abs() / ss[j];
                assert!(
                    rel_err < 0.10,
                    "Integral {} did not recover: final={:.6}, ss={:.6}, rel_err={:.4}",
                    INTEGRAL_NAMES[j],
                    final_state[j],
                    ss[j],
                    rel_err
                );
            }
        }
    }

    #[test]
    fn test_lyapunov_exponent_negative() {
        // The Lyapunov exponent should be negative (stable) for the default
        // 20s partition scenario.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let pcfg = PartitionConfig::default();
        let lyap = compute_lyapunov_exponent(&cfg, &rates, &pcfg);

        println!("  Lyapunov exponent: μ₁ = {:.6}", lyap.mu1);
        println!("  Renormalization events: {}", lyap.renorm_count);
        if !lyap.running_estimate.is_empty() {
            println!("  Running estimate convergence:");
            for &(t, mu) in lyap
                .running_estimate
                .iter()
                .rev()
                .take(5)
                .collect::<Vec<_>>()
                .iter()
                .rev()
            {
                println!("    t={:.1}s: μ₁ = {:.6}", t, mu);
            }
        }

        assert!(
            lyap.mu1 < 0.0,
            "Lyapunov exponent should be negative for stable system, got μ₁ = {:.6}",
            lyap.mu1
        );
    }

    #[test]
    fn test_linear_nonlinear_divergence() {
        // The linearized model should have significant error during partition,
        // consistent with the Dyson divergence (ρ > 1).
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let pcfg = PartitionConfig::default();
        let comp = compare_linear_nonlinear(&cfg, &rates, &pcfg);

        println!("  Linear vs nonlinear comparison:");
        println!("    Max trajectory error: {:.4}", comp.max_trajectory_error);
        println!(
            "    Mean trajectory error: {:.4}",
            comp.mean_trajectory_error
        );
        println!("    Per-integral peak errors:");
        for j in 0..DIM {
            println!(
                "      {}: {:.4} at t={:.2}s",
                INTEGRAL_NAMES[j],
                comp.per_integral_peak_error[j],
                comp.per_integral_peak_error_time[j]
            );
        }

        // We expect measurable divergence since ρ > 1
        // Use a modest threshold since the linear model starts from the same
        // steady state but uses different dynamics
        assert!(
            comp.max_trajectory_error > 1e-3,
            "Expected measurable linear vs nonlinear divergence, got max_err = {:.6}",
            comp.max_trajectory_error
        );
    }

    #[test]
    fn test_sensitivity_sweep_monotonic() {
        // Longer partitions should produce larger peak displacements.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let durations = vec![5.0, 20.0, 60.0];
        let sweep = partition_duration_sweep(&cfg, &rates, &durations);

        println!("  Sensitivity sweep (peak displacement):");
        for pt in &sweep {
            println!(
                "    {}s: peak_Δ={:.4}, recovery={:.1}s, μ₁={:.6}",
                pt.duration, pt.peak_displacement, pt.recovery_time, pt.lyapunov_mu1
            );
        }

        for window in sweep.windows(2) {
            assert!(
                window[1].peak_displacement >= window[0].peak_displacement * 0.95,
                "Peak displacement should grow with duration: {:.4} ({}s) vs {:.4} ({}s)",
                window[0].peak_displacement,
                window[0].duration,
                window[1].peak_displacement,
                window[1].duration,
            );
        }
    }

    #[test]
    fn test_full_nonlinear_partition_analysis() {
        // Integration test: runs the complete nonlinear partition analysis
        // and prints the full report.
        let cfg = default_cfg();
        let report = full_nonlinear_partition_analysis(&cfg);
        let output = format_nonlinear_partition_report(&report);
        println!("{}", output);

        // Lyapunov should be negative (definitive stability certificate)
        assert!(
            report.lyapunov.mu1 < 0.0,
            "System is Lyapunov-unstable during partition! μ₁ = {:.6}",
            report.lyapunov.mu1
        );

        // Dyson rho should be > 1 (confirming why nonlinear analysis was needed)
        assert!(
            report.dyson_rho > 1.0,
            "Expected Dyson ρ > 1 for partition, got {:.4}",
            report.dyson_rho
        );

        // All integrals should show recovery in the steady-state comparison
        let ss = report.steady_state;
        let final_state = report.simulation.time_series.states.last().unwrap();
        for j in 0..DIM {
            if ss[j] > 1e-6 {
                let rel_err = (final_state[j] - ss[j]).abs() / ss[j];
                assert!(
                    rel_err < 0.10,
                    "Full analysis: integral {} did not recover (rel_err={:.4})",
                    INTEGRAL_NAMES[j],
                    rel_err
                );
            }
        }
    }

    // ----- spectral gap & eigenvector orthogonality tests -----

    #[test]
    fn test_eigenvectors_are_eigenvectors() {
        // For each computed eigenvector v_k, verify J·v_k ≈ λ_k·v_k.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let op = OperatingPoint::idle();
        let jacobian = build_jacobian(&cfg, &rates, &op);
        let eigs_raw = jacobian.complex_eigenvalues();
        let mut eigs: Vec<Complex<f64>> = eigs_raw.iter().cloned().collect();
        eigs.sort_by(|a, b| {
            a.re.abs()
                .partial_cmp(&b.re.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let eigvecs = compute_eigenvectors(&jacobian, &eigs);

        println!("  Eigenvector verification (J·v ≈ λ·v):");
        for k in 0..DIM {
            let v_col = eigvecs.column(k);
            let jv = &jacobian * &v_col;
            // For real eigenvalues, J·v = λ·v directly.
            // For complex pairs stored as real vectors, the residual is approximate.
            let lam_re = eigs[k].re;
            let lv = &v_col * lam_re;
            let residual_vec = &jv - &lv;
            let residual = residual_vec.norm();
            let v_norm = v_col.norm();
            let rel_residual = if v_norm > 1e-15 {
                residual / v_norm
            } else {
                residual
            };
            println!(
                "    mode {}: |J·v - λ·v|/|v| = {:.2e}  (λ = {:.6} + {:.6}i)",
                k, rel_residual, eigs[k].re, eigs[k].im
            );
            // For complex pairs the real-vector residual is O(|Im(λ)|) not O(ε),
            // so we only check real eigenvalues to machine precision.
            if eigs[k].im.abs() < 1e-10 {
                assert!(
                    rel_residual < 1e-8,
                    "Eigenvector {} has large residual: {:.2e}",
                    k,
                    rel_residual
                );
            }
        }
    }

    #[test]
    fn test_identity_orthogonal() {
        // For a diagonal (normal) matrix with distinct eigenvalues, eigenvectors
        // are the standard basis, κ(V) ≈ 1, and Henrici departure ≈ 0.
        // Use explicitly distinct values to avoid repeated-eigenvalue degeneracy.
        let mut diag_j = DMatrix::<f64>::zeros(DIM, DIM);
        let lambdas = [0.1, 0.2, 0.3, 0.5, 0.7, 1.0, 2.0, 4.0];
        for i in 0..DIM {
            diag_j[(i, i)] = -lambdas[i];
        }

        let eigs_raw = diag_j.complex_eigenvalues();
        let mut eigs: Vec<Complex<f64>> = eigs_raw.iter().cloned().collect();
        eigs.sort_by(|a, b| {
            a.re.abs()
                .partial_cmp(&b.re.abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let eigvecs = compute_eigenvectors(&diag_j, &eigs);
        let svd_v = eigvecs.svd(false, false);
        let svals = &svd_v.singular_values;
        let sigma_max = svals.iter().cloned().fold(0.0_f64, f64::max);
        let sigma_min = svals.iter().cloned().fold(f64::INFINITY, f64::min);
        let kappa = sigma_max / sigma_min;

        // Henrici departure
        let frob_sq: f64 = diag_j.iter().map(|x| x * x).sum();
        let eig_norm_sq: f64 = eigs
            .iter()
            .map(|lam| lam.re * lam.re + lam.im * lam.im)
            .sum();
        let henrici = (frob_sq - eig_norm_sq).max(0.0).sqrt();

        println!("  Diagonal (normal) matrix:");
        println!("    κ(V) = {:.6}", kappa);
        println!("    δ_H  = {:.6}", henrici);

        assert!(
            kappa < 2.0,
            "Diagonal matrix should have κ(V) ≈ 1, got {:.4}",
            kappa
        );
        assert!(
            henrici < 1e-10,
            "Diagonal matrix should have δ_H ≈ 0, got {:.2e}",
            henrici
        );
    }

    #[test]
    fn test_spectral_gap_positive() {
        // γ₁ > 0 at all three operating points — equivalent to stability
        // but verified through the spectral gap code path.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let ops = [
            ("idle", OperatingPoint::idle()),
            ("half-critical", OperatingPoint::half_critical(&cfg)),
            ("near-critical", OperatingPoint::near_critical(&cfg)),
        ];

        println!("  Spectral gap positivity:");
        for (name, op) in &ops {
            let report = analyze_spectral_gap(name, &cfg, &rates, op);
            println!(
                "    {}: γ₁ = {:.6}, γ₂ = {:.6}, ratio = {:.4}",
                name,
                report.spectral_gap_gamma1,
                report.spectral_gap_gamma2,
                report.spectral_gap_ratio,
            );
            assert!(
                report.spectral_gap_gamma1 > 0.0,
                "γ₁ should be positive at {}, got {:.6}",
                name,
                report.spectral_gap_gamma1
            );
        }
    }

    #[test]
    fn test_stability_radius_positive() {
        // r(J) > 0 at all operating points.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let ops = [
            ("idle", OperatingPoint::idle()),
            ("half-critical", OperatingPoint::half_critical(&cfg)),
            ("near-critical", OperatingPoint::near_critical(&cfg)),
        ];

        println!("  Stability radius:");
        for (name, op) in &ops {
            let jac = build_jacobian(&cfg, &rates, op);
            let (rad, omega_star) = stability_radius(&jac);
            println!("    {}: r(J) = {:.6}, ω* = {:.4}", name, rad, omega_star);
            assert!(
                rad > 0.0,
                "Stability radius should be positive at {}, got {:.6}",
                name,
                rad
            );
        }
    }

    #[test]
    fn test_henrici_zero_for_symmetric() {
        // For the symmetric part (J+Jᵀ)/2 — which is by definition normal —
        // the Henrici departure should be approximately zero.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let op = OperatingPoint::idle();
        let jacobian = build_jacobian(&cfg, &rates, &op);
        let jsym = (&jacobian + jacobian.transpose()) * 0.5;

        let eigs_raw = jsym.complex_eigenvalues();
        let eigs: Vec<Complex<f64>> = eigs_raw.iter().cloned().collect();

        let frob_sq: f64 = jsym.iter().map(|x| x * x).sum();
        let eig_norm_sq: f64 = eigs
            .iter()
            .map(|lam| lam.re * lam.re + lam.im * lam.im)
            .sum();
        let henrici = (frob_sq - eig_norm_sq).max(0.0).sqrt();

        println!("  Symmetric part Henrici departure: δ_H = {:.2e}", henrici);
        assert!(
            henrici < 1e-8,
            "Symmetric matrix should have δ_H ≈ 0, got {:.2e}",
            henrici
        );
    }

    #[test]
    fn test_condition_number_bounded() {
        // κ(V) should be reasonable (< 1000) for an 8×8 non-symmetric system.
        let cfg = default_cfg();
        let rates = BaseImpulseRates::moderate();
        let op = OperatingPoint::idle();
        let report = analyze_spectral_gap("idle", &cfg, &rates, &op);

        println!(
            "  Eigenvector condition number at idle: κ(V) = {:.4}",
            report.eigenvector_condition_number
        );
        println!(
            "  Guaranteed decay time: {:.2}s",
            report.guaranteed_decay_time
        );
        assert!(
            report.eigenvector_condition_number < 1000.0,
            "κ(V) unexpectedly large: {:.4}",
            report.eigenvector_condition_number
        );
        assert!(
            report.guaranteed_decay_time < 1000.0,
            "Decay time unexpectedly large: {:.2}s",
            report.guaranteed_decay_time
        );
    }

    #[test]
    fn test_full_spectral_analysis() {
        // Integration test: runs all 7 scenarios, prints the full report,
        // and verifies the key invariants.
        let cfg = default_cfg();
        let report = full_spectral_analysis(&cfg);
        let output = format_spectral_report(&report);
        println!("{}", output);

        // All scenarios should have positive spectral gap
        for s in &report.scenarios {
            assert!(
                s.spectral_gap_gamma1 > 0.0,
                "γ₁ should be positive for '{}', got {:.6}",
                s.scenario,
                s.spectral_gap_gamma1
            );
        }

        // All scenarios should have positive stability radius
        for s in &report.scenarios {
            assert!(
                s.stability_radius > 0.0,
                "r(J) should be positive for '{}', got {:.6}",
                s.scenario,
                s.stability_radius
            );
        }

        // Condition number should be finite across all scenarios
        assert!(
            report.worst_condition_number < f64::INFINITY,
            "κ(V) is infinite in some scenario"
        );

        // The combined certificate should contain PASS
        assert!(
            report.combined_certificate.contains("PASS"),
            "Certificate should contain at least one PASS"
        );

        println!("\n  All 7 scenarios passed spectral gap analysis");
        println!(
            "  Worst γ₁ = {:.6}, worst r(J) = {:.6}, worst κ(V) = {:.4}",
            report.worst_gamma1, report.worst_stability_radius, report.worst_condition_number
        );
    }
}
