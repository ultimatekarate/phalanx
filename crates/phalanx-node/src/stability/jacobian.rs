use crate::vitals::HomeostaticConfig;
use nalgebra::DMatrix;

use super::config::*;

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
    // ψ(e) = ψ_max / (1 + (k·e)²)  — quadratic denominator zeros derivative
    // at e=0, preserves half-endowment at e = 1/k, and improves Sybil defense.
    let e_val = op.vals[E];
    let ke = cfg.k_sybil * e_val;
    let endowment = cfg.psi_max / (1.0 + ke.powi(2));
    let dendowment_de =
        -cfg.psi_max * 2.0 * cfg.k_sybil.powi(2) * e_val / (1.0 + ke.powi(2)).powi(2);
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
    j[(M, S)] = rates.u_m * sigma_b * endowment_frac * sigma_m * dscaler(op.vals[S], cfg.s_crit);
    j[(M, E)] = rates.u_m * sigma_b * sigma_s * sigma_m * (dendowment_de / cfg.psi_max);
    j[(M, M)] = -cfg.lambda_mem
        + rates.u_m * sigma_b * sigma_s * endowment_frac * dscaler(op.vals[M], cfg.m_crit);
    // M-W coupling is zero: storage→memory rejection is threshold-activated
    // (fires only when W > 95% of w_crit), not proportional. The correct
    // linearization at all analyzed operating points is J[M,W] = 0.
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
