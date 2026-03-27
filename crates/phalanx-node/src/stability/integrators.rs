// crates/phalanx-node/src/stability/integrators.rs
//
// Numerical ODE integration: fixed-step RK4 and adaptive Dormand-Prince
// RK4(5) with PI step size control. Domain-independent except for the
// NonlinearSystem parameter type (provides rhs() evaluation).

use nalgebra::{DMatrix, DVector};

use super::config::DIM;
use super::nonlinear::NonlinearSystem;

// =====================================================================
// DORMAND-PRINCE RK4(5) BUTCHER TABLEAU
// =====================================================================
//
// Embedded 4th/5th order pair (Dormand & Prince 1980).  7 stages, FSAL.
// The 5th-order solution advances the state; the 4th-order solution
// provides the local error estimate for step size control.

// Node coefficients c_i (used implicitly via the a_ij coupling)
// c2 = 1/5, c3 = 3/10, c4 = 4/5, c5 = 8/9, c6 = 1, c7 = 1

// Coupling coefficients a_ij
const A21: f64 = 1.0 / 5.0;
const A31: f64 = 3.0 / 40.0;
const A32: f64 = 9.0 / 40.0;
const A41: f64 = 44.0 / 45.0;
const A42: f64 = -56.0 / 15.0;
const A43: f64 = 32.0 / 9.0;
const A51: f64 = 19372.0 / 6561.0;
const A52: f64 = -25360.0 / 2187.0;
const A53: f64 = 64448.0 / 6561.0;
const A54: f64 = -212.0 / 729.0;
const A61: f64 = 9017.0 / 3168.0;
const A62: f64 = -355.0 / 33.0;
const A63: f64 = 46732.0 / 5247.0;
const A64: f64 = 49.0 / 176.0;
const A65: f64 = -5103.0 / 18656.0;
// A7i = B_i (FSAL property), so we use B_i directly below.

// 5th-order weights
const B1: f64 = 35.0 / 384.0;
// B2 = 0
const B3: f64 = 500.0 / 1113.0;
const B4: f64 = 125.0 / 192.0;
const B5: f64 = -2187.0 / 6784.0;
const B6: f64 = 11.0 / 84.0;
// B7 = 0

// 4th-order weights (for error estimation)
const E1: f64 = 71.0 / 57600.0;
// E2 = 0
const E3: f64 = -71.0 / 16695.0;
const E4: f64 = 71.0 / 1920.0;
const E5: f64 = -17253.0 / 339200.0;
const E6: f64 = 22.0 / 525.0;
const E7: f64 = -1.0 / 40.0;

// =====================================================================
// ADAPTIVE STEP SIZE CONFIGURATION
// =====================================================================

/// Configuration for the adaptive Dormand-Prince RK4(5) integrator.
///
/// Controls local error tolerance, step size bounds, and the PI controller
/// that adjusts dt between accepted steps.
#[derive(Debug, Clone)]
pub struct AdaptiveStepConfig {
    /// Absolute tolerance for each component.
    pub atol: f64,
    /// Relative tolerance for each component.
    pub rtol: f64,
    /// Minimum allowed step size (seconds).
    pub dt_min: f64,
    /// Maximum allowed step size (seconds).
    pub dt_max: f64,
    /// Safety factor for step size controller (< 1.0).
    pub safety: f64,
    /// Maximum growth factor per step.
    pub max_growth: f64,
    /// Minimum shrink factor per step.
    pub min_shrink: f64,
}

impl Default for AdaptiveStepConfig {
    fn default() -> Self {
        Self {
            atol: 1e-8,
            rtol: 1e-6,
            dt_min: 1e-6,
            dt_max: 0.5,
            safety: 0.9,
            max_growth: 5.0,
            min_shrink: 0.2,
        }
    }
}

/// Statistics from the adaptive integrator.
#[derive(Debug, Clone, Default)]
pub struct StepStatistics {
    /// Number of accepted steps.
    pub n_accepted: usize,
    /// Number of rejected steps (step retried with smaller dt).
    pub n_rejected: usize,
    /// Smallest dt actually used in an accepted step.
    pub dt_min_used: f64,
    /// Largest dt actually used in an accepted step.
    pub dt_max_used: f64,
    /// History of accepted step sizes (for diagnostics).
    pub dt_history: Vec<f64>,
}

impl StepStatistics {
    pub(super) fn new() -> Self {
        Self {
            dt_min_used: f64::INFINITY,
            dt_max_used: 0.0,
            ..Default::default()
        }
    }

    pub(super) fn record_accepted(&mut self, dt: f64) {
        self.n_accepted += 1;
        self.dt_min_used = self.dt_min_used.min(dt);
        self.dt_max_used = self.dt_max_used.max(dt);
        self.dt_history.push(dt);
    }
}

// ---------------------------------------------------------------------
// RK4 INTEGRATOR
// ---------------------------------------------------------------------

/// Fourth-order Runge-Kutta step for the nonlinear system.
///
/// dt·λ_max = 0.05 × 4.0 = 0.2, well within RK4 stability boundary (~2.785).
pub(super) fn rk4_step(sys: &NonlinearSystem, x: &[f64; DIM], dt: f64) -> [f64; DIM] {
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
pub(super) fn rk4_variational_step(jac: &DMatrix<f64>, delta: &[f64; DIM], dt: f64) -> [f64; DIM] {
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
// DORMAND-PRINCE RK4(5) ADAPTIVE STEPPER
// ---------------------------------------------------------------------

/// One Dormand-Prince step: returns (x_new_5th, error_estimate).
///
/// 7 stages, 6 RHS evaluations (the 7th stage = FSAL, reusable as k1 of
/// the next step, but we don't exploit that here to keep the code simple).
/// The 5th-order solution advances the state; the difference between 5th
/// and 4th order solutions gives the local truncation error estimate.
pub(super) fn dopri5_step(
    sys: &NonlinearSystem,
    x: &[f64; DIM],
    dt: f64,
) -> ([f64; DIM], [f64; DIM]) {
    let k1 = sys.rhs(x);

    let mut xs = [0.0; DIM];
    for i in 0..DIM {
        xs[i] = x[i] + dt * A21 * k1[i];
    }
    let k2 = sys.rhs(&xs);

    for i in 0..DIM {
        xs[i] = x[i] + dt * (A31 * k1[i] + A32 * k2[i]);
    }
    let k3 = sys.rhs(&xs);

    for i in 0..DIM {
        xs[i] = x[i] + dt * (A41 * k1[i] + A42 * k2[i] + A43 * k3[i]);
    }
    let k4 = sys.rhs(&xs);

    for i in 0..DIM {
        xs[i] = x[i] + dt * (A51 * k1[i] + A52 * k2[i] + A53 * k3[i] + A54 * k4[i]);
    }
    let k5 = sys.rhs(&xs);

    for i in 0..DIM {
        xs[i] = x[i] + dt * (A61 * k1[i] + A62 * k2[i] + A63 * k3[i] + A64 * k4[i] + A65 * k5[i]);
    }
    let k6 = sys.rhs(&xs);

    // 5th-order solution
    let mut x_new = [0.0; DIM];
    for i in 0..DIM {
        x_new[i] =
            (x[i] + dt * (B1 * k1[i] + B3 * k3[i] + B4 * k4[i] + B5 * k5[i] + B6 * k6[i])).max(0.0);
    }

    // Stage 7 (needed for error estimate only; FSAL)
    let k7 = sys.rhs(&x_new);

    // Error estimate: difference between 5th and 4th order solutions
    // err_i = dt * (E1*k1 + E3*k3 + E4*k4 + E5*k5 + E6*k6 + E7*k7)
    let mut err = [0.0; DIM];
    for i in 0..DIM {
        err[i] = dt * (E1 * k1[i] + E3 * k3[i] + E4 * k4[i] + E5 * k5[i] + E6 * k6[i] + E7 * k7[i]);
    }

    (x_new, err)
}

/// Mixed-tolerance error norm (Hairer & Wanner convention).
///
/// Returns sqrt(1/DIM · Σ(err_i / (atol + rtol · max(|x_i|, |x_new_i|)))²).
/// A value ≤ 1.0 means the step meets tolerance; > 1.0 means reject.
pub(super) fn error_norm(
    err: &[f64; DIM],
    x: &[f64; DIM],
    x_new: &[f64; DIM],
    atol: f64,
    rtol: f64,
) -> f64 {
    let mut sum_sq = 0.0;
    for i in 0..DIM {
        let scale = atol + rtol * x[i].abs().max(x_new[i].abs());
        let ratio = err[i] / scale;
        sum_sq += ratio * ratio;
    }
    (sum_sq / DIM as f64).sqrt()
}

/// Try one adaptive step. Returns (x_new, dt_used, dt_next, accepted).
///
/// If the error norm ≤ 1.0, the step is accepted and dt_next is grown.
/// Otherwise the step is rejected and dt_next is shrunk.  The PI controller
/// uses the standard formula: dt_next = safety · dt · err^(-1/5).
pub(super) fn adaptive_step(
    sys: &NonlinearSystem,
    x: &[f64; DIM],
    dt: f64,
    acfg: &AdaptiveStepConfig,
) -> ([f64; DIM], f64, f64, bool) {
    let (x_new, err) = dopri5_step(sys, x, dt);
    let en = error_norm(&err, x, &x_new, acfg.atol, acfg.rtol);

    if en <= 1.0 {
        // Accept: grow dt for next step
        let growth = if en < 1e-10 {
            acfg.max_growth
        } else {
            (acfg.safety * en.powf(-0.2)).min(acfg.max_growth)
        };
        let dt_next = (dt * growth).min(acfg.dt_max);
        (x_new, dt, dt_next, true)
    } else {
        // Reject: shrink dt and retry
        let shrink = (acfg.safety * en.powf(-0.2)).max(acfg.min_shrink);
        let dt_next = (dt * shrink).max(acfg.dt_min);
        (*x, dt, dt_next, false)
    }
}

/// Advance the system from the current time to `t_end`, recording states.
///
/// Supports both adaptive (Dormand-Prince) and fixed-step (RK4) modes.
/// The burst timer is decremented by the actual step size after each
/// accepted step during recovery phases.
pub(super) fn advance_to(
    sys: &mut NonlinearSystem,
    x: &mut [f64; DIM],
    t: &mut f64,
    t_end: f64,
    dt: &mut f64,
    times: &mut Vec<f64>,
    states: &mut Vec<[f64; DIM]>,
    adaptive: Option<&AdaptiveStepConfig>,
    stats: &mut StepStatistics,
) {
    match adaptive {
        Some(acfg) => {
            while *t < t_end - 1e-12 {
                times.push(*t);
                states.push(*x);

                // Clamp dt to not overshoot phase boundary
                let dt_try = (*dt).min(t_end - *t).max(acfg.dt_min);

                let (x_new, dt_used, dt_next, accepted) = adaptive_step(sys, x, dt_try, acfg);
                if accepted {
                    *x = x_new;
                    *t += dt_used;
                    stats.record_accepted(dt_used);

                    // Tick down burst timer by actual step size
                    sys.tick_burst(dt_used);

                    *dt = dt_next;
                } else {
                    stats.n_rejected += 1;
                    *dt = dt_next;
                }
            }
        }
        None => {
            let fixed_dt = *dt;
            let n_steps = ((t_end - *t) / fixed_dt).ceil() as usize;
            for _ in 0..n_steps {
                times.push(*t);
                states.push(*x);

                // Tick down burst timer
                sys.tick_burst(fixed_dt);

                *x = rk4_step(sys, x, fixed_dt);
                *t += fixed_dt;
                stats.record_accepted(fixed_dt);
            }
        }
    }
}

/// Linearly interpolate the state trajectory at a query time.
///
/// Uses binary search to find the bracketing interval, then linear
/// interpolation between the two bounding states.  Needed when comparing
/// adaptive (irregular) and fixed-step (uniform) time grids.
pub(super) fn interpolate_state(times: &[f64], states: &[[f64; DIM]], t_query: f64) -> [f64; DIM] {
    debug_assert!(!times.is_empty());
    if t_query <= times[0] {
        return states[0];
    }
    if t_query >= *times.last().unwrap() {
        return *states.last().unwrap();
    }

    // Binary search for the right bracket
    let idx = match times.binary_search_by(|t| t.partial_cmp(&t_query).unwrap()) {
        Ok(i) => return states[i], // exact match
        Err(i) => i,               // t_query is between times[i-1] and times[i]
    };

    let t0 = times[idx - 1];
    let t1 = times[idx];
    let alpha = (t_query - t0) / (t1 - t0);

    let mut result = [0.0; DIM];
    for j in 0..DIM {
        result[j] = states[idx - 1][j] * (1.0 - alpha) + states[idx][j] * alpha;
    }
    result
}
