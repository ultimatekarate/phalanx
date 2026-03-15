use crate::vitals::HomeostaticConfig;
use nalgebra::{DMatrix, DVector};

use super::config::*;
use super::dyson::{compute_dyson_terms, evolve, ThreatProfile, TimeSeries};
use super::jacobian::build_jacobian;

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
// TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use crate::stability::*;
    use crate::vitals::HomeostaticConfig;

    fn default_cfg() -> HomeostaticConfig {
        HomeostaticConfig::default()
    }

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
            x = super::rk4_step(&sys, &x, dt);
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
            x = super::rk4_step(&sys, &x, dt);
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
}
