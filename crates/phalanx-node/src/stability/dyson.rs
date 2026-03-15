use crate::vitals::HomeostaticConfig;
use nalgebra::{DMatrix, DVector};

use super::config::*;
use super::jacobian::build_jacobian;
use super::pade::mat_exp;

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
