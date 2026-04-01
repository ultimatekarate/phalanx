# Shield Wall Extraction Plan

## Overview

The Shield Wall — Byzantine actor detection via spectral analysis of Volterra integral
coupling — separates into **two standalone crates** plus a residual layer that stays in Phalanx.
Each crate is independently publishable and useful outside the Phalanx ecosystem.

---

## Crate Architecture

```
volterra-stability          spectral-guard             phalanx-node (residual)
(pure numerical analysis)   (behavioral detection)     (application-specific wiring)
         |                        |                           |
    nalgebra 0.33            std only                   depends on both
         |                        |                           |
  No domain knowledge     No domain knowledge        8-integral topology
  No Phalanx types        No Phalanx types           HomeostaticConfig
  Generalizes to any      Generalizes to any         build_jacobian()
  dynamical system        heartbeat protocol         NonlinearSystem
                                                     ThreatProfile factories
```

---

## Crate 1: `volterra-stability`

**Purpose**: Research-grade spectral analysis toolkit for coupled dynamical systems.

**Dependencies**: `nalgebra = "0.33"` only.

**Audience**: Anyone working with dynamical systems — distributed systems, control theory,
robotics, ecological modeling, economic simulation.

### Trait Boundary

```rust
/// User-provided dynamical system.
/// Implement this to use the Lyapunov, RK4, and nonlinear simulation tools.
pub trait DynamicalSystem {
    fn dim(&self) -> usize;
    fn rhs(&self, x: &[f64]) -> Vec<f64>;

    /// Optional analytical Jacobian. Falls back to finite differences if None.
    fn jacobian(&self, x: &[f64]) -> Option<DMatrix<f64>> {
        None
    }
}
```

### Module Structure

```
volterra-stability/
  src/
    lib.rs
    eigenvalue.rs       -- analyze_stability(), eigenvalue decomposition
    mat_exp.rs          -- Pade(13) matrix exponential (Higham 2005)
    dyson.rs            -- Dyson series, convergence radius, GL quadrature
    lyapunov.rs         -- Benettin's algorithm for maximal Lyapunov exponent
    spectral_gap.rs     -- spectral gap, eigenvectors, stability radius, Henrici
    gershgorin.rs       -- Gershgorin disc analysis (extracted from test)
    integrator.rs       -- RK4, variational RK4, exponential integrator (evolve)
    impulse.rs          -- impulse_response(), cascade_analysis()
    types.rs            -- all report/result structs, ThreatProfile (struct only)
    format.rs           -- human-readable report formatting (label-parameterized)
```

### Functions to Extract (verbatim or near-verbatim)

#### `mat_exp.rs` — Pade(13) Matrix Exponential

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `PADE13_B` | 507-522 | const | 14 Pade coefficients, verbatim |
| `THETA_13` | 538 | const | `5.371920351148152`, verbatim |
| `mat_exp()` | 528-587 | `pub fn mat_exp(a: &DMatrix<f64>) -> DMatrix<f64>` | Verbatim. Zero Phalanx dependencies. Higham 2005 scaling-and-squaring with LU solve. |

#### `eigenvalue.rs` — Stability Analysis

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `analyze_stability()` | 329-356 | `pub fn analyze_stability(scenario: &str, jacobian: &DMatrix<f64>) -> StabilityReport` | Verbatim. Takes `DMatrix`, returns eigenvalues, spectral abscissa, symmetric part check. |

#### `spectral_gap.rs` — Spectral Gap and Eigenvector Analysis

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `compute_eigenvectors()` | 2203-2290 | `pub fn compute_eigenvectors(jacobian: &DMatrix<f64>, eigenvalues: &[Complex<f64>]) -> DMatrix<f64>` | Verbatim. SVD null-space extraction with deflation for repeated eigenvalues. |
| `stability_radius()` | 2306-2380 | `pub fn stability_radius(jacobian: &DMatrix<f64>) -> (f64, f64)` | Verbatim. Real 2n x 2n block-matrix trick, three-stage refinement (coarse/fine/ultra-fine). |
| `analyze_spectral_gap()` | 2386-2467 | Refactor: `pub fn analyze_spectral_gap(scenario: &str, jacobian: &DMatrix<f64>, labels: &[&str]) -> SpectralGapReport` | Remove `HomeostaticConfig`/`BaseImpulseRates`/`OperatingPoint` params. Accept pre-built Jacobian + string labels. Move `build_jacobian` call to Phalanx wrapper. |
| `build_combined_certificate()` | 2541-2611 | `pub fn build_combined_certificate(results: &[SpectralGapReport], worst_g1: f64, worst_rad: f64, worst_kappa: f64) -> String` | Verbatim. |

#### `gershgorin.rs` — Gershgorin Disc Analysis

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| Test `test_gershgorin_analysis` | 2952-2998 | Extract to `pub fn gershgorin_analysis(matrix: &DMatrix<f64>) -> GershgorinReport` | Currently only exists as a test. Promote to a first-class utility. Computes disc centers, radii, diagonal dominance margins per row. |

**New struct:**

```rust
pub struct GershgorinDisc {
    pub row: usize,
    pub center: f64,              // diagonal entry
    pub radius: f64,              // off-diagonal row sum
    pub margin: f64,              // -(center + radius), positive = diagonally dominant
    pub is_diagonally_dominant: bool,
}

pub struct GershgorinReport {
    pub discs: Vec<GershgorinDisc>,
    pub all_diagonally_dominant: bool,
    pub guaranteed_nonsingular: bool,  // true if irreducibly diag. dominant
}
```

#### `dyson.rs` — Dyson Series Perturbation Theory

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `GL16_NODES` | 594-611 | const | 16-point Gauss-Legendre nodes, verbatim |
| `GL16_WEIGHTS` | 614-631 | const | 16-point Gauss-Legendre weights, verbatim |
| `gl16_rescale()` | 634-644 | `pub fn gl16_rescale(a: f64, b: f64) -> ([f64; 16], [f64; 16])` | Verbatim. |
| `compute_dyson_terms()` | 863-920 | `pub fn compute_dyson_terms(j: &DMatrix<f64>, v: &DMatrix<f64>, t_onset: f64, t_end: f64) -> DysonTerms` | Verbatim. First and second-order correction terms. |
| `convergence_radius()` | 1024-1067 | `pub fn convergence_radius(j: &DMatrix<f64>, v_direction: &DMatrix<f64>, t_onset: f64, t_end: f64) -> f64` | Verbatim. Binary search for series convergence boundary. |

#### `lyapunov.rs` — Benettin's Algorithm

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `rk4_variational_step()` | 1475-1489 | `pub fn rk4_variational_step(jac: &DMatrix<f64>, delta: &[f64], dt: f64) -> Vec<f64>` | Generalize from `[f64; DIM]` to `&[f64]`. |
| `compute_lyapunov_exponent()` | 1700-1790 | Refactor to accept `&dyn DynamicalSystem` | Extract Benettin's algorithm: warmup, co-evolution of state + perturbation, periodic renormalization, accumulation of stretching factor. Phalanx provides `NonlinearSystem` as the `DynamicalSystem` impl. |

**Generic signature:**

```rust
pub fn compute_lyapunov_exponent(
    system: &dyn DynamicalSystem,
    x0: &[f64],
    dt: f64,
    warmup_steps: usize,
    measurement_steps: usize,
    renorm_interval: usize,
) -> LyapunovResult
```

#### `integrator.rs` — Numerical Integration

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `rk4_step()` | 1445-1471 | Refactor to accept `&dyn DynamicalSystem` | Generic RK4 with non-negativity clamping. |
| `evolve()` | 749-843 | `pub fn evolve(j: &DMatrix<f64>, threats: &[ThreatProfile], x0: &[f64], t_final: f64, dt: f64) -> TimeSeries` | Generalize from `[f64; DIM]` to `&[f64]`. Exponential integrator using pre-computed `mat_exp(J * dt)`. |

**Generic signatures:**

```rust
pub fn rk4_step(
    system: &dyn DynamicalSystem,
    x: &[f64],
    dt: f64,
) -> Vec<f64>

pub fn evolve(
    j: &DMatrix<f64>,
    threats: &[ThreatProfile],
    x0: &[f64],
    t_final: f64,
    dt: f64,
) -> TimeSeries
```

#### `impulse.rs` — Impulse Response and Cascade Analysis

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `impulse_response()` | 937-977 | `pub fn impulse_response(j: &DMatrix<f64>, threats: &[ThreatProfile], scenario: &str) -> ImpulseResponseReport` | Verbatim. |
| `cascade_analysis()` | 991-1020 | `pub fn cascade_analysis(j: &DMatrix<f64>, threat_a: &ThreatProfile, threat_b: &ThreatProfile) -> CascadeReport` | Verbatim. |

#### `types.rs` — Report and Result Structs

All fully generic, extracted verbatim:

| Struct | Source Line | Notes |
|--------|------------|-------|
| `StabilityReport` | 305-326 | Eigenvalues, spectral abscissa, symmetric part |
| `ThreatProfile` | 648-659 | Name, onset, duration, forcing, coupling delta. **Struct only** — factory methods stay in Phalanx. |
| `TimeSeries` | 738-742 | `times: Vec<f64>`, `states: Vec<Vec<f64>>` (generalized from `[f64; DIM]`) |
| `DysonTerms` | 847-856 | First/second order terms, convergence ratio |
| `ImpulseResponseReport` | 924-934 | Scenario name, peak/final norms, time series |
| `CascadeReport` | 981-988 | Two impulse response reports |
| `DysonAnalysisReport` | 1071-1076 | Collection of impulse, cascade, dyson results |
| `PartitionConfig` | 1227-1246 | Warmup, partition, recovery durations, burst config |
| `NonlinearSimulationResult` | 1497-1505 | Warmup/partition/recovery time series, steady state |
| `LinearNonlinearComparison` | 1595-1608 | Max divergence, relative error, time series pair |
| `LyapunovResult` | 1684-1691 | Exponent, convergence flag, steps |
| `SweepPoint` | 1798-1811 | Duration, peak deviation, recovery time, Lyapunov |
| `NonlinearPartitionReport` | 1899-1912 | Simulation, comparison, Lyapunov, sweep results |
| `SpectralGapReport` | 2141-2173 | Eigenvalues, spectral gap, condition number, Henrici, stability radius, eigenvector matrix, dominant mode |
| `FullSpectralReport` | 2176-2187 | Collection of spectral gap reports |

#### `format.rs` — Report Formatting

| Source | Line | Target | Notes |
|--------|------|--------|-------|
| `format_report()` | 413-500 | `pub fn format_stability_report(reports: &[StabilityReport], labels: &[&str]) -> String` | Replace `INTEGRAL_NAMES` with `labels` parameter. |
| `format_dyson_report()` | 1129-1210 | `pub fn format_dyson_report(report: &DysonAnalysisReport, labels: &[&str]) -> String` | Replace `INTEGRAL_NAMES` with `labels` parameter. |
| `format_nonlinear_partition_report()` | 1953-2122 | `pub fn format_nonlinear_report(report: &NonlinearPartitionReport, labels: &[&str]) -> String` | Replace `INTEGRAL_NAMES` with `labels` parameter. |
| `format_spectral_report()` | 2616-2713 | `pub fn format_spectral_report(report: &FullSpectralReport, labels: &[&str]) -> String` | Replace `INTEGRAL_NAMES` with `labels` parameter. |

### Tests to Extract

| Test | Source Line | Notes |
|------|------------|-------|
| `test_mat_exp_identity` | 3005-3015 | Pure math, verbatim |
| `test_mat_exp_diagonal` | 3018-3049 | Pure math, verbatim |
| `test_mat_exp_known_2x2` | 3052-3061 | Pure math, verbatim |
| `test_eigenvectors_are_eigenvectors` | 3634-3681 | Pure math, verbatim |
| `test_identity_orthogonal` | 3684-3731 | Pure math, verbatim |
| `test_henrici_zero_for_symmetric` | 3793-3821 | Pure math, verbatim |
| `test_rk4_recovers_exponential_decay` | 3395-3430 | Needs minor refactor to use `DynamicalSystem` trait |

### Estimated Extraction: ~2,200 lines of source + ~300 lines of tests

---

## Crate 2: `spectral-guard`

**Purpose**: Behavioral anomaly detection for distributed systems with heartbeat protocols.

**Dependencies**: `std` only (uses `Instant`, `VecDeque`, `HashMap`).

**Audience**: Anyone building a distributed system where peers broadcast state claims and
you can observe their actual behavior.

### Trait Boundary

```rust
/// Identity type for peers in the network.
pub trait PeerId: Hash + Eq + Clone {}

/// A heartbeat or status message from a peer.
pub trait HeartbeatMessage {
    fn claimed_load(&self) -> f64;        // [0.0, 1.0] resource utilization
    fn is_passive(&self) -> bool;         // claims to be a non-producing node
    fn claimed_integrals(&self) -> Option<&[f64]>;  // optional self-reported state
}

/// A pluggable consistency check beyond the built-in checks.
pub trait ConsistencyCheck<Id: PeerId> {
    fn evaluate(&self, observation: &PeerObservation<Id>) -> f64;  // squared error
}
```

### Module Structure

```
spectral-guard/
  src/
    lib.rs
    observer.rs         -- PeerObservation, BehavioralObserver
    residual.rs         -- compute_residual(), built-in consistency checks
    reputation.rs       -- DecayingIntegral, ReputationTracker
```

### Components to Extract

#### `observer.rs` — Behavioral Observer

| Source | File | Line | Notes |
|--------|------|------|-------|
| `PeerObservation` | vitals.rs | 1038-1064 | Generalize: replace `NetworkId` with `Id: PeerId`, replace `ControlMessage` with `impl HeartbeatMessage`. Ring buffer of heartbeat timestamps, claimed load history, data volume tracking. |
| `SpectralObserver` | vitals.rs | 1072-1213 | Rename to `BehavioralObserver<Id: PeerId>`. Replace `HashMap<NetworkId, ...>` with `HashMap<Id, ...>`. Methods: `record_heartbeat()`, `record_data_volume()`, `evaluate()`, `remove_peer()`. |

**Generic struct:**

```rust
pub struct PeerObservation {
    heartbeat_times: VecDeque<Instant>,
    data_bytes: u64,
    window_start: Instant,
    claimed_load: f64,
    claimed_passive: bool,
    claimed_integrals: Option<Vec<f64>>,
}

pub struct BehavioralObserver<Id: PeerId> {
    peers: HashMap<Id, PeerObservation>,
    window_duration: Duration,
    min_observations: usize,
    anomaly_threshold: f64,           // default 0.3
    custom_checks: Vec<Box<dyn ConsistencyCheck<Id>>>,
}
```

#### `residual.rs` — Consistency Checks

| Check | Source Line | Description | Generic? |
|-------|-----------|-------------|----------|
| Load-Throughput | vitals.rs ~1150-1170 | `observed_rate` normalized against baseline vs `1.0 - claimed_load`. Squared error if observed exceeds predicted. | Yes — any system where load should inversely correlate with throughput. |
| Heartbeat Regularity | vitals.rs ~1170-1185 | Coefficient of variation of heartbeat intervals. Suspiciously low jitter under high claimed load. Squared error. | Yes — any heartbeat protocol. |
| Passive Contradiction | vitals.rs ~1185-1195 | Claims passive/leaf role but sends significant data volume. Returns 1.0 squared error. | Yes — any system with passive/active roles. |

**Residual computation:**

```rust
/// Computes the L2 residual across all consistency checks.
/// Returns None if insufficient observations.
pub fn compute_residual(
    observation: &PeerObservation,
    custom_checks: &[Box<dyn ConsistencyCheck>],
) -> Option<f64> {
    // ... built-in checks + custom checks -> sqrt(sum of squared errors)
}
```

#### `reputation.rs` — Decaying Integral Reputation

| Source | File | Line | Notes |
|--------|------|------|-------|
| `DecayingIntegral` | vitals.rs | 310-330 | Verbatim. `value = impulse + value * exp(-lambda * dt)`. |

**Generic wrapper:**

```rust
pub struct DecayingIntegral {
    pub value: f64,
    last_update: Instant,
}

impl DecayingIntegral {
    pub fn new() -> Self;
    pub fn record(&mut self, impulse: f64, decay_rate: f64);
    pub fn current(&self, decay_rate: f64) -> f64;  // read without impulse
}

pub struct ReputationTracker<Id: PeerId> {
    integrals: HashMap<Id, DecayingIntegral>,
    decay_rate: f64,
}

impl<Id: PeerId> ReputationTracker<Id> {
    pub fn record_anomaly(&mut self, peer: Id, residual: f64);
    pub fn is_coupled(&self, peer: &Id) -> bool;  // integral >= 0.0
    pub fn score(&self, peer: &Id) -> f64;
}
```

### Tests to Extract

| Test | Source | Notes |
|------|--------|-------|
| `shield_wall_tests` module | vitals.rs 1219+ | 7+ tests covering: honest peer passes, load-throughput mismatch detected, heartbeat jitter anomaly, leaf contradiction, threshold sensitivity, recovery after anomaly ceases. Refactor to use `PeerId`/`HeartbeatMessage` traits. |

### Estimated Extraction: ~350 lines of source + ~200 lines of tests

---

## Residual: Stays in `phalanx-node`

Everything that encodes Phalanx's specific 8-integral topology and protocol semantics.

### Types

| Item | File | Line | Reason |
|------|------|------|--------|
| `HomeostaticConfig` | vitals.rs | 243-300 | 8 specific lambda/crit pairs, Sybil endowment params, temporal tolerance. Implements `volterra-stability::DynamicalSystem` via `NonlinearSystem`. |
| `BaseImpulseRates` | stability.rs | 34-44 | 8 specific rate fields (u_s, u_d, ...). Factory methods `light()`, `moderate()`, `heavy()`. |
| `OperatingPoint` | stability.rs | 93-95 | Factory methods `idle()`, `half_critical()`, `near_critical()` depend on `HomeostaticConfig`. |
| `IntegralState` | vitals.rs | 332+ | 8 named `DecayingIntegral` fields. |
| `SystemGovernor` | vitals.rs | 400+ | Orchestrates integrals, scalers, endowments. Holds `SpectralObserver` (now `BehavioralObserver` from `spectral-guard`). |
| `HealthTracker` | vitals.rs | 150+ | Per-node health with spectral observer reference. |

### Constants

| Item | File | Line | Reason |
|------|------|------|--------|
| `S, D, E, L, M, W, B, C` | stability.rs | 13-20 | Index labels for the 8 integrals. |
| `DIM = 8` | stability.rs | 22 | Fixed dimension. |
| `INTEGRAL_NAMES` | stability.rs | 25 | String labels. Passed to `volterra-stability` format functions. |

### Functions

| Function | File | Line | Reason |
|----------|------|------|--------|
| `build_jacobian()` | stability.rs | 152-297 | Encodes the exact 8-integral coupling structure: which rows couple to which columns, the scaler partial derivatives, the Sybil endowment Jacobian entries, the latency positive feedback. This is the heart of Phalanx's specific dynamics. |
| `NonlinearSystem::new()` | stability.rs | 1286-1300 | Constructs from `HomeostaticConfig` + `BaseImpulseRates`. |
| `NonlinearSystem::rhs()` | stability.rs | 1396-1413 | The 8-integral nonlinear dynamics: `dx_j/dt = impulse_j(x) - lambda_j * x_j`. |
| `NonlinearSystem::throughput()` | stability.rs | 1335-1350 | Product of 6 scalers. Phalanx-specific coupling. |
| `NonlinearSystem::impulse_rates()` | stability.rs | 1357-1393 | 8 rates modulated by throughput, endowment, tolerance. |
| `NonlinearSystem::scaler()` | stability.rs | 1312-1315 | `max(0, 1 - x/crit)`. Generic utility but trivial; can be duplicated. |
| `NonlinearSystem::endowment_frac()` | stability.rs | 1320-1322 | `psi_max / (1 + k_sybil * x_e)`. Phalanx-specific. |
| `NonlinearSystem::tol_factor()` | stability.rs | 1327-1331 | `1 + (max_tol/base_tol - 1) * (x_l / l_crit)`. Phalanx-specific. |
| `NonlinearSystem::instantaneous_jacobian()` | stability.rs | 1420-1435 | Finite difference Jacobian. Implements `DynamicalSystem::jacobian()`. |
| `full_analysis()` | stability.rs | 360-406 | Wires 3 scenarios with `build_jacobian`. |
| `full_dyson_analysis()` | stability.rs | 1079-1126 | Wires 5 threat profiles. |
| `full_nonlinear_partition_analysis()` | stability.rs | 1915-1950 | Wires partition simulation + Lyapunov + sweep. |
| `full_spectral_analysis()` | stability.rs | 2473-2539 | Wires 7 scenarios for spectral gap. |
| `nonlinear_partition_simulation()` | stability.rs | 1512-1587 | Uses `NonlinearSystem` with `rk4_step`. |
| `compare_linear_nonlinear()` | stability.rs | 1612-1676 | Compares linearized vs full nonlinear trajectories. |
| `partition_duration_sweep()` | stability.rs | 1814-1891 | Sweeps partition durations. |
| All `ThreatProfile` factory methods | stability.rs | 663-734 | `sybil_flood()`, `bandwidth_ddos()`, `storage_exhaustion()`, `network_partition()`, `cascade_ddos_then_sybil()`. |

### Tests That Stay

28 of 35 tests remain in Phalanx — they depend on `HomeostaticConfig`, `build_jacobian()`,
or `NonlinearSystem`.

### Integration Point

`NonlinearSystem` implements `volterra_stability::DynamicalSystem`:

```rust
use volterra_stability::DynamicalSystem;

impl DynamicalSystem for NonlinearSystem {
    fn dim(&self) -> usize { 8 }

    fn rhs(&self, x: &[f64]) -> Vec<f64> {
        let arr: [f64; 8] = x.try_into().expect("dim mismatch");
        self.rhs_internal(&arr).to_vec()
    }

    fn jacobian(&self, x: &[f64]) -> Option<DMatrix<f64>> {
        let arr: [f64; 8] = x.try_into().expect("dim mismatch");
        Some(self.instantaneous_jacobian(&arr))
    }
}
```

`ControlMessage` implements `spectral_guard::HeartbeatMessage`:

```rust
use spectral_guard::HeartbeatMessage;

impl HeartbeatMessage for ControlMessage {
    fn claimed_load(&self) -> f64 { self.load_factor as f64 }
    fn is_passive(&self) -> bool { self.is_leaf }
    fn claimed_integrals(&self) -> Option<&[f64]> { None }  // f32 -> f64 adapter needed
}
```

---

## Dependency Graph After Extraction

```
                  volterra-stability (nalgebra only)
                         |
                         | (used by)
                         v
                    phalanx-node
                         ^
                         | (used by)
                         |
                  spectral-guard (std only)
```

`volterra-stability` and `spectral-guard` have **no dependency on each other**.
They compose inside `phalanx-node`, where the spectral gap analysis from
`volterra-stability` provides the mathematical foundation, and the behavioral
observer from `spectral-guard` provides the runtime detection. The *insight* that
these two things compose to produce Byzantine detection is Phalanx's contribution.

---

## Extraction Effort Estimate

| Crate | Lines (source) | Lines (tests) | Effort |
|-------|---------------|---------------|--------|
| `volterra-stability` | ~2,200 | ~300 | 2-3 days. Mostly verbatim extraction. Main work: generalize `[f64; DIM]` to `&[f64]`/`Vec<f64>`, replace `HomeostaticConfig` with `DynamicalSystem` trait in Lyapunov/RK4, parameterize format functions with labels. Promote Gershgorin from test to utility. |
| `spectral-guard` | ~350 | ~200 | 1 day. Define `PeerId`/`HeartbeatMessage`/`ConsistencyCheck` traits. Replace `NetworkId`/`ControlMessage` with trait bounds. |
| Phalanx rewiring | ~200 changed | ~100 changed | 1 day. Implement `DynamicalSystem` for `NonlinearSystem`, `HeartbeatMessage` for `ControlMessage`. Update imports. Verify all 35 tests pass. |

**Total: 4-5 days of focused work.**

---

## Publication Value

### `volterra-stability`

A standalone spectral analysis toolkit for dynamical systems. Competes with MATLAB
toolboxes. Contains a research-grade Pade(13) matrix exponential, Dyson perturbation
theory with Gauss-Legendre quadrature, Benettin's Lyapunov algorithm, eigenvector
extraction via SVD null-space with deflation, stability radius computation, Gershgorin
disc analysis, and comprehensive human-readable reporting.

No Rust crate currently provides this combination of tools.

**Publishable as**: crates.io crate + companion paper on arXiv (numerical methods /
dynamical systems).

### `spectral-guard`

A zero-dependency behavioral anomaly detector for distributed systems. Any system with
peer heartbeats can use it. The L2 residual across consistency checks, fed through a
decaying integral reputation tracker, provides Byzantine detection at ~30 FLOPs per peer
per heartbeat.

**Publishable as**: crates.io crate + blog post / conference paper on lightweight
Byzantine detection.

### The composition

The paper that matters most is the one that explains why these two independent tools
compose to produce an emergent Byzantine detection mechanism — the Shield Wall. That
paper references both crates and Phalanx as the proof-of-concept system.

---

## Dedication

The Gershgorin disc analysis in `volterra-stability` is a direct application of the
spectral localization techniques taught by Dr. Richard Varga. The instinct to reach
for eigenvalue localization as a *practical tool* — not merely a classroom theorem —
traces directly to his influence.
