# The Spectral Observer: Byzantine Detection Through Coupled Dynamics

## The Core Idea

Every node in a Phalanx mesh broadcasts claims about its state: how loaded it is, how much bandwidth it has, whether it is a leaf. These claims flow through heartbeat messages. An honest node's claims are consistent with its observed behavior because both arise from the same physical reality. A dishonest node fabricates its claims independently from its behavior.

Phalanx's resource signals are coupled through a system of Volterra integral equations. The coupling is not a design choice that can be circumvented — it is a consequence of the physics. Bandwidth pressure gates ingestion, ingestion drives CPU and memory, memory pressure throttles further ingestion. A node that lies about one signal but behaves honestly on another produces an internally inconsistent state. The Spectral Observer measures that inconsistency.

The spectral lie is the distance between what a peer claims and what the Jacobian of the coupled system says is physically possible. A dishonest node has nowhere to hide — it cannot escape the math.

---

## The Coupled Integral System

Phalanx models node health as eight Volterra integral equations of the second kind, each tracking a different resource pressure. The continuous-time model for each integral is:

```
dI_i/dt = f_i(I_0, ..., I_7) - lambda_i * I_i
```

The first term `f_i` is the impulse rate — the rate at which events feed pressure into integral `i`. The second term is exponential decay with rate `lambda_i = ln(2) / half_life`. Without new impulses, each integral relaxes to zero at its characteristic rate.

The discrete update rule is exact (not Euler integration):

```
I(t + dt) = impulse + I(t) * exp(-lambda * dt)
```

This is possible because the exponential decay kernel reduces the integral equation to a first-order linear ODE with constant coefficients: `dI/dt = impulse_rate - lambda * I`. The exponential function is the eigenfunction of differentiation — `d/dt exp(-lambda*t) = -lambda * exp(-lambda*t)` — so the homogeneous solution is known in closed form. The impulse enters as an initial condition at time `t`, and the decay from `t` to `t+dt` is multiplication by the exact homogeneous solution. No Taylor truncation, no step-size dependence, no accumulated error.

Euler integration approximates the exponential: `exp(-lambda*dt) ≈ 1 - lambda*dt`. For the CPU integral (lambda = 4.08), a 60-second dormant tick gives `lambda*dt = 244.8` — the approximation goes catastrophically negative. Even with smaller steps, the linear approximation accumulates truncation error that produces different steady-state values at different tick rates. On a phone where the vitals tick varies from 5s (Normal) to 60s (Dormant), Euler would give different answers for the same physical state at different power levels, causing oscillation at state boundaries. The exact exponential is unconditionally stable and tick-rate-invariant because it is the actual solution, not an approximation of one.

### The Eight Integrals

| Index | Symbol | Resource | λ | Half-Life | Critical Threshold | Physical Anchor |
| ------- | -------- | ---------- | --- | ----------- | ------------------- | ----------------- |
| 0 | S | CPU / metabolic | 4.08 | 170 ms | 10.0 CPU-sec | Linux CFS scheduler preemption quantum. CPU contention resolves within one scheduling round. |
| 1 | D | I/O digestion | 0.495 | 1.4 s | 25.0 I/O-sec | Typical disk flush cycle (ext4 commit interval / SQLite WAL checkpoint). |
| 2 | E | Entry / Sybil | 0.099 | 7.0 s | 25.0 count | Sybil attack detection window. Must be long enough to detect coordinated join floods. |
| 3 | L | Latency | 0.990 | 700 ms | 10.0 seconds | Network RTT changes rapidly — half a round-trip is the minimum observation window. |
| 4 | M | Memory / buffer | 0.301 | 2.3 s | 512 MiB | Rust drop/dealloc cycles for large buffers (Reassembler context eviction). |
| 5 | W | WAL / storage | 0.0495 | 14.0 s | 0.8 ratio | WAL rotation period. Storage fills and drains slowly compared to memory. |
| 6 | B | Bandwidth | 0.495 | 1.4 s | 100 MiB | Matched to I/O — bandwidth bursts are transient and recover on the same timescale. |
| 7 | C | Connection | 0.198 | 3.5 s | 0.9 ratio | TCP/QUIC handshake window. Connection churn settles within a few handshakes. |

Every half-life is anchored to a physical time constant of the resource it measures. They are not free parameters — they are derived from the hardware.

### Coupling Through Scalers

The impulse rates `f_i` are not independent. They are modulated by *scaler functions* that depend on the state of other integrals. This is what makes the system coupled.

**Throughput scaler:**

```
sigma(x) = max(0, 1 - x / x_crit)
```

When integral `x` approaches its critical threshold, the scaler drops toward zero, throttling any process gated by that resource. In the linear regime (`x < x_crit`), the derivative is `d(sigma)/dx = -1/x_crit`. At saturation (`x >= x_crit`), the derivative is zero. This piecewise linearity is important for the Jacobian — it means the coupling coefficients are constant within each regime, which makes the convexity argument in the contractivity proof work.

Each integral that participates in the ingestion pipeline produces a scaler:

| Scaler | Formula | Effect |
| -------- | --------- | ------- |
| `sigma_s` | `1 - s/s_crit` | CPU gate — throttles ingestion delay |
| `sigma_m` | `1 - m/m_crit` | Memory gate — blocks shard acceptance |
| `sigma_b` | `1 - b/b_crit` | Bandwidth gate — limits network intake |
| `sigma_w` | `1 - w/w_crit` | Storage gate — restricts WAL writes |

**Sybil endowment:**

```
psi(e) = psi_max / (1 + (k * e)^2)
```

A Lorentzian that smoothly reduces ingestion capacity as Sybil pressure (entry count) rises. The quadratic denominator zeros the derivative at `e = 0` (no false positive at idle), provides half-endowment at `e = 1/k`, and has a long tail that always leaves a nonzero endowment — preventing complete starvation even under sustained Sybil attack. An exponential (`exp(-k*e)`) approaches zero too aggressively; the Lorentzian does not.

The derivative with respect to `e`:

```
d(psi)/de = -psi_max * 2 * k^2 * e / (1 + (k*e)^2)^2
```

This derivative appears directly in the Jacobian's column E entries — it is how Sybil pressure couples into the impulse rates of all throughput-gated integrals.

**Throughput product:**

```
T = sigma_b * sigma_s * (psi(e) / psi_max) * sigma_m
```

This is the effective ingestion rate. It is the product of four gates — bandwidth, CPU, Sybil defense, and memory. Every integral fed by the ingestion pipeline has its impulse rate scaled by this product. A bottleneck in any single resource throttles the entire pipeline.

The throughput product is the central coupling mechanism. Because it is a *product*, the partial derivative with respect to any one gate involves all the other gates as multiplicative factors. This is why fabricating one signal while leaving others honest produces an inconsistency — the chain rule ties them together.

---

## The Jacobian

Linearizing the coupled system at an operating point yields the 8x8 Jacobian matrix:

```
J[i, j] = df_i/dI_j - lambda_i * delta_{ij}
```

The diagonal entries combine the decay rate with the self-coupling effect (how an integral's own pressure throttles its input). The off-diagonal entries encode cross-coupling: how pressure in integral `j` affects the impulse rate of integral `i`.

### Row-by-Row Derivation

Each row of the Jacobian is derived by applying the chain rule to the impulse rate function. The base impulse rate `u_i` is the unthrottled event rate (events per second that would feed integral `i` if no scaler were active). Three traffic regimes define the `u_i` values:

```
            u_s   u_d   u_e   u_l    u_m    u_w     u_b    u_c
Light:      0.5   0.2   2.0   0.1    5.0    0.01    2.0    0.05
Moderate:   2.0   1.0   10.0  0.5    50.0   0.05    10.0   0.2
Heavy:      5.0   3.0   50.0  2.0    200.0  0.15    40.0   0.5
```

**Row S (CPU/metabolic):** Recorded at end of ingestion processing. Impulse rate is `f_s = u_s * sigma_b * sigma_s * endowment_frac * sigma_m`. Applying the chain rule:

```
J[S,S] = -lambda_sys + u_s * sigma_b * endowment_frac * sigma_m * d(sigma_s)/ds
J[S,E] = u_s * sigma_b * sigma_s * sigma_m * d(endowment_frac)/de
J[S,M] = u_s * sigma_b * sigma_s * endowment_frac * d(sigma_m)/dm
J[S,B] = u_s * sigma_s * endowment_frac * sigma_m * d(sigma_b)/db
```

All other entries in row S are zero. The pattern is: differentiate the throughput product with respect to the gate variable, multiply by the base rate and the remaining gates.

**Row D (I/O digestion):** Driven by retrieval, a separate pipeline. Self-coupled only:

```
J[D,D] = -lambda_io + u_d * d(sigma_d)/dd
```

All off-diagonal entries zero. Retrieval is downstream and does not share the ingestion throughput product.

**Row E (Entry/Sybil):** Recorded per allocated shard. Same throughput gating as S:

```
J[E,S] = u_e * sigma_b * endowment_frac * sigma_m * d(sigma_s)/ds
J[E,E] = -lambda_entry + u_e * sigma_b * sigma_s * sigma_m * d(endowment_frac)/de
J[E,M] = u_e * sigma_b * sigma_s * endowment_frac * d(sigma_m)/dm
J[E,B] = u_e * sigma_s * endowment_frac * sigma_m * d(sigma_b)/db
```

**Row L (Latency):** Has the same throughput coupling as S and E, plus **positive feedback**. Higher latency pressure widens the temporal tolerance window, which accepts older shards, which increases average impulse magnitude. The positive feedback term is:

```
alpha_l = dtol_dl / max_tol_secs
```

where `dtol_dl = 1.0` when tolerance hasn't hit the clamp (current tolerance < max), and `0.0` when clamped. The diagonal entry becomes:

```
J[L,L] = -lambda_lat + u_l * T * alpha_l
```

The `+u_l * T * alpha_l` term is the one potentially destabilizing contribution in the entire Jacobian. Stability requires that the decay rate `lambda_lat = 0.990` dominates. The contractivity proof verifies this holds everywhere.

Row L also has the standard throughput couplings to S, E, M, B (same chain-rule pattern as row S).

**Row M (Memory):** Two impulse sources. Normal flow (buffered data proportional to throughput) gives the standard throughput couplings to S, E, M, B. Storage rejection backpressure (`f_m2 = u_m_reject * (w/w_crit)`) would add a positive J[M,W] entry — but this coupling is zero. Storage-to-memory rejection is threshold-activated (fires only when W > 95% of w_crit), not proportional. The correct linearization at all analyzed operating points is `J[M,W] = 0`.

**Row W (WAL/storage):** Driven by ingestion rate. Standard throughput coupling plus self-gating:

```
J[W,W] = -lambda_wal + u_w * sigma_b * sigma_s * endowment_frac * d(sigma_w)/dw * sigma_m
```

The `d(sigma_w)/dw` term means that as storage fills, the scaler drops, which throttles further storage writes — a self-limiting mechanism.

**Row B (Bandwidth):** Entry point. Externally driven by network traffic. Self-gated only:

```
J[B,B] = -lambda_bw + u_b * d(sigma_b)/db
```

All off-diagonal entries zero. Bandwidth is the source; it does not depend on internal processing state.

**Row C (Connection):** Tracked but not gating anything. Pure decay:

```
J[C,C] = -lambda_conn
```

Constant, decoupled. Connection count is informational.

### Sparsity Structure

```
       S   D   E   L   M   W   B   C
  S [  x   .   x   .   x   .   x   .  ]
  D [  .   x   .   .   .   .   .   .  ]
  E [  x   .   x   .   x   .   x   .  ]
  L [  x   .   x   x   x   .   x   .  ]
  M [  x   .   x   .   x   .   x   .  ]
  W [  x   .   x   .   x   x   x   .  ]
  B [  .   .   .   .   .   .   x   .  ]
  C [  .   .   .   .   .   .   .   x  ]
```

The throughput-coupled block (rows S, E, L, M, W × columns S, E, M, B) is clearly visible. D, B, and C are isolated. Row L has the only diagonal entry that can go positive (the latency feedback). Every `x` in the off-diagonal represents a physical coupling that a dishonest node cannot independently control — this is the origin of the spectral lie.

### The Key Insight

The off-diagonal entries are not free parameters. They are the partial derivatives of the scaler and gate functions evaluated at the operating point. The scaler functions are determined by the physics of resource flow. A node cannot choose to have high CPU pressure without affecting its throughput scaler, which in turn throttles entry rate, latency accumulation, memory buffering, and storage writes. The Jacobian encodes these constraints as mathematical identities.

---

## The Spectral Gap

The eigenvalues of the Jacobian determine the system's stability and robustness. For asymptotic stability, all eigenvalues must lie in the left half of the complex plane — every `Re(lambda_k) < 0` — meaning perturbations decay rather than grow.

The stability analysis computes five robustness metrics across a sweep of seven operating scenarios:

```
1. idle    + light traffic
2. idle    + moderate traffic
3. idle    + heavy traffic
4. half-critical + moderate traffic
5. near-critical + moderate traffic
6. half-critical + heavy traffic
7. near-critical + heavy traffic
```

These span the full operating envelope from quiescent to near-saturation under all traffic intensities.

### Spectral Gap (gamma_1)

```
gamma_1 = |Re(lambda_dominant)|
```

The absolute value of the real part of the dominant (slowest-decaying) eigenvalue. This is the distance from the instability boundary. A larger spectral gap means perturbations decay faster and anomalies are more quickly exposed.

The dominant eigenvalue is the slowest mode — it determines how long a transient disturbance can persist before the system re-equilibrates. For Byzantine detection, this sets the *detection timescale*: an inconsistency in a peer's claimed state will become visible within approximately `1/gamma_1` seconds.

### Modal Gap (gamma_2)

```
gamma_2 = |Re(lambda_2)| - |Re(lambda_1)|
```

The separation between the two slowest modes. A wide modal gap means there is a single clear bottleneck mode, not a cluster of near-marginal modes that could interact to produce complex transient behavior. The dimensionless ratio `gamma_2 / gamma_1` measures how cleanly the dominant mode separates from the rest of the spectrum.

### Eigenvector Condition Number (kappa)

```
kappa(V) = sigma_max(V) / sigma_min(V)
```

The ratio of the largest to smallest singular values of the eigenvector matrix V (computed via SVD null-space extraction for each eigenvalue). This bounds transient amplification:

```
||exp(J*t)|| <= kappa(V) * exp(alpha * t)
```

where `alpha = max Re(lambda)`. Even though all modes eventually decay, non-orthogonal eigenvectors allow transient growth up to a factor of `kappa` before the exponential envelope takes over. The guaranteed decay time — after which the transient is guaranteed to have died out — is:

```
t_decay = ln(kappa) / gamma_1
```

This is a hard upper bound. After `t_decay` seconds, the system state is dominated by exponential decay regardless of initial conditions. For Byzantine detection, `t_decay` is the worst-case time before a consistent lie can no longer be maintained.

### Stability Radius (r)

```
r(J) = min_omega  sigma_min(i*omega*I - J)
```

The smallest operator-norm perturbation to the Jacobian that can push an eigenvalue across the imaginary axis (destabilize the system). Computed via a real block-matrix trick:

```
sigma_min(i*omega*I - J) = sigma_min(M(omega))

where M(omega) = [[ -J,  -omega*I ],
                   [ omega*I,  -J  ]]   in R^{2n x 2n}
```

This converts the complex sigma_min problem to a real 2n x 2n SVD. Three-stage frequency refinement (coarse: omega in [0,10] step 0.5; fine: +/-0.5 step 0.05; ultra-fine: +/-0.05 step 0.005) locates the minimizing frequency `omega*`.

The stability radius quantifies how much an adversary would need to perturb the system dynamics to break stability. It is the mathematical measure of the system's resistance to manipulation.

### Henrici Departure from Normality (delta_H)

```
delta_H = sqrt(||J||_F^2 - sum |lambda_k|^2)
```

Zero for normal matrices (where `J*J^T = J^T*J` and eigenvectors are orthogonal). Nonzero values indicate skewed eigenvectors, which enable transient growth. The Henrici departure works with the condition number to characterize how "well-behaved" the transient response is. A small departure means the eigenvalue analysis tells nearly the whole story; a large departure means transient overshoots are significant and the Lyapunov analysis becomes essential.

### The Lyapunov Certificate

Beyond eigenvalue analysis, the system carries a Lyapunov matrix `P` (8x8, symmetric positive definite) that provides a **contractivity proof**:

```
Q(x) = P * J_n(x) + J_n(x)^T * P    is negative definite
```

for all `x` in the feasible operating region `[0, x_crit]^8` and all traffic regimes. `J_n` is the normalized Jacobian (each integral divided by its critical threshold to produce dimensionless quantities in [0,1]).

**How P was found:** Semidefinite programming (CVXPY 1.8.2 with Clarabel backend, iterative cutting-plane method with 2 SDP iterations).

**Structural features of P:**

- `P[M,E] = -0.637`: The largest off-diagonal entry in magnitude. This negative cross-term is the key innovation over a diagonal Lyapunov function. It means that simultaneous memory and entry pressure partially cancel in the stability measure, compensating for the asymmetric M-E coupling in the Jacobian. A diagonal P cannot capture this — the off-diagonal structure is essential.

- `P[M,M] = 3.117, P[B,B] = 3.438`: Memory and bandwidth receive the heaviest weights, reflecting their central role in the coupling structure. These are the integrals with the most off-diagonal coupling; P weights them proportionally.

- Rows 1 (D) and 7 (C) have zero off-diagonal entries in P, reflecting that I/O and connection pressure are dynamically independent of the other channels. P's sparsity mirrors the Jacobian's.

**Eigenvalues of P:** [0.019, 0.025, 0.063, 0.221, 0.478, 0.489, 2.598, 4.107]. Condition number: 214.

**Verification is two-layered:**

*Layer 1 — Grid verification:* Q(x) is evaluated at 15,552 grid vertices (3 traffic regimes x 2^5 scaler vertices x 162 e-grid points). Worst margin: **0.01649**, attained at heavy traffic with s=0, m=0, b=95, w=0.8, l=0, e=0. Zero violations.

*Layer 2 — Continuity (grid covers the continuous region):*

For the five scaler variables (s, m, b, w, l): J_n is piecewise linear (linear in each scaler regime, piecewise constant in l at the tolerance threshold). Therefore Q(x) is linear in these variables for fixed e and traffic. The maximum eigenvalue of a linear symmetric matrix pencil `(1-t)A + tB` is convex in t (it is the pointwise supremum of linear Rayleigh quotients `v^T A(t) v`). Convexity means grid vertices are sufficient — no intermediate point can exceed the vertex maximum.

For the entry variable e: Q(x) is nonlinear through the endowment function `psi(e) = 1/(1+(ke)^2)`. The Jacobian is decomposed as `J_n(e) = J_const + ef(e)*A_ef + def(e)*A_def` where the coefficient matrices are e-independent. At each of the 162 e-grid endpoints, eigenvalue perturbation theory (Temple-Kato bound in Schur basis) bounds the interpolation error. The key insight: the action of the perturbation on Q's dominant eigenvector `v_1` replaces the worst-case operator norm, exploiting misalignment between the perturbation structure and Q's dominant eigenspace. Maximum perturbation/margin ratio: **0.861**.

**Consequences of contractivity:**

1. **Negative Lyapunov exponent**: All trajectories converge exponentially to equilibrium at rate >= margin/||P||_2.
2. **Bounded transition matrix**: The Dyson series (operator exponential of the integral kernel) converges absolutely. Transient overshoots are bounded.
3. **Self-healing**: Perturbations from equilibrium decay exponentially under all traffic conditions. Not an engineered behavior — an emergent mathematical consequence of the integral equation structure.
4. **Robustness**: The margin of 0.01649 provides tolerance against parameter uncertainty and numerical errors.

---

## How the Lie Shows Up in the Spectral Gap

The Jacobian defines a **feasibility manifold**: the set of all (load, throughput, jitter, role) tuples that are physically consistent with the coupled dynamics. Every honest node lives on this manifold because its claimed state arises from the same physical process that generates its observed behavior.

A dishonest node fabricates its claims. It might report high load while flooding data, or claim leaf status while originating traffic. These fabricated claims place the node *outside* the feasibility manifold.

### The Manifold Constraints

The throughput product `T = sigma_b * sigma_s * psi * sigma_m` imposes coupled constraints on what an honest node can do:

**Constraint 1 — Load bounds throughput.** If a node claims high CPU pressure (high `s`, low `sigma_s`), the throughput product `T` is low because `sigma_s` appears as a multiplicative factor. Low throughput means low data emission rate. A peer claiming 95% CPU load but producing data at full rate violates this constraint — the scaler relationship encoded in row S of the Jacobian forbids it.

**Constraint 2 — Load induces jitter.** High integral values mean high resource contention. On real hardware, contention means scheduler preemption, garbage collection pauses, and I/O blocking — all of which produce measurable jitter in heartbeat timing. The 170ms half-life of the CPU integral (S) is anchored to the Linux CFS preemption quantum precisely because CPU contention resolves at that timescale. A simulated node that fabricates high load but runs on idle hardware produces heartbeats with implausibly low variance — the dynamical consequence of the integral state (jitter proportional to load) is absent.

**Constraint 3 — Role bounds behavior.** A leaf node (high composite stress, escalated power state) is passive by definition — it has reduced its activity to conserve resources. It should not be originating data traffic. This is not a statistical relationship; it is an architectural invariant.

### Detection Timescale

The spectral gap `gamma_1` determines how quickly deviations from the manifold are exposed. A wide spectral gap means the system is stiff — the coupled dynamics drive inconsistent states apart from physically realizable behavior at a rate proportional to `gamma_1`. The guaranteed decay time `t_decay = ln(kappa) / gamma_1` is the worst-case interval before a fabricated state becomes detectable: after `t_decay` seconds, the transient amplification (bounded by `kappa`) has been absorbed by the exponential decay.

A narrow spectral gap would allow inconsistencies to linger, making detection harder. The contractivity proof guarantees the gap is bounded away from zero across all operating conditions and all traffic regimes.

### The Three Checks as Manifold Projections

The spectral observer's three consistency checks are **projections onto the feasibility manifold** — each samples a different axis of the Jacobian's constraint space:

1. **Load-throughput** probes the scaler coupling (Constraint 1). It measures the discrepancy between claimed `sigma_s` and observed data rate. This directly tests the functional relationship encoded in rows S, E, L, M, W of the Jacobian.

2. **Heartbeat jitter** probes the dynamical consequence of the integral state (Constraint 2). It measures whether the *second-order statistics* (variance) of the peer's timing are consistent with the *first-order claim* (load). This tests whether the peer is actually evolving under the Jacobian's dynamics.

3. **Leaf contradiction** probes a hard architectural boundary (Constraint 3). It is a binary test of whether the peer's role claim is consistent with its traffic pattern.

The **residual** is the L2 distance from the manifold across these three axes. Each axis is independent (they probe different physical quantities), so the L2 aggregation is geometrically natural — it is the Euclidean distance in the three-dimensional projection space.

---

## The Three Consistency Checks: Computation Detail

The `compute_residual()` function evaluates three independent checks and combines them into a single scalar. Each check compares a claim (from the peer's `ControlMessage` heartbeat) against an observation (from the spectral observer's accumulated state).

### Input: ControlMessage

Every heartbeat carries:

| Field | Type | Range | Meaning |
| ------- | ------ | ------- | --------- |
| `sender` | `NetworkId` | — | Peer identity |
| `load_factor` | `f32` | [0.0, 1.0] | Claimed CPU load (0 = idle, 1 = saturated) |
| `storage_remaining_mb` | `u64` | — | Remaining storage capacity |
| `heartbeat_ms` | `u64` | — | Heartbeat interval (ms) |
| `is_leaf` | `bool` | — | Claimed leaf (passive) role |
| `integral_summary` | `Option<[f32; 8]>` | — | Tier 2: claimed integral state vector |

The spectral observer records `load_factor`, `is_leaf`, and `integral_summary` on each heartbeat. It independently tracks heartbeat arrival timestamps and data volume received from the peer.

### Check 1: Load-Throughput Consistency

A peer claiming load factor `L` (where 0.0 = idle, 1.0 = saturated) implies a maximum data emission rate of `1 - L` (normalized). The scaler relationship `sigma_s = 1 - s/s_crit` means that as CPU pressure rises, throughput drops proportionally. The observer measures actual throughput:

```
window_secs    = max(elapsed_seconds, 1.0)
observed_rate  = data_volume_bytes / window_secs
observed_norm  = min(observed_rate / 100_000, 1.0)     // 100 KB/s = "full throughput"
predicted_max  = max(1.0 - claimed_load, 0.0)

error_1 = max(0, observed_norm - predicted_max)
```

The 100 KB/s normalization baseline represents full throughput — a peer sending at or above this rate is considered to be at maximum output. The error is one-sided: underperformance relative to claimed capacity is not penalized (a node may legitimately choose not to send data). Only *overperformance* relative to claimed load is anomalous.

**Worked example:** A peer claims `load_factor = 0.95` (CPU nearly saturated) but sends 500 KB in a 10-second window.

```
observed_rate = 500_000 / 10 = 50_000 bytes/s
observed_norm = min(50_000 / 100_000, 1.0) = 0.5
predicted_max = max(1.0 - 0.95, 0.0) = 0.05

error_1 = max(0, 0.5 - 0.05) = 0.45
error_1^2 = 0.2025
```

The peer claims it can produce at most 5% of full throughput, but it is producing 50%. The squared error is 0.2025.

### Check 2: Heartbeat Regularity

Genuine nodes under load exhibit jitter in their heartbeat timing due to scheduler contention. The observer measures the coefficient of variation (CV) of inter-heartbeat intervals:

```
intervals = [t_1 - t_0, t_2 - t_1, ..., t_n - t_{n-1}]
mean      = sum(intervals) / n
variance  = sum((interval_i - mean)^2) / n
cv        = sqrt(variance) / mean
```

The expected minimum CV is proportional to claimed load:

```
expected_min_cv = claimed_load * 0.05
```

The factor 0.05 is empirically calibrated: at full load, we expect at least 5% variation in heartbeat timing from scheduler contention. The check triggers only when two conditions are met simultaneously:

1. `claimed_load > 0.3` — Low load legitimately produces low jitter. No penalty for precise timing at low claimed load.
2. `cv < expected_min_cv * 0.5` — Observed jitter is less than half of what the claimed load predicts. This is a generous threshold; it only catches grossly implausible precision.

When both conditions are met:

```
error_2 = expected_min_cv - cv
error_2^2 = (expected_min_cv - cv)^2
```

**Worked example:** A peer claims `load_factor = 0.8` and sends 5 heartbeats at exactly 5.000s intervals (CV ≈ 0).

```
expected_min_cv = 0.8 * 0.05 = 0.04
check: claimed_load (0.8) > 0.3  ✓
check: cv (≈0) < 0.04 * 0.5 = 0.02  ✓

error_2 = 0.04 - 0.0 = 0.04
error_2^2 = 0.0016
```

The peer claims 80% load but has zero scheduling jitter. The squared error is 0.0016 — small individually, but it accumulates with the other checks.

### Check 3: Leaf State Contradiction

A peer claiming leaf status (`is_leaf = true`) should not originate data traffic. If the observer has recorded more than 10 KB of data volume from a leaf peer:

```
if claimed_is_leaf AND data_volume_bytes > 10_000:
    error_3^2 = 1.0     // hard penalty
```

This is a binary architectural violation, not a graduated signal. The 10 KB threshold allows for control messages and protocol overhead — it only triggers on meaningful data traffic. The penalty of 1.0 (which contributes a residual of at least 1.0 by itself) ensures that leaf contradictions are always above the anomaly threshold (default 0.3).

### Residual Aggregation

The three errors are combined as an L2 norm:

```
residual = sqrt(error_1^2 + error_2^2 + error_3^2)
```

The residual is non-negative. Zero means perfectly consistent behavior. Each check contributes independently to the total distance from the feasibility manifold.

**Worked example (full):** A peer claims `load_factor = 0.95`, `is_leaf = false`, sends 5 MB in a 60-second window, and has 5 heartbeats with CV = 0.001.

```
Check 1: observed_norm = min(5_000_000/60/100_000, 1.0) = min(0.833, 1.0) = 0.833
         predicted_max = 0.05
         error_1 = 0.783
         error_1^2 = 0.613

Check 2: expected_min_cv = 0.95 * 0.05 = 0.0475
         check: 0.95 > 0.3 ✓, 0.001 < 0.02375 ✓
         error_2 = 0.0475 - 0.001 = 0.0465
         error_2^2 = 0.00216

Check 3: not leaf → error_3^2 = 0

residual = sqrt(0.613 + 0.00216 + 0) = sqrt(0.615) = 0.784
```

This residual (0.784) is well above the anomaly threshold (0.3). The peer is flagged.

---

## From Residual to Decoupling

The spectral observer runs passively within the `HealthTracker`, which is embedded in the `MeshSentinel` actor. The full pipeline:

### Step 1: Observation

On every heartbeat received from a peer:

```
health_tracker.spectral.record_heartbeat(peer_id, &msg)
```

This records the heartbeat arrival timestamp in the peer's ring buffer (bounded to `max_history = 10`) and captures the claimed state from the `ControlMessage`.

On every data message received from a peer:

```
health_tracker.spectral.record_data_received(peer_id, bytes)
```

This accumulates data volume in the current observation window. The window resets every `window_duration` (60s).

### Step 2: Evaluation

Immediately after recording a heartbeat, the MeshSentinel evaluates:

```
if let Some(residual) = health_tracker.spectral.evaluate(&peer_id) {
    if residual > health_tracker.spectral.anomaly_threshold {
        // Anomaly detected
    }
}
```

`evaluate()` returns `None` if fewer than `min_observations` (3) heartbeats have been recorded for this peer — the observer does not judge until it has enough data.

### Step 3: Reputation Impulse

When the residual exceeds the threshold, the MeshSentinel calls:

```
system_governor.record_spectral_anomaly(&peer_id.to_string(), residual)
```

Inside the governor:

```
r_integrals
    .entry(peer_id)
    .or_insert_with(|| DecayingIntegral::new(lambda_rep))
    .record(-residual)
```

This records a **negative impulse** of magnitude `-residual` on the peer's reputation integral. The reputation integral uses `lambda_rep ≈ 0.01` (half-life ≈ 69 seconds). This is the same integral that receives `+1.0` impulses for each valid piece of evidence the peer contributes.

### Step 4: Decoupling

The existing `is_peer_coupled()` check in the ingestion pipeline reads the peer's reputation integral. When the integral's value drops below zero, the peer is **decoupled** — its contributions are rejected.

This is not a binary ban; it is a continuous signal. A peer that produces one borderline anomaly (residual = 0.35) will see a small negative impulse that the 69-second decay will clear, especially if the peer is also contributing valid evidence (+1.0 per event). But a peer that consistently fabricates state will accumulate negative impulses faster than decay and positive contributions can compensate, driving the integral steadily downward.

### Dynamics of Recovery

The 69-second half-life means trust decisions are sticky. After a peer is decoupled:

- Negative impulses stop (the peer is no longer sending heartbeats through this mesh relationship)
- The reputation integral decays toward zero at rate `exp(-0.01 * dt)`
- After approximately 5 half-lives (~345 seconds, ~6 minutes), the integral is within 3% of zero
- If the peer reconnects and behaves honestly, positive impulses from valid evidence will push the integral above zero

A peer cannot game the recovery process without sustained honest behavior — and sustained honest behavior is indistinguishable from actually being honest.

---

## Parameters

| Parameter | Default | Purpose |
| ----------- | --------- | --------- |
| `min_observations` | 3 | Minimum heartbeats before evaluation begins. Prevents false positives from insufficient data. |
| `max_history` | 10 | Maximum heartbeat timestamps retained per peer (ring buffer). Bounds memory and focuses the jitter check on recent behavior. |
| `window_duration` | 60 s | Data volume measurement window. Balances sensitivity (shorter catches bursts) vs. stability (longer averages out noise). |
| `anomaly_threshold` | 0.3 | Residual above this triggers a reputation impulse. Set below the leaf contradiction penalty (1.0) and above the typical honest-peer noise floor (~0.01). |

---

## Source Files

| File | Role |
| ------ | ------ |
| `phalanx-node/src/vitals/spectral.rs` | `SpectralObserver`, `PeerObservation`, `compute_residual()` |
| `phalanx-node/src/stability/jacobian.rs` | `build_jacobian()` — 8x8 coupling matrix construction |
| `phalanx-node/src/stability/spectral.rs` | `SpectralGapReport`, `analyze_spectral_gap()`, stability radius, Henrici departure |
| `phalanx-node/src/stability/config.rs` | Integral indices, `BaseImpulseRates`, `OperatingPoint`, `LYAPUNOV_P` |
| `phalanx-node/src/stability/eigenvalues.rs` | QR-based eigenvalue computation, symmetric part analysis |
| `phalanx-node/src/stability/nonlinear.rs` | Lyapunov exponent from partition analysis (`compute_lyapunov_exponent()`) |
| `phalanx-node/src/vitals/governor.rs` | `SystemGovernor::record_spectral_anomaly()`, `is_peer_coupled()`, `DecayingIntegral` |
| `phalanx-node/src/vitals/health.rs` | `HealthTracker` — embeds `SpectralObserver`, updated by MeshSentinel |
| `phalanx-node/src/actors/meshsentinel.rs` | Evaluation call site — runs spectral check on every heartbeat |
| `phalanx-proto/src/vitals.rs` | `ControlMessage` — the heartbeat carrying claimed state |
| `docs/contractivity-proof.md` | Full contractivity proof with Lyapunov matrix P and verification details |
| `docs/homeostasis.md` | Complete description of the integral system, scalers, and feedback loops |
