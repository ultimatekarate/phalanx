# Phalanx Homeostasis

The SystemGovernor is a continuous adaptive control system that keeps a Phalanx node alive on constrained hardware. It uses Volterra second-kind integrals — exponentially decaying accumulators — to convert transient resource pressure signals into smooth, hysteresis-aware decisions about ingestion rate, power state, and peer admission.

This document explains what each integral measures, why the math works the way it does, and how the feedback loops close.

---

## Why Volterra second-kind

A Volterra integral of the second kind has the form:

```
I(t) = impulse + ∫₀ᵗ K(t-τ) · I(τ) dτ
```

In Phalanx, the kernel K is exponential decay: `K(dt) = exp(-λ·dt)`. This gives the discrete update rule:

```
I(t + dt) = impulse + I(t) · exp(-λ · dt)
```

This is not Euler integration. There is no step-size sensitivity and no accumulated truncation error. The exponential is computed exactly — `exp(-λ·dt)` has a closed-form solution regardless of how large `dt` is. A node that sleeps for 10 minutes and then wakes up gets the same answer as one that ticked every second.

> **Design rationale**: Euler integration (I += impulse - λ·I·dt) is step-size-dependent: large `dt` overshoots, small `dt` accumulates floating-point error. On a phone where the vitals tick rate varies from 5s (Normal) to 60s (Dormant), Euler would produce different steady-state values at different power states. The exact exponential doesn't have this problem. This matters because the composite stress thresholds that drive power state transitions must be consistent regardless of tick rate — otherwise you get oscillation at the Conserving↔Normal boundary.

---

## The integral bank

Each `DecayingIntegral` has its own time cursor (`last_update: Instant`). This is critical: before this design, all integrals shared a single tick clock. High-frequency updates to one integral (e.g., bandwidth on every packet) would suppress decay in all others, causing phantom cross-coupling and ~10× pressure inflation under load.

### Resource integrals

| Symbol | Name | Half-life | λ | Critical threshold | Unit | Fed by |
|--------|------|-----------|---|-------------------|------|--------|
| `s` | System/metabolic | 170ms | 4.08 | 10.0 | seconds | `record_metabolic_pressure(duration)` — IngestionActor, StorageActor |
| `d` | I/O digestion | 1.4s | 0.495 | 25.0 | seconds | `record_io_pressure(duration)` — StorageActor disk ops |
| `l` | Latency | 700ms | 0.990 | — | seconds | `record_latency_pressure(duration)` — network RTT |
| `m` | Memory | 2.3s | 0.301 | 512 MiB* | MiB | `record_memory_pressure(bytes)` — Reassembler, Crucible |
| `w` | WAL/storage | 14s | 0.0495 | 0.80 | ratio | `record_storage_pressure(used, max)` — MediaEgressActor outbound queue |
| `b` | Bandwidth | 1.4s | 0.495 | 100 MiB | MiB | `record_bandwidth_pressure(bytes)` — transport I/O counters |
| `c` | Connection | 3.5s | 0.198 | 0.90 | ratio | `record_connection_pressure(active, max)` — peer count gauge |
| `e` | Entry/Sybil | 7s | 0.099 | — | count | `record_entry_pressure()` — PeerDiscovered events, eclipse impulse |

\* m_crit is `device_RAM × 0.125`. On a 4GB phone: 512 MiB. Overridden by HardwareProbe if actual RAM is known.

### Per-peer integrals (r_integrals)

The `r_integrals` HashMap contains per-entity `DecayingIntegral` instances keyed by string. Three namespaces share this map:

| Key pattern | Half-life | Purpose |
|-------------|-----------|---------|
| `{peer_did}` | 69s | Peer reputation. +1 per valid evidence, −ω (100) per offense. Goes negative → decoupled. |
| `bw:{peer_id}` | 69s | Per-peer bandwidth. +1 per event. Exceeds `psi_max` (50) → throttled. |
| `ret:{recording_id}` | 69s | Per-recording retrieval rate. +1 per request. Exceeds `psi_max` → rate-limited. |

---

## Half-life derivation

Every half-life is anchored to a physical time constant of the resource it measures:

| Integral | Half-life | Physical anchor |
|----------|-----------|----------------|
| `s` (metabolic) | 170ms | Linux CFS scheduler preemption quantum. CPU contention resolves within one scheduling round. |
| `d` (I/O) | 1.4s | Typical disk flush cycle (ext4 commit interval / SQLite WAL checkpoint). |
| `l` (latency) | 700ms | Network RTT changes rapidly — half a round-trip is the minimum observation window. |
| `m` (memory) | 2.3s | Rust drop/dealloc cycles for large buffers (Reassembler context eviction). |
| `w` (storage) | 14s | WAL rotation period. Storage fills and drains slowly compared to memory. |
| `b` (bandwidth) | 1.4s | Matched to I/O — bandwidth bursts are transient and recover on the same timescale. |
| `c` (connection) | 3.5s | TCP/QUIC handshake window. Connection churn settles within a few handshakes. |
| `e` (entry) | 7s | Sybil attack detection window. Must be long enough to detect coordinated join floods. |
| `r` (reputation) | 69s | Multiple topology maintenance ticks (5 min). Trust decisions are intentionally sticky. |

The decay rate is: `λ = ln(2) / half_life`

---

## Scalers: how integrals become decisions

Each integral produces a **scaler** — a value in [0.0, 1.0] where 1.0 means nominal and 0.0 means saturated:

```
scaler = max(0, 1 - I(t) / I_crit)
```

| Scaler | Formula | Read by | Effect |
|--------|---------|---------|--------|
| `ingestion_scaler` | `1 - s/s_crit` | IngestionActor | Throttle delay on incoming shards. At 0.01, delay = 100× base. |
| `finalization_scaler` | `1 - d/d_crit` | RetrievalActor | I/O saturation gate. Below threshold → reject retrieval requests. |
| `memory_scaler` | `1 - m/m_crit` | IngestionActor | Memory pressure gate. |
| `storage_scaler` | `1 - w/w_crit` | StorageActor | Storage pressure gate (P6 hard limit). |
| `bandwidth_scaler` | `1 - b/b_crit` | IngestionActor | Bandwidth pressure gate. |
| `connection_scaler` | `1 - c/c_crit` | MeshSentinel | Connection pressure — feeds topology decisions. |
| `sybil_endowment` | `ψ_max / (1 + (k·e)²)` | IngressGovernor | Per-peer resource ceiling. Squeezes as entry pressure rises. |
| `temporal_tolerance` | `base + l` (clamped) | IngestionActor | How much clock drift to accept. Expands under latency pressure. |

> **Design rationale**: The sybil endowment uses a Lorentzian `1/(1+x²)` rather than exponential decay because it needs to squeeze *smoothly* toward zero without ever reaching it. An exponential (`exp(-k·e)`) approaches zero too aggressively — at high entry pressure, legitimate peers would get zero allocation. The Lorentzian has a long tail that always leaves a nonzero endowment, preventing complete starvation even under sustained Sybil attack.

---

## Composite stress and power state

Five integrals combine into a single composite stress value:

```
composite = Σ wᵢ · min(1, Iᵢ/Iᵢ_crit)
```

| Weight | Integral | Rationale |
|--------|----------|-----------|
| 0.25 | `s` (metabolic) | Highest — blocks all work when CPU is saturated |
| 0.20 | `d` (I/O) | Equal tier — all limit throughput |
| 0.20 | `m` (memory) | Equal tier |
| 0.20 | `b` (bandwidth) | Equal tier |
| 0.15 | `w` (storage) | Lowest — can defer writes without immediate data loss |

### Power state transitions

Composite stress maps to `PowerState` through a hysteresis state machine:

```
                 composite stress
     0.0         0.30        0.50        0.85        1.0
      ├───────────┼───────────┼───────────┼───────────┤
      │  Normal   │   (dead   │ Conserving│   Leaf    │
      │           │   zone)   │           │           │
      └───────────┴───────────┴───────────┴───────────┘

    Escalation:   3 consecutive ticks above threshold
    De-escalation: 5 consecutive ticks below threshold
```

- **Normal** → **Conserving**: composite > 0.50 for 3 ticks
- **Conserving** → **Leaf**: composite > 0.85 for 3 ticks
- **Any** → **Normal**: composite < 0.30 for 5 ticks
- **Dormant**: *never* produced by stress — exclusively from battery gate (see below)

The dead zone between 0.30 and 0.50 plus the asymmetric tick counts (3 up, 5 down) prevent oscillation at state boundaries. De-escalation is deliberately slower because premature de-escalation wastes battery.

> **Design rationale**: The tick counts are small integers, not integrals, because hysteresis needs discrete threshold behavior. An integral would smooth away the very transitions we're trying to detect. The asymmetry (3 vs. 5) encodes a prior: on a phone recording evidence under stress, it's better to stay in a lower power state slightly too long than to bounce between states.

### Battery gate (hard override)

Battery is **not** a composite stress weight. It short-circuits directly to PowerState because a dead phone produces zero evidence:

| Condition | Override |
|-----------|----------|
| Background (iOS/Android) | → Dormant |
| Battery < 10% | → Leaf |
| Battery < 50% (not charging) | → Conserving |
| Charging or > 50% | → Normal |

Final power state = `max(battery_gate, stress_recommendation)` — the more restrictive state always wins.

---

## The FPS self-regulation loop

This is the most important feedback loop in the system. It connects the camera to the network to the storage to the power state and back:

```
Camera captures frame
  → MediaEgressActor encrypts + fountain encodes
    → Publish to mesh
      → On failure: persist to OutboundQueue WAL
        → Queue depth / max_storage_bytes = storage ratio
          → record_storage_pressure(ratio)
            → w integral rises
              → composite_stress rises
                → PowerState escalates (Normal → Conserving → Leaf)
                  → TrafficGovernor restricts ingestion
                  → Vitals polling interval increases (5s → 15s → 30s)
                    → Slower integral decay (fewer ticks, but exact exponential
                       means no drift — this is why Euler would fail here)

Meanwhile:
  → Network recovers
    → OutboundQueue drains
      → record_storage_pressure(lower ratio)
        → w integral decays (14s half-life)
          → composite_stress drops
            → PowerState de-escalates (after 5 stable ticks)
              → TrafficGovernor opens ingestion
              → Camera FPS can increase
```

The 14-second half-life on `w` (storage) is the governor on this loop. It's long enough that a brief network hiccup doesn't immediately drop FPS, but short enough that sustained congestion produces a visible response within ~30 seconds (2 half-lives ≈ 75% decay).

---

## Vitals polling

A dedicated tokio task (spawned in `MeshSentinel::new()`) calls `SystemGovernor::update_vitals()` on a **power-state-adaptive interval**:

| PowerState | Interval | Rationale |
|------------|----------|-----------|
| Normal | 5s | Fast response to load changes during active recording |
| Conserving | 15s | Balanced energy vs. responsiveness |
| Leaf | 30s | Minimal overhead, battery critical |
| Dormant | 60s | Background — thermal/battery readings only, no capture |

Each tick:
1. Read thermal sensor → map to `SystemStress` → inject heat penalty into `s` integral
2. Read battery level → map to `SystemStress`
3. Check internet connectivity (30s grace period since last non-mDNS peer)
4. Sample transport I/O counters → compute deltas → feed `b` and `c` integrals
5. Compute `composite_stress()` → evaluate hysteresis → update `recommended_state`

> **Design rationale**: The polling interval is adaptive because polling itself costs energy. On a phone at 5% battery (Leaf state), polling thermal sensors every 5 seconds is wasteful — the thermal state isn't changing that fast, and the 30-second interval is well within the response time needed (the phone is already in survival mode). The exact exponential decay means the integrals produce correct values regardless of tick rate.

---

## Hardware abstraction

`SystemGovernor` reads hardware state through the `HardwareProbe` trait:

```rust
pub trait HardwareProbe: Send + Sync {
    fn thermal_reading(&self) -> Option<f64>;
    fn thermal_thresholds(&self) -> ThermalThresholds;
    fn battery_level(&self) -> Option<NonZeroU8>;
    fn is_charging(&self) -> bool;
    fn is_background(&self) -> bool;
    fn total_ram_bytes(&self) -> Option<u64>;
}
```

- **Android/iOS**: Real implementations reading sysfs/IOKit
- **Desktop**: `SysfsProbe` (Linux thermal zones) or no-op (returns `None` → assume AC power, no thermal limit)
- **Tests/sim**: Mock probes with configurable values

When a probe provides `total_ram_bytes()`, `m_crit` is recalculated as `RAM × 0.125` at construction time. This means a 2GB phone gets `m_crit = 256 MiB` while an 8GB phone gets `m_crit = 1024 MiB` — the memory integral automatically calibrates to the device.

---

## Pressure signal reference

Quick reference: who feeds each integral, and when.

| Signal | Integral | Called from | Frequency |
|--------|----------|------------|-----------|
| `record_metabolic_pressure(duration)` | `s` | IngestionActor (per shard processing time), StorageActor (per disk op) | Per event |
| `record_io_pressure(duration)` | `d` | StorageActor (Guardian write latency) | Per disk write |
| `record_latency_pressure(duration)` | `l` | Network RTT measurements | Per peer interaction |
| `record_entry_pressure()` | `e` | MeshSentinel (PeerDiscovered event) | Per new peer |
| `record_eclipse_impulse(magnitude)` | `e` | MeshSentinel (eclipse probe detection) | On eclipse signal |
| `record_memory_pressure(bytes)` | `m` | Reassembler (context allocation), Crucible (buffer growth) | Per allocation |
| `record_storage_pressure(used, max)` | `w` | MediaEgressActor (outbound queue depth) | Per failed publish |
| `record_bandwidth_pressure(bytes)` | `b` | SystemGovernor (transport I/O counter delta) | Per vitals tick |
| `record_connection_pressure(active, max)` | `c` | SystemGovernor (peer count gauge) | Per vitals tick |
| `record_peer_evidence(peer, valid)` | `r[peer]` | TrustActor (per evidence validation) | Per event |
| `record_peer_bandwidth(peer)` | `r[bw:peer]` | IngestionActor (per-peer bandwidth tracking) | Per shard |
| `record_retrieval_attempt(recording)` | `r[ret:rec]` | RetrievalActor (per retrieval request) | Per request |
| `record_spectral_anomaly(peer, residual)` | `r[peer]` | SpectralObserver (Shield Wall detection) | On anomaly |
| Heat penalty | `s` | SystemGovernor (thermal reading → scaled impulse) | Per vitals tick |
