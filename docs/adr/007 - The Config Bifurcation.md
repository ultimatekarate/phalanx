# ADR 007: Separation of Physical Laws from Static Configuration

* **Status:** Accepted
* **Date:** 2026-02-06
* **Context:** Parameter Decoherence and Time Dilation in Simulation

**Context**:

In early iterations of Phalanx, network timing parameters (heartbeats, timeouts, buffer expiry) were defined as static integers in `PhalanxConfig` (loaded from `phalanx.toml`).

This caused several critical issues:

1. **Parameter Decoherence:** It was possible to configure a `pulse_timeout` shorter than the `heartbeat_interval`, causing nodes to commit suicide even in a healthy network.
2. **Time Dilation Incompatibility:** Integration tests running in a "Fast Universe" (milliseconds) required a separate configuration file from Production (seconds). This led to fragile tests that did not accurately reflect production logic.
3. **The "Snapshot" Problem:** Passing calculated physics values into the Config at startup created a static snapshot. This prevented the system from adapting to dynamic runtime changes (e.g., simulating a sudden network degradation or "Satellite Mode" switch).

**Decision**:

We will strictly separate **User Policy** (`PhalanxConfig`) from **System Mechanism** (`PhalanxPhysics`).

1. **Removal of Magic Numbers:** Fields such as `heartbeat_interval_secs` and `pulse_timeout_secs` are removed from `PhalanxConfig`.
2. **Runtime Injection:** `PhalanxPhysics` is passed as a separate runtime dependency to components (Sentinel, Swarm, HealthTracker) alongside `PhalanxConfig`.
3. **Dynamic Derivation:** Components must ask the Physics engine for values at the moment of execution (e.g., `physics.shard_timeout()`) rather than reading a stored field.

**Consequences**:

**Positive**:

* **Mathematical Consistency:** It is now impossible to instantiate a system where the timeout is mathematically shorter than the heartbeat. Safety margins are enforced by the `PhalanxPhysics` struct.
* **Simulation Fidelity:** We can inject `PhalanxPhysics::test_profile()` into tests to run them 100x faster than real-time without changing a single line of application logic or maintaining separate config files.
* **Runtime Adaptation:** The system can support "War Gaming" scenarios where environmental variables (RTT, CPU Jitter) change on the fly, and the Sentinel automatically adjusts its patience levels without restart.
* **Serialization Purity:** `PhalanxConfig` remains a simple, serializable representation of the TOML file, without needing to handle complex logic or derived state during deserialization.

**Negative**:

* **Signature Complexity:** Constructors and methods for core components (`Sentinel::new`, `setup_phalanx_swarm`) now require an additional argument (`physics`).
* **Verbosity:** Simple lookups like `config.timeout` are replaced by method calls `physics.shard_timeout()`.
