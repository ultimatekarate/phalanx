### ADR 006: Physics-Based Time Constant Derivation

* **Status:** Accepted
* **Date:** 2026-02-06
* **Context:** Integration Test Instability & "Magic Number" fragility.

**Context**:

The Phalanx protocol relies on several critical time-based thresholds:

1. `Gossipsub` Heartbeat Interval
2. `Crucible` Ingestion Timeout
3. `Kademlia` Query Timeout
4. `Tombstone` TTL (Time-To-Live)

Previously, these values were defined as independent constants (e.g., `const TIMEOUT = 500ms`). This led to **Parameter Decoherence**:

* **Integration Test Failures:** In high-contention test environments (CI runners), the OS scheduler introduced latencies that violated tight, hardcoded timeouts, causing false negatives.
* **Race Conditions:** Logic that assumed $Heartbeat < Timeout$ would break if one value was tweaked without manually updating the other.
* **Rigidity:** The system could not be easily tuned for different network profiles (e.g., LAN vs. Satellite link).

**Decision**:

We will replace all independent "Magic Numbers" with a **Derived System of Inequalities**.

We assert that the entire temporal behavior of the system is governed by only two independent variables (Axioms):

1. **$\tau$ (Tau) - The Network Quanta:** The maximum expected Round Trip Time (RTT) between two peers.
2. **$\delta$ (Delta) - The Compute Cost:** The CPU time required to verify signatures and process protocol overhead.

All other system thresholds must be calculated as functions of $\tau$ and $\delta$. We are implementing a `PhalanxPhysics` struct to enforce these relationships at runtime.

#### The Derived Equations

We have established the following functional relationships to guarantee mathematical consistency:

##### 1. The Heartbeat Frequency ($H_{hz}$)

To prevent aliasing (missing messages that arrive between checks), the system must sample the network state at least twice per network quantum (Nyquist-Shannon heuristic).

$$T_{heartbeat} \le \frac{\tau}{2}$$

##### 2. The Shard Timeout ($T_{out}$)

A shard cannot be declared "Dead" until we have allowed time for:

* Transmission ($\tau/2$)
* Verification ($\delta$)
* Acknowledgement Return ($\tau/2$)
* Safety Margin (Jitter Factor $k$, typically $3\sigma$)

$$T_{out} = k \cdot (\tau + \delta)$$

##### 3. The Tombstone TTL ($T_{grave}$)

To prevent "Zombie Replays" (where a late packet resurrects a closed window), the system must remember dead events significantly longer than the timeout window.

$$T_{grave} \ge 2 \cdot T_{out}$$

#### Implementation

We introduce a `PhalanxPhysics` configuration object.

```rust
pub struct PhalanxPhysics {
    pub tau_rtt: u64,      // The fundamental independent variable
    pub delta_cpu: u64,    // The compute constraint
    pub jitter_factor: u64 // The safety margin (k)
}

impl PhalanxPhysics {
    pub fn heartbeat_interval(&self) -> u64 {
        (self.tau_rtt / 2).max(1)
    }

    pub fn shard_timeout(&self) -> u64 {
        self.jitter_factor * (self.tau_rtt + self.delta_cpu)
    }
}
```