# 🏛️ Phalanx: Architectural Design Pivots & Decision Records

This document outlines the critical "Fork in the Road" moments where Phalanx diverged from standard industry practices to solve specific forensic constraints.

---

## ADR 001: The Transport Pivot (Integrity vs. Continuity)

### Context

The initial hypothesis was to utilize standard WebRTC (similar to Zoom or Google Meet) to achieve low-latency video transmission over UDP. However, this approach failed due to the "Lie of Smoothness." WebRTC optimizes for *Quality of Experience (QoE)*; when packets are dropped, it employs "Packet Loss Concealment" (PLC) to interpolate pixels and smooth over glitches. In a legal context, software-generated pixel interpolation is inadmissible and can be argued by defense counsel as "tampering" or "manufacturing evidence."

### Decision

We engineered **Crucible**, a custom ingestion engine, to replace WebRTC.

* **Mechanism:** Instead of skipping gaps to maintain visual flow, Crucible materializes gaps as cryptographically signed "Tombstones."
* **Constraint:** Zero percent interpolation is permitted.

### Consequences

* **Positive:** The stream is treated as a sparse set cover problem. The viewer sees exactly what was received, with verified cryptographic proof of exactly what was lost.
* **Negative:** The viewing experience may be jittery or contain visual artifacts (black frames) where data is missing, prioritizing forensic accuracy over viewer comfort.

---

## ADR 002: The Data Pivot (File-Based vs. Shard-Based)

**Context**: The standard industry practice is to record video to `.mp4` containers and hash the file upon completion. This introduced the "Atom Vulnerability": MP4 files require a global header (the MOOV atom) to be written at the *end* of the recording. If the device is destroyed, power is cut, or the application crashes mid-recording, this header is never written, rendering the entire file corrupt and unreadable.

**Decision**: We implemented the **Witness Envelope** architecture.

**Mechanism:** A custom serialization format where every "Volley" (a discrete temporal unit) is wrapped in its own self-sovereign identity structure containing independent metadata.

**Consequences**:

* **Positive:** **Atomic Validity.** If a device is destroyed at 10:05, the evidence captured at 10:04 remains functionally independent, playable, and legally admissible.
* **Positive:** Eliminates the single point of failure associated with global file headers.

---

## ADR 003: The Consensus Pivot (Global vs. Local)

**Context**: We hypothesized that hashing every frame to a public ledger/blockchain would ensure immutability. This failed due to the "Throughput Trap." Public blockchains have low throughput (e.g., 15 TPS) and high costs, while private blockchains are too heavy for mobile battery life. The latency required to achieve "Global Consensus" caused buffer overflows on the recording device, compromising the recording itself.

**Decision**: We shifted to **Recursive Assembly** using a local "Merkle Tree of Time."

**Mechanism:** The system does not attempt to prove the world agrees the video exists, but rather that the *Sensor* saw it. Shards are smelted into Volleys, and Volleys into Archives locally.

**Consequences**:

* **Positive:** Achieves a rigorous "Chain of Custody" without the network overhead and latency of global consensus.
* **Positive:** Significantly reduces battery and bandwidth consumption on the client device.

---

## ADR 004: The Routing Pivot (Equality vs. Biology)

**Context**: Standard P2P gossip protocols (like Gossipsub) treat every node as an equal peer that relays messages to maximize network health. In high-stress scenarios (protests, disasters), this created a "Tragedy of the Commons," where relaying heavy video traffic drained the batteries of the very phones trying to record critical evidence.

**Decision**: We implemented **Vampire Routing** (Biological Resource Governance).

**Mechanism:** We derived a utility function based on the derivative of battery drain ($\frac{dE}{dt}$). Nodes dynamically demote themselves to "Leaf Mode" (Listen-Only) when they detect they are under resource stress.

**Consequences**:

* **Positive:** The network degrades gracefully under load.
* **Trade-off:** The mesh explicitly sacrifices "Routing Efficiency" (bandwidth throughput) to preserve "Witness Survivability" (device uptime).

---

### ADR 005: The Use-Case Pivot (Viewership vs. Archival)

**Context**: The original goal was to build a "P2P Twitch" for distributed live streaming, allowing users to broadcast events to multiple peers in real-time. This failed due to the "Fan-Out Bottleneck." Mobile networks have highly asymmetric bandwidth (low upload speeds). Attempting to serve a live stream to multiple viewing peers saturated the uploader's bandwidth, causing buffer bloat and dropped frames, which compromised the quality of the forensic recording.

**Decision**: We shifted the protocol's primary objective to **Streaming Upload** (The "Lifeboat" Protocol).

**Mechanism:** We abandoned the "One-to-Many" broadcast model in favor of a "One-to-One" (or One-to-Few) offload model. The goal changed from *broadcasting* the event to *evacuating* the data.

**Consequences:**

* **Positive:** We optimize for "Save Rate" rather than "View Rate."
* **Outcome:** The network functions as a "Bucket Brigade" for data safekeeping rather than a Content Delivery Network (CDN) for entertainment.

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

#### Visualization

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
