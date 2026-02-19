# ADR 005: Dual-Clock Separation for Distributed Forensic Integrity

## Status

Accepted

## Context

In a distributed forensic system like the Phalanx mesh, timing is a security primitive. We face two distinct temporal challenges:

1. **Resource Exhaustion (DDoS/OOM):** Attackers may attempt to keep stale buffers alive by spoofing packet timestamps or exploiting wall-clock drift (NTP adjustments) to bypass LRU eviction logic.
2. **Evidentiary Validity:** Forensic data (VideoShards) requires absolute, verifiable global consensus to be admissible and cryptographically provable across Stronghold nodes.

## Decision

We will enforce a strict **Dual-Clock Architecture** that separates local resource management from global forensic provenance. This creates a "Hard Boundary" between the ingress pipeline and the global mesh state.

### 1. The Transient Layer (Local Node Memory)

* **Implementation:** `ReassemblyBuffer` / `tokio::time::Instant`
* **Clock Type:** Monotonic
* **Domain:** Ingress Pipeline
* **Purpose:** Resource management and Out-of-Memory (OOM) defense.
* **Security Imperative:** The duration a partial chunk sits in memory is strictly a local concern. A monotonic clock guarantees that the `BufferCapacityGate` calculates LRU eviction deterministically. Time always moves forward, preventing attackers from artificially keeping stale buffers alive via wall-clock manipulation.

### 2. The Forensic Layer (VideoShard / PhalanxTimestamp)

* **Implementation:** `VideoShard` / `PhalanxTimestamp`
* **Clock Type:** Verifiable Wall Clock (`TrustedClock`)
* **Domain:** Global Mesh State (Crucible / Vault)
* **Purpose:** Cryptographic provenance, evidentiary timelines, and temporal governance.
* **Security Imperative:** Once raw bytes are reassembled into a `VideoShard`, they transition into "Evidence." The `PhalanxTimestamp` provides the global consensus required for `WitnessEnvelope` sealing. A `TimeError` here must correctly abort the creation of invalid evidence.

## Implementation Standards

* **Typestate Enforcement:** The `create_video_shard` function must enforce the acquisition of a `forensic_now` timestamp. This must propagate as a monadic `Result` to prevent the instantiation of untimed (and therefore unprovable) forensic data.
* **Boundary Maintenance:** * Do not allow `PhalanxTimestamp` to bleed into local state management or buffer eviction logic.
  * Do not allow `tokio::time::Instant` to be serialized into mesh payloads or stored in the Vault.

## Consequences

* **Positive:** Elimination of wall-clock manipulation as a vector for OOM/DoS attacks against the reassembly pipeline.
* **Positive:** Guaranteed cryptographic integrity and auditability for all forensic evidence.
* **Negative:** Increased ceremony in the `create_video_shard` transition, requiring explicit interaction with the `TrustedClock` provider.
