# Phalanx Mesh: Engineering Roadmap (Q1 2026)

This document outlines the critical architectural gaps required to move the Phalanx Mesh from a verified prototype to a forensic-ready distributed system.

---

## ️ 1. Security & Arbitration (The Justiciar)

*Objective: Transition from local peer penalties to mesh-wide programmatic reputation management.*

- [ ] **Justiciar Module Implementation:** Create a dedicated arbiter to evaluate cumulative telemetry.
- [ ] **Consensus Rejection Protocol:** Implement a gossip-based mechanism for nodes to share `Offense` reports.
- [ ] **Reputation Decay:** Implement a "Cooling Off" period where transient network errors (Clock Skew) eventually age out of the blacklist.
- [ ] **Sybil Resistance:** Integrate Proof-of-Vitality checks before a node's reputation update is accepted by the mesh.

## 2. Distributed Egress (Stronghold "Serve" Phase)

*Objective: Enable the recovery of archived evidence via the Kademlia DHT.*

- [x] **Kademlia Query Handlers:** Implement handlers for `kad::GetRecord` to respond to requests for specific `VolleyId` ranges.
- [ ] **Authenticated Retrieval:** Ensure that only authorized DIDs (or those with valid `StorageGrants`) can pull raw bytes from a Stronghold.
- [x] **Egress Gating:** Apply `ForensicGate` and `PrivacyGate` to all outbound data transfers to ensure evidence remains encrypted and audited during recovery.

## 3. Hardware Ingress (Driver Unification)

*Objective: Extend the zero-trust boundary to the physical sensor layer.*

- [ ] **Sensor Gate Integration:** Refactor `camera.rs` and `audio.rs` to return `Result<Shard, ShardError>`.
- [x] **Atomic Witnessing:** Ensure hardware buffers are wrapped in `PrivacyGate` (encryption) and `WitnessGate` (signing) the millisecond they are captured.
- [ ] **Chronos Hardware Sync:** Utilize PTP (Precision Time Protocol) where available to minimize `ClockSkew` rejections at the Guardian layer.

## 4. Deterministic Recovery (State Checkpointing)

*Objective: Prevent data loss in the Sentinel reassembly layer during crashes.*

- [x] **Crucible Checkpointing:** Implement a periodic "Freeze" of `ReassemblyBuffer` states to the WAL.
- [x] **Sentinel Resumption:** Allow the `Sentinel` to reconstruct partial video/audio shards from the WAL upon process restart.
- [x] **WAL Compaction:** Implement a cleanup task to prune WAL entries that have been successfully promoted to the `Guardian` vault.

## 5. Resource & Performance Audit

*Objective: Eliminate blocking I/O and potential async deadlocks.*

- [x] **Tokio FS Migration:** Transition all `std::fs` calls in `vault.rs` to `tokio::fs` or `spawn_blocking` to prevent executor starvation.
- [x] **Circular Dependency Audit:** Map `Arc` and `RwLock` hierarchies between `Swarm` and `Guardian` to ensure no recursive locking exists.
- [x] **Real-World Quotas:** Replace `TODO: Real disk check` with a `sysinfo` integration to monitor hardware mount points.

---

> **Guiding Principle:** Logic must be deterministic. Given the same input and state, the output must be identical across all nodes.
