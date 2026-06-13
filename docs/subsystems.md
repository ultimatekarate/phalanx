# Phalanx Subsystem Map

> New to Phalanx? Start with [architecture.md](architecture.md) for orientation — this file is the per-subsystem code index.

Phalanx is built from 34 subsystems. Each one does exactly one thing. The [Linguistic Code Model](../linguistic-code-model.md) prevents them from growing into each other — crate boundaries make entanglement a compiler error, not a code review finding. This document maps every subsystem, what it does, and where it lives.

---

## Evidence Lifecycle

How evidence moves from camera sensor to encrypted storage to shared proof.

### ForensicLens

Analyzes raw camera pixels for sensor fingerprint (PRNU variance) and screen recapture artifacts (Moiré energy). Runs on a 256×256 center crop that fits in L1 cache. Benchmarked at 150μs per frame.

**Files:** `phalanx-lens/src/scalar.rs`

### Witness Authority

Signs evidence into envelopes with Ed25519 and chains them via signature hashes. Every envelope carries a cryptographic proof of who created it and what came before it.

**Files:** `phalanx-forensics/src/pipeline/witness.rs`

### Reassembler

Fountain code reconstruction. Collects RaptorQ symbols from the network and decodes them into complete evidence envelopes. Symbols are self-describing — the decoder initializes from any received symbol with no ordering dependency.

**Files:** `phalanx-forensics/src/pipeline/reassembler.rs`

### Crucible

Generic streaming accumulator. Holds a map of keys to work contexts and delegates all domain logic to a `Mold` strategy. Used twice in series: `Crucible<ShardMold>` reassembles symbols into envelopes, `Crucible<RecordingAmalgam>` assembles envelopes into recordings with ownership tracking.

**Files:** `phalanx-forensics/src/pipeline/crucible.rs`

### Guardian Vault

Encrypted disk storage for forensic evidence. Manages per-recording encryption keys, per-DID storage quotas, and a storage ledger that tracks capacity. Owns the in-memory Crucible and the on-disk recording logs.

**Files:** `phalanx-node/src/persistence/vault/mod.rs`, `vault/crypto.rs`, `vault/recording_log.rs`, `vault/wal.rs`

### Revocation

Cryptographic forgetting. A 12-word mnemonic derives a one-time revocation signing key that is never stored. The signed token triggers destruction of the per-recording encryption key before the data is removed. Propagates across the mesh.

**Files:** `phalanx-forensics/src/trust/revocation.rs`

### Media Transcoding

Converts JPEG video frames and PCM audio into H.264+AAC MP4 containers with aggregated forensic metrics. Pure computation — no IO.

**Files:** `phalanx-forensics/src/pipeline/transcode.rs`

---

## Cryptography

Identity, key management, and selective sharing.

### Identity Management

BIP39 mnemonic generation and restoration. Derives an Ed25519 signing keypair from the first 32 bytes of the seed and a revocation keypair from the second 32 bytes. Persists to disk with passphrase encryption.

**Files:** `phalanx-node/src/identity.rs`

### Cryptographic Bridge

Converts Ed25519 signing keys to X25519 encryption keys via Edwards→Montgomery point decompression. This is what allows a single DID identity to both sign evidence and participate in key exchange.

**Files:** `phalanx-forensics/src/cryptography/bridge.rs`

### Grant Authority

Seals per-recording encryption keys for specific recipients using ECDH over Curve25519 with XChaCha20-Poly1305. Permissions are bound into the authenticated additional data so they cannot be modified after sealing.

**Files:** `phalanx-forensics/src/cryptography/grant.rs`

### Payload Cipher

Symmetric encryption and decryption of evidence payloads. XChaCha20-Poly1305 with idempotent application — already-encrypted payloads are passed through unchanged.

**Files:** `phalanx-forensics/src/verification/judge.rs`

---

## Trust and Detection

Who to believe, who to reject, and how to tell the difference.

### Monadic Gates

Composable verification pipeline. Each gate makes a single accept/reject decision. Gates chain monadically — if any gate rejects, the pipeline short-circuits. LensGate checks sensor provenance. IntegrityGate verifies signatures and timestamps. PromotionGate advances evidence through the `Unverified → Verified` typestate. ContinuityGate validates the hash chain.

**Files:** `phalanx-forensics/src/verification/gate.rs`

### Traffic Governors

Three governors that make per-request policy decisions. IngressGovernor allocates slots with IWFQ trust-weighted preemption. TrafficGovernor filters by power state. EgressGovernor authorizes outbound evidence — and encryption is a mandatory side effect of authorization, enforced by the type system.

**Files:** `phalanx-forensics/src/policy.rs`

### Topology Gate

Per-peer admission control for eclipse attack defense. Enforces subnet diversity and transport class quotas so no single network region can dominate the peer set.

**Files:** `phalanx-forensics/src/verification/topology_gate.rs`

### Bloom Filter

Rotating probabilistic replay protection. Two-generation window with bounded memory (~250KB). Evidence hashes are checked after reassembly — retransmitting the same envelope is rejected without storing every hash forever.

**Files:** `phalanx-forensics/src/verification/bloom.rs`

### Eclipse Detection

Passive mesh fingerprint consistency checking. Detects when an attacker is trying to partition a node from the honest network by monitoring the peer set for suspicious changes.

**Files:** `phalanx-forensics/src/trust/eclipse.rs`

### Offense and Reputation

Fixed penalty matrix mapping protocol violations to score reductions. Quota exceeded costs 25 points. Invalid signature costs 101 — enough to blacklist in one shot. Feeds into the Trust Registry and the per-peer reputation integrals.

**Files:** `phalanx-forensics/src/trust/evaluation.rs`

### Trust Registry

Per-peer reputation database with community-aware trust elevation. A peer's effective trust level is the higher of their individual reputation and their community membership standing. Fail-secure on lock poisoning — a poisoned lock is treated as blacklisted.

**Files:** `phalanx-node/src/trust.rs`

---

## Adaptive Control

Self-regulation, stability, and Byzantine detection.

### Coupled Integral System

Eight Volterra second-kind integrals with exponential decay, each measuring a different resource: CPU, IO, latency, memory, storage, bandwidth, connections, and peer entry rate. The integrals are coupled through the Jacobian — pressure in one resource propagates to others. Physically-derived half-lives range from 170ms (CPU) to 69s (reputation). This is the nervous system.

**Files:** `phalanx-node/src/vitals/governor.rs`, `phalanx-node/src/vitals/config.rs`

### Stability Analysis

Diagnostic tooling for the integral system. Jacobian linearization, eigenvalue computation via QR iteration, Padé approximants, Dyson series expansion. Verifies that the coupled system remains stable under all operating conditions. Not runtime — analysis only.

**Files:** `phalanx-node/src/stability/jacobian.rs`, `stability/eigenvalues.rs`, `stability/spectral.rs`, `stability/pade.rs`, `stability/dyson.rs`, `stability/nonlinear.rs`, `stability/config.rs`

### Spectral Observer

Three-axis behavioral consistency check for Byzantine detection. Compares each peer's claimed load against their observed throughput, heartbeat regularity, and leaf-state behavior. Inconsistencies accumulate as spectral residuals that feed into per-peer reputation integrals.

**Files:** `phalanx-node/src/vitals/spectral.rs`

### Silent Canary

Community-scoped dead man's switch. Requires both mesh disconnection and heartbeat staleness before alerting — prevents false positives from transient network blips. Tracks which peers went dark and which recordings they contributed to. All state is ephemeral — seizure of a powered-off device reveals nothing.

**Files:** `phalanx-node/src/vitals/canary.rs`

### Trusted Clock

NTP-synchronized system clock with fallback to last-known-good timestamp. Global time authority for all evidence timestamps. Maintains an offset between local and network time so a node that loses NTP connectivity continues producing valid timestamps.

**Files:** `phalanx-node/src/clock.rs`

---

## Corroboration

Proving that independent devices observed the same event.

### PRNU Calibration

Derives a per-sensor fingerprint threshold from calibration frames. Statistical filter with three-sigma confidence margin. Rejects mixed-sensor calibration sets. The threshold gates all subsequent authenticity checks.

**Files:** `phalanx-forensics/src/pipeline/calibrate.rs`

### Corroboration Gate

Multi-device independence verification using Kolmogorov-Smirnov statistical testing. Compares PRNU profiles across recordings to confirm they came from different physical sensors observing the same event within a temporal window. Pure laboratory logic — no IO.

**Files:** `phalanx-forensics/src/trust/corroboration.rs`

### C2PA Extensions

Embeds Phalanx forensic assertions — node identity, lens metrics, corroboration proof — into C2PA content authenticity manifests. Three tiers: basic, with-lens, with-corroboration.

**Files:** `phalanx-forensics/src/pipeline/c2pa_ext.rs`

### Handover Authority

Dual-signed custody transfer between device identities. When a recording's ownership changes hands, both the old and new identity co-sign a BLAKE3-hashed manifest. The Crucible's `RecordingAmalgam` tracks this as a `Tentative → Authoritative` ownership transition.

**Files:** `phalanx-forensics/src/storage/handover.rs`

---

## Infrastructure

Networking, storage, capture, and testing.

### Transport and Mesh

libp2p swarm with QUIC primary and TCP fallback. Gossipsub for pub/sub, Kademlia DHT for peer discovery, mDNS for local discovery, relay and hole-punching for NAT traversal. Connection limits, peer scoring, and PSK support for private networks.

**Files:** `phalanx-transport/src/factory.rs`, `transport/src/builder.rs`, `transport/src/behaviour.rs`

### Kademlia Governor

Reputation-weighted DHT provider insertion with temporal decay. When the provider set is full, the lowest-reputation peer is evicted. Peers with accumulated spectral anomalies are naturally excluded from DHT results.

**Files:** `phalanx-transport/src/kademlia.rs`

### Hardware Capture

Adaptive camera and audio capture with power-state FPS duty cycling. FPS ramps up instantly but ramps down smoothly over one second to avoid visible stuttering. Audio uses a watchdog+driver thread pattern with broadcast channels for multi-subscriber output.

**Files:** `phalanx-node/src/hardware/camera.rs`, `hardware/audio.rs`

### File Journal and Outbound Queue

WAL-backed persistence. FileJournal wraps async file IO with vault key encryption. OutboundQueue is a persistent retry queue for failed mesh publishes with exponential backoff, idempotent drain, and a 10-attempt abandonment limit. Queue depth feeds storage pressure into the integral system.

**Files:** `phalanx-node/src/persistence/journal.rs`, `persistence/outbound.rs`

### Actor System

Eight node-side actors and three stronghold-side actors communicating via bounded mpsc channels with oneshot request/reply. MeshSentinel orchestrates. SystemGovernor is shared via Arc — no channel needed for pressure signals. See [actors.md](actors.md) for the full reference.

**Files:** `phalanx-node/src/actors/*`, `phalanx-stronghold/src/actors/*`

### Trusted Communities

Quorum-based membership with Ed25519 vouches. Community identity is deterministic — a hash of the membership graph, not a central keypair. k-of-n existing members must vouch for each new member. Communities expire automatically and dissolve with zeroization.

**Files:** `phalanx-proto/src/identity/community.rs`, `phalanx-stronghold/src/actors/community.rs`

### Stronghold Operations

Server-side one-shot operations for grant decryption, corroboration proof assembly, and C2PA-packaged export. Zeroizes decrypted key material on drop. Re-verifies grant-community bindings at execution time — zero trust even on the server.

**Files:** `phalanx-stronghold/src/ops/corroborate.rs`, `phalanx-stronghold/src/ops/export.rs`

### Simulation Harness

Spawns real MeshSentinel instances with virtual transport and deterministic clock. Tests run against the actual actor system with in-memory channels replacing libp2p. Reproducible by design.

**Files:** `phalanx-sim/src/harness.rs`, `sim/src/world.rs`, `sim/src/clock.rs`, `sim/src/physics.rs`

### DHT Payload Authority

Serialization, validation, and expiration checking for DHT payloads. Self-describing format with ownership verification. Laboratory logic — the transport layer delivers payloads without understanding them.

**Files:** `phalanx-forensics/src/kademlia.rs`
