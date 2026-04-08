# Phalanx Threat Model

Phalanx assumes the network is hostile, the device is vulnerable, and every peer is lying until proven otherwise. This document catalogs every attack the system defends against, the mechanism that stops it, and where the defense lives in code.

---

## 1. Evidence Fabrication

**Threat:** An attacker submits synthetic video, AI-generated frames, or screen-recaptured footage as genuine evidence.

**Defense:** LensGate (Gate 3)

Every video frame passes through a forensic sensor fingerprint analysis before it can enter the evidence pipeline.

- **PRNU detection.** Every physical camera sensor has a unique Photo Response Non-Uniformity noise pattern. The LensGate checks that incoming frames exhibit PRNU variance consistent with a real sensor. Frames with zero PRNU (bypass attempt) or low PRNU (synthetic/AI-generated) are rejected. Thresholds are calibrated per-device via a Bayesian online estimator that converges during normal recording — no setup step required.

- **Moire detection.** Screen recaptures produce characteristic interference patterns. The LensGate measures horizontal and vertical Moire energy via Laplacian edge detection. Natural scenes produce 5-40 energy units. Screen recaptures produce 40,000-50,000. The 400x gap makes this a high-confidence detector.

- **Auto-exposure resilience.** All thresholds scale by mean luminance at comparison time, so changing lighting conditions do not trigger false positives.

- **Re-verification.** Honest nodes can re-verify received evidence by decoding the JPEG payload to YUV420, re-running the ForensicLens, and checking the recomputed metrics against the LensGate. Spoofed metrics are caught because the pixel data does not support the claimed fingerprint.

**Files:** `phalanx-forensics/src/verification/gate.rs` (lines 194-391), `phalanx-forensics/src/pipeline/calibrate.rs`, `phalanx-lens/src/scalar.rs`

---

## 2. Signature Forgery and Tampering

**Threat:** An attacker modifies evidence in transit or forges the identity of the recording device.

**Defense:** Integrity Gate (Gate 2) + Hash Chain

Every evidence envelope is Ed25519-signed at creation and verified unconditionally on receipt.

- **Unconditional cryptographic verification.** The receiving node always verifies the Ed25519 signature against the claimed DID, regardless of prior trust. There is no "trusted peer" fast path that skips signature verification.

- **Unconditional temporal validation.** Timestamps are checked against the local trusted clock. Future-dated evidence is rejected. This prevents an attacker from pre-signing envelopes with future timestamps to corrupt the timeline.

- **Hash chain.** Each envelope carries `prev_hash`, the signature hash of the preceding envelope. The Continuity Gate (Gate 8) verifies this chain, detecting dropped, reordered, or injected envelopes. A break in the chain is a hard rejection.

- **Evidence hash binding.** Gate 7 (Coasting Gate) recomputes the BLAKE3 hash of the serialized evidence and compares it to the embedded `evidence_hash`. Any modification to the payload invalidates the hash.

**Files:** `phalanx-forensics/src/verification/gate.rs` (lines 110-170, 529-578), `phalanx-proto/src/evidence/envelope.rs`

---

## 3. Replay Attacks

**Threat:** An attacker re-submits previously valid evidence to inflate storage, corrupt recording sequences, or waste resources.

**Defense:** Rotating Bloom Filter

A two-generation probabilistic filter rejects evidence that has been seen recently.

- **Mechanism.** Two Bloom filters rotate on a timer. Evidence hashes are checked against both (current and previous). Insertions go into current only. On rotation, current becomes previous and a new current is allocated. This gives a detection window of approximately 2x the rotation interval.

- **Post-crash seeding.** On node restart, the Bloom filter is seeded from the most recent persisted evidence hashes (up to 50 per recording), preventing post-crash replay attacks.

- **Bounded memory.** Each generation uses 1,000,000 bits. At 10,000 insertions per rotation, the false positive rate is below 1%.

- **No cross-session tracking.** The filter is ephemeral and never persisted. Seizure of a powered-off device reveals no history of which evidence was processed.

**Files:** `phalanx-forensics/src/verification/bloom.rs`, `phalanx-node/src/actors/storage.rs` (seed_replay_filter)

---

## 4. Sybil Attacks

**Threat:** An attacker creates many fake identities to exhaust per-peer resource allocations or overwhelm the mesh with fraudulent peers.

**Defense:** Lorentzian Sybil Endowment + Entry Pressure Integral

The system tracks new peer arrivals as an exponentially decaying integral. As entry pressure rises, per-peer resource allocations shrink.

- **Entry pressure integral.** Each new peer arrival adds an impulse to the entry integral `e(t)`, which decays with a 7-second half-life. Under normal conditions, the integral stays low. During a Sybil flood, it spikes.

- **Lorentzian endowment.** Each peer's resource ceiling is `psi_max / (1 + k * (e / psi_max)^2)`. At low entry pressure, each peer gets the full ceiling (50 units). As entry pressure rises toward `psi_max / k`, the endowment halves. This is smooth, not a cliff — the system degrades gracefully under attack.

- **Reciprocity enforcement.** Peers that consume resources without contributing (non-reciprocal behavior) accumulate reputation penalties. A 10-minute grace period prevents false positives for newly joined peers.

**Files:** `phalanx-forensics/src/policy.rs` (lines 339-540), `phalanx-forensics/src/trust/evaluation.rs`

---

## 5. Eclipse Attacks

**Threat:** An attacker controls all peer slots, isolating the victim from the honest network.

**Defense:** Topology Gate + Passive Eclipse Detection

Two independent mechanisms — one preventive, one detective.

- **Subnet diversity enforcement (preventive).** The Topology Gate caps peers per subnet (e.g., max 2 from the same /24 CIDR block) and enforces a dynamic transport class balance between local mesh and internet peers. An attacker cannot fill all slots from a single network region.

- **Mesh fingerprinting (detective).** The Eclipse Probe periodically snapshots the peer set as a lightweight fingerprint: a BLAKE3 hash of sorted peer IDs, peer count, and subnet distribution. If the peer set hash has not changed across 3+ consecutive snapshots (stagnation) AND more than 60% of peers share 2 or fewer subnet buckets (concentration), the risk escalates to Critical. Elevated risk triggers defensive peer rotation.

- **Anchor persistence.** Trusted peers that have been promoted to anchor status cannot be evicted by the admission system. Promotion requires an `AnchorEligible` proof with a reputation score above 0.5, making it expensive for an attacker to plant anchors.

**Files:** `phalanx-forensics/src/verification/topology_gate.rs`, `phalanx-forensics/src/trust/eclipse.rs`

---

## 6. Byzantine Peers

**Threat:** A peer claims one state (e.g., "I am under heavy load") while behaving differently (e.g., emitting data at high throughput).

**Defense:** Spectral Observer

Three independent behavioral consistency checks detect lying peers.

- **Check 1: Load-throughput consistency.** A peer claiming high load should emit less data. If observed throughput exceeds the predicted maximum for the claimed load, the peer is inconsistent.

- **Check 2: Heartbeat regularity.** Under genuine high load, heartbeat intervals become more variable (higher coefficient of variation). A peer claiming high load but maintaining suspiciously regular heartbeats is likely simulating load.

- **Check 3: Leaf state contradiction.** A peer claiming leaf mode (local-only, no relay) should not be sending data to the network. More than 10 KB of outbound data in the observation window contradicts the claim.

- **Residual composition.** Each check produces a squared error. The spectral residual is `sqrt(e1^2 + e2^2 + e3^2)`. When the residual exceeds the anomaly threshold (0.3), a SpectralAnomaly offense is recorded against the peer, feeding into reputation decay.

**Files:** `phalanx-node/src/vitals/spectral.rs`

---

## 7. Resource Exhaustion

**Threat:** An attacker overwhelms the node's CPU, memory, bandwidth, storage, or connections.

**Defense:** Coupled Volterra Integral System + Traffic Governors

Eight exponentially decaying integrals track resource pressure across independent dimensions. The integrals couple through the Jacobian — pressure in one resource propagates to others.

| Integral | Resource | Half-life | Critical threshold |
| ---------- | ---------- | ----------- | ------------------- |
| s | CPU contention | 170ms | 10.0 |
| d | I/O flush cycles | 1.4s | — |
| l | Latency (RTT) | 700ms | — |
| m | Memory | 2.3s | 12.5% of RAM |
| b | Bandwidth | 1.4s | 100 MiB/tick |
| w | Storage (WAL) | 14s | 80% utilization |
| c | Connections | 3.5s | 90% utilization |
| e | Peer entry (Sybil) | 7.0s | — |

Each integral uses the exact exponential update `I(t+dt) = impulse + I(t) * exp(-lambda * dt)`, avoiding Euler discretization errors that would accumulate at the fast tick rates (170ms half-life with 1s ticks gives lambda*dt = 4.08 — Euler would explode).

Three traffic governors translate integral pressure into admission decisions:

- **IngressGovernor.** Under nominal stress: full slot capacity. Under fair stress: 1/3 capacity. Under serious/critical: 1 slot, restricted to Ally or Verified peers only. When at capacity, the lowest-trust peer is evicted (IWFQ preemption).

- **TrafficGovernor.** In Leaf or Dormant power states, only loopback traffic is accepted. All relay traffic is rejected to conserve battery.

- **EgressGovernor.** Rejects outbound evidence under critical stress or to blocked/ignored peers. Encryption is a mandatory side effect of egress authorization — the type system makes it impossible to transmit unencrypted evidence.

**Files:** `phalanx-forensics/src/policy.rs`, `phalanx-node/src/vitals/governor.rs`, `phalanx-node/src/vitals/config.rs`

---

## 8. Plaintext Evidence Leakage

**Threat:** Evidence is intercepted in transit or extracted from storage without authorization.

**Defense:** Per-Recording Encryption + Grant System + Privacy Gate

- **Per-recording keys.** Each recording gets its own XChaCha20-Poly1305 symmetric key. Keys are stored in a keyring that is persisted to disk and loaded on restart.

- **Mandatory encryption on egress.** The Privacy Gate (Gate 4) applies encryption before any evidence leaves the node. The EgressGovernor's `.seal()` method — the only path to a `Sealed` forensic unit — requires encryption to have been applied. This is enforced by the type system: you cannot construct a `ForensicUnit<T, Sealed>` without going through the governor.

- **Grant-based selective sharing.** Per-recording keys can be sealed for specific recipients using ECDH over Curve25519 with XChaCha20-Poly1305. Permissions are bound into the authenticated additional data (AAD), so they cannot be modified after sealing.

- **Idempotent encryption.** `apply_encryption()` is a no-op on already-encrypted payloads, preventing double-encryption bugs.

**Files:** `phalanx-forensics/src/verification/judge.rs`, `phalanx-forensics/src/verification/gate.rs` (Privacy Gate), `phalanx-forensics/src/cryptography/grant.rs`

---

## 9. Forced Evidence Retention

**Threat:** A user cannot delete their own recordings, or deletion is reversible.

**Defense:** Cryptographic Forgetting via BIP39 Mnemonic

- **Mnemonic-derived revocation key.** During identity creation, a 12-word BIP39 mnemonic derives both a signing keypair (bytes 0-31) and a revocation keypair (bytes 32-63). The mnemonic is shown to the user once and never stored on the device.

- **Self-contained revocation tokens.** The user provides the mnemonic, the system derives the revocation signing key, signs a token binding the recording ID and a timestamp, and zeroizes the mnemonic from memory. The token is self-verifying — any node can validate it against the revocation public key embedded in the original evidence envelope, with no central authority.

- **Key destruction.** Revocation triggers destruction of the per-recording encryption key. Without the key, the encrypted evidence is unrecoverable. Key destruction is persisted to the journal and propagated across the mesh via gossipsub.

- **Ghost key cleanup.** On restart, the storage actor scans for revoked recordings that still have content keys (from a partial crash) and destroys them.

**Files:** `phalanx-forensics/src/trust/revocation.rs`, `phalanx-ffi/src/forget.rs`, `phalanx-node/src/actors/storage.rs` (cleanup_ghost_keys)

---

## 10. Unauthorized Mesh Access

**Threat:** An unauthorized device joins the mesh and begins receiving evidence.

**Defense:** Pre-Shared Key + Trust Gating

- **PSK enforcement.** When `require_psk` is set, the node refuses to start without a valid 32-byte swarm key. Only peers with the correct key can establish libp2p connections.

- **Trust Gate (Gate 0).** The first gate in the verification pipeline checks the sender's reputation. Blacklisted peers are rejected before any cryptographic verification is attempted.

- **Offense-driven blacklisting.** Protocol violations accumulate reputation penalties. An invalid signature costs 101 points — enough to blacklist in a single offense. Blacklisted peers require manual pardon; there is no automatic recovery.

**Files:** `phalanx-node/src/psk.rs`, `phalanx-forensics/src/verification/gate.rs` (lines 69-84), `phalanx-forensics/src/trust/evaluation.rs`

---

## 11. Custody Chain Tampering

**Threat:** A recording's ownership is changed without the consent of both parties.

**Defense:** Dual-Signed Handover

Custody transfers require co-signatures from both the old and new identity.

- **Mechanism.** The recording ID, sequence, old DID, new DID, and an anchor hash are serialized into a deterministic manifest. BLAKE3 hashes the manifest. Both the old identity and the new identity sign the hash independently. Verification reconstructs the manifest, re-hashes, and checks both signatures.

- **Ownership tracking.** The Crucible's `RecordingAmalgam` tracks custody state as `Tentative -> Authoritative`, requiring a valid handover proof for the transition.

**Files:** `phalanx-forensics/src/storage/handover.rs`

---

## 12. Peer Disappearance During Recording

**Threat:** A collaborating peer goes dark during a recording session — either voluntarily (seized device, dead battery) or due to network partition.

**Defense:** Silent Canary

A dead man's switch that monitors mesh presence and heartbeat staleness.

- **Two-stage confirmation.** Disconnection alone is not sufficient — transient network blips are common. The canary requires both mesh disconnection AND consecutive heartbeat staleness ticks before confirming a peer as silent.

- **Alert payload.** When a peer is confirmed dark, the canary reports which peers went silent, which recordings they were contributing to, and how many peers remain.

- **Ephemeral state.** The canary stores nothing to disk. Seizure of a powered-off device reveals no roster of collaborating peers, no NetworkId-to-DID mapping, and no history of who was present.

**Files:** `phalanx-node/src/vitals/canary.rs`

---

## 13. Crash-Induced Denial of Service

**Threat:** A malformed network packet, integer overflow, or unexpected input crashes the node, preventing evidence recording when it matters.

**Defense:** Panic-Free Codebase

The workspace enforces deny-level clippy lints that make panics a compile error.

| Lint | What it prevents |
| ------ | ----------------- |
| `unwrap_used` / `expect_used` | Panic on None/Err |
| `indexing_slicing` | Out-of-bounds panic from malformed packet lengths |
| `arithmetic_side_effects` | Silent integer overflow corrupting sequence numbers |
| `cast_possible_truncation` | Bit truncation from narrowing casts |
| `panic` | Explicit panics, `unreachable!()`, `todo!()` |
| `await_holding_lock` | Deadlocks on the tokio runtime |

Every error path returns `Result` or uses saturating arithmetic. There is no actor supervision system because there is nothing to supervise — the code cannot panic in production. Software that crashes is software that cannot record when it needs to.

**Files:** `Cargo.toml` (workspace lint configuration), `CONTRIBUTING.md` (developer guidance)

---

## 14. Data Validation Bypass

**Threat:** An internal code path processes evidence that has not passed verification, or transmits evidence that has not been authorized for egress.

**Defense:** Typestate Enforcement

The type system makes invalid state transitions a compile error.

- **Three states.** `ForensicUnit<T, Unverified>`, `ForensicUnit<T, Verified>`, `ForensicUnit<T, Sealed>` are distinct types. You cannot pass a `Verified` unit to a function expecting `Sealed`, or vice versa.

- **Promotion.** `Unverified -> Verified` requires passing through the Promotion Gate (Gate 9), which orchestrates the Integrity Gate, Coasting Gate, and Continuity Gate in sequence.

- **Sealing.** `Verified -> Sealed` requires the EgressGovernor's `authorize()` method — the only code path that calls `.seal()`. The `.seal()` method has `pub(crate)` visibility, so no code outside the forensics crate can construct a Sealed unit.

- **Invariant.** If evidence is on the wire, it is `Sealed`. If it is `Sealed`, it passed the full gate chain. This is not a convention — it is enforced by the Rust compiler.

**Files:** `phalanx-proto/src/types.rs` (state definitions), `phalanx-forensics/src/verification/gate.rs` (promotion), `phalanx-forensics/src/policy.rs` (sealing)

---

## 15. Configuration Tampering

**Threat:** An attacker modifies the node's configuration file to weaken security settings (disable PSK, change vault path, alter topic routing).

**Defense:** Compiled Defaults + Explicit Opt-In

- **No config file by default.** The node starts with compiled defaults. No configuration file ships with the application.

- **Explicit opt-in.** A config file is only loaded if the `PHALANX_CONFIG` environment variable is explicitly set. If set but the file fails to parse, the node logs a warning and falls back to compiled defaults — it never silently runs with a partial or corrupt config.

- **Unknown field rejection.** All config structs use `#[serde(deny_unknown_fields)]`. A stale or typo'd key in a config file is a hard parse error, not a silent no-op.

**Files:** `phalanx-node/src/config.rs`

---

## 16. Compromised Recording Device (Graphite-Class Spyware)

**Threat:** The recording device is infected with mercenary spyware (Paragon Graphite, NSO Pegasus, or similar). The attacker has OS-level access and can read process memory, hook system frameworks, and exfiltrate data. This is a fundamentally different threat class from the previous fifteen — the device itself is adversarial.

**Defense:** Defense-in-Depth (Cross-Device Corroboration + Device Integrity Attestation)

No single defense can protect against a fully compromised operating system. Phalanx layers multiple mechanisms so that a compromised device is detectable after the fact and its damage is bounded.

### 16a. Pre-Encryption Evidence Interception

The spyware reads evidence frames from process memory before the Privacy Gate (Gate 4) applies XChaCha20-Poly1305 encryption.

- **Per-recording key isolation.** Each recording uses an independent symmetric key. Compromising one recording does not expose others.
- **BIP39 revocation.** Once compromise is detected, the RevocationToken system allows cryptographic deletion of all evidence from the compromised recording. The revocation key is derived from the recorder's BIP39 mnemonic (seed bytes [32..64]).
- **Zeroize.** Sensitive buffers are zeroized after use, reducing the window for memory scraping.

**Residual risk: Accepted, not mitigated.** If the OS kernel is compromised, the attacker reads process memory. Application-layer defenses cannot prevent this. The mitigation path is hardware-backed keystores (Secure Enclave / Android Keymaster) — future work.

### 16b. Sensor Metric Fabrication

The spyware hooks the camera pipeline or ForensicLens analysis to inject fabricated PRNU/Moiré metrics, making synthetic evidence appear genuine.

- **Re-verification by honest receivers.** The `verify_provenance_from_jpeg()` function allows any honest receiving node to decode the JPEG payload to YUV420, re-run ScalarLens, and check recomputed metrics against the claimed values. Spoofed metrics are caught because the pixel data does not support the claimed fingerprint.
- **Corroboration KS-test.** The `corroborate()` function performs pairwise Kolmogorov-Smirnov tests on PRNU distributions. A compromised device's fabricated PRNU profile will fail divergence testing against genuine profiles from other devices.
- **Bayesian PRNU posterior.** `check_provenance_bayesian()` detects sudden shifts in a device's PRNU characteristics that do not match its historical model.

**Residual risk:** If the spyware also injects fake sensor noise into the pixel data itself (not just the metrics), single-device re-verification is defeated. Cross-device corroboration remains the strongest defense — fabricating consistent sensor noise across multiple independent devices is infeasible.

### 16c. Encryption Key Exfiltration

The spyware extracts per-recording XChaCha20-Poly1305 symmetric keys or the Ed25519 signing key from memory.

- **Per-recording key isolation** limits blast radius to one recording.
- **BIP39 revocation** enables post-discovery cryptographic deletion.
- **Zeroize** on all key material reduces the exfiltration window.

**Residual risk: Accepted, not mitigated.** Same TEE boundary as 16a. Keys that never leave a Trusted Execution Environment cannot be exfiltrated via application-level spyware. Hardware keystore integration is future work.

### 16d. Fabricated Evidence Injection

The spyware creates fake WitnessEnvelopes signed with the device's stolen Ed25519 key and injects them into the mesh.

- **Hash chain (Gate 8).** Each envelope carries `prev_hash`. Injected envelopes must link to the real chain. An attacker who does not know the current chain head produces a break — a hard rejection.
- **Temporal freshness (Gate 2).** Timestamps are checked against the local trusted clock. Future-dated or stale evidence is rejected.
- **Bloom filter.** Prevents replay of previously seen envelopes.
- **Spectral Observer.** Detects behavioral anomalies like sudden evidence bursts from a device that was previously idle.

**Residual risk:** An attacker with full device access knows the current chain head and can produce valid continuations. Cross-device corroboration is required to detect fabricated content.

### 16e. Shadow Node Impersonation

The spyware exfiltrates the Ed25519 signing key. The attacker operates a shadow node impersonating the compromised device from a different network location.

- **`IdentityTheft` offense.** The existing offense type triggers immediate blacklisting (101 points).
- **Eclipse detection.** The `EclipseProbe` detects anomalous changes in peer set composition.
- **ProximityWitness BLE auth.** BLE mutual authentication verifies physical presence — a remote impersonator cannot produce valid proximity witnesses.
- **`DualPresence` offense (new).** Detects simultaneous evidence arrival from the same DID at geographically incompatible network locations. Type defined in this iteration; detection logic deferred (requires `Did -> Set<NetworkId>` tracking in MeshSentinel and heuristics to distinguish key theft from NAT/mobile-network transitions).

### Explicit Non-Goals

The following are outside application-layer scope:

- **OS kernel compromise prevention.** Phalanx cannot prevent a rootkit from reading process memory. The mitigation path is hardware-backed keystores (future work).
- **Firmware/baseband compromise.** A compromised baseband processor or secure enclave is below the application's trust boundary.
- **Supply chain attacks on the Phalanx binary.** A trojanized build of the application itself is outside the runtime threat model.

**Files:** `phalanx-forensics/src/verification/gate.rs` (re-verification, LensGate), `phalanx-forensics/src/trust/corroboration.rs` (KS-test, corroboration), `phalanx-proto/src/identity/trust.rs` (DualPresence offense)

---

## Defense-in-Depth Summary

An evidence envelope entering the system passes through this chain before it can be stored or retransmitted:

```
Wire bytes
  -> Gate 0a: Deserialization size limit (64 MiB)
  -> Gate 0b: Wire bounds structural validation
  -> Gate 0:  Trust standing (blacklist check)
  -> Gate 2:  Ed25519 signature + temporal freshness
  -> Gate 3:  PRNU sensor fingerprint + Moire screen recapture (Video)
  -> Gate 7:  BLAKE3 evidence hash recomputation
  -> Gate 8:  Hash chain causality verification
  -> Gate 9:  Typestate promotion (Unverified -> Verified)
  -> Bloom:   Replay filter
  -> Ingress: Capacity + trust-weighted slot allocation
  -> Vault:   Per-recording XChaCha20-Poly1305 encryption
```

Outbound evidence passes through the reverse chain:

```
Verified evidence
  -> EgressGovernor: Stress gate + trust gate
  -> Privacy Gate:   Mandatory encryption (type-enforced)
  -> .seal():        Typestate promotion (Verified -> Sealed)
  -> Wire
```

The gates are monadic — each one returns `Result`, and a rejection at any stage short-circuits the pipeline. There is no fallthrough. There is no override.
