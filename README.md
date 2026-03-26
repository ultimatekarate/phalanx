[![CI](https://github.com/ultimatekarate/phalanx/actions/workflows/android-build.yml/badge.svg)](https://github.com/ultimatekarate/phalanx/actions/workflows/android-build.yml)
[![iOS](https://github.com/ultimatekarate/phalanx/actions/workflows/ios-build.yml/badge.svg)](https://github.com/ultimatekarate/phalanx/actions/workflows/ios-build.yml)

# Phalanx

Mobile-first, cross-platform forensic evidence provenance system. Phalanx captures, verifies, and distributes forensic evidence across a peer-to-peer mesh with cryptographic integrity guarantees at every layer. The stronghold binary provides forensic corroboration — determining whether distinct videos from independent devices observed the same event.

## Architecture

The codebase is governed by a [Linguistic Code Model](linguistic-code-model.md) that partitions all code by linguistic role. Crate boundaries are structural — the compiler enforces them, not convention.

| Crate | Role | Description |
| --- | --- | --- |
| `phalanx-proto` | Dictionary (Nouns) | Data types, trait contracts, error types. No IO. |
| `phalanx-forensics` | Laboratory (Verbs) | Verification, validation, state machines, crypto. No `tokio::fs`. |
| `phalanx-transport` | Post Office (Prepositions) | Network adapters, routing, peer mapping, wire codecs. |
| `phalanx-node` | Sentence | Actors, persistence, orchestration. Environment-dependent. |
| `phalanx-lens` | Optics | Camera and media capture pipeline. |
| `phalanx-ffi` | FFI Bridge | C ABI surface for iOS and Android. |
| `phalanx-stronghold` | Vault | At-rest encrypted storage for witness envelopes. |
| `phalanx-sim` | Simulator | Network simulation and adversarial testing. |
| `phalanx-test-fixtures` | Phrasebook | Synthetic test data satisfying validation preconditions. |

## Capabilities

- **Real-time capture-to-mesh pipeline** — Camera frames flow through L1-cache-native forensic analysis (PRNU, Moire — benchmarked at 150μs), compress (YCbCr JPEG, no RGB conversion), encrypt (XChaCha20-Poly1305), fountain-code (RaptorQ), and publish to the mesh — non-blocking, backpressure-aware, with power-state FPS throttling
- **Trusted communities** — Decentralized trust circles with k-of-n quorum vouch requirements, Ed25519-signed member attestations, deterministic community fingerprints, ephemeral lifecycle with zeroize dissolution
- **Fountain-coded sharding** — RaptorQ erasure coding with self-describing OTI headers. Shard ingestion is order-independent (proven in Lean 4)
- **ECDH grant authority** — Ed25519→X25519 key exchange with AAD-protected permission grants. Two-layer encryption: XChaCha20-Poly1305 in-flight and at-rest
- **Type-state forensic units** — `ForensicUnit<T, State>` with compile-time `Unverified → Verified → Sealed` enforcement
- **Volterra backpressure** — 8-integral coupled system with physically-derived decay half-lives (0.17s–69s), IWFQ trust-weighted preemption, hysteretic power-state transitions
- **Byzantine detection via spectral lie** — Honest nodes live on an 8-dimensional manifold defined by the coupled integral equations. A dishonest node can claim state, but the coupling constraints are not independently satisfiable — the spectral gap of the Jacobian exposes fabricated state vectors
- **Stability guarantee** — Jacobian linearization with Dyson series transient propagation proves the 8-integral system remains bounded under adversarial conditions. Dormand-Prince RK4(5) adaptive integration handles nonlinear regimes when perturbation exceeds the linear threshold. Lyapunov exponent μ₁ < 0 certifies asymptotic stability — nodes cannot be driven into an unstable state
- **Formal verification** — Lean 4 proof of mold commutativity: `assemble()` produces identical output regardless of shard ingestion order
- **Ad hoc mesh network** — Devices form a self-organizing peer-to-peer mesh over QUIC, BLE, and WiFi Direct with no infrastructure dependency. Kademlia DHT for peer discovery, gossipsub for pub/sub overlay

## Emergent Properties

The coupled integral system produces behaviors that are not explicitly programmed:

- **Self-healing** — No recovery logic exists. When load drops, exponential decay drains the integrals, scalers recover, and throughput returns. Recovery is a consequence of `exp(-λt)`.
- **Natural load shedding order** — Untrusted peers shed first (hyperbolic endowment gate), then bandwidth-gated work, then memory, then storage, then CPU. This priority falls out of the Jacobian coupling coefficients, not from an explicit rule.
- **Sybil resistance with diminishing returns** — The endowment gate `ψ = ψ_max / (1 + k·e)` means each additional attacker contributes less pressure than the last. Flooding requires overwhelming bandwidth, not just peer count.
- **Phantom memory pressure** — Positive coupling `j[M,W]` causes memory to rise when storage backs up, even without direct allocation. Writes queue because they can't flush. The coupling coefficient creates this, not application logic.
- **Thermal throttling as a natural consequence** — Heat is an impulse into the system integral, which gates everything downstream. A phone throttles itself the same way it throttles a Sybil attack — by raising pressure in the coupled system.

## Build

```bash
cargo build --workspace
```

Minimum Rust version: **1.93.1**

## Test

```bash
cargo test --workspace
```

## Security Posture

Phalanx assumes zero trust at every boundary. No peer, device, or network path is trusted by default.

- **Every envelope is signed and verified** — evidence carries Ed25519 signatures from capture through reassembly. Nothing is accepted on claim alone.
- **Every payload is encrypted in transit and at rest** — two independent XChaCha20-Poly1305 layers with distinct keys
- **Every peer earns trust** — reputation scoring tracks invalid signatures, quota violations, and protocol deviations. Misbehaving peers are demoted or blocked.
- **Byzantine actors are mathematically detectable** — fabricated state is exposed via Jacobian analysis of the coupled integral system
- **Key material is ephemeral where possible** — ECDH grants use per-session derivation, stack intermediates are zeroized, community keys dissolve on expiration
- **The compiler enforces the posture** — workspace deny lints eliminate `unwrap`, `panic`, unchecked indexing, arithmetic overflow, and lock-holding-across-await at compile time. These are not conventions — they are build failures.

## Lint Governance

The workspace enforces deny-level clippy lints across all crates:

**Reliability** — `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`

**Data Integrity** — `cast_possible_truncation`, `arithmetic_side_effects`, `cast_sign_loss`, `cast_possible_wrap`, `float_cmp`

**Concurrency** — `await_holding_lock`

**Safety** — `undocumented_unsafe_blocks`

See `Cargo.toml` workspace lints for the full configuration.

## License

Not yet specified.
