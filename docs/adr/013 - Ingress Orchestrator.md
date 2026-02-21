# ADR 005: Unified Ingress Orchestration and Trust Delegation

## Status

Accepted

## Context

Following the refactoring of the `Guardian` (persistent storage) and `Sentinel` (transient buffer) layers to be strictly stateless, a "logic gap" emerged. These layers correctly identify protocol violations (cryptographic failures, signature mismatches, quota breaches) but no longer possess the authority to penalize peers or manage reputation.

In the production environment (`PhalanxEngine`), this logic was handled by intercepting errors in the event loop. However, the simulation harness (`SimNode`) utilized a divergent loop, leading to a failure in forensic telemetry during "Vampire Attack" testing. The simulation was rejecting malicious chunks but failing to update the `TrustRegistry`, thereby never reaching the blacklist threshold required for test assertions.

## Decision

We will implement a shared `IngressOrchestrator` located in `src/security/ingress.rs`. This component will serve as the single source of truth for the data ingestion pipeline across all execution environments.

### Architectural Patterns

1. **Parameter Object Pattern:** To avoid "Parameter Bloat" in the async pipeline, we encapsulate environment state into `IngressContext` and mutable security state into `SecurityPipeline`.
2. **Unified Interception:** All `ShardError` (Sentinel) and `GuardianError` (Vault) variants are mapped to stateful `Offense` types within this orchestrator.
3. **Transport Agnosticism:** The orchestrator is decoupled from `libp2p` or `mpsc` specifics, allowing it to function identically in physical hardware nodes and logical simulation actors.

## Technical Structure

### Parameter Objects

- **`IngressContext`**: Contains immutable data: `PhalanxConfig`, `PhalanxIdentity`, `NetworkId`, and `TrustedClock`.
- **`SecurityPipeline`**: Contains mutable references to the core state machines: `Sentinel`, `Guardian`, and `TrustRegistry`.

### Error Mapping

- `GuardianError::InvalidSignature` -> `Offense::InvalidSignature`
- `ShardError::SigningError` -> `Offense::InvalidSignature`
- `GuardianError::QuotaExceeded` -> `Offense::QuotaExceeded`
- `ShardError::Serialization` -> `Offense::MalformedPacket`

## Consequences

### Positive

- **Behavioral Parity:** Simulation tests now provide 100% fidelity to production security behavior.
- **Reduced Complexity:** Both `PhalanxEngine` and `SimNode` actor loops are simplified by delegating complex match-arms to the orchestrator.
- **Auditability:** Security researchers can audit the entire ingress gating flow in a single file (`ingress.rs`).

### Negative

- **Borrowing Complexity:** The use of mutable references for the `SecurityPipeline` requires careful lifetime management (handled via Rust's `'a` lifetime annotations).

## Alternatives Considered

- **Internalizing Trust in Guardian/Sentinel:** Rejected to maintain the "Statelessness by Default" principle, which is required for deterministic recovery and clean state checkpointing.
- **Trait-based Orchestration:** Considered, but direct implementation with Parameter Objects was chosen for better performance and reduced abstraction overhead in high-concurrency loops.
