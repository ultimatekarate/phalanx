# Architecture Decision Record (ADR)

## Title: ADR-014: Decoupling of Ingestion and Finalization Pipelines via Sentinel/Guardian Split

**Status:** Accepted and Implemented (Phase 4)
**Date:** February 20, 2026

## Context

The legacy iteration of the Phalanx Core utilized a monolithic collaborative storage model. Ingestion of raw network bytes, cryptographic validation, and persistent storage were tightly coupled. This architecture presented critical limitations regarding the Forensic Zero-Trust mandate:

1. **State Leakage:** Partial, unverified fragments could contaminate the permanent storage layer if an ingestion thread panicked or power loss occurred.
2. **I/O Bottlenecks:** Blocking disk operations during the ingestion phase throttled the `libp2p` swarm, causing dropped connections and non-deterministic network behavior.
3. **Testing Constraints:** Validating storage logic required full filesystem access, complicating deterministic simulation and continuous integration.

A structural separation was required to isolate the transient state of incomplete data fragments from the permanent, cryptographically verified forensic archive.

## Decision

We will implement a strictly decoupled data pipeline, categorized as the **Sentinel/Guardian Split**.

### 1. Ingress Orchestration (Perimeter Defense)

Data must pass through the `IngressOrchestrator` before any memory allocation occurs. This layer evaluates peer vitality, network topology (`NodeMode`), and reputation (`TrustRegistry`). Malicious behavior is logged and penalized immediately.

### 2. Sentinel Layer (Reassembler & Transient WAL)

The `Reassembler` acts as a data factory. It operates purely in memory to aggregate `ShardChunk` units into complete payloads.

* To ensure resilience against power loss without coupling to permanent storage, the Reassembler writes to a decoupled Write-Ahead Log (WAL) defined by the `TransientJournal` asynchronous trait.
* This layer is completely ignorant of long-term archive rules.

### 3. Guardian Layer (Vault)

The `Guardian` acts as the permanent forensic archive.

* It is isolated from partial fragment logic.
* It explicitly requires a fully materialized `WitnessEnvelope`.
* Entry into the Guardian is gated by mandatory `.verify()` cryptographic execution.

### 4. Dependency Inversion

The core `PhalanxEngine` and `StorageActor` must not hardcode file system operations. The WAL dependency must be injected via generic bounds (`<J: TransientJournal>`). Edge binaries (`sentinel`, `stronghold`) are responsible for instantiating the concrete `FileJournal` (backed by `tokio::fs`) and passing it to the engine.

## Consequences

### Positive

* **Deterministic Recovery:** Replaying the length-prefixed `TransientJournal` upon boot hydrates the `Reassembler` to its exact pre-crash state without corrupting the Vault.
* **Auditability:** The strict boundary enforces that no data can be promoted to the Guardian without passing through the `SecurityPipeline`.
* **Testability:** The generic trait bound allows seamless injection of a `NoOpJournal` or `MockJournal` for high-throughput memory simulations and deterministic unit testing.

### Negative

* **FFI Complexity:** The C-ABI does not support Rust generic types. We must explicitly monomorphize pointers across the FFI boundary (e.g., `*mut PhalanxEngine<NoOpJournal>`), which adds maintenance overhead to the `phalanx-ffi` crate.
* **Increased Allocation:** Copying data from the transient WAL to the permanent Vault induces a localized spike in memory allocation, though this is mitigated by zero-copy deserialization practices where applicable.
