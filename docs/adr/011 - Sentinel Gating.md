# ADR-011: Sentinel Gating & Forensic Pipelines

* **Status:** Accepted
* **Date:** 2026-02-18
* **Context:** Forensic Zero-Trust Architecture
* **Tags:** security, error-handling, rust, patterns

## Context and Problem Statement

As the Phalanx Core codebase grew, the implementation of "Forensic Zero-Trust" (verify everything, assume breach) led to significant boilerplate. The `engine.rs` and `simulation.rs` loops were heavily nested with `match` statements and manual error logging.

This introduced several risks:

1. **Cognitive Load (The "Thinking Tax"):** Developers struggled to see the "Happy Path" of data flow amidst the error handling.
2. **Panic Vectors:** To reduce verbosity, there was a temptation to use `.unwrap()` or `.expect()`, violating the "Zero Panic" requirement of a high-availability forensic node.
3. **Inconsistent Auditing:** Some errors were logged with `tracing::error!`, others with `warn!`, and some were silently dropped. In a forensic system, a dropped packet is evidence of failure or attack and must be logged uniformly.

We needed a standardized, non-panicking way to enforce security boundaries without obscuring the business logic.

## Decision

We will adopt the **Sentinel Gating** pattern, a domain-specific implementation of **Railroad Oriented Programming (ROP)**.

Instead of imperative validation checks, all data transitions (Ingestion, Signing, Reception) must pass through a "Gate." A Gate is a functional trait that:

1. Consumes the input (taking ownership).
2. Performs a validation or transformation.
3. **Side-Effect:** Logs any failure with a structured forensic schema (`event`, `node`, `error`).
4. Returns `Option<T>`: `Some(T)` if the data is valid/safe, `None` if it was dropped.

We define three specific gates in `security/gate.rs`:

### 1. The Witness Gate (`seal`)

Handles the transition from raw `Evidence` (Video/Audio) to a signed `WitnessEnvelope`. It encapsulates key management, serialization, and cryptographic signing.

### 2. The Forensic Gate (`ok_or_log`)

An extension trait on `Result<T, E>`. It allows any fallible operation (Serialization, I/O, Chunking) to be chained. It converts `Err` to `None` after emitting a structured log, effectively creating a "Log and Drop" firewall.

### 3. The Integrity Gate (`check_integrity`)

Used on the reception side (Network -> Engine). It enforces:

* Cryptographic Signature Verification.
* Temporal Freshness (via `PhalanxTimestamp`).
* Replay Protection.

## Detailed Design

### The Pipeline Flow

The `Engine` event loop is refactored from nested matching to linear pipelines.

**Before:**

```rust
match create_shard(...) {
    Ok(shard) => {
        match sign(shard) {
            Ok(env) => ...
            Err(e) => log(e)
        }
    }
    Err(e) => log(e)
}
```

**After (Sentinel Gating):**

```Rust
create_shard(...)
    .ok_or_log("gen_error", ...)       // Forensic Gate
    .and_then(|s| s.seal(id, ...))     // Witness Gate
    .and_then(|e| e.chunkify(...))     // Domain Method
    .ok_or_log("chunk_error", ...)     // Forensic Gate
```

## Type-Driven Security

We enforce validity via types, not boolean flags.

* Raw Data: u64 timestamp (Unsafe).
* Gated Data: PhalanxTimestamp (Safe).
* The IntegrityGate requires interaction with TrustedClock to promote raw data to trusted data.

## Consequences

### Positive

* Zero Panic: The pipeline relies on Option, making it physically impossible for the node to crash due to malformed input or transient I/O errors.

* Audit Parity: Every dropped packet, regardless of source (local sensor or hostile peer), generates an identical log structure for the ELK/Grafana stack.
* Readability: The run() loop in engine.rs now reads as a high-level description of data flow requirements.
* Isolation: Attack logic (e.g., in simulation.rs) can be tested by intentionally feeding bad data; the Gates will naturally catch and log it without special test harness code.

### Negative

* "Swallowed" Errors: Because we convert Result to Option, the caller loses the programmatic context of exactly why a failure occurred. The error exists only in the logs. This is acceptable for a "Fire and Forget" forensic stream but would be bad for a transactional database.

* Performance: There is a microscopic overhead to the functional chaining and tracing calls compared to raw if statements, but this is negligible compared to the cryptographic operations (Ed25519/XChaCha20) occurring inside the gates.

## Compliance

All new modules introduced to the Phalanx Core must utilize ForensicGate for fallible operations. Use of .unwrap() or .expect() is strictly forbidden in crates/phalanx-core/src/base and src/engine.rs.
