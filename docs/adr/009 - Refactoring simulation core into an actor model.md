# ADR 009: Refactoring Simulation Core to Actor Model

* **Status:** Accepted
* **Date:** 2026-02-16

## Context and Problem Statement

The current simulation implementation in `crates/phalanx-core/src/simulation.rs` relies on a monolithic `spawn_node` function. This function initializes the node identity, sets up the `Guardian` and `Sentinel` subsystems, and runs the main `tokio::select!` event loop all within a single async closure.

As we have added features—Chaos Modes (Packet Loss, Vampire Attacks), Node Roles (Guardians vs. Strongholds), and Defense Telemetry—the complexity of this function has grown unmanageable (The "God Function" anti-pattern).

1. **Readability:** The event loop mixes infrastructure wiring (channel management) with domain logic (attack signatures, offloading strategies).
2. **Extensibility:** Adding new behaviors (e.g.,
