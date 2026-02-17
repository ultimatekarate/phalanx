# ADR 005: Workspace Restructuring and Crate Splitting

* **Status:** Accepted
* **Date:** 2026-02-16

## Context and Problem Statement

Phalanx started as a single monolithic Rust crate. As functionality expanded to include complex storage proofs (`Guardian`), network security simulations (`Sentinel`), and a visualization layer (`Dashboard`), the codebase became increasingly difficult to manage.

1. **Compile Times:** Any change to the UI logic triggered a recompile of the heavy cryptographic and storage modules, slowing down the feedback loop.
2. **Dependency Bloat:** The core logic required `ratatui` and `crossterm` dependencies even if we only wanted to run a headless simulation or CLI tool.
3. **Leaky Abstractions:** Without hard crate boundaries, it was easy for the UI code to reach into internal storage structures that should have been private, leading to tight coupling.

We need a structure that enforces architectural boundaries and optimizes build performance.

## Decision Drivers

* **Separation of Concerns:** The Simulation Engine should not know about the UI rendering logic.
* **Build Performance:** We need parallel compilation for independent components.
* **Deployability:** We may want to deploy a "Headless Node" without the visualization overhead in the future.

## Considered Options

1. **Modules (`mod`):** Keep a single crate but use strict module visibility (`pub(crate)`).
    * *Pros:* Simple `Cargo.toml` management.
    * *Cons:* Does not solve compile time issues; dependencies are still shared globally.
2. **Cargo Workspace (Selected):** Split the project into multiple crates within a single repository.
    * *Pros:* strict dependency isolation, parallel builds, clear public APIs.
    * *Cons:* More configuration management (multiple `Cargo.toml` files).

## Decision

We will adopt a **Cargo Workspace** structure located in the `crates/` directory.

The project will be split into the following primary crates:

1. **`phalanx-core`**:
    * **Responsibility:** The library containing the domain logic.
    * **Contents:** `Sentinel` (Security), `Guardian` (Storage), `SimulationHarness` (Engine), and `Primitives` (Identity, Shards).
    * **Dependencies:** `tokio`, `tracing`, `serde`, `postcard`. (No UI dependencies).

2. **`phalanx-dashboard`**:
    * **Responsibility:** The TUI visualization application.
    * **Contents:** `main.rs` (UI Loop), `widgets.rs`.
    * **Dependencies:** `phalanx-core`, `ratatui`, `crossterm`.

3. **`phalanx-ffi` (Planned)**:
    * **Responsibility:** It's the mobile UI
    * **Dependencies:** `phalanx-core`.

## Consequences

### Positive

* **Encapsulation:** `phalanx-dashboard` can only access `pub` types from `phalanx-core`. This forces us to design better APIs (e.g., the Telemetry Event Stream) rather than accessing internal state directly.
* **Performance:** Modifying the Dashboard widgets no longer triggers a rebuild of the Storage engine.
* **Clarity:** Dependencies are scoped. `phalanx-core` does not depend on `ratatui`, making it portable to other environments (e.g., embedded or WASM).

### Negative

* **Complexity:** We must manage versioning and local path dependencies (`phalanx-core = { path = "../phalanx-core" }`) in multiple files.
* **Refactoring Friction:** Moving a struct from one crate to another is slightly more involved than moving a file between modules.

## Implementation Plan

1. Create a root `Cargo.toml` defining the workspace `[workspace] members = ["crates/*"]`.
2. Move existing logic into `crates/phalanx-core/src/lib.rs`.
3. Move the TUI executable logic into `crates/phalanx-dashboard/src/main.rs`.
4. Update all import paths (change `crate::model` to `phalanx_core::model`).
