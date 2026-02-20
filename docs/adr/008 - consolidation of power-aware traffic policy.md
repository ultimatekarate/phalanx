# ADR 008: Consolidation of Power-Aware Traffic Policy

## Status

Proposed

## Context

The Phalanx node currently implements two separate ingestion paths for network data:

1. **Sentinel (`sentinel.rs`)**: Reassembles fragments for signing/witnessing.
2. **Guardian (`guardian.rs`)**: Reassembles fragments for forensic salvage/persistence.

With the introduction of **Leaf Mode** (triggered when battery < 15%), both modules independently required logic to filter foreign traffic. Maintaining duplicated environmental monitoring (battery polling) and policy enforcement across two discrete modules introduces architectural drift and testing complexity.

## Decision

We will centralize the node's **Power Strategy** within the `Sentinel` module. The `Guardian` will remain a passive execution layer that receives policy flags from the `Sentinel` via the main orchestration loop.

Key changes include:

* **Centralized Monitoring**: The `get_system_battery()` mock and threshold logic will reside exclusively in `sentinel.rs`.
* **State Authority**: `Sentinel` manages the `PowerState` enum (`Normal` vs `Leaf`).
* **Flag Propagation**: The `PhalanxNode` in `main.rs` will query
