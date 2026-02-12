# 📊 Phalanx Simulation Monitoring Roadmap

This roadmap builds a terminal-based "Mission Control" for the `sim.rs` integration test suite, transforming it from a text log into an interactive forensic network simulator.

## Phase 1: Dependencies & Infrastructure

*Goal: Set up the rendering engine and event pipeline.*

- [ ] **Update `Cargo.toml`**
  - [ ] Add `ratatui` (latest version) for the TUI engine.
  - [ ] Add `crossterm` for raw terminal handling.
  - [ ] Add `tui-logger` or `tracing-subscriber` with a channel writer for capturing logs.

- [ ] **Create `src/sim/metrics.rs`**
  - [ ] Define `pub enum MetricEvent`:
    - `NodeJoined { id: NetworkId, role: String }`
    - `PacketSent { from: NetworkId, to: NetworkId, size: usize }`
    - `EvidenceSecured { did: Did, size: usize }`
    - `Heartbeat { id: NetworkId, load: f32, storage_used: u64 }`
    - `NodeError { id: NetworkId, error: String }`
  - [ ] Define `pub struct SimState`:
    - `pub nodes: HashMap<NetworkId, NodeView>`
    - `pub total_evidence: u64`
    - `pub global_tps: Vec<u64>` (Transactions per second history)
  - [ ] Implement `SimState::apply(&mut self, event: MetricEvent)` to update the state.

## Phase 2: The Telemetry Pipeline (The "Nerve Center")

*Goal: Decouple the simulation logic from the visualization logic.*

- [ ] **Update `src/sim.rs` (Orchestrator)**
  - [ ] Create the Telemetry Channel:

        ```rust
        let (metric_tx, metric_rx) = tokio::sync::mpsc::
