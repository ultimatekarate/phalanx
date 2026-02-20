# 📊 Phalanx Simulation Monitoring Roadmap

This roadmap builds a terminal-based "Mission Control" for the `sim.rs` integration test suite, transforming it from a text log into an interactive forensic network simulator.

## Phase 1: Dependencies & Infrastructure

*Goal: Set up the rendering engine and event pipeline.*

- [x] **Update `Cargo.toml`**
  - [x] Add `ratatui` (latest version) for the TUI engine.
  - [x] Add `crossterm` for raw terminal handling.
  - [ ] Add `tui-logger` or `tracing-subscriber` with a channel writer for capturing logs.

- [x] **Create `src/sim/metrics.rs`**
  - [x] Define `pub enum MetricEvent`:
    - `NodeJoined { id: NetworkId, role: String }`
    - `PacketSent { from: NetworkId, to: NetworkId, size: usize }`
    - `EvidenceSecured { did: Did, size: usize }`
    - `Heartbeat { id: NetworkId, load: f32, storage_used: u64 }`
    - `NodeError { id: NetworkId, error: String }`
  - [x] Define `pub struct SimState`:
    - `pub nodes: HashMap<NetworkId, NodeView>`
    - `pub total_evidence: u64`
    - `pub global_tps: Vec<u64>` (Transactions per second history)
  - [x] Implement `SimState::apply(&mut self, event: MetricEvent)` to update the state.

## Phase 2: The Telemetry Pipeline (The "Nerve Center")

*Goal: Decouple the simulation logic from the visualization logic.*

- [x] **Update `src/sim.rs` (Orchestrator)**