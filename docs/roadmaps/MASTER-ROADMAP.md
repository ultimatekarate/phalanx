# 🗺️ Phalanx Master Roadmap

This plan synthesizes all specialized roadmaps (Network, Security, Stronghold, Hardware, Assembly, Mobile, Monitoring, and Documentation) into a single execution path prioritized by architectural dependency.

## Phase 1: The Foundation (Network & Core Logic)

*Goal: Move from a LAN-only prototype to a WAN-capable, forensic-grade P2P network.*
**Dependencies:** `network-upgrades.md`, `recurse-assembly-roadmap.md`, `stronghold-upgrades.md`

- [x'] **Network Architecture Refactor**
  - [x] Create `src/network.rs` and decouple logic from `lib.rs` (The Facade Pattern).
  - [x] Implement **Kademlia DHT** (`libp2p::kad`) to enable WAN peer discovery.
  - [x] Implement **Service Discovery** (`announce_stronghold`, `find_strongholds`).
- [x] **Infrastructure Setup**
  - [x] **Cloud Bootstrap Node:** Deploy a minimal Stronghold on a public VPS (static IP) to act as the permanent Relay/Bootstrap peer for development.
- [ ] **Forensic Integrity Engine**
  - [X] Implement `ForensicAssembler<T>` generic struct for gap detection.
  - [X] Refactor `Stronghold` to use the **Recursive Assembly** pattern (Shards → Volleys → Archives).
  - [x] Implement **Atomic Archival** (`.tmp` → `.phlx` rename) to prevent corruption.
- [ ] **Governance & Quotas**
  - [ ] Implement `StorageConfig` with `max_foreign_storage_bytes`.
  - [ ] Implement **Eviction Policy**: `prune_foreign_evidence` (delete oldest non-owned data when full).
- [ ] **NAT Traversal (The "Hole Punch")**
  - [ ] **Stronghold Relay:** Configure `libp2p::relay` server on the Stronghold node.
  - [ ] **Mobile DCUtR:** Enable `libp2p::dcutr` on clients to upgrade relay connections to direct P2P links.
  - [ ] **Auto-NAT:** Implement `libp2p::autonat` so nodes know if they are publicly reachable.

## Phase 2: Security & Hardening (The "Moat")

*Goal: Secure the mesh against Sybil attacks, spam, and eavesdropping.*
**Dependencies:** `security-todo.md`, `hardware-hardening-roadmap.md`

- [ ] **Network Security**
  - [ ] Implement **Private Swarms** (PSK) using `libp2p-pnet` and `swarm.key`.
  - [ ] Implement **Payload Encryption** (E2EE) for `WitnessEnvelope`.
  - [ ] Strictly enforce **Protocol Versioning** in `Identify`.
- [ ] **Trusted Time**
  - [ ] **NTP Sync:** Implement `sntpc` (Simple Network Time Protocol) to calculate clock offset before signing evidence, preventing rejection due to local clock drift.
- [ ] **Identity Security (Recovery)**
  - [ ] **Deterministic Keys:** Refactor `PhalanxIdentity::generate()` to use a 12-word mnemonic seed (BIP-39).
  - [ ] **Restore Flow:** Create a CLI utility to regenerate `identity.bin` from a seed phrase (prerequisite for Mobile UI).
- [ ] **Hardware Robustness**
  - [ ] **Camera:** Fix time drift using `Instant` delta calculation and implement hot-plug logic.
  - [ ] **Audio:** Integrate `cpal` for real hardware access and implement buffering.
  - [ ] **Anti-Vampire:** Implement Rate Limiting in `sentinel.rs` to ignore spammy peers.
  - [ ] **Dynamic Heartbeats:** If battery < 20%, increase heartbeat interval from 30s to 300s.
  - [ ] **Leaf Mode:** If battery < 15%, unsubscribe from all Gossipsub topics except `my_volley` to stop relaying traffic.

## Phase 3: Integration & Observability

*Goal: Verify the system works at scale without physical deployment.*
**Dependencies:** `monitoring-roadmap.md`

- [ ] **Simulation Dashboard**
  - [ ] Implement `SimMetrics` struct and telemetry channel in `sim.rs`.
  - [ ] Build the **TUI Dashboard** using `ratatui` to visualize node states, TPS, and storage.
  - [ ] Add **Chaos Controls** (kill node, sever stronghold) to interactive simulation.

- [ ] **WAN Integration Tests**
  - [ ] Create `tests/wan_integration.rs` to verify Bootstrapping and Service Discovery in a simulated WAN environment.

## Phase 4: Mobile Transformation (The App)

*Goal: Package the Rust core into a user-friendly Android/iOS application.*
**Dependencies:** `mobile-ui-roadmap.md`

- [ ] **Rust Bridge (FFI)**
  - [ ] Refactor `lib.rs` to expose C-compatible FFI methods (`phalanx_init`, `phalanx_start_camera`).
  - [ ] Set up **Cross-Compilation** for Android (`cargo ndk`) and iOS (`cargo lipo`).

- [ ] **Flutter UI Shell**
  - [ ] Initialize `phalanx_mobile` Flutter project.
  - [ ] Implement **Texture Hardware Mapping** for zero-copy camera preview.
  - [ ] Build the **HUD**, **Vault**, and **Network Radar** screens.

- [ ] **Mobile Integration**
  - [ ] Implement `WorkManager`/`BackgroundTasks` for background execution.
  - [ ] Handle Android/iOS Permissions (`CAMERA`, `LOCATION`).

## Phase 5: Documentation & Release

*Goal: Make the project accessible to other developers and users.*
**Dependencies:** `documentation-roadmap.md`

- [ ] **Developer Experience**
  - [ ] Overhaul `README.md` with Architecture Diagrams and Docker Quickstart.
  - [ ] Write **Architectural Decision Records (ADRs)** for Kademlia, Recursive Assembly, and Governance.
- [ ] **Field Manual**
  - [ ] Create `docs/deployment.md` (Docker/VPS guide).
  - [ ] Create `docs/security_model.md` (Threat Model & Key Management).
- [ ] **Protocol Spec**
  - [ ] Document the `postcard` Wire Format and Topic Naming conventions.
- [ ] **Verification CLI:** Create `phalanx-verify` binary:
  - [ ] Input: `.phlx` archive.
  - [ ] Output: Verified `.mp4` video + `report.json` (Signatures, GPS, Hash).

## Critical Path Summary

1. **Network Refactor:** You cannot deploy mobile clients without WAN discovery.
2. **Storage Governance:** You cannot deploy to mobile without storage limits (orphaned data risk).
3. **Private Swarm:** You cannot safely test on the open internet without PSK authentication.
4. **Mobile FFI:** You cannot build the app without the library interface.
