# Phalanx Documentation Roadmap

## Phase 1: Developer Onboarding (The "Read Me First")

*Goal: Enable a new developer to build, run, and understand the core loop in < 15 minutes.*

- [ ] **`README.md` Overhaul**
  - [ ] **Architecture Diagram:** Add a high-level chart showing data flow: `Camera -> Sentinel -> Gossipsub -> Stronghold -> Disk`.
  - [ ] **Quickstart:** Add copy-pasteable commands for:
    - Running the Stronghold: `docker-compose up`.
    - Running a Mobile Client: `cargo run -- --mode mobile`.
  - [ ] **Prerequisites:** List dependencies (Rust toolchain, Docker, `protoc`, `libssl-dev`).

- [ ] **`CONTRIBUTING.md`**
  - [ ] **Code Style:** Explicitly link to the project's "Software Development Persona" rules (Standard Lib First, No Emojis, Type Safety).
  - [ ] **Testing Strategy:** Explain the difference between Unit Tests (logic) and Integration Tests (network).

## Phase 2: Architectural Decision Records (ADRs)

*Goal: Document *why* decisions were made. This is crucial for answering "Why is Phalanx not BitTorrent?"*

Create a `docs/adr/` directory and populate it with:

- [ ] **`001-kademlia-for-discovery.md`**
  - **Context:** We need WAN discovery. mDNS is LAN-only. Central servers are single points of failure.
  - **Decision:** Use `libp2p::kad` for peer discovery and service advertisement.

- [ ] **`002-recursive-assembly.md`**
  - **Context:** Live video is infinite; files are static. We must bridge this gap without data loss on crash.
  - **Decision:** Use the `ForensicAssembler<T>` pattern (Shards → Volleys → Archives) with gap detection logic.

- [ ] **`003-governance-and-quotas.md`**
  - **Context:** Mobile devices have limited storage. Public mesh invites spam.
  - **Decision:** Implement strict "Foreign Data" quotas and a "Mini Stronghold" failover policy.

## Phase 3: Inline Code Documentation (Rustdoc)

*Goal: Ensure `cargo doc --open` produces a usable API reference.*

- [ ] **Module-Level Docs (`//!`)**
  - [ ] **`src/network.rs`:** Explain the swarm behavior and `Kademlia`/`Gossipsub` interaction.
  - [ ] **`src/stronghold.rs`:** Explain the "Ingest → WAL → Archive" lifecycle.

- [ ] **Struct/Function Docs (`///`)**
  - [ ] **`WitnessEnvelope`:** Document the exact fields in the signature payload (critical for forensic admissibility).
  - [ ] **`Sentinel::process_chunk`:** Explain the reassembly state machine.
  - [ ] **`Stronghold::ingest_envelope`:** Document the 5-step validation process (WAL, Crypto, Replay Protection).

## Phase 4: Operational Guides (The "Field Manual")

*Goal: Explain how to deploy and secure the network in the real world.*

- [ ] **`docs/deployment.md`**
  - [ ] **Docker Deployment:** Guide for running the Stronghold on a VPS (AWS/DigitalOcean).
  - [ ] **Private Swarms:** Step-by-step guide on generating `swarm.key` and distributing it to team devices.

- [ ] **`docs/security_model.md`**
  - [ ] **Threat Model:** List attacks (Sybil, Eclipse, Physical Extraction) and mitigations (PSK, Encryption).
  - [ ] **Key Management:** Best practices for handling `identity.bin`.

## Phase 5: Protocol Specification

*Goal: Allow others to write compatible clients (e.g., a Kotlin Android app).*

- [ ] **`docs/protocol_spec.md`**
  - [ ] **Wire Format:** Document the `postcard` serialization format for `VideoShard` and `WitnessEnvelope`.
  - [ ] **Topic Naming:** Define the standard topic structure (`phalanx/{version}/{type}`).
  - [ ] **State Machine:** Diagram the lifecycle of a video frame from Capture to Archival.
