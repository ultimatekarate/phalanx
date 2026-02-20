# Phalanx Network Upgrade Roadmap: WAN & Discovery

This roadmap details the steps to upgrade Phalanx from a Local-Only Mesh (mDNS) to a WAN-Capable Grid (Kademlia DHT).

## Phase 1: Architecture Refactor (The Facade Pattern)

*Goal: Decouple network logic from the library definition to improve maintainability.*

- [x] **Create `src/network.rs`**
  - [x] Create a new file `src/network.rs`.
  - [x] Move the `PhalanxBehaviour` struct definition from `lib.rs` to `network.rs`.
  - [x] Move the `PhalanxEvent` enum from `lib.rs` to `network.rs`.
  - [x] Move the `setup_phalanx_swarm` function from `lib.rs` to `network.rs`.
  - [x] **Verification:** Ensure `cargo check` passes (update imports in `main.rs` and `lib.rs` as needed).

- [x] **Clean up `src/lib.rs`**
  - [x] Remove all `libp2p` imports and logic from `lib.rs`.
  - [x] Add `pub mod network;`.
  - [x] Add re-exports for convenience: `pub use network::{PhalanxBehaviour, setup_phalanx_swarm, PhalanxEvent};`.

## Phase 2: Kademlia Implementation (The Engine)

*Goal: Enable the Distributed Hash Table (DHT) so nodes can route messages over the internet.*

- [x] **Update `PhalanxBehaviour` (in `src/network.rs`)**
  - [x] Import `libp2p::kad` and `libp2p::identify`.
  - [x] Add `kademlia: kad::Behaviour<kad::store::MemoryStore>` to the struct fields.
  - [x] Add `identify: identify::Behaviour` to the struct fields (required for NAT traversal).

- [x] **Update `PhalanxEvent` (in `src/network.rs`)**
  - [x] Add `Kademlia(kad::Event)` variant.
  - [x] Add `Identify(identify::Event)` variant.
  - [x] Implement `From<kad::Event>` and `From<identify::Event>` for `PhalanxEvent`.

- [x] **Update `setup_phalanx_swarm` (in `src/network.rs`)**
  - [x] Initialize Kademlia with `MemoryStore::new(local_peer_id)`.
  - [x] Configure `kad::Config` with a 60s query timeout.
  - [x] Initialize Identify with protocol version `"/phalanx/1.0.0"`.
  - [x] **Bootstrapping Logic:** Iterate through `config.network.bootstrap_peers` (see Phase 3) and call `kademlia.add_address`.

## Phase 3: Configuration & Discovery (The Wiring)

*Goal: Allow nodes to find each other and advertise the Stronghold service.*

- [x] **Update `src/config.rs`**
  - [x] In `NetworkConfig` struct, add field: `pub bootstrap_peers: Vec<String>`.
  - [x] In `NetworkConfig` struct, add constant or field: `pub stronghold_service_key: String` (Default: `"phalanx-stronghold-v1"`).
  - [x] Update `test_defaults()` to include an empty `bootstrap_peers` vector.

- [x] **Implement Service Discovery Methods (in `src/network.rs`)**
  - [x] Implement `impl PhalanxBehaviour`:
    - [x] `fn announce_stronghold(&mut self)`: Calls `self.kademlia.start_providing(key)`.
    - [x] `fn find_strongholds(&mut self)`: Calls `self.kademlia.get_providers(key)`.

- [x] **Wire `src/main.rs`**
  - [x] In the main loop, handle `SwarmEvent::Behaviour(PhalanxEvent::Kademlia(...))`.
  - [x] **Routing Updates:** When a new peer is discovered via Kademlia, ensure it is added to the `HealthTracker` in `sentinel.rs`.

## Phase 4: Security Perimeter (The "Moat")

*Goal: Prevent unauthorized nodes from joining the swarm using a Pre-Shared Key (PSK).*

  - [x] Check for existence of file `swarm.key` in the current directory.
  - [x] **If exists (Private Mode):**
    - [x] Read bytes from `swarm.key`.
    - [x] Create `libp2p::pnet::PreSharedKey`.
    - [x] Wrap the TCP transport with `PnetConfig::new(psk)`.
  - [x] **If missing (Public Mode):**
    - [x] Log a warning (`tracing::warn!`).
    - [x] Use standard TCP transport.

- [x] **Key Generation Utility**
  - [x] Create a helper function `generate_swarm_key()` that writes 32 random bytes to `swarm.key` (can be a separate binary or a `--init` CLI flag).

## Phase 5: Verification (The Tests)

*Goal: Verify the new network stack works without physical deployment.*

- [ ] **Create `tests/wan_integration.rs`**
  - [ ] **Test 1: Bootstrap:** Spin up Node A (Server) and Node B (Client). Point B to A's address. Assert B finds A in its routing table.
  - [ ] **Test 2: Service Discovery:** Have Node A call `announce_stronghold()`. Have Node B call `find_strongholds()`. Assert B receives A's Peer ID.
