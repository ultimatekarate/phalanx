# Phalanx Network Upgrade Roadmap: WAN & Discovery

This roadmap details the steps to upgrade Phalanx from a Local-Only Mesh (mDNS) to a WAN-Capable Grid (Kademlia DHT).

## Phase 1: Architecture Refactor (The Facade Pattern)

*Goal: Decouple network logic from the library definition to improve maintainability.*

- [ ] **Create `src/network.rs`**
  - [ ] Create a new file `src/network.rs`.
  - [ ] Move the `PhalanxBehaviour` struct definition from `lib.rs` to `network.rs`.
  - [ ] Move the `PhalanxEvent` enum from `lib.rs` to `network.rs`.
  - [ ] Move the `setup_phalanx_swarm` function from `lib.rs` to `network.rs`.
  - [ ] **Verification:** Ensure `cargo check` passes (update imports in `main.rs` and `lib.rs` as needed).

- [ ] **Clean up `src/lib.rs`**
  - [ ] Remove all `libp2p` imports and logic from `lib.rs`.
  - [ ] Add `pub mod network;`.
  - [ ] Add re-exports for convenience: `pub use network::{PhalanxBehaviour, setup_phalanx_swarm, PhalanxEvent};`.

## Phase 2: Kademlia Implementation (The Engine)

*Goal: Enable the Distributed Hash Table (DHT) so nodes can route messages over the internet.*

- [ ] **Update `PhalanxBehaviour` (in `src/network.rs`)**
  - [ ] Import `libp2p::kad` and `libp2p::identify`.
  - [ ] Add `kademlia: kad::Behaviour<kad::store::MemoryStore>` to the struct fields.
  - [ ] Add `identify: identify::Behaviour` to the struct fields (required for NAT traversal).

- [ ] **Update `PhalanxEvent` (in `src/network.rs`)**
  - [ ] Add `Kademlia(kad::Event)` variant.
  - [ ] Add `Identify(identify::Event)` variant.
  - [ ] Implement `From<kad::Event>` and `From<identify::Event>` for `PhalanxEvent`.

- [ ] **Update `setup_phalanx_swarm` (in `src/network.rs`)**
  - [ ] Initialize Kademlia with `MemoryStore::new(local_peer_id)`.
  - [ ] Configure `kad::Config` with a 60s query timeout.
  - [ ] Initialize Identify with protocol version `"/phalanx/1.0.0"`.
  - [ ] **Bootstrapping Logic:** Iterate through `config.network.bootstrap_peers` (see Phase 3) and call `kademlia.add_address`.

## Phase 3: Configuration & Discovery (The Wiring)

*Goal: Allow nodes to find each other and advertise the Stronghold service.*

- [ ] **Update `src/config.rs`**
  - [ ] In `NetworkConfig` struct, add field: `pub bootstrap_peers: Vec<String>`.
  - [ ] In `NetworkConfig` struct, add constant or field: `pub stronghold_service_key: String` (Default: `"phalanx-stronghold-v1"`).
  - [ ] Update `test_defaults()` to include an empty `bootstrap_peers` vector.

- [ ] **Implement Service Discovery Methods (in `src/network.rs`)**
  - [ ] Implement `impl PhalanxBehaviour`:
    - [ ] `fn announce_stronghold(&mut self)`: Calls `self.kademlia.start_providing(key)`.
    - [ ] `fn find_strongholds(&mut self)`: Calls `self.kademlia.get_providers(key)`.

- [ ] **Wire `src/main.rs`**
  - [ ] In the main loop, handle `SwarmEvent::Behaviour(PhalanxEvent::Kademlia(...))`.
  - [ ] **Routing Updates:** When a new peer is discovered via Kademlia, ensure it is added to the `HealthTracker` in `sentinel.rs`.
  - [ ] **Startup Logic:**
    - [ ] If `config.storage.max_peers > 10` (Stronghold Mode): Call `swarm.behaviour_mut().announce_stronghold()`.
    - [ ] If `config.storage.max_peers <= 10` (Mobile Mode): Call `swarm.behaviour_mut().find_strongholds()`.

## Phase 4: Security Perimeter (The "Moat")

*Goal: Prevent unauthorized nodes from joining the swarm using a Pre-Shared Key (PSK).*

- [ ] **Update `setup_phalanx_swarm` (in `src/network.rs`)**
  - [ ] Check for existence of file `swarm.key` in the current directory.
  - [ ] **If exists (Private Mode):**
    - [ ] Read bytes from `swarm.key`.
    - [ ] Create `libp2p::pnet::PreSharedKey`.
    - [ ] Wrap the TCP transport with `PnetConfig::new(psk)`.
  - [ ] **If missing (Public Mode):**
    - [ ] Log a warning (`tracing::warn!`).
    - [ ] Use standard TCP transport.

- [ ] **Key Generation Utility**
  - [ ] Create a helper function `generate_swarm_key()` that writes 32 random bytes to `swarm.key` (can be a separate binary or a `--init` CLI flag).

## Phase 5: Verification (The Tests)

*Goal: Verify the new network stack works without physical deployment.*

- [ ] **Create `tests/wan_integration.rs`**
  - [ ] **Test 1: Bootstrap:** Spin up Node A (Server) and Node B (Client). Point B to A's address. Assert B finds A in its routing table.
  - [ ] **Test 2: Service Discovery:** Have Node A call `announce_stronghold()`. Have Node B call `find_strongholds()`. Assert B receives A's Peer ID.
