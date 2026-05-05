# Welcome to The Friendly Manual

The codebase is structured so that each [technical specialty](#files-by-technical-specialty) (as I understand them) occupies a well-defined set of files with minimal entanglement. A networking engineer can improve the QUIC transport without understanding Padé approximants. A statistician can refine the Kolmogorov-Smirnov corroboration test without knowing how libp2p gossipsub works. A storage engineer can optimize the vault without touching the actor system.

---

## Before You Submit

Don't you dare disrespect yourself by submitting anything less than your best. Mistakes are acceptable, that is how we learn. The important thing is that we try. I do have some rules:

1. Read `linguistic-code-model.md` — particularly Sections I (Parts of Speech) and II (Structural Enforcement), I promise it is worth it. Read the friendly manual.
2. If you added a new type, check the linguistic model to determine which crate it belongs in. Nouns go in the Dictionary. Verbs go in the Laboratory. Prepositions go in the Post Office.
3. Run `cargo clippy --workspace --all-targets` — zero errors, zero governance lint warnings.
4. Run `cargo test --workspace` — all tests pass.
5. If you added an `#[allow(clippy::...)]`, include a comment explaining why the suppression is safe.

---

## Surviving the Deny Lints

The workspace enforces deny-level clippy lints that reject patterns most Rust tutorials teach as idiomatic. If you're coming from the Rust book or standard library examples, this section will save you time.

### `unwrap_used` / `expect_used`

**Denied because:** A panic in production means evidence isn't recorded. On a phone in someone's pocket, a crash is a denial of service.

| Instead of | Write |
| --- | --- |
| `option.unwrap()` | `option.ok_or(MyError::Missing)?` |
| `result.expect("msg")` | `result.map_err(\|e\| MyError::from(e))?` |
| `map.get("key").unwrap()` | `map.get("key").ok_or(MyError::KeyNotFound)?` |
| `channel.send(msg).unwrap()` | `channel.send(msg).map_err(\|_\| MyError::ChannelClosed)?` |

If you truly cannot propagate the error (e.g., inside a `map` closure), restructure to use `and_then` or `match`.

### `indexing_slicing`

**Denied because:** Out-of-bounds indexing panics. A malformed network packet with an unexpected length becomes a crash vector.

| Instead of | Write |
| --- | --- |
| `vec[0]` | `vec.first().ok_or(MyError::Empty)?` |
| `vec[i]` | `vec.get(i).ok_or(MyError::OutOfBounds)?` |
| `slice[1..3]` | `slice.get(1..3).ok_or(MyError::OutOfBounds)?` |
| `for i in 0..vec.len() { vec[i] }` | `for item in &vec { ... }` |

### `arithmetic_side_effects`

**Denied because:** Integer overflow wraps silently in release mode. In a system tracking sequence numbers, byte counts, and integral accumulators, silent wrapping corrupts state.

| Instead of | Write |
| --- | --- |
| `a + b` | `a.checked_add(b).ok_or(MyError::Overflow)?` |
| `a - b` | `a.saturating_sub(b)` (if underflow to zero is safe) |
| `a * b` | `a.checked_mul(b).ok_or(MyError::Overflow)?` |
| `counter += 1` | `counter = counter.saturating_add(1)` |

When the arithmetic is provably safe (e.g., loop counter bounded by a small constant), suppress with `#[allow(clippy::arithmetic_side_effects)]` and a comment explaining why.

### `cast_possible_truncation` / `cast_sign_loss` / `cast_possible_wrap`

**Denied because:** `as` casts silently truncate or reinterpret. `u64 as u32` drops the high bits. `i64 as u64` reinterprets negative values.

| Instead of | Write |
| --- | --- |
| `x as u32` | `u32::try_from(x).map_err(\|_\| MyError::Overflow)?` |
| `x as usize` | `usize::try_from(x).map_err(\|_\| MyError::Overflow)?` |
| `x as f64` | `x as f64` is fine for widening (e.g., `u32 as f64`) — only narrowing is denied |

### `float_cmp`

**Denied because:** Floating-point equality is almost never what you mean. `0.1 + 0.2 != 0.3` in IEEE 754. I learned this the hard way.

| Instead of | Write |
| --- | --- |
| `a == b` | `(a - b).abs() < f64::EPSILON` |
| `a == 0.0` | `a.abs() < f64::EPSILON` |

For domain types, consider `UnitInterval` (in `phalanx-proto/src/types.rs`) which filters NaN in the constructor and safely implements `Eq`.

### `await_holding_lock`

**Denied because:** Holding a mutex guard across an `.await` point can deadlock the tokio runtime. The task yields, another task on the same thread tries to acquire the lock, and neither can proceed.

| Instead of | Write |
| --- | --- |
| `let guard = mutex.lock(); do_async().await; drop(guard);` | `{ let val = mutex.lock().clone(); } do_async(val).await;` |

Copy what you need out of the lock, drop the guard, then await.

### `panic`

**Denied because:** Same rationale as `unwrap`. This also catches `unimplemented!()`, `unreachable!()`, and `todo!()` (`todo` is a separate warning-level lint).

| Instead of | Write |
| --- | --- |
| `panic!("bad state")` | `return Err(MyError::BadState)` |
| `unreachable!()` | `return Err(MyError::InternalInvariantViolation)` |
| `todo!()` | Implement it or return a placeholder `Err` |

### In Tests

Test modules suppress these lints:

```rust
#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests { ... }
```

Tests are the one place where panicking is acceptable — a failing assertion *should* panic. Production code never gets these allows.

---

## Files by Technical Specialty

### Cryptography & Identity

DID resolution, Ed25519 key management, AEAD payload encryption, signature verification, and decentralized identity.

| File | What it does |
| ------ | ------------- |
| `phalanx-proto/src/identity/crypto.rs` | `SymmetricKey` with zeroization on drop, cryptographic error types |
| `phalanx-proto/src/identity/did.rs` | `Did`, `NetworkId`, `PhalanxIdentity`, `RecordingId`, `ShardId` |
| `phalanx-forensics/src/identity.rs` | DID resolution — extracting Ed25519 public keys from `did:key` URIs |
| `phalanx-forensics/src/pipeline/witness.rs` | `WitnessAuthority` — signing, verifying, and chunking evidence envelopes |
| `phalanx-forensics/src/verification/judge.rs` | Shard and recording amalgam causality validation |
| `phalanx-node/src/identity.rs` | `PhalanxNodeIdentityExt` — node-level identity and retrieval authorization |
| `phalanx-node/src/psk.rs` | Pre-shared key management |
| `phalanx-transport/src/identity_ext.rs` | Converts `PhalanxIdentity` to libp2p keypairs and `NetworkId`s |
| `phalanx-stronghold/src/signing.rs` | Stronghold-side signing operations |

### Networking & Peer-to-Peer

libp2p swarm management, gossipsub, Kademlia DHT, QUIC transport, mDNS discovery, and protocol wiring.

| File | What it does |
| ------ | ------------- |
| `phalanx-transport/src/adapters/libp2p.rs` | `Libp2pAdapter` — mesh publish/subscribe, peer messaging, `PeerId` → `NetworkId` boundary |
| `phalanx-transport/src/adapters/quic/client.rs` | QUIC client with connection cycling and backoff |
| `phalanx-transport/src/adapters/quic/server.rs` | QUIC server with identity handshake and message routing |
| `phalanx-transport/src/adapters/quic/wire.rs` | QUIC wire protocol framing |
| `phalanx-transport/src/adapters/quic/config.rs` | QUIC transport configuration |
| `phalanx-transport/src/behaviour.rs` | `PhalanxBehaviour` — aggregates gossipsub, Kademlia, mDNS, relay, request-response |
| `phalanx-transport/src/builder.rs` | QUIC and TCP fallback transport builders with TLS 1.3 |
| `phalanx-transport/src/codec.rs` | `PhalanxRetrievalProtocol` — postcard serialization with length-prefixed framing |
| `phalanx-transport/src/dht.rs` | Re-exports of libp2p DHT types for custom backends |
| `phalanx-transport/src/events.rs` | `PhalanxEvent` — unified swarm event enum |
| `phalanx-transport/src/factory.rs` | Swarm construction with persistent Kademlia store and gossipsub |
| `phalanx-transport/src/io.rs` | Async length-prefixed I/O with size validation |
| `phalanx-transport/src/kademlia.rs` | `KademliaGovernor` — reputation-weighted provider insertion with temporal decay |
| `phalanx-transport/src/routing.rs` | Central switchboard routing `NetworkEvent`s to actors |
| `phalanx-proto/src/network/events.rs` | `NetworkEvent`, `IngressPort`, `EgressPort`, `LocalMeshPort` trait contracts |
| `phalanx-proto/src/network/kademlia.rs` | DHT payload kinds and provider data structures |
| `phalanx-forensics/src/kademlia.rs` | DHT timestamp conversion and expiration verification |
| `phalanx-node/src/network/orchestrator.rs` | Transport stack factory for swarm construction |
| `phalanx-node/src/persistence/kademlia.rs` | redb-backed `RecordStore` for persistent DHT records |
| `phalanx-stronghold/src/swarm.rs` | Stronghold-side swarm management |

### Network Security

Eclipse attack detection, topology-aware peer admission, traffic governance, and bloom filter replay protection.

| File | What it does |
| ------ | ------------- |
| `phalanx-forensics/src/trust/eclipse.rs` | Passive eclipse attack detection via `MeshFingerprint` and peer set analysis |
| `phalanx-forensics/src/verification/topology_gate.rs` | Per-peer admission control enforcing subnet diversity and transport quotas |
| `phalanx-forensics/src/verification/bloom.rs` | `RotatingBloomFilter` — probabilistic replay protection |
| `phalanx-forensics/src/policy.rs` | `IngressGovernor`, `TrafficGovernor`, `EgressGovernor` — traffic shaping |
| `phalanx-forensics/src/verification/gate.rs` | Monadic gate combinators — `LensGate`, `IntegrityGate` |
| `phalanx-proto/src/network/topology.rs` | `SubnetBucket`, `TransportClass`, eclipse risk types |
| `phalanx-proto/src/identity/trust.rs` | `TrustLevel`, `Offense`, `OffenseSeverity` |

### Media & Codecs

JPEG/PCM capture, MP4 transcoding, fountain code encoding/reassembly, C2PA content authenticity, and media playback.

| File | What it does |
| ------ | ------------- |
| `phalanx-forensics/src/pipeline/transcode.rs` | JPEG frames + PCM audio → MP4 container |
| `phalanx-forensics/src/pipeline/reassembler.rs` | Fountain-coded chunk reassembly into complete envelopes |
| `phalanx-forensics/src/pipeline/c2pa_ext.rs` | C2PA manifest builder embedding Phalanx forensic assertions |
| `phalanx-proto/src/evidence/envelope.rs` | `WitnessEnvelope`, `ShardChunk`, `VideoShard`, `AudioShard`, `Evidence` |
| `phalanx-node/src/playback/sink.rs` | Media sink for forensic evidence replay |
| `phalanx-node/src/actors/media_egress.rs` | Encrypts, seals, fountain-encodes, and publishes video/audio evidence |
| `phalanx-ffi/src/playback.rs` | FFI playback bridge to Flutter UI |

### Control Theory & Stability

Volterra integral feedback, Jacobian linearization, eigenvalue stability analysis, Padé approximants, Dyson series, and homeostatic self-regulation.

| File | What it does |
| ------ | ------------- |
| `phalanx-node/src/stability/jacobian.rs` | Linearized Jacobian matrix for homeostatic stability analysis |
| `phalanx-node/src/stability/eigenvalues.rs` | Eigenvalue computation for pole placement and stability verification |
| `phalanx-node/src/stability/spectral.rs` | Spectral gap and eigenvector orthogonality for control loop robustness |
| `phalanx-node/src/stability/nonlinear.rs` | Nonlinear dynamics analysis |
| `phalanx-node/src/stability/pade.rs` | Padé approximant computation |
| `phalanx-node/src/stability/dyson.rs` | Dyson series expansion |
| `phalanx-node/src/stability/config.rs` | Stability analysis configuration |
| `phalanx-node/src/vitals/governor.rs` | `SystemGovernor` — stress integrals, power states, feedback loops |
| `phalanx-node/src/vitals/config.rs` | Vitals tuning parameters |
| `phalanx-stronghold/src/governor.rs` | Stronghold-side ingestion governance |

### Statistics & Signal Processing

PRNU sensor fingerprinting, Kolmogorov-Smirnov testing, spectral analysis, and calibration pipelines.

| File | What it does |
| ------ | ------------- |
| `phalanx-forensics/src/pipeline/calibrate.rs` | PRNU calibration — deriving per-sensor fingerprint thresholds. **This needs attention.** |
| `phalanx-forensics/src/trust/corroboration.rs` | Gate 8 multi-device proof generation with K-S statistical testing |
| `phalanx-proto/src/evidence/corroboration.rs` | Corroboration proof types and temporal event windows |
| `phalanx-node/src/vitals/spectral.rs` | Spectral analysis for vitals frequency-domain monitoring |
| `phalanx-lens/src/scalar.rs` | PRNU and Moire Pattern detection |
| `phalanx-transport/src/counting.rs` | Statistical counting utilities |
| `phalanx-ffi/src/calibrate.rs` | FFI bridge for sensor calibration |
| `phalanx-stronghold/src/ops/corroborate.rs` | Stronghold-side corroboration proof assembly |

### Storage & Persistence

Encrypted vault storage, append-only journals, WAL-backed retry queues, and redb key-value persistence.

| File | What it does |
| ------ | ------------- |
| `phalanx-node/src/persistence/vault.rs` | `Guardian` vault — encrypted, compressed forensic evidence storage |
| `phalanx-node/src/persistence/journal.rs` | `FileJournal` — append-only encrypted log with vault key management |
| `phalanx-node/src/persistence/outbound.rs` | `OutboundQueue` — WAL-backed retry queue with exponential backoff |
| `phalanx-node/src/persistence/kademlia.rs` | redb-backed `RecordStore` for persistent DHT records |
| `phalanx-proto/src/storage.rs` | `TransientJournal` trait contract, `PendingEgress`, `GuardianError` |
| `phalanx-stronghold/src/persistence/evidence_store.rs` | Stronghold evidence storage backend |
| `phalanx-stronghold/src/persistence/proof_store.rs` | Stronghold corroboration proof storage |
| `phalanx-stronghold/src/ops/export.rs` | Encrypted recording export with grant decryption |
| `phalanx-ffi/src/export.rs` | FFI bridge for evidence export |

### Mobile & Hardware

Camera and audio capture pipelines, BLE authentication, WiFi Direct, Flutter FFI bridges, and power-aware duty cycling.

| File | What it does |
| ------ | ------------- |
| `phalanx-node/src/hardware/camera.rs` | Adaptive video capture with JPEG compression, PRNU metrics, FPS duty cycling |
| `phalanx-node/src/hardware/audio.rs` | PCM audio capture at configured sample rate and channel count |
| `phalanx-node/src/vitals/hardware.rs` | Hardware capability detection and configuration |
| `phalanx-transport/src/adapters/local_mesh.rs` | BLE and WiFi Direct adapters via FFI (mobile), no-op fallback (desktop) |
| `phalanx-ffi/src/capture.rs` | FFI bridge for camera/audio capture from Flutter |
| `phalanx-ffi/src/ble_auth.rs` | BLE proximity authentication |
| `phalanx-ffi/src/probe.rs` | Hardware probe and capability detection |
| `phalanx-ffi/src/local_mesh.rs` | FFI bridge for local mesh transport |
| `phalanx-ffi/src/handle.rs` | FFI handle lifecycle management |
| `phalanx-ffi/src/memory.rs` | Cross-FFI memory management |

### Trust & Reputation

Peer scoring, offense tracking, reputation decay, community membership, and web-of-trust governance.

| File | What it does |
| ------ | ------------- |
| `phalanx-proto/src/identity/trust.rs` | `TrustLevel`, `PetName`, `Offense`, `OffenseSeverity` |
| `phalanx-proto/src/identity/community.rs` | Web-of-trust community types with quorum-based membership voting |
| `phalanx-forensics/src/trust/evaluation.rs` | Offense penalty assessment and reputation scoring traits |
| `phalanx-node/src/trust.rs` | `TrustRegistry`, `ReputationProjection` — peer scoring with fail-secure locks |
| `phalanx-node/src/actors/trust_actor.rs` | `TrustActor` — offense recording, reputation scoring, blacklisting |
| `phalanx-stronghold/src/actors/community.rs` | Community membership actor |
| `phalanx-ffi/src/trust.rs` | FFI bridge for trust queries |

### Actor Systems & Orchestration

The full reference for Tokio actor lifecycle, message passing, event loop design, and inter-actor coordination can be found in [`docs/actors.md`](docs/actors.md). They are complex enough to warrant their own document.

Key entry points: `phalanx-node/src/actors/meshsentinel.rs` (orchestrator), `phalanx-node/src/bin/sentinel.rs` (node binary), `phalanx-stronghold/src/bin/stronghold.rs` (stronghold binary).

### Simulation & Testing

Deterministic simulation harness, virtual clocks, and test fixture construction.

| File | What it does |
| ------ | ------------- |
| `phalanx-sim/src/harness.rs` | `SimulationHarness` — deterministic multi-node simulation |
| `phalanx-sim/src/clock.rs` | `VirtualClock` — deterministic time for reproducible simulations |
| `phalanx-sim/src/physics.rs` | Simulated network physics — latency, bandwidth, loss |
| `phalanx-sim/src/world.rs` | World state management for simulation scenarios |
| `phalanx-proto/src/telemetry.rs` | `ChaosMode`, `DiscoverySource`, `SimEvent` |
| `phalanx-transport/src/adapters/mock.rs` | Mock transport for integration tests |
| `phalanx-test-fixtures/src/chunks.rs` | Pre-built `ShardChunk` fixtures |
| `phalanx-test-fixtures/src/envelope.rs` | Pre-built `WitnessEnvelope` fixtures |
| `phalanx-test-fixtures/src/metrics.rs` | Pre-built lens metrics fixtures |
| `phalanx-test-fixtures/src/shards.rs` | Pre-built shard fixtures |
