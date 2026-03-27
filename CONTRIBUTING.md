# CONTRIBUTING TO PHALANX

The codebase is structured so that each technical specialty occupies a well-defined set of files with minimal entanglement. A networking engineer can improve the QUIC transport without understanding Padé approximants. A statistician can refine the Kolmogorov-Smirnov corroboration test without knowing how libp2p gossipsub works. A storage engineer can optimize the vault without touching the actor system. The linguistic model (`linguistic-code-model.md`) enforces these boundaries at the crate level — they are not conventions, they are compiler-enforced facts.

Before contributing, read `linguistic-code-model.md`. It defines the parts of speech (Nouns, Verbs, Conjunctions, Prepositions, etc.) and the rules that govern them. Then find your specialty below and start there.

---

## Files by Technical Specialty

### Cryptography & Identity

DID resolution, Ed25519 key management, AEAD payload encryption, signature verification, and decentralized identity.

| File | What it does |
| ------ | ------------- |
| `phalanx-proto/src/crypto.rs` | `SymmetricKey` with zeroization on drop, cryptographic error types |
| `phalanx-proto/src/identity.rs` | `Did`, `NetworkId`, `PhalanxIdentity`, `RecordingId`, `ShardId` |
| `phalanx-forensics/src/identity.rs` | DID resolution — extracting Ed25519 public keys from `did:key` URIs |
| `phalanx-forensics/src/witness.rs` | `WitnessAuthority` — signing, verifying, and chunking evidence envelopes |
| `phalanx-forensics/src/judge.rs` | Shard and recording amalgam causality validation |
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
| `phalanx-proto/src/network.rs` | `NetworkEvent`, `IngressPort`, `EgressPort`, `LocalMeshPort` trait contracts |
| `phalanx-proto/src/kademlia.rs` | DHT payload kinds and provider data structures |
| `phalanx-forensics/src/kademlia.rs` | DHT timestamp conversion and expiration verification |
| `phalanx-node/src/network/orchestrator.rs` | Transport stack factory for swarm construction |
| `phalanx-node/src/persistence/kademlia.rs` | redb-backed `RecordStore` for persistent DHT records |
| `phalanx-stronghold/src/swarm.rs` | Stronghold-side swarm management |

### Network Security

Eclipse attack detection, topology-aware peer admission, traffic governance, and bloom filter replay protection.

| File | What it does |
| ------ | ------------- |
| `phalanx-forensics/src/eclipse.rs` | Passive eclipse attack detection via `MeshFingerprint` and peer set analysis |
| `phalanx-forensics/src/topology_gate.rs` | Per-peer admission control enforcing subnet diversity and transport quotas |
| `phalanx-forensics/src/bloom.rs` | `RotatingBloomFilter` — probabilistic replay protection |
| `phalanx-forensics/src/policy.rs` | `IngressGovernor`, `TrafficGovernor`, `EgressGovernor` — traffic shaping |
| `phalanx-forensics/src/gate.rs` | Monadic gate combinators — `LensGate`, `IntegrityGate` |
| `phalanx-proto/src/topology.rs` | `SubnetBucket`, `TransportClass`, eclipse risk types |
| `phalanx-proto/src/trust.rs` | `TrustLevel`, `Offense`, `OffenseSeverity` |

### Media & Codecs

JPEG/PCM capture, MP4 transcoding, fountain code encoding/reassembly, C2PA content authenticity, and media playback.

| File | What it does |
| ------ | ------------- |
| `phalanx-forensics/src/transcode.rs` | JPEG frames + PCM audio → MP4 container |
| `phalanx-forensics/src/reassembler.rs` | Fountain-coded chunk reassembly into complete envelopes |
| `phalanx-forensics/src/c2pa_ext.rs` | C2PA manifest builder embedding Phalanx forensic assertions |
| `phalanx-proto/src/evidence.rs` | `WitnessEnvelope`, `ShardChunk`, `VideoShard`, `AudioShard`, `Evidence` |
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
| `phalanx-forensics/src/calibrate.rs` | PRNU calibration — deriving per-sensor fingerprint thresholds |
| `phalanx-forensics/src/corroboration.rs` | Gate 8 multi-device proof generation with K-S statistical testing |
| `phalanx-proto/src/corroboration.rs` | Corroboration proof types and temporal event windows |
| `phalanx-node/src/vitals/spectral.rs` | Spectral analysis for vitals frequency-domain monitoring |
| `phalanx-lens/src/neon.rs` | NEON SIMD-accelerated PRNU computation |
| `phalanx-lens/src/scalar.rs` | Scalar fallback PRNU computation |
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
| `phalanx-proto/src/trust.rs` | `TrustLevel`, `PetName`, `Offense`, `OffenseSeverity` |
| `phalanx-proto/src/community.rs` | Web-of-trust community types with quorum-based membership voting |
| `phalanx-forensics/src/trust.rs` | Offense penalty assessment and reputation scoring traits |
| `phalanx-node/src/trust.rs` | `TrustRegistry`, `ReputationProjection` — peer scoring with fail-secure locks |
| `phalanx-node/src/actors/trust_actor.rs` | `TrustActor` — offense recording, reputation scoring, blacklisting |
| `phalanx-stronghold/src/actors/community.rs` | Community membership actor |
| `phalanx-ffi/src/trust.rs` | FFI bridge for trust queries |

### Actor Systems & Orchestration

Tokio actor lifecycle, message passing, event loop design, and inter-actor coordination.

| File | What it does |
| ------ | ------------- |
| `phalanx-node/src/actors/meshsentinel.rs` | `MeshSentinel` — top-level event loop, network event dispatch |
| `phalanx-node/src/actors/ingestion.rs` | `IngestionActor` — inbound chunk verification and vault storage |
| `phalanx-node/src/actors/egress.rs` | `EgressActor` — outbound dispatch, DHT announces, retry with backoff |
| `phalanx-node/src/actors/media_egress.rs` | `MediaEgressActor` — media encryption, sealing, fountain encoding, publishing |
| `phalanx-node/src/actors/retrieval.rs` | `RetrievalActor` — secure retrieval with rate limiting and egress policy |
| `phalanx-node/src/actors/storage.rs` | `StorageActor` — shard writes, recording finalization, vault maintenance |
| `phalanx-node/src/actors/playback.rs` | `PlaybackCoordinator` — decryption and media sink during replay |
| `phalanx-node/src/actors/trust_actor.rs` | `TrustActor` — trust ledger management |
| `phalanx-node/src/bin/sentinel.rs` | Node binary entry point |
| `phalanx-stronghold/src/actors/aggregation.rs` | Stronghold ingestion and storage orchestration |
| `phalanx-stronghold/src/sentinel.rs` | Stronghold event loop |
| `phalanx-stronghold/src/bin/stronghold.rs` | Stronghold binary entry point |

### Simulation & Testing

Deterministic simulation harness, chaos injection, virtual clocks, and test fixture construction.

| File | What it does |
| ------ | ------------- |
| `phalanx-sim/src/harness.rs` | `SimulationHarness` — deterministic multi-node simulation |
| `phalanx-sim/src/chaos.rs` | Chaos injection — partition, delay, corruption scenarios |
| `phalanx-sim/src/clock.rs` | `VirtualClock` — deterministic time for reproducible simulations |
| `phalanx-sim/src/physics.rs` | Simulated network physics — latency, bandwidth, loss |
| `phalanx-sim/src/world.rs` | World state management for simulation scenarios |
| `phalanx-proto/src/telemetry.rs` | `ChaosMode`, `DiscoverySource`, `SimEvent` |
| `phalanx-transport/src/adapters/mock.rs` | Mock transport for integration tests |
| `phalanx-test-fixtures/src/chunks.rs` | Pre-built `ShardChunk` fixtures |
| `phalanx-test-fixtures/src/envelope.rs` | Pre-built `WitnessEnvelope` fixtures |
| `phalanx-test-fixtures/src/metrics.rs` | Pre-built lens metrics fixtures |
| `phalanx-test-fixtures/src/shards.rs` | Pre-built shard fixtures |

---

## Before You Submit

1. Read `linguistic-code-model.md` — particularly Sections I (Parts of Speech) and II (Structural Enforcement).
2. Run `cargo clippy --workspace --all-targets` — zero errors, zero governance lint warnings.
3. Run `cargo test --workspace` — all tests pass.
4. If you added an `#[allow(clippy::...)]`, include a comment explaining why the suppression is safe.
5. If you added a new type, check the linguistic model to determine which crate it belongs in. Nouns go in the Dictionary. Verbs go in the Laboratory. Prepositions go in the Post Office.
