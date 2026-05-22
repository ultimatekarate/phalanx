# Phalanx Actor Reference

Actors are the sentences of the Linguistic Code Model — they compose nouns (types from `phalanx-proto`) and verbs (functions from `phalanx-forensics`) into runtime behavior. Every actor owns a `tokio::select!` event loop, communicates via bounded `mpsc` channels, and runs as a detached tokio task.

This document covers what each actor does, what messages it handles, how it connects to other actors, and why it was designed that way.

---

## Topology

```
                          ┌─────────────────────────────────────────┐
                          │            MeshSentinel                 │
                          │  (orchestrator — spawns all actors)     │
                          │                                        │
  Network ───IngressPort──│  select! on:                           │
                          │    ingress (network events)            │
                          │    local_mesh (BLE/WiFi Direct)        │
                          │    commit_notify_rx (DHT announce)     │
                          │    discovery_rx (playback gaps)        │
                          │    lifecycle_rx (foreground/background) │
                          └──┬────┬────┬────┬────┬────┬────────────┘
                             │    │    │    │    │    │
              ┌──────────────┘    │    │    │    │    └──────────────┐
              ▼                   ▼    │    ▼    ▼                   ▼
    ┌──────────────┐  ┌────────────┐  │  ┌────────────┐  ┌──────────────────┐
    │IngestionActor│  │EgressActor │  │  │TrustActor  │  │MediaEgressActor  │
    │ (ingress     │  │ (network   │  │  │ (reputation│  │ (capture →       │
    │  gate)       │  │  output)   │  │  │  engine)   │  │  encrypt → mesh) │
    └──────┬───────┘  └────────────┘  │  └────────────┘  └──────────────────┘
           │               ▲          │        ▲              │
           │               │          │        │              │
           ▼               │          ▼        │              │
    ┌──────────────────────┴──────────────────┐│              │
    │           StorageActor                   ││  ◄───────────┘
    │  (pure vault — disk I/O, reassembly,     ││    (local shard write)
    │   WAL recovery, revocation)              ││
    └──────────────┬───────────────────────────┘│
                   │                             │
                   ▼                             │
    ┌──────────────────────┐                     │
    │ PlaybackCoordinator  │─────────────────────┘
    │  (ephemeral, per     │     (requests remote shards
    │   UI playback)       │      via EgressActor)
    └──────────────────────┘

    ─── Arrows show command flow (mpsc channels) ───
    ─── oneshot channels used for request/reply ───
```

### Stronghold (server variant)

```
    ┌─────────────────────────┐
    │   StrongholdSentinel    │
    │  (server event router)  │
    └────┬──────────┬─────────┘
         │          │
         ▼          ▼
  ┌──────────────┐  ┌───────────────┐
  │Aggregation   │  │CommunityActor │
  │Actor (dual   │  │ (roster,      │
  │ Crucible)    │  │  vouch, DID   │
  └──────────────┘  │  routing)     │
                    └───────────────┘
```

---

## Channel conventions

All actor channels follow the same pattern:

- **Commands**: `mpsc::Sender<XCommand>` / `mpsc::Receiver<XCommand>` — fire-and-forget dispatch.
- **Request/reply**: Command variant contains a `oneshot::Sender<T>` for the response.
- **Pressure feedback**: `Arc<SystemGovernor>` shared across all actors — each records pressure signals, each reads composite stress levels. No channel needed.
- **Watch channels**: Used for slowly-changing state (e.g., `content_key_tx` for per-recording encryption key).

### When to extract an actor vs. handle inline

The heuristic: **if a handler needs to read many things and write one thing, inline it in the router. If it needs to read one thing and do expensive work, give it an actor.**

- `PeerDiscovered` reads topology + trust + health + eclipse state and emits a single admit/reject decision → **inline in MeshSentinel**. Extracting a TopologyActor would require either duplicating that state or adding 4-5 channel round-trips per peer connection — unacceptable latency during eclipse attack floods.
- `Ingest` reads one shard but does gate checks + fountain reassembly + disk I/O → **actor** (IngestionActor + StorageActor). The work is expensive and must not block the event router.
- `SecureRetrieval` reads one request but does auth verification + disk fetch + response sealing → **actor** (RetrievalActor).

An inline handler is *not* a code smell as long as it only mutates local router state (topology, health) and communicates externally through the standard channel pattern (`EgressCommand::DisconnectPeer`, `TrustCommand::RecordOffense`).

---

## phalanx-node actors

### MeshSentinel

**File**: `crates/phalanx-node/src/actors/meshsentinel.rs`

**Role**: Orchestrator. Spawns every other actor during `new()`, then enters a `select!` loop routing network events to the appropriate handler. Not a pure actor — it's the singleton coordinator.

**Event loop arms**:

| Arm | Source | Action |
| ----- | -------- | -------- |
| `ingress.next_event()` | Network (QUIC / libp2p) | Route by `NetworkEvent` variant (see below) |
| `local_mesh.next_event()` | BLE / WiFi Direct | Same routing as ingress |
| `commit_notify_rx` | StorageActor | `EgressCommand::AnnounceRecording` — tell DHT we have this shard |
| `discovery_rx` | PlaybackCoordinator | `EgressCommand::FindProviders` — ask DHT who has missing shards |
| `lifecycle_rx` | Mobile OS | Recalculate `PowerState` on foreground/background transitions |
| 5-minute tick | Timer | Topology maintenance: eclipse probe, spectral analysis, mesh fingerprint |

**Network event routing**:

| Event | Dispatched to | Via |
| ------- | -------------- | ----- |
| `DataReceived` | IngestionActor | `IngestionCommand::ProcessChunk` |
| `PeerDiscovered` | (handled inline) | Eclipse probe, topology gate, E6 rate limiting |
| `RecordingRequested` | RetrievalActor | `RetrievalCommand::SecureRetrieval` |
| `ProvidersDiscovered` | PlaybackCoordinator | `providers_tx` channel |
| `ShardResponseReceived` | StorageActor | `StorageCommand::WriteShard` |
| `PeerDisconnected` | (handled inline) | CanaryMonitor, reputation tracking |

**Embedded state machines** (not separate actors):

- **TopologyGate** — peer admission control for eclipse defense
- **EclipseProbe** — mesh fingerprint consistency checking
- **CanaryMonitor** — Silent Canary dead man's switch
- **HealthTracker** — peer heartbeat and spectral observation

> **Design rationale**: MeshSentinel is large because routing decisions require access to topology, trust, and health state simultaneously. Splitting it into smaller actors would require passing this state through channels, adding latency to every network event. The tradeoff is a 1143-line file in exchange for zero-copy routing decisions.

---

### StorageActor

**File**: `crates/phalanx-node/src/actors/storage.rs`

**Role**: Pure vault. Handles only disk I/O, WAL recovery, fountain reassembly, and cryptographic operations. No network logic, no routing.

**State**:

- `reassembler: Reassembler` — fountain code reconstruction via `Crucible<ShardMold>`
- `guardian: Guardian` — encrypted disk vault (keyring, recording ledger, revocation)
- `journal: J` — write-ahead log for crash recovery
- `replay_filter: RotatingBloomFilter` — evidence dedup (1M bits per generation, ~250KB)

**Commands**:

| Command | Purpose | Reply |
| --------- | --------- | ------- |
| `Ingest` | Process incoming shard through reassembly pipeline | `Result<(), GuardianError>` |
| `Retrieval` | Fetch recording envelopes from vault | `Vec<WitnessEnvelope>` |
| `GetShard` | Single shard fetch for playback | `Option<WitnessEnvelope>` |
| `WriteShard` | Direct write (remote shards from DHT) | `Result<(), GuardianError>` |
| `IngestEnvelope` | Bypass reassembly (internal Guardian ops) | `Result<(), GuardianError>` |
| `EmergencySalvage` | Backup egress queues on shutdown | None |
| `Revoke` | Cryptographic forgetting — destroy recording evidence | `Result<(), GuardianError>` |
| `StartRecording` | Derive per-recording DEK and (if publishable) append a manifest-catalog shard for fresh-device recovery | `Result<SymmetricKey, GuardianError>` |
| `StartRecordingWithOptions` | Same as `StartRecording`, but exposes the per-recording `publishable` policy. Unpublishable recordings get no manifest entry and are never gossipped. | `Result<SymmetricKey, GuardianError>` |
| `GetContentKey` | Resolve per-recording DEK (keyring hit for foreign + legacy own; HKDF-derived from `dek_master` for own under the v2 regime) | `Option<SymmetricKey>` (always `Some` under v2; `Option` retained for callers' historical fallback paths) |

**Ingest pipeline**: Storage pressure gate → hard limit (P6) → foreign storage enforcement → per-owner quota → reassemble via Crucible → persist.

**Maintenance tick** (1s): Bloom filter rotation + recording finalization (flush stale Crucible contexts by TTL).

**Commit notification**: After each successful shard write, fires `commit_notify_tx` so MeshSentinel can announce the recording on the DHT.

> **Design rationale**: StorageActor is the only actor that touches disk. This means crash recovery has exactly one place to look: the StorageActor's journal and Guardian vault. Every other actor is stateless across restarts — they rebuild from what StorageActor persists.

---

### IngestionActor

**File**: `crates/phalanx-node/src/actors/ingestion.rs`

**Role**: Ingress gate. Receives raw network data, applies policy checks, and forwards verified shards to StorageActor. This is where adversarial input is rejected.

**Single command**: `IngestionCommand::ProcessChunk { peer_id, data, topic }`

**Gate sequence** (each can reject):

1. **TrafficGovernor** — power-state-aware per-peer bandwidth limit
2. **IngressGovernor** — slot allocation (sybil endowment)
3. **ReputationProjection** — lock-free trust level check
4. **Deserialization + verification** — `ForensicUnit<ShardChunk, Unverified>` → `Verified`
5. **Stale shard check** — reject if timestamp too old

**On rejection**: Sends `TrustCommand::RecordOffense` to TrustActor with the specific offense type.

**Outputs**: `StorageCommand::Ingest` on success; `TrustCommand::RecordOffense` on violation.

> **Design rationale**: Ingestion is separated from storage so that the gate checks (which are CPU-bound and touch no disk) don't block disk I/O. If ingestion were inline in StorageActor, a burst of adversarial traffic could starve legitimate shard writes.

---

### EgressActor

**File**: `crates/phalanx-node/src/actors/egress.rs`

**Role**: Network output. All outbound messages flow through EgressActor — mesh publishes, DHT announces, peer disconnects, retrieval responses.

**State**:

- `pending: VecDeque<PendingEgress>` — retry queue for failed sends
- `announced: HashSet<RecordingId>` — dedup window for DHT announces (clears every 30s)

**Event loop**: `select!` on command channel + 500ms retry tick for pending queue.

**Commands** (12 variants):

| Command | Purpose |
| --------- | --------- |
| `Dispatch` | Send retrieval response to requester |
| `AnnounceRecording` | DHT provider announcement |
| `FindProviders` | DHT query for recording providers |
| `RequestShards` | Shard retrieval from specific peer |
| `DisconnectPeer` | Eclipse remediation — force disconnect |
| `ReBootstrap` | Eclipse remediation — re-dial bootstrap peers |
| `PublishRevocation` | Gossipsub revocation token broadcast |
| `WithdrawProvider` | Remove local DHT provider record |
| `AnnounceTombstone` | DHT tombstone for revoked recording |
| `PublishMesh` | Generic gossipsub publish (Silent Canary alerts) |
| `DrainForSalvage` | Shutdown: return pending queue for WAL backup |

> **Design rationale**: Centralizing all egress through one actor gives a single point for connection pressure tracking (feeds the `c` integral in the Volterra system) and for dedup/rate-limiting outbound messages. The 500ms retry tick with WAL-backed pending queue means network blips don't lose evidence.

---

### RetrievalActor

**File**: `crates/phalanx-node/src/actors/retrieval.rs`

**Role**: Retrieval gate. When a remote peer requests recordings, RetrievalActor decides whether to serve them based on trust, system load, and authorization.

**Single command**: `RetrievalCommand::SecureRetrieval { origin, request, channel_id }`

**Gate sequence**:

1. **Per-recording rate limit** — prevent targeted DoS on popular recordings
2. **I/O saturation check** — finalization scaler from SystemGovernor
3. **Thermal/battery check** — `check_permission` (mobile-specific)
4. **Privacy auth verification** — `verify_retrieval_auth` (ECDH + Ed25519 signed request)
5. **EgressGovernor** — policy-based authorization considering trust level and system stress

**On auth failure**: `TrustCommand::RecordOffense`

**On success**: `StorageCommand::Retrieval` → fetch envelopes → integrity check → seal → `EgressCommand::Dispatch`

> **Design rationale**: Retrieval is separated from ingestion because the trust model is asymmetric. Ingestion rejects bad input (defensive). Retrieval authorizes good output (permissive). They have different gate sequences, different failure modes, and different pressure characteristics.

---

### MediaEgressActor

**File**: `crates/phalanx-node/src/actors/media_egress.rs`

**Role**: Capture pipeline. Receives raw video/audio frames from the FFI camera callback, encrypts, signs, fountain-encodes, and publishes to the mesh.

**State**:

- `video_prev_hash, audio_prev_hash: Option<SignatureHash>` — hash chain for causality
- `outbound_queue: OutboundQueue` — WAL-backed retry with exponential backoff (5s base, 5min cap)
- `content_key_rx: watch::Receiver<Option<SymmetricKey>>` — per-recording DEK from MeshSentinel

**Event loop**: `select!` on video channel + audio channel + 5s retry tick. Exits when both channels close AND retry queue is drained.

**Pipeline per frame**:

1. **LensGate** — sensor provenance check (PRNU/Moire verification)
2. **AEAD encryption** — XChaCha20-Poly1305 with per-recording DEK (or vault key fallback)
3. **Seal envelope** — sign with Ed25519, set `prev_hash` for causality chain
4. **Fountain chunkify** — RaptorQ encode into self-describing symbols
5. **Publish** — broadcast symbols to mesh topic

**On publish failure**: Persist to OutboundQueue WAL. Queue depth feeds `record_storage_pressure()` for FPS self-regulation via the Volterra `w` integral.

> **Design rationale**: Encryption runs here (async worker) rather than on the FFI capture thread. Low-end Mediatek devices with weak entropy sources and slow cores drop frames when XChaCha20 + `getrandom()` block the camera HAL return path. The watch channel for `content_key_rx` avoids per-frame channel overhead — the key changes once per recording, not once per frame.

---

### TrustActor

**File**: `crates/phalanx-node/src/actors/trust_actor.rs`

**Role**: Reputation engine. Maintains per-peer trust scores, handles community imports, and periodically accumulates reputation via the Volterra trust integral.

**State**: `TrustRegistry` — the full peer trust database.

**Commands**:

| Command | Source | Purpose |
| --------- | -------- | --------- |
| `RecordOffense` | Ingestion, Retrieval | Degrade peer trust score |
| `CheckTrust` | (query) | Read current trust level |
| `IsBlacklisted` | (query) | Check if peer is banned |
| `ListPeers` | FFI | Mobile UI peer list |
| `SetTrustLevel` | FFI | Manual trust override |
| `AssignPetName` | FFI | Human-readable nickname |
| `RemovePeer` | FFI | Delete peer from registry |
| `ImportCommunity` | FFI | Import trusted community roster |
| `DissolveCommunity` | FFI | Zeroize community membership |

**Maintenance tick** (60s): `TrustArbiter::accumulate()` — Volterra reputation integral step. Slowly decays negative trust toward neutral, rewards sustained good behavior.

**Lock-free reads**: Other actors don't query TrustActor for routine trust checks. Instead, `ReputationProjection` (a lock-free snapshot) is shared via `Arc`. TrustActor updates the projection after community imports and offense records. This avoids channel round-trips on the hot ingestion path.

> **Design rationale**: Trust state changes slowly (offense records, 60s accumulation ticks) but is read on every incoming shard (IngestionActor gate check). The `ReputationProjection` pattern — write via channel, read via atomic snapshot — eliminates the latency that a request/reply channel would add to every ingestion decision.

---

### PlaybackCoordinator

**File**: `crates/phalanx-node/src/actors/playback.rs`

**Role**: Ephemeral playback session. Spawned by FFI when the user requests recording playback. Not a persistent actor — created on demand, dropped when playback ends.

**Lifecycle**: `new()` → `run(recording_id)` → loop fetching shards → drop.

**Playback loop**:

1. Request shard at `current_sequence` from StorageActor
2. If found: decrypt, re-verify LensGate, route to video/audio sink, increment sequence
3. If missing: trigger **Samson Reflex** — send `discovery_tx` to MeshSentinel, which queries DHT for providers. Then request shards from discovered providers via EgressActor with ECDH-sealed, Ed25519-signed requests.
4. Non-blocking `try_recv()` on `providers_rx` for DHT results (avoids cancelling oneshot replies)

**Sequence**: Starts at `StorageSequence(1)` — forensic truth starts at 1, not 0 (seq 0 is the genesis frame, handled differently).

> **Design rationale**: PlaybackCoordinator is ephemeral because playback is a UI concern with no persistence requirement. If the app is killed during playback, there's nothing to recover — the user just starts playback again. Making it persistent would add WAL complexity for zero benefit.

---

## phalanx-stronghold actors

### StrongholdSentinel

**File**: `crates/phalanx-stronghold/src/sentinel.rs`

**Role**: Server-side event router. Analog to MeshSentinel but simpler — a Stronghold doesn't capture media, doesn't have a UI, and doesn't manage mobile lifecycle.

**Spawns**: AggregationActor, CommunityActor.

**Event loop**: `select!` on ingress + 60s maintenance tick. Routes `DataReceived` → `AggregationCommand::IngestChunk`. Routes community-related events to CommunityActor.

**Channel capacity**: 512 per actor (vs. MeshSentinel's smaller buffers — Stronghold is server-grade).

---

### AggregationActor

**File**: `crates/phalanx-stronghold/src/actors/aggregation.rs`

**Role**: Dual Crucible pipeline. Receives ShardChunks from the mesh, reassembles into recordings, stores encrypted. **Never decrypts** — grant-based decryption happens at corroboration/export time.

**State**:

- `shard_crucible: Crucible<ShardMold>` — 100K capacity (vs. phone's 1K)
- `recording_crucible: Crucible<RecordingAmalgam>` — 100K concurrent recording assemblies
- `evidence_store: EvidenceStore` — encrypted disk persistence
- `community_routing: HashMap<Did, Vec<CommunityId>>` — DID-to-community cache
- `replay_filter: RotatingBloomFilter` — evidence dedup

**Commands**:

| Command | Purpose |
| --------- | --------- |
| `IngestChunk` | Main flow: reassemble → amalgamate → store |
| `FetchRecordings` | Retrieve recordings by community + recording IDs |
| `FetchProximity` | Retrieve proximity witnesses for corroboration |
| `RefreshRouting` | Update DID-to-community cache from CommunityActor |
| `Revoke` | Cryptographic forgetting |

**Maintenance tick** (30s): Flush stale contexts (300s TTL) + bloom rotation.

> **Design rationale**: The Stronghold runs a dual Crucible (ShardMold → RecordingAmalgam) in a single actor rather than splitting reassembly and amalgamation into separate actors. On a server, there's no mobile power-state concern, and the two stages are tightly coupled — the output of stage 1 is the input of stage 2. Keeping them together avoids a channel hop between stages.

---

### CommunityActor

**File**: `crates/phalanx-stronghold/src/actors/community.rs`

**Role**: Community roster lifecycle. Manages import (with vouch signature verification), expiration sweep, dissolution (with zeroize), and DID-to-community routing.

**State**:

- `communities: HashMap<CommunityId, Community>` — active rosters
- `did_index: HashMap<Did, HashSet<CommunityId>>` — reverse index for fast DID lookup

**Commands**:

| Command | Purpose |
| --------- | --------- |
| `Import` | Verify expiration + vouch signatures, build index |
| `Dissolve` | Zeroize community membership |
| `LookupMember` | Which communities does this DID belong to? |
| `ListCommunities` | All (id, name) pairs |
| `SnapshotRouting` | Full DID-to-community table for AggregationActor |

**Maintenance tick** (60s): `sweep_expired()` — remove communities past their expiration timestamp.

> **Design rationale**: Community management is separated from aggregation because community imports require cryptographic verification (vouch signatures) that shouldn't block the high-throughput shard ingestion path. The `SnapshotRouting` pattern lets AggregationActor cache the routing table and refresh it periodically rather than querying per-shard.

---

## Vitals (actor-adjacent, not standalone actors)

These modules hold state that is updated by multiple actors but don't have their own event loops.

### SystemGovernor

**File**: `crates/phalanx-node/src/vitals/governor.rs`

Shared via `Arc` across all actors. Implements the Volterra second-kind integral system for resource management. Each actor calls `record_*_pressure()` to feed signals (memory, bandwidth, storage, I/O, connection, thermal). Gate checks call `is_*_ok()` to read composite stress. A dedicated vitals polling task (spawned in MeshSentinel, 1s tick) calls `update_vitals()` to step the integrals and poll hardware sensors.

### CanaryMonitor

**File**: `crates/phalanx-node/src/vitals/canary.rs`

Embedded in MeshSentinel. Tracks community-scoped peer liveness. When enough peers go silent (stale or disconnected), emits `CanaryState` escalation signals that trigger evidence distribution priority increases and Stronghold flush.

### SpectralObserver

**File**: `crates/phalanx-node/src/vitals/spectral.rs` 

Embedded in HealthTracker. Records per-peer heartbeat timing and data volume. Evaluates behavioral consistency — detects Byzantine peers by checking whether their claimed state matches their observed behavior (the Shield Wall).

### HealthTracker

**File**: `crates/phalanx-node/src/vitals/health.rs`

Embedded in MeshSentinel. Tracks peer heartbeats, capacities, and contracts. Contains SpectralObserver as a field. Updated passively as heartbeats arrive from the network.

---

## Tracing a data path

### Inbound shard (network → disk)

```
Network event (DataReceived)
  → MeshSentinel routes to IngestionActor
    → TrafficGovernor gate
    → IngressGovernor gate
    → ReputationProjection gate
    → Deserialize + verify → ForensicUnit<ShardChunk, Verified>
      → StorageActor::Ingest
        → Storage pressure gate
        → Reassembler::ingest_chunk (Crucible<ShardMold>)
          → ShardMold::ingest (RaptorQ decode)
          → If complete: ShardMold::assemble → WitnessEnvelope
            → Guardian::ingest (Crucible<RecordingAmalgam>)
              → RecordingAmalgam ownership check
              → If sealed: Recording written to disk
        → commit_notify_tx → MeshSentinel → EgressCommand::AnnounceRecording
```

### Outbound frame (camera → mesh)

```
FFI camera callback pushes VideoShard
  → MediaEgressActor::video_rx
    → LensGate (PRNU/Moire check)
    → AEAD encrypt with per-recording DEK
    → Seal envelope (Ed25519 sign, set prev_hash)
    → FountainChunkifier → Vec<ShardChunk>
    → For each chunk: publish to mesh topic
      → On failure: persist to OutboundQueue WAL
        → 5s retry tick re-attempts
        → Queue depth → record_storage_pressure() → FPS self-regulation
```

### Playback (UI request → decrypted frames)

```
FFI calls spawn_playback(recording_id)
  → PlaybackCoordinator::run(recording_id)
    → Loop: StorageCommand::GetShard(seq)
      → If found: decrypt → LensGate re-verify → PlaybackSink
      → If missing: discovery_tx → MeshSentinel → FindProviders
        → ProvidersDiscovered → providers_rx
        → EgressCommand::RequestShards (ECDH sealed, Ed25519 signed)
        → ShardResponseReceived → StorageActor::WriteShard → retry GetShard
```
