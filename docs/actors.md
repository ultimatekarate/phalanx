# Phalanx Actor Reference

Actors are the sentences of the Linguistic Code Model — they compose nouns (types from `phalanx-proto`) and verbs (functions from `phalanx-forensics`) into runtime behavior. Every actor owns a `tokio::select!` event loop, communicates via bounded `mpsc` channels, and runs as a detached tokio task.

This document covers what each actor does, what messages it handles, how it connects to other actors, and why it was designed that way.

---

## Topology

```
                    ┌────────────────────────────────────────────────┐
                    │                  MeshSentinel                  │
                    │   (orchestrator — spawns every actor, routes   │
                    │    events; holds no business logic or state)   │
  Network ─Ingress──│  select!: ingress · local_mesh ·               │
                    │           commit_notify_rx · discovery_rx ·    │
                    │           lifecycle_rx · sentinel_cmd_rx (FFI) │
                    └──┬──────────────────┬───────────────────┬──────┘
       forwards to     │  spawns/owns     │  spawns/owns       │  spawns/owns
   ┌────────────────────┴──┐   ┌──────────┴─────────┐   ┌──────┴────────────┐
   │  Pipeline / Storage   │   │     Shield Wall     │   │  Capture/Playback │
   │  IngestionActor       │   │  EclipseRouter      │   │  MediaEgressActor │
   │  EgressActor          │   │  CanarySupervisor   │   │  PlaybackCoord.   │
   │  RetrievalActor       │   │  VitalsActor        │   └───────────────────┘
   │  TrustActor           │   │  ArchiveCoordinator │
   │  StorageActor (disk)  │   │  RevocationActor    │
   └───────────────────────┘   └─────────────────────┘
              ▲                            │
              └── Arc<HealthTracker>, Arc<SystemGovernor> shared (no channel) ──┘

    ─── Inbound events are forwarded to actors over bounded mpsc channels ───
    ─── oneshot reply channels used for request/reply (e.g. TryAdmit) ───
    ─── the Shield Wall group is spawned together by `actors::fleet` ───
```

The data path is unchanged: IngestionActor → StorageActor (disk) → PlaybackCoordinator;
MediaEgressActor writes local shards directly to StorageActor. See "Tracing a data path".

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

- `PeerDiscovered` reads topology + trust + health + eclipse state and emits a single admit/reject decision. This was once inline, but the topology state (admission gate, eclipse-fingerprint history, reciprocity ledgers, DID cache) is large and stateful, so it lives in **EclipseRouter**. The latency worry is resolved by a single `TryAdmit` → `AdmitOutcome` round-trip (one oneshot reply, not 4-5 queries): the orchestrator passes Eclipse the inputs and gets back the decision plus the follow-on flags (`was_first_seen`) it needs to fan out proximity-witness capture and revocation replay.
- `Ingest` reads one shard but does gate checks + fountain reassembly + disk I/O → **actor** (IngestionActor + StorageActor). The work is expensive and must not block the event router.
- `SecureRetrieval` reads one request but does auth verification + disk fetch + response sealing → **actor** (RetrievalActor).

An inline handler is *not* a code smell as long as it only mutates local router state (topology, health) and communicates externally through the standard channel pattern (`EgressCommand::DisconnectPeer`, `TrustCommand::RecordOffense`).

---

## phalanx-node actors

### MeshSentinel

**File**: `crates/phalanx-node/src/actors/meshsentinel.rs`

**Role**: Orchestrator. Spawns every other actor during `new()` (delegating the Shield Wall group to `actors::fleet`), then enters a `select!` loop that routes events to a handler or forwards them to an actor over a bounded channel. Holds **no business logic and no business state** — heartbeat crypto, revocation, archive custody, and spectral judgment all live in dedicated actors.

**Event loop arms**:

| Arm | Source | Action |
| ----- | -------- | -------- |
| `ingress.next_event()` | Network (QUIC / libp2p) | Route by `NetworkEvent` variant (see below) |
| `local_mesh.next_event()` | BLE / WiFi Direct | Same routing as ingress |
| `commit_notify_rx` | StorageActor | Forward `ArchiveCommand::StageRecording` → ArchiveCoordinator; `EgressCommand::AnnounceRecording` → EgressActor |
| `discovery_rx` | PlaybackCoordinator | `EgressCommand::FindProviders` — ask DHT who has missing shards |
| `lifecycle_rx` | Mobile OS | Recalculate `PowerState` on foreground/background transitions |
| `sentinel_cmd_rx` | FFI | start/stop recording, spawn playback, spawn recovery |

> There is no 5-minute tick arm anymore — topology maintenance is EclipseRouter's own `tokio::time::interval`, and the vitals/heartbeat cadence is VitalsActor's pinned timer.

**Network event routing**:

| Event | Dispatched to | Via |
| ------- | -------------- | ----- |
| `DataReceived` (control topic) | VitalsActor | `VitalsCommand::InboundHeartbeat` (try_send) |
| `DataReceived` (revocation topic) | RevocationActor | `RevocationCommand::InboundToken` (send().await) |
| `DataReceived` (data topic) | IngestionActor | `IngestionCommand::ProcessChunk` |
| `PeerDiscovered` | EclipseRouter (+ inline fan-out) | `EclipseCommand::TryAdmit`; on success: proximity-witness capture, `CanaryCommand::OnPeerReconnected`, `ReplayRevocations` |
| `RecordingRequested` | RetrievalActor | `RetrievalCommand::SecureRetrieval` |
| `ProvidersDiscovered` | PlaybackCoordinator | `providers_tx` channel |
| `ArchiveReceiptReceived` | ArchiveCoordinator | `ArchiveCommand::ReceiptReceived` |
| `ShardResponseReceived` | StorageActor + CanarySupervisor | `StorageCommand::WriteShard` + `CanaryCommand::RegisterContribution` |
| `PeerDisconnected` | EclipseRouter + CanarySupervisor | `EclipseCommand::PeerDisconnected` + `CanaryCommand::PeerDisconnected` (+ `HealthTracker::remove_spectral_peer`) |

**Retained inline state** (structural, not business logic):

- **playback slot** — the at-most-one-playback `JoinHandle` invariant (`spawn_playback` / `spawn_recovery`)
- **RecordingSessionState** — active recording id, content-key watch, proximity-witness buffer (drained to the egress actor on stop, sealed as `Evidence::Proximity`)
- **edge gates** in `handle_data_received` / `handle_data_chunk` — oversized-message rejection, bandwidth gating
- writes the shared `Arc<HealthTracker>` (data-volume observation on inbound chunks; spectral-peer cleanup on disconnect)

> **Design rationale**: MeshSentinel stays a thin router. The one decision that genuinely needs multi-field state — peer admission — is delegated to EclipseRouter through a single `TryAdmit` → `AdmitOutcome` round-trip, and the stateful/expensive paths (heartbeat crypto, revocation, archive staging) are forwarded to their own actors. The result is a ~1166-line file that is orchestration, not business logic: adding a handler here that reads multi-field state is a regression toward the God Object shape the Shield Wall actors were split out of.

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

**Role**: Ingress gate. Receives raw network data, applies policy checks, and forwards admitted shards to StorageActor. This is where adversarial input is rejected.

**Single command**: `IngestionCommand::ProcessChunk { peer_id, data, topic }`

**Gate sequence** (each can reject):

1. **Deserialization** — unmarshal the gossipsub bundle into `Vec<ShardChunk>` (a fountain fragment has no signature — nothing to verify until reassembly)
2. **TrafficGovernor** — power-state-aware per-peer bandwidth limit
3. **ReputationProjection** — lock-free trust level check
4. **Stale shard check** — reject if timestamp too old
5. **IngressGovernor** — slot allocation (sybil endowment)

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

## The Shield Wall group

EclipseRouter, CanarySupervisor, VitalsActor, ArchiveCoordinator, and RevocationActor are the **Shield Wall** — the security-actor group that MeshSentinel spawns together via [`actors/fleet.rs`](../crates/phalanx-node/src/actors/fleet.rs). `fleet::spawn_shield_wall` takes a `Shared` bundle of the common singletons (config, identity, clock, system_governor, `Arc<HealthTracker>`, reputation, used-bytes gauge, shutdown) and returns a `ShieldWall` of the five command senders plus their `JoinHandle`s — ordered EclipseRouter-first so they drain ahead of the storage/egress recipients they dispatch to. This keeps `MeshSentinel::new` an assembly step. The storage/pipeline actors stay inline in `new()` because they are interleaved with channel and Guardian setup and don't extract cleanly.

### EclipseRouter

**File**: `crates/phalanx-node/src/actors/eclipse_router.rs`

**Role**: Eclipse remediation. Owns topology admission (`TopologyGate`), eclipse-fingerprint history (`EclipseProbe`), the reciprocity floor's per-peer first-seen ledger, and a local DID cache (populated via `DidLearned` from CanarySupervisor). Reads the shared `Arc<HealthTracker>`.

**Commands**: `TryAdmit { … reply_to: AdmitOutcome }`, `PeerDisconnected`, `DidLearned`, `ReplayRevocations`.

**Cadence**: 5-minute topology tick (anchor promotion, eclipse evaluation, reciprocity sweep, integral pruning) + per-command.

> **Design rationale**: admission needs topology + trust + health at once, but that state is large and stateful. Rather than inline it in the router, it's a request/reply actor — the orchestrator sends `TryAdmit` and receives an `AdmitOutcome` (admitted / evicted / `was_first_seen`), keeping Eclipse state encapsulated without per-decision channel chatter.

---

### CanarySupervisor

**File**: `crates/phalanx-node/src/actors/canary_supervisor.rs`

**Role**: Silent Canary. Owns the `CanaryMonitor` (community-peer-liveness dead-man's-switch), the memory-only peer DID cache, and a local mirror of the recording-active flag. Reads the shared `Arc<HealthTracker>`.

**Commands**: `RegisterContribution`, `OnPeerReconnected`, `PeerDisconnected`, `RecordingStarted`, `RecordingStopped`.

**Cadence**: command-driven — staleness is confirmed on `PeerDisconnected` via `HealthTracker::is_peer_stale`. On confirmed darkness it emits `FindProviders` / `EmergencySalvage` and broadcasts an encrypted `CanaryAlert`; it also notifies EclipseRouter via `DidLearned`.

---

### VitalsActor

**File**: `crates/phalanx-node/src/actors/vitals_actor.rs`

**Role**: The node's presence cadence — **publish** (vitals refresh + Tier 2 Shield Wall heartbeat, per-community encrypted, `BroadcastGate`-gated) and **receive** (per-community decrypt, strict-binding origin check, spectral-consistency evaluation). Writes the shared `Arc<HealthTracker>` via `register_activity`.

**Command**: `InboundHeartbeat { origin, data }`.

**Event loop**: `select!` on shutdown + a **single pinned publish timer** (adaptive vitals interval, 5–60s by PowerState, reset only after it fires) + the command channel. Post-loop `try_recv` drain so heartbeats queued before shutdown are processed deterministically.

> **Design rationale**: publish and receive both operate on the same community keyset and the shared HealthTracker, so they're one cohesive actor. The pinned-sleep-reset (vs. recreating the sleep each loop) ensures a busy mesh's inbound heartbeats never reset — and thus never starve — the node's own publish cadence.

---

### ArchiveCoordinator

**File**: `crates/phalanx-node/src/actors/archive_coordinator.rs`

**Role**: Stronghold custody. Owns the per-session staging dedup set and the per-recording replica/deadline ledger. Runs the directed archive PUSH (fetch envelopes from StorageActor → mint per-peer export grants → `PushArchive`) off the run loop, and records inbound custody receipts.

**Commands**: `StageRecording { recording_id }`, `ReceiptReceived { receipt }`.

> **Design rationale**: staging does a storage round-trip plus per-peer grant minting — too heavy for the run-loop arm it used to occupy. MeshSentinel forwards `StageRecording` with `send().await` (not `try_send`) so a single-shard recording's lone staging directive is never dropped; this is deadlock-free because StorageActor emits `commit_notify` via `try_send`.

---

### RevocationActor

**File**: `crates/phalanx-node/src/actors/revocation.rs`

**Role**: Cryptographic forgetting. Stateless. Deserializes and verifies an inbound revocation token, forwards it to StorageActor for authorization/execution, then on success re-publishes to gossipsub and withdraws the local DHT provider records.

**Command**: `InboundToken { origin, data }`.

> **Design rationale**: distinct from `recovery.rs` (manifest-walk recovery) — different domain and trigger. Moving the verify + storage `Revoke` round-trip into an actor keeps it off the sentinel's run loop while preserving no-drop backpressure (`send().await`).

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

## Vitals (shared state, not standalone actors)

These modules hold state shared across actors via `Arc` but don't own their own event loops.

### SystemGovernor

**File**: `crates/phalanx-node/src/vitals/governor.rs`

Shared via `Arc` across all actors. Implements the Volterra second-kind integral system for resource management. Each actor calls `record_*_pressure()` to feed signals (memory, bandwidth, storage, I/O, connection, thermal); gate checks call `is_*_ok()` to read composite stress. `update_vitals()` — which steps the integrals and polls hardware sensors — is driven by **VitalsActor** on the adaptive vitals interval (5–60s by PowerState), not by a fixed 1s task.

### HealthTracker

**File**: `crates/phalanx-node/src/vitals/health.rs`

Shared via `Arc` (per-field RwLocks, never held across `.await`). Tracks peer heartbeats, capacities, and contracts; contains SpectralObserver as a field. **Written** by MeshSentinel (data-volume observation on inbound chunks; spectral-peer cleanup on disconnect) and by VitalsActor (`register_activity` per accepted heartbeat). **Read** by EclipseRouter and CanarySupervisor (e.g. `is_peer_stale`).

### SpectralObserver

**File**: `crates/phalanx-node/src/vitals/spectral.rs`

A field of HealthTracker. Records per-peer heartbeat timing and data volume and evaluates behavioral consistency — detecting Byzantine peers whose claimed state contradicts their observed behavior (the Shield Wall). Evaluated by VitalsActor on the heartbeat-receive path (`evaluate_spectral`).

### CanaryMonitor

**File**: `crates/phalanx-node/src/vitals/canary.rs`

Owned by **CanarySupervisor** (no longer embedded in MeshSentinel). The community-peer-liveness dead-man's-switch: when enough peers go silent (stale or disconnected), it emits `CanaryState` escalation that triggers evidence re-distribution and Stronghold flush.

---

## Tracing a data path

### Inbound shard (network → disk)

```
Network event (DataReceived)
  → MeshSentinel routes to IngestionActor
    → Deserialize bundle → ShardChunk
    → TrafficGovernor gate
    → ReputationProjection gate
    → IngressGovernor gate
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
