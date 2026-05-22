# PHALANX LINGUISTIC MODEL: ARCHITECTURAL GOVERNANCE

This document establishes the "Linguistic Model" of Phalanx. All code must be partitioned based on its linguistic role to ensure all parts remain testable. It is my attempt to create an enforceable architectural paradigm that makes the code base tractable for humans AND LLMs.
 
**A Note on the Metaphor.** The linguistic model is a tool for partitioning code. Some of the comparisons in this document are overwrought — add linguist to the list of things I am not. And if I'm being totally honest, this is little more than Apollo-era DSKY flavored Functional Core, Imperative Shell that uses the Rust compiler to give it actual teeth. If language is logic, it should also be architecture. Maintain the analogy insofar as it is useful, abandon it when it is not. When in doubt, the Cargo.toml files are the source of truth.

**Multi-scale governance.** The model operates at two reinforcing scales. I took inspiration from multi-grid solvers. The *coarse grid* is this document — it partitions the entire codebase into linguistic roles (Dictionary, Laboratory, Post Office, Sentence) so that any contributor can make a correct high-level decision without reading implementation code. The *fine grid* is the local context inside each file — semantic constructor names, type-state transitions, named handler methods, and workspace-level compiler lints. A contributor working inside a single function has enough local information to make correct decisions at that scope. Errors at one scale are caught at the other: a type placed in the wrong crate violates the coarse grid; a function that grows too complex or smuggles an `unwrap()` past governance is caught by the fine grid. Correct code emerges from convergence across both scales, not from exhaustive global knowledge.

---

## I. Definitions

Every element of Phalanx code maps to a linguistic role. Understanding these parts of speech is prerequisite to understanding the crate structure, placement rules, and governance commands that follow.

### I.a. Parts of Speech
- **Noun** — A data type, trait contract, or error type. Things that exist. `WitnessEnvelope`, `WitnessId`, `MeshAddress`, `TransientJournal`, `GuardianError`. Nouns live in the Dictionary (`phalanx-proto`).
- **Adjective** — A qualifier that narrows a noun's meaning. Type-state markers (`Verified`, `Sealed`, `Ephemeral`), configuration types, and constructor suffixes (`new_verified()`, `new_ephemeral()`). Adjectives attach to nouns — they describe *what kind* of noun you have. An adjective normally lives wherever its noun lives; the exception is a type-state marker whose states are produced and consumed solely by Laboratory verbs and which has no wire representation — that marker co-locates with the verbs that transition it. `ForensicUnit` and its `Unverified`/`Verified`/`Sealed` markers therefore live in the Laboratory (`phalanx-forensics`), not the Dictionary.
- **Verb** — Pure logic that acts on nouns. Validation, verification, transformation, encoding. `check_integrity()`, `fountain_chunkify()`, `authorize()`. Verbs live in the Laboratory (`phalanx-forensics`). A verb never touches the filesystem or network.
- **Preposition** — The directional relationships that define how nouns move through the system. Routing, codecs, adapter boundary mappings, serialization. The `PeerId` → `MeshAddress` translation at the libp2p boundary. Postcard encoding of envelopes into wire bytes. The routing switchboard that delivers events to the correct actor. `from_<source>()` constructors. Prepositions live in the Post Office (`phalanx-transport`) and at the edges of the Sentence (`phalanx-node`).
- **Conjunction** — Monadic gates that chain verbs together and short-circuit the pipeline on failure. `LensGate`, `IntegrityGate`, `TopologyGate`. A conjunction says "and" between verbs — verify integrity *and* check provenance *and* gate bandwidth. If any conjunction fails, the sentence stops. Conjunctions live in the Laboratory.
- **Interjection** — Forensic telemetry that observes and records without altering control flow. `tracing::error!("CRITICAL: Integrity validation failed")`, `tracing::warn!("P5: Oversized message rejected")`. Interjections are exclamations — they announce that something noteworthy happened but do not change what happens next.

### I.b. Compositions
- **Sentence** — A composition of nouns through verbs, joined by conjunctions, routed by prepositions, into running behavior. Actors and orchestration. `MeshSentinel`, `IngestionActor`, `EgressActor`. Sentences live in `phalanx-node`.
- **Phrasebook** — Pre-composed test sentences. The Phrasebook (`phalanx-test-fixtures`) constructs synthetic nouns that satisfy verb preconditions, so that test code in the Sentence layer doesn't need to know the Laboratory's validation rules.

---

## II. STRUCTURAL ENFORCEMENT

This model is not a metaphor, a style guide, or a set of suggestions. It is structurally enforced at multiple levels. A violation cannot reach production through negligence — it must actively defeat the safeguards.

**Crate dependency graph.** The linguistic boundaries are physical. `phalanx-proto` (Dictionary) has no dependency on `tokio`, `libp2p`, or any IO runtime. `phalanx-forensics` (Laboratory) depends only on `phalanx-proto` and pure computation crates. A verb cannot touch the filesystem because its crate literally does not have the dependency. A libp2p type cannot leak into the Dictionary because the crate has never heard of libp2p. These are not conventions — they are `Cargo.toml` facts that the compiler enforces on every build.

**Workspace governance lints.** The root `Cargo.toml` defines strict clippy lints at the `deny` level, and every crate inherits them via `[lints] workspace = true`:

*Reliability:*
- `unwrap_used = "deny"` — No infallible unwrapping. Handle the error or fail secure.
- `expect_used = "deny"` — Same. If you need an exception, add `#[allow]` with a justification comment.
- `panic = "deny"` — No panics in production code. The system must degrade, not crash.
- `indexing_slicing = "deny"` — No unchecked indexing. Use `.get()` and handle the `None`.

*Data Integrity:*
- `arithmetic_side_effects = "deny"` — No unchecked arithmetic. Overflow is a data integrity violation.
- `cast_possible_truncation = "deny"` — No silent truncation. If a cast is safe, prove it in a comment.
- `cast_sign_loss = "deny"` — No silent sign loss in casts.
- `cast_possible_wrap = "deny"` — No silent wrapping in casts.
- `float_cmp = "deny"` — No direct float equality. Use epsilon or `ulps_eq!` or `MACHEPS` (See `crates/phalanx-lens/src/scalar.rs`, line 203).

*Concurrency:*
- `await_holding_lock = "deny"` — No holding locks across `.await` points.

*Safety:*
- `undocumented_unsafe_blocks = "deny"` — Every `unsafe` block requires a `// SAFETY:` comment.

*Quality (warn, not deny):*
- `cognitive_complexity = "warn"` — Functions exceeding complexity 20 trigger a warning.
- `large_futures = "warn"` — Large futures that risk stack overflow.
- `todo = "warn"` — TODOs are visible in CI output.

Every `#[allow(clippy::...)]` in the codebase has a comment explaining why the suppression is safe. The suppression is the exception. The denial is the rule.

**Type-state enforcement.** A `ForensicUnit<WitnessEnvelope, Verified>` cannot be constructed without calling a verification verb. A `ForensicUnit<WitnessEnvelope, Sealed>` cannot be constructed without passing through egress authorization. These are not runtime checks — they are type system constraints. The wrong state literally does not compile.

**Cognitive complexity budget.** Functions exceeding a cognitive complexity of 20 trigger a clippy warning. The resolution is handler extraction — decompose the function into named methods, each with a clear responsibility. The function reads like a table of contents; the handlers contain the logic.

---

## III. SUBJECT-VERB AGREEMENT

**Rule:** When a Noun flows through a Verb, the Noun's values must satisfy the Verb's preconditions. This is the code equivalent of grammatical agreement — subject and verb must agree in tense.

**The General Principle:** The tense of the Noun must match the tense of the Verb. If the Verb validates against live state, the Noun must come from live state. If the Verb validates against a fixed schema, the Noun must conform to that schema. Disagreement between subject and verb is a grammatical error — in natural language it sounds wrong; in code it fails at runtime.

**Temporal Agreement:** A Noun carrying a timestamp that flows through a temporal Verb (freshness check, expiry validation, window alignment) must be constructed from the same clock source the Verb uses for validation. A past-tense Noun (fixed timestamp) cannot satisfy a present-tense Verb (freshness gate). In production, the clock source is `TrustedClock`. In tests, the clock source is `SystemClock` — never a fixed literal unless the test explicitly does not pass through a temporal Verb.

**Cryptographic Agreement:** A Noun carrying a signature or DID that flows through a verification Verb must use the matching keypair. A `Did` constructed for a `verify_envelope()` call must correspond to the `SigningKey` that produced the signature.

**Structural Agreement:** A Noun carrying a collection or identifier that flows through a validation Verb must satisfy that Verb's bounds. A `SubnetBucket` consumed by `TopologyGate::admit()` must be in valid range. A `ShardGapReport` consumed by a retrieval Verb must have `missing_indices.len() <= MAX_GAP_INDICES`.

---

## IV. GOVERNANCE COMMANDS

1. **NEVER** allow libp2p types to leak into the Lab or the Dictionary. Map them to `MeshAddress` in the Adapter.
2. **NEVER** allow filesystem IO (`std::fs`, `tokio::fs`) or network IO (`std::net`, `tokio::net`) into the Lab. In-memory byte assembly (`std::io::Cursor`, `std::io::Write` on `Vec<u8>`) is permitted when required by codec dependencies. For persistence, use the `TransientJournal` trait.
3. **ALWAYS** define reassembly strategies as `Mold` implementations in the Lab.
4. **PREFER** the `prelude` for cross-crate imports of first-class Nouns. Import persistence contracts, scheduling types, and operational state directly from their defining module.
5. **NEVER** await on a present-tense state. Treat network deadlocks as a conflict of tense. Organize resources by temporal kind:
- Past: sealed / immutable data. Read freely, no lock needed.
- Present: in-flight operations, currently-held state. Touched briefly, never awaited on.
- Future: pending commitments (PendingEgress). Enqueued, not held.
The rule that falls out: never await on present while holding present. Wait on past (free) or future (enqueued); never on a peer's current-tense state. That breaks deadlock's cycle requirement by construction. Use Mutex and RwLock only when it is absolutely necessary. 
6. **ALWAYS** ensure subject-verb agreement: a Noun constructed for consumption by a Verb must satisfy that Verb's preconditions. Temporal Nouns must agree with temporal Verbs. Cryptographic Nouns must agree with verification Verbs.
7. **NEVER** construct test Nouns with fixed values when the consumption path includes a Verb that validates against live state. Use the same source the Verb uses.
8. **NEVER** add `phalanx-test-fixtures` as a production `[dependency]`. The Phrasebook exists only in dev-dependency graphs. If a fixture is needed at runtime, promote the construction logic to its owning crate as a semantic constructor.

---

## V. CONSTRUCTOR NAMING

Constructors carry semantic weight. The name documents the construction invariant — what the caller must understand about the object being created.

- **`new()`** means simple construction with minimal or no validation. The caller gets a value with no implied preconditions beyond the type signature.
- **`new_<qualifier>()`** means the qualifier is a precondition, mode, or invariant that distinguishes this construction from other possible constructions. The suffix is documentation — it tells the caller *what kind* of value they are getting. Do not rename qualified constructors to bare `new()`.
- **`from_<source>()`** means type conversion from a different representation. The source name documents what is being converted.

When a type has only one constructor and it carries a semantic qualifier, the qualifier takes precedence over the convention of `new()`. A constructor named for its invariant is more valuable than one named for convention.

---

## VI. TYPE PLACEMENT

Types belong where the linguistic model places them, not where they are consumed most heavily.

- **Temporal primitives are Tenses.** A monotonic clock, a timestamp, or a duration belongs with other time concepts, not in the module that uses it for bookkeeping. *Example:* `PhalanxTimestamp`, `MonotonicClock`, and the `TrustedClock` trait all live in `phalanx-proto/src/time.rs` — not in `phalanx-node` where they are consumed most heavily.
- **Capability contracts are Nouns.** A trait that defines what a component *can do* (persist state, provide a clock, enforce wire bounds) is a contract — a shape of interaction. Contracts belong in the Dictionary alongside the types they operate on. *Example:* `TransientJournal` (persistence contract) is defined in `phalanx-proto/src/storage.rs`, not in `phalanx-node` where `FileJournal` implements it. `WireBound` (structural enforcement) is defined in `phalanx-proto/src/wire.rs`. `IngressPort`, `EgressPort`, and `LocalMeshPort` (network contracts) are defined in `phalanx-proto/src/network.rs`, not in `phalanx-transport` where `Libp2pAdapter` implements them.
- **Operational state is not a first-class Noun.** Retry queues, scheduling metadata, and actor-internal bookkeeping serve the implementation, not the domain model. They belong in their implementing crate, not in shared contracts. *Example:* `OutboundQueue` (WAL-backed retry queue for failed publishes) is defined in `phalanx-node/src/persistence/outbound.rs`. `PendingEgress` lives in `phalanx-proto/src/storage.rs` because it crosses the `TransientJournal` trait boundary, but it is explicitly excluded from the prelude — consumers import it directly from `phalanx_proto::storage::PendingEgress`.
- **Consumer gravity is a drift pattern.** When a type is used heavily in one module, the temptation is to move it closer. Resist this — check the model first. If the type is a Tense, it stays with the Tenses regardless of who reads it most. *Example:* `PhalanxTimestamp` is used pervasively in `phalanx-node` (vault, outbound queue, actors) but remains defined in `phalanx-proto/src/time.rs`. Its `now()` constructor is `pub(crate)` — external consumers must obtain timestamps through a `TrustedClock` implementor, which reinforces the placement boundary.
- **Trait signatures in the Dictionary should reference domain types, not runtime-specific types.** If a trait requires a runtime type in its signature, refactor the signature to use domain-shaped abstractions rather than exempting the trait from placement rules. *Example:* `EgressPort::publish()` takes `&MeshTopic` and `EgressPort::disconnect_peer()` takes `&MeshAddress` — domain types defined in the Dictionary. The trait never references `libp2p::PeerId` or `Multiaddr`; the `Libp2pAdapter` in `phalanx-transport` maps between domain types and runtime types at the boundary.

---

## VII. PRELUDE DISCIPLINE

The prelude is the public vocabulary of a crate — the set of names that every consumer gets by default.

- Only types that most consumers need belong in the prelude. Core evidence types, identity types, and error types qualify. Persistence contracts, scheduling types, and operational state do not.
- Adding a type to the prelude is a deliberate act. It increases the default cognitive load for every consumer of the crate.
- When in doubt, require direct import. A consumer who needs a specialized type can import it from the defining module. A consumer who doesn't need it should never see it.

---

## VIII. CRATE REFERENCE

The following sections are a module-level inventory of each crate. The file list isn't exhaustive. Sections I–VI define the rules. This section shows where everything lives.

### The Dictionary (phalanx-proto)

**Role:** The Nouns and Adjectives. Shared Reality.
**Constraint:** Inert. No IO. No tokio. No libp2p.

**Identity & Evidence — Who, What, Where:**

- **identity.rs:** Who is talking? (`Did`, `WitnessId`, `MeshAddress`, `PhalanxIdentity`, `RecordingId`, `ShardId`)
- **evidence.rs:** What are they saying? (`WitnessEnvelope`, `ShardChunk`, `VideoShard`, `AudioShard`, `Evidence`)
- **topic.rs:** Where are they saying it? (`MeshTopic`)
- **retrieval.rs:** What are they asking for? (`RecordingRequest`, `RecordingResponse`)

**Temporal & Cryptographic Primitives:**

- **time.rs:** When did it happen? (`PhalanxTimestamp`, `MonotonicClock`, `TrustedClock` trait, `TimeError`)
- **crypto.rs:** Key material and cryptographic error types. (`SymmetricKey` with zeroization on drop)

**Trust & Topology — Social Structure:**

- **trust.rs:** How much do we trust them? (`TrustLevel`, `PetName`, `Offense`, `OffenseSeverity`)
- **topology.rs:** What does the network look like? (`SubnetBucket`, `TransportClass`, eclipse risk types)
- **community.rs:** Who belongs together? Decentralized web-of-trust with quorum-based membership voting.
- **kademlia.rs:** DHT payload kinds, provider entries, and Kademlia protocol data structures.

**Capability Contracts — Traits that define what a component can do:**

- **network.rs:** `NetworkEvent` enum, `IngressPort`, `EgressPort`, `LocalMeshPort` traits. Defines the shape of network interaction without referencing runtime types.
- **storage.rs:** `TransientJournal` trait (persistence contract), `PendingEgress` (egress salvage noun), `GuardianError`.
- **wire.rs:** `WireBound` trait — post-deserialization structural constraint enforcement.
- **playback.rs:** `PlaybackSink` trait — exit gate for decrypted forensic data to UI or C2PA files.

**Coordination & Telemetry:**

- **vitals.rs:** `ControlMessage` heartbeat structure for mesh load-balancing and peer vitality.
- **telemetry.rs:** `ChaosMode`, `DiscoverySource`, `SimEvent` — simulation and chaos testing nouns.
- **corroboration.rs:** Multi-device corroboration proof types and temporal event windows.

**Supporting Types:**

- **types.rs:** `PhalanxPhysics`, unit interval types, `TaskCost`.
- **error.rs:** `ShardError`, `TimeError` — domain error types.
- **constants.rs:** Global protocol constants and DHT error types.

### The Laboratory (phalanx-forensics)

**Role:** The Verbs, Conjunctions, and The Law. Pure Logic.
**Constraint:** 100% Testable. No tokio::fs. No libp2p.

**The Verification Typestate:**

- **unit.rs:** `ForensicUnit<WitnessEnvelope, State>` and its `Unverified`/`Verified`/`Sealed` markers — the type-state wrapper, relocated here from the Dictionary. It has no wire form (deliberately not `Serialize`/`Deserialize`) and its unchecked constructors are `pub(crate)`, so a `Verified` or `Sealed` unit can only be minted by this crate's gates. The marker adjectives co-locate with the verbs that transition them.

**Core Forensic Verbs:**

- **crucible.rs:** The Verb "To Stage." Generic engine for data aggregation and envelope sealing.
- **reassembler.rs:** The Verb "To Assemble." Fountain-coded chunk reassembly into complete envelopes.
- **judge.rs:** The Verb "To Verify." Shard and recording amalgam causality validation.
- **witness.rs:** The Verb "To Witness." `WitnessAuthority` trait for signing, verifying, and chunking evidence.

**Gate System — Conjunctions (Composable Verification):**

- **gate.rs:** Monadic gate combinators for deserialization, integrity checks, and forensic verification. `LensGate` for sensor provenance, `IntegrityGate` for envelope validation.
- **policy.rs:** The Verb "To Govern." `IngressGovernor`, `TrafficGovernor`, `EgressGovernor` — traffic shaping and power state logic.
- **topology_gate.rs:** The Verb "To Admit." Per-peer admission control enforcing subnet diversity and transport quotas.
- **bloom.rs:** The Verb "To Remember." `RotatingBloomFilter` for probabilistic replay protection.
- **eclipse.rs:** The Verb "To Detect." Passive eclipse attack detection via `MeshFingerprint` and peer set change analysis.

**Media & Standards:**

- **transcode.rs:** The Verb "To Transcode." Converts decoded JPEG frames and PCM audio into MP4 containers.
- **c2pa_ext.rs:** The Verb "To Certify." C2PA manifest builder embedding Phalanx forensic assertions.
- **calibrate.rs:** The Verb "To Calibrate." PRNU calibration pipeline deriving per-sensor fingerprint thresholds.

**Trust & Identity Verification:**

- **trust.rs:** The Verb "To Evaluate." Offense penalty assessment and reputation scoring traits.
- **identity.rs:** The Verb "To Resolve." DID resolution extracting Ed25519 public keys from `did:key` URIs.
- **corroboration.rs:** The Verb "To Corroborate." Gate 8 multi-device proof generation with Kolmogorov-Smirnov statistical testing.
- **kademlia.rs:** DHT timestamp conversion and expiration verification utilities.

### The Post Office (phalanx-transport)

**Role:** The Prepositions. Delivery without comprehension.
**Constraint:** Translates between domain-typed contracts (`IngressPort`, `EgressPort`) and physical network protocols. No forensic logic — only delivery.

**Adapters — Protocol Boundaries:**

- **adapters/libp2p.rs:** `Libp2pAdapter` implementing mesh publish/subscribe and direct peer messaging. Translates `PeerId` to `MeshAddress` at the boundary.
- **adapters/quic/:** Standalone QUIC transport for direct phone-to-Stronghold connections bypassing the libp2p mesh. Split into `client.rs`, `server.rs`, and `wire.rs`.
- **adapters/local_mesh.rs:** BLE and WiFi Direct adapters via FFI (mobile) with no-op fallback (desktop).
- **adapters/mock.rs:** Test double for transport-layer integration tests.

**Wiring & Protocol Machinery:**

- **factory.rs:** Mesh transport factory — constructs libp2p swarm with persistent Kademlia store and gossipsub.
- **builder.rs:** QUIC and TCP fallback transport builders with TLS 1.3 and connection pooling.
- **behaviour.rs:** `PhalanxBehaviour` aggregating gossipsub, Kademlia, mDNS, relay, and request-response sub-protocols.
- **events.rs:** `PhalanxEvent` enum unifying all swarm behaviour event types into a single stream.
- **routing.rs:** Central switchboard routing `NetworkEvent`s and matching responses to pending requests.
- **codec.rs:** `PhalanxRetrievalProtocol` codec — postcard serialization with length-prefixed framing.
- **io.rs:** Async I/O utilities for length-prefixed payload serialization with size validation.

**DHT & Identity:**

- **kademlia.rs:** `KademliaGovernor` with reputation-weighted provider insertion and temporal decay.
- **dht.rs:** Re-exports of libp2p DHT types for custom backend implementations.
- **identity_ext.rs:** Extension trait converting `PhalanxIdentity` to libp2p keypairs and `MeshAddress`es.

### The Sentence (phalanx-node)

**Role:** The Sentences. Compositions of nouns through verbs, joined by conjunctions, routed by prepositions, into running behavior.
**Constraint:** Environment-dependent. Touches hard drives, wires, cameras, and microphones.

**Actors — The Narrators:**

- **actors/meshsentinel.rs:** `MeshSentinel` — top-level event loop. Dispatches network events to handler methods, coordinates topology maintenance and eclipse remediation.
- **actors/ingestion.rs:** `IngestionActor` — consumes inbound mesh chunks, applies forensic gate verification, stores to Guardian vault.
- **actors/egress.rs:** `EgressActor` — manages outbound dispatch, DHT announces with dedup, shard requests, and retry with backoff.
- **actors/media_egress.rs:** `MediaEgressActor` — encrypts, seals, fountain-encodes, and publishes video/audio evidence with WAL-backed retry.
- **actors/retrieval.rs:** `RetrievalActor` — services secure retrieval requests with rate limiting, integrity checking, and egress policy.
- **actors/storage.rs:** `StorageActor` — persistence coordinator for shard writes, recording finalization, and vault maintenance.
- **actors/playback.rs:** `PlaybackCoordinator` — decryption and media sink operations during forensic evidence replay.
- **actors/trust_actor.rs:** `TrustActor` — offense recording, reputation scoring, and peer blacklist management.

**Persistence — The Memory:**

- **persistence/vault.rs:** `Guardian` vault — encrypted, compressed forensic evidence storage implementing `TransientJournal`.
- **persistence/journal.rs:** `FileJournal` — append-only encrypted log persistence with vault key management.
- **persistence/outbound.rs:** `OutboundQueue` — WAL-backed persistent queue for failed media publishes with exponential backoff.
- **persistence/kademlia.rs:** redb-backed `RecordStore` for persistent DHT provider records.

**Stability — The Nervous System:**

Most of this code does not execute during run time. This is the instrumentation that I use to test the stability of the network. I have lifted it into `cargo build`. See line 308 of `crates/phalanx-node/src/stability/contractivity.rs`.

- **stability/jacobian.rs:** Linearized Jacobian matrix construction for homeostatic stability analysis.
- **stability/spectral.rs:** Spectral gap and eigenvector orthogonality analysis for control loop robustness.
- **stability/eigenvalues.rs:** Eigenvalue computation for system pole placement and stability verification.
- **stability/nonlinear.rs, pade.rs, dyson.rs, config.rs:** Nonlinear dynamics, Padé approximants, Dyson series, and stability configuration.

**Vitals — The Autonomic System:**

- **vitals/governor.rs:** `SystemGovernor` — core homeostasis engine managing stress integrals, power states, and feedback loops.
- **vitals/health.rs:** Observability initialization with tracing and spectral health telemetry.
- **vitals/spectral.rs:** Spectral analysis for vitals frequency-domain monitoring.
- **vitals/hardware.rs:** Hardware capability detection and configuration.

**Hardware — The Senses:**

- **hardware/camera.rs:** Adaptive video capture with JPEG compression, PRNU lens metrics, and power-aware FPS duty cycling.
- **hardware/audio.rs:** PCM audio capture at configured sample rate and channel count for sharding.

**Support:**

- **trust.rs:** `TrustRegistry` and `ReputationProjection` — peer scoring with fail-secure lock handling.
- **clock.rs:** `TrustedClock` implementation — NTP-synchronized system clock with monotonic guarantees.
- **identity.rs:** `PhalanxNodeIdentityExt` — node-level identity operations and retrieval authorization.
- **network/orchestrator.rs:** Transport stack factory constructing libp2p swarm with persistent Kademlia store.

### The Phrasebook (phalanx-test-fixtures)

**Role:** Pre-composed Test Sentences. Construction knowledge encapsulation.
**Constraint:** Dev-dependency only. No IO. No new Verbs. No new domain types.

A Phrasebook composes Dictionary Nouns with Laboratory Verbs to produce synthetic test instances. It exists because tests in the Hands should not need to know the Laboratory's validation preconditions in order to construct valid Nouns.

- May depend on the Dictionary (phalanx-proto) and the Laboratory (phalanx-forensics).
- Must NOT depend on the Hands (phalanx-node, phalanx-transport).
- Must NOT introduce domain types — it only constructs existing ones.
- Must NOT introduce Verbs — it only calls existing ones.
- Must appear only in `[dev-dependencies]`, never in `[dependencies]`.
- Must self-test: fixtures that claim to pass a Laboratory Verb must prove it.

## IX. POSTSCRIPT

These rules are written in blood. They are derived from my specific experiences while working on this specific project. Governance command 5, treating network deadlocks as a conflict of tense, exists because I find asynchronous programming monumentally difficult to reason about. The entire section about constructor naming exists because I kept encountering, and fixing, specific hallucinations. The prelude section exists because I traded correctness for expediency when I refactored this codebase from a mono-crate ball of mud into a proper multi-crate workspace. The section about temporal agreement exists for a similar reason.

Fundamentally, this document is a contract between my present self and my future self. It is a promise to future me that present me will not repeat the mistakes of past me.