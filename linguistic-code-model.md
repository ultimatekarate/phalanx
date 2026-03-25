# PHALANX LINGUISTIC MODEL: ARCHITECTURAL GOVERNANCE

This document establishes the "Linguistic Model" of Phalanx. All code must be partitioned based on its linguistic role to ensure forensic integrity and system stability.

---

## I. THE DICTIONARY (phalanx-proto)

**Role:** The Nouns and Adjectives. Shared Reality.
**Constraint:** Inert. No IO. No tokio. No libp2p.

* **identity.rs:** Who is talking? (Did, NetworkId, PhalanxIdentity)
* **evidence.rs:** What are they saying? (WitnessEnvelope, ShardChunk, RecordingId)
* **topic.rs:** Where are they saying it? (MeshTopic)
* **error.rs:** What went wrong? (ShardError, TimeError)
* **storage.rs:** The Vault Nouns (GuardianError)

## II. THE LABORATORY (phalanx-forensics)

**Role:** The Verbs and The Law. Pure Logic.
**Constraint:** 100% Testable. No tokio::fs. No libp2p.

* **crucible.rs:** The Verb "To Stage." A generic engine for data aggregation.
* **reassembler.rs:** The Verb "To Assemble." Logic for turning Chunks into Envelopes.
* **judge.rs:** The Verb "To Verify." Logic for Shard and Recording Amalgams (Causality).
* **policy.rs:** The Verb "To Govern." Traffic governors and power state logic.

## III. THE HANDS (phalanx-node & phalanx-transport)

**Role:** The Physical Action. Implementation.
**Constraint:** Environment-dependent. Touches Hard Drives and Wires.

* **phalanx-transport/adapters:** The "Mouth." Specifically `Libp2pAdapter`. Translates wire signals into `NetworkEvents`.
* **phalanx-node/storage:** The "Memory." Specifically `Vault`, `Journal`, and `RedbStore`. Manages NVMe persistence.
* **phalanx-node/actors:** The "Narrators." `MeshSentinel` and `StorageActor`. Orchestrates the whole body.

---

## IV. SUBJECT-VERB AGREEMENT

**Rule:** When a Noun flows through a Verb, the Noun's values must satisfy the Verb's preconditions. This is the code equivalent of grammatical agreement — subject and verb must agree in tense.

**The General Principle:** The tense of the Noun must match the tense of the Verb. If the Verb validates against live state, the Noun must come from live state. If the Verb validates against a fixed schema, the Noun must conform to that schema. Disagreement between subject and verb is a grammatical error — in natural language it sounds wrong; in code it fails at runtime.

**Temporal Agreement:** A Noun carrying a timestamp that flows through a temporal Verb (freshness check, expiry validation, window alignment) must be constructed from the same clock source the Verb uses for validation. A past-tense Noun (fixed timestamp) cannot satisfy a present-tense Verb (freshness gate). In production, the clock source is `TrustedClock`. In tests, the clock source is `SystemClock` — never a fixed literal unless the test explicitly does not pass through a temporal Verb.

**Cryptographic Agreement:** A Noun carrying a signature or DID that flows through a verification Verb must use the matching keypair. A `Did` constructed for a `verify_envelope()` call must correspond to the `SigningKey` that produced the signature.

**Structural Agreement:** A Noun carrying a collection or identifier that flows through a validation Verb must satisfy that Verb's bounds. A `SubnetBucket` consumed by `TopologyGate::admit()` must be in valid range. A `ShardGapReport` consumed by a retrieval Verb must have `missing_indices.len() <= MAX_GAP_INDICES`.

---

## V. GOVERNANCE COMMANDS

1. **NEVER** allow libp2p types to leak into the Lab or the Dictionary. Map them to `NetworkId` in the Adapter.
2. **NEVER** allow filesystem IO (`std::fs`, `tokio::fs`) or network IO (`std::net`, `tokio::net`) into the Lab. In-memory byte assembly (`std::io::Cursor`, `std::io::Write` on `Vec<u8>`) is permitted when required by codec dependencies. For persistence, use the `TransientJournal` trait.
3. **ALWAYS** define reassembly strategies as `Mold` implementations in the Lab.
4. **PREFER** the `prelude` for cross-crate imports of first-class Nouns. Import persistence contracts, scheduling types, and operational state directly from their defining module.
5. **NEVER** use mutex or RwLock unless it is absolutely necessary. Treat network deadlocks as a conflict of tense.  
6. **ALWAYS** ensure subject-verb agreement: a Noun constructed for consumption by a Verb must satisfy that Verb's preconditions. Temporal Nouns must agree with temporal Verbs. Cryptographic Nouns must agree with verification Verbs.
7. **NEVER** construct test Nouns with fixed values when the consumption path includes a Verb that validates against live state. Use the same source the Verb uses.
8. **NEVER** add `phalanx-test-fixtures` as a production `[dependency]`. The Phrasebook exists only in dev-dependency graphs. If a fixture is needed at runtime, promote the construction logic to its owning crate as a semantic constructor.

---

## VI. CONSTRUCTOR NAMING

Constructors carry semantic weight. The name documents the construction invariant — what the caller must understand about the object being created.

- **`new()`** means simple construction with minimal or no validation. The caller gets a value with no implied preconditions beyond the type signature.
- **`new_<qualifier>()`** means the qualifier is a precondition, mode, or invariant that distinguishes this construction from other possible constructions. The suffix is documentation — it tells the caller *what kind* of value they are getting. Do not rename qualified constructors to bare `new()`.
- **`from_<source>()`** means type conversion from a different representation. The source name documents what is being converted.

When a type has only one constructor and it carries a semantic qualifier, the qualifier takes precedence over the convention of `new()`. A constructor named for its invariant is more valuable than one named for convention.

---

## VII. TYPE PLACEMENT

Types belong where the linguistic model places them, not where they are consumed most heavily.

- **Temporal primitives are Tenses.** A monotonic clock, a timestamp, or a duration belongs with other time concepts, not in the module that uses it for bookkeeping.
- **Capability contracts are Nouns.** A trait that defines what a component *can do* (persist state, provide a clock, enforce wire bounds) is a contract — a shape of interaction. Contracts belong in the Dictionary alongside the types they operate on.
- **Operational state is not a first-class Noun.** Retry queues, scheduling metadata, and actor-internal bookkeeping serve the implementation, not the domain model. They belong in their implementing crate, not in shared contracts.
- **Consumer gravity is a drift pattern.** When a type is used heavily in one module, the temptation is to move it closer. Resist this — check the model first. If the type is a Tense, it stays with the Tenses regardless of who reads it most.
- **Trait signatures in the Dictionary should reference domain types, not runtime-specific types.** If a trait requires a runtime type in its signature, refactor the signature to use domain-shaped abstractions rather than exempting the trait from placement rules.

---

## VIII. PRELUDE DISCIPLINE

The prelude is the public vocabulary of a crate — the set of names that every consumer gets by default.

- Only types that most consumers need belong in the prelude. Core evidence types, identity types, and error types qualify. Persistence contracts, scheduling types, and operational state do not.
- Adding a type to the prelude is a deliberate act. It increases the default cognitive load for every consumer of the crate.
- When in doubt, require direct import. A consumer who needs a specialized type can import it from the defining module. A consumer who doesn't need it should never see it.

---

## IX. THE PHRASEBOOK (phalanx-test-fixtures)

**Role:** Pre-composed Test Sentences. Construction knowledge encapsulation.
**Constraint:** Dev-dependency only. No IO. No new Verbs. No new domain types.

A Phrasebook composes Dictionary Nouns with Laboratory Verbs to produce synthetic test instances. It exists because tests in the Hands should not need to know the Laboratory's validation preconditions in order to construct valid Nouns.

* May depend on the Dictionary (phalanx-proto) and the Laboratory (phalanx-forensics).
* Must NOT depend on the Hands (phalanx-node, phalanx-transport).
* Must NOT introduce domain types — it only constructs existing ones.
* Must NOT introduce Verbs — it only calls existing ones.
* Must appear only in `[dev-dependencies]`, never in `[dependencies]`.
* Must self-test: fixtures that claim to pass a Laboratory Verb must prove it.
