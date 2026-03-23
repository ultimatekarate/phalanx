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
2. **NEVER** allow `std::io` or `tokio::fs` into the Lab. Use the `TransientJournal` trait.
3. **ALWAYS** define reassembly strategies as `Mold` implementations in the Lab.
4. **ALWAYS** use the `prelude` for cross-crate imports to maintain namespace sanity.
5. **NEVER** use mutex or RwLock unless it is absolutely necessary. Treat network deadlocks as a conflict of tense.  
6. **ALWAYS** ensure subject-verb agreement: a Noun constructed for consumption by a Verb must satisfy that Verb's preconditions. Temporal Nouns must agree with temporal Verbs. Cryptographic Nouns must agree with verification Verbs.
7. **NEVER** construct test Nouns with fixed values when the consumption path includes a Verb that validates against live state. Use the same source the Verb uses.
