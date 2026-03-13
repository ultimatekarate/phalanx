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

## IV. GOVERNANCE COMMANDS

1. **NEVER** allow libp2p types to leak into the Lab or the Dictionary. Map them to `NetworkId` in the Adapter.
2. **NEVER** allow `std::io` or `tokio::fs` into the Lab. Use the `TransientJournal` trait.
3. **ALWAYS** define reassembly strategies as `Mold` implementations in the Lab.
4. **ALWAYS** use the `prelude` for cross-crate imports to maintain namespace sanity.
