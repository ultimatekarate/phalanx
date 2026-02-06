# Phalanx: Recursive Assembly & Archival Roadmap

## Phase 1: The Core Assembly Engine

*Build the generic foundation that handles sequencing and gap detection.*

- [x] **Define `ForensicAssembler<T>`**: Create the generic struct with a `BTreeMap<u32, T>` for sorted storage.
- [x] **Implement Logic**:
  - [x] `new(total: u32)`: Initialize with an expected count.
  - [x] `is_complete()`: Check if `parts.len() == total_expected`.
  - [x] `is_continuous()`: Validate that there are no gaps in the `BTreeMap` keys starting from 0.
- [x] **Define `Sealable` Trait**:
  - [x] Create the trait with `type Output` and `fn seal(self) -> Self::Output`.

---

## Phase 2: Layer 1 — Shard Assembly (Micro)

*Convert raw network packets into verified forensic units.*

- [x] **Implement `ShardAssembler`**:
  - [x] Wrap `ForensicAssembler<Vec<u8>>`.
  - [x] Implement `add_chunk(chunk: ShardChunk)`.
- [x] **Implement `Sealable` for `ShardAssembler`**:
  - [x] Flatten the `BTreeMap` of byte vectors into a single `Vec<u8>`.
- [x] **Sentinel/Stronghold Hand-off**:
  - [x] Update `Stronghold` state to include `pending_shards: HashMap<ShardId, ShardAssembler>`.
  - [x] Logic to "promote" a sealed Shard (bytes) into a `WitnessEnvelope` via `postcard` deserialization.

---

## Phase 3: Layer 2 — Volley Assembly (Macro)

*Organize verified shards into a continuous event.*

- [x] **Implement `VolleyAssembler`**:
  - [x] Wrap `ForensicAssembler<WitnessEnvelope>`.
  - [x] Include metadata fields: `volley_id`, `owner_did`, and `start_time`.
- [x] **Implement `Sealable` for `VolleyAssembler`**:
  - [x] Flatten the `BTreeMap` of envelopes into a single serialized binary stream (the `.phlx` format).
- [x] **Volley Logic**:
  - [x] Implement `is_ready_to_seal()`: Only true if `complete` AND `continuous`.

---

## Phase 4: Recursive Archival & Stronghold Integration

*Connect the layers and handle edge cases like node death (salvage).*

- [x] **Refactor `ingest_chunk`**:
  - [x] Entry point: Accepts `ShardChunk`.
  - [x] Logic: Routes to Layer 1 → Promotes to Layer 2 → Triggers Layer 3 Archival.
- [x] **Implement `seal_and_archive(volley_id)`**:
  - [x] Calls `.seal()` on the `VolleyAssembler`.
  - [x] Writes resulting blob to `{DID}/{VOLLEY_ID}.phlx`.
- [x] **Implement "Dirty Seal" (Salvage)**:
  - [x] Update `archive_stale_sessions` to force-call `.seal()` even if `is_continuous` is false.
- [x] **WAL Integration**:
  - [x] Update Write-Ahead Log to record `ShardChunks` instead of `WitnessEnvelopes`.

---

## Phase 5: Verification

*Prove the recursion works across the simulation.*

- [x] **Unit Test: Recursive Shard**: Verify 10 chunks → 1 Shard.
- [x] **Unit Test: Recursive Volley**: Verify 5 shards → 1 Volley.
- [x] **Simulation Test**: Verify `test_salvage_on_node_death` still passes with the new `ingest_chunk` entry point.
