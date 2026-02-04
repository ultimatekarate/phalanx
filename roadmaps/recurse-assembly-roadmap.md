# Phalanx: Recursive Assembly & Archival Roadmap

## Phase 1: The Core Assembly Engine

*Build the generic foundation that handles sequencing and gap detection.*

- [ ] **Define `ForensicAssembler<T>`**: Create the generic struct with a `BTreeMap<u32, T>` for sorted storage.
- [ ] **Implement Logic**:
  - [ ] `new(total: u32)`: Initialize with an expected count.
  - [ ] `is_complete()`: Check if `parts.len() == total_expected`.
  - [ ] `is_continuous()`: Validate that there are no gaps in the `BTreeMap` keys starting from 0.
- [ ] **Define `Sealable` Trait**:
  - [ ] Create the trait with `type Output` and `fn seal(self) -> Self::Output`.

---

## Phase 2: Layer 1 — Shard Assembly (Micro)

*Convert raw network packets into verified forensic units.*

- [ ] **Implement `ShardAssembler`**:
  - [ ] Wrap `ForensicAssembler<Vec<u8>>`.
  - [ ] Implement `add_chunk(chunk: ShardChunk)`.
- [ ] **Implement `Sealable` for `ShardAssembler`**:
  - [ ] Flatten the `BTreeMap` of byte vectors into a single `Vec<u8>`.
- [ ] **Sentinel/Stronghold Hand-off**:
  - [ ] Update `Stronghold` state to include `pending_shards: HashMap<ShardId, ShardAssembler>`.
  - [ ] Logic to "promote" a sealed Shard (bytes) into a `WitnessEnvelope` via `postcard` deserialization.

---

## Phase 3: Layer 2 — Volley Assembly (Macro)

*Organize verified shards into a continuous event.*

- [ ] **Implement `VolleyAssembler`**:
  - [ ] Wrap `ForensicAssembler<WitnessEnvelope>`.
  - [ ] Include metadata fields: `volley_id`, `owner_did`, and `start_time`.
- [ ] **Implement `Sealable` for `VolleyAssembler`**:
  - [ ] Flatten the `BTreeMap` of envelopes into a single serialized binary stream (the `.phlx` format).
- [ ] **Volley Logic**:
  - [ ] Implement `is_ready_to_seal()`: Only true if `complete` AND `continuous`.

---

## Phase 4: Recursive Archival & Stronghold Integration

*Connect the layers and handle edge cases like node death (salvage).*

- [ ] **Refactor `ingest_chunk`**:
  - [ ] Entry point: Accepts `ShardChunk`.
  - [ ] Logic: Routes to Layer 1 → Promotes to Layer 2 → Triggers Layer 3 Archival.
- [ ] **Implement `seal_and_archive(volley_id)`**:
  - [ ] Calls `.seal()` on the `VolleyAssembler`.
  - [ ] Writes resulting blob to `{DID}/{VOLLEY_ID}.phlx`.
- [ ] **Implement "Dirty Seal" (Salvage)**:
  - [ ] Update `archive_stale_sessions` to force-call `.seal()` even if `is_continuous` is false.
- [ ] **WAL Integration**:
  - [ ] Update Write-Ahead Log to record `ShardChunks` instead of `WitnessEnvelopes`.

---

## Phase 5: Verification

*Prove the recursion works across the simulation.*

- [ ] **Unit Test: Recursive Shard**: Verify 10 chunks → 1 Shard.
- [ ] **Unit Test: Recursive Volley**: Verify 5 shards → 1 Volley.
- [ ] **Simulation Test**: Verify `test_salvage_on_node_death` still passes with the new `ingest_chunk` entry point.
