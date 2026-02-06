# 🏛️ Phalanx Stronghold Upgrade Roadmap

This roadmap upgrades `stronghold.rs` from a naive "save everything" engine to a governance-aware forensic vault suitable for mobile deployment.

## Phase 1: Storage Governance (Quotas & Limits)

*Goal: Prevent the Stronghold (especially on mobile) from consuming infinite disk space.*

- [ ] **Update `StorageConfig` in `config.rs`**
  - [ ] Add field `pub max_storage_bytes: u64` (Default: 1GB for mobile, 1TB for server).
  - [ ] Add field `pub max_foreign_storage_bytes: u64` (Limit specific to non-owned data).

- [ ] **Implement Usage Tracking in `stronghold.rs`**
  - [ ] Add `current_storage_usage: u64` to `Stronghold` struct.
  - [ ] Add `foreign_storage_usage: u64` to `Stronghold` struct.
  - [ ] Implement `fn calculate_usage(&self) -> u64`: Recursively walk `vault_storage` on startup to initialize these counters.

- [ ] **Implement `prune_foreign_evidence`**
  - [ ] Create logic to identify "Foreign" sessions (where `did != my_did`).
  - [ ] **Eviction Policy:** If `foreign_storage_usage > max_foreign_storage_bytes`:
    - [ ] Sort foreign sessions by `last_updated` (oldest first).
    - [ ] Delete oldest sessions until usage is below threshold.
    - [ ] Log every deletion (`tracing::warn!`).

- [ ] **Hook Pruning into Ingest**
  - [ ] In `ingest_envelope`, before writing to WAL:
    - [ ] Check if `envelope.did != local_identity`.
    - [ ] If foreign, check quotas.
    - [ ] Trigger `prune_foreign_evidence` if near limit.
    - [ ] **Hard Reject:** If pruning fails to free space, return error and drop envelope.

## Phase 2: Metadata & Indexing

*Goal: Make the vault queryable without reading every single file.*

- [ ] **Create Session Index**
  - [ ] Maintain a lightweight `index.json` in the root of `vault_storage`.
  - [ ] Structure: `Vec<SessionMetadata { did, volley_id, start_time, size_bytes, is_archived } >`.
  - [ ] Update this index whenever `archive_session` succeeds.

- [ ] **Implement `get_foreign_inventory`**
  - [ ] Create method: `fn get_foreign_inventory(&self, my_did: &Did) -> Vec<WitnessEnvelope>`.
  - [ ] Logic:
    - [ ] Read `index.json` or scan directories.
    - [ ] Filter for entries where `owner_did != my_did`.
    - [ ] Return a random sample (or oldest) envelopes.
    - *Use Case:* This allows the "Trickle Sync" feature to find data to upload back to the server.

## Phase 3: Resilience & Recovery

*Goal: Ensure data survives crashes and corruption.*

- [x] **Atomic Archival**
  - [x] Modify `archive_session` to write to a `.tmp` file first.
  - [x] Use `std::fs::rename` to atomically move `.tmp` to `.phlx`.
  - [x] Only delete WAL entries *after* the rename is successful.

- [ ] **Corrupt WAL Handling**
  - [ ] In `recover_from_wal`:
    - [ ] If `postcard::from_bytes` fails (corrupt file), move the file to a `quarantine/` folder.
    - [ ] Do not crash the node; log the error and continue.
