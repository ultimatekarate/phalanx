# Phalanx Forensic Node - Development Board

## 🔴 Backlog

- [ ] **[identity.rs] Implement `FromStr` for Newtypes**: Add `FromStr` to `Did`, `NetworkId`, and `StorageSequence` to allow easy parsing from CLI and config strings.
- [ ] **[sentinel.rs] Gossipsub Event Router**: Expand the `match` arm in `lib.rs` to route `Subscribed` and `Unsubscribed` events for dynamic peer tracking.
- [ ] **[config.rs] Path Sanitization**: Add a pre-flight check to ensure `vault_path` exists and is writable before hardware threads start capturing.
- [ ] **[stronghold.rs] Storage Compression**: Implement optional Zstd compression for `.phlx` archive files to reduce disk footprint.

## 🟡 In Progress

- [ ] **[shards.rs] Evidence Abstraction**: Refactor `WitnessEnvelope` to wrap a generic `Evidence` enum instead of being hardcoded to `VideoShard`.

## 🟢 Testing / QA

- [ ] **[identity.rs] Reserved Character Audit**: Verify `Did::to_safe_name()` covers all Windows/Linux illegal characters beyond just the colon (`:`).
- [ ] **[stronghold.rs] Recovery Forensic Audit**: Run `test_stronghold_crash_recovery` under `RUST_LOG=trace` to confirm 1:1 metadata restoration.
- [ ] **[main.rs] Hardware Shutdown Signal**: Verify hardware threads stop immediately when the `Swarm` event loop exits.

## ✅ Done

- [x] **[stronghold.rs] WAL Auto-Cleanup**: Ensure `clear_session_wal` is called immediately after a successful `archive_session` to prevent duplicate recovery attempts.
- [x] **Newtype Decoupling**: Decoupled `Did`, `NetworkId`, and `StorageSequence` from raw primitives to prevent type-confusion bugs.
- [x] **Identity Bridge**: Implemented interceptor in `lib.rs` to convert `PeerId` to `NetworkId` at the network boundary.
- [x] **Enum Boxing**: Reduced stack size by boxing heavy `Gossipsub` events in `PhalanxEvent`.
- [x] **ADS Bug Fix**: Removed `seq:` prefix from `StorageSequence` Display trait to prevent 0-byte file corruption on Windows.
- [x] **WAL Recovery**: Implemented deserialization-safe recovery loop with forensic logging.
- [x] **[sim.rs] Simulation Precision**: Update `test_salvage_on_node_death` to verify that salvaged shards maintain exact `StorageSequence` continuity.
- [x] **[shards.rs] Newtype Arithmetic**: Implement `Add`, `Sub`, and `Deref` for `StorageSequence` to remove the `.0` boilerplate in `audio.rs` and `camera.rs`.
  
---

## 🛠️ Architecture Notes

- **Identity Rule**: Never use the `Display` trait of a newtype for file pathing if it contains colons or slashes. Use `.0` or a dedicated `to_safe_name()` method.
- **Storage Pattern**: The `Stronghold` maps `Did -> EvidenceSequence -> Envelope`. This ensures we can reconstruct the timeline even if shards arrive out of order via P2P.
