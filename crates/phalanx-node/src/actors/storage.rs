// crates/phalanx-node/src/actors/storage.rs
use crate::actors::shutdown::ShutdownSignal;
use crate::config::NodeConfig;
use crate::persistence::vault::Guardian;
use crate::vitals::{Homeostasis, SystemGovernor};
use phalanx_forensics::bloom::RotatingBloomFilter;
use phalanx_forensics::crucible::EvidenceExt;
use phalanx_forensics::prelude::*;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_proto::evidence::EnvelopeState;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::ManifestEntry;
use phalanx_proto::evidence::PrnuPosterior;
use phalanx_proto::evidence::RecordingOptions;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::prelude::{ShardChunk, ShardError};
use phalanx_proto::revocation::RevocationToken;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::storage::PendingEgress;
use phalanx_proto::storage::TransientJournal;
use phalanx_proto::types::ForensicUnit;
use phalanx_proto::types::Verified;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::interval;

/// The Pure Vault: Responsible ONLY for disk I/O, WAL recovery, and cryptographic reassembly.
pub struct StorageActor<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub guardian: Guardian,
    pub journal: J,
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub current_tolerance: Duration,
    pub system_governor: Arc<SystemGovernor>,
    /// Fires after each successful shard write **for publishable recordings**.
    /// MeshSentinel translates each notify into an `EgressCommand::AnnounceRecording`,
    /// so this channel is the security-relevant publish gate: only recording IDs
    /// flowing through here are gossipped to the mesh. Senders MUST consult
    /// `Guardian::is_recording_publishable` before calling `try_send` — see
    /// `handle_ingest` and `handle_write_shard`. Bypassing the gate would
    /// silently re-enable mesh announcement for a recording the operator
    /// marked local-only.
    pub commit_notify_tx: Option<mpsc::Sender<RecordingId>>,
    /// Replay detection: rotating Bloom filter for evidence_hash dedup.
    /// 1M bits per generation (~125KB × 2 = ~250KB fixed). Rotates on maintenance tick.
    pub replay_filter: RotatingBloomFilter,
    /// Shared cancellation signal. The run loop's select! polls this arm with
    /// `biased;` priority so cancel wins deterministically at shutdown.
    pub shutdown: Arc<ShutdownSignal>,
    /// Local-bytes gauge mirrored from `guardian.ledger.total_local_bytes()`.
    /// Refreshed on the 1s maintenance tick. Read by the vitals task (in
    /// `MeshSentinel`) to populate `ControlMessage::storage_remaining_mb`
    /// without a per-tick channel round-trip. At most 1s stale, which is
    /// well inside the heartbeat cadence.
    pub used_bytes_gauge: Arc<std::sync::atomic::AtomicU64>,
}

#[allow(clippy::large_enum_variant)]
pub enum StorageCommand {
    /// Pure ingestion. No routing logic or network ACKs.
    Ingest {
        unit: ForensicUnit<ShardChunk, Verified>,
        reply_to: oneshot::Sender<Result<(), GuardianError>>,
        ttl: Duration,
    },
    /// Pure retrieval. Returns raw envelopes directly from the vault.
    Retrieval {
        recording_id: RecordingId,
        owner_did: Option<phalanx_proto::identity::Did>,
        reply_to: oneshot::Sender<Vec<WitnessEnvelope>>,
    },
    /// Single shard retrieval for local PlaybackCoordinator UI playback.
    GetShard {
        recording_id: RecordingId,
        sequence_id: StorageSequence,
        reply_to: oneshot::Sender<Option<WitnessEnvelope>>,
    },
    /// Direct shard write to recording log (used by MediaEgressActor for local capture
    /// and MeshSentinel for DHT shard responses). Disk-first, then verify.
    WriteShard {
        envelope: WitnessEnvelope,
        reply_to: oneshot::Sender<Result<(), GuardianError>>,
    },
    /// Direct envelope ingestion bypass (used internally by Guardian operations).
    IngestEnvelope {
        state: EnvelopeState,
        reply_to: oneshot::Sender<Result<(), GuardianError>>,
        ttl: Duration,
    },
    /// Emergency backup of egress queues during node shutdown.
    EmergencySalvage(Vec<PendingEgress>),
    /// Cryptographic Forgetting: destroy all evidence for a recording.
    Revoke {
        token: RevocationToken,
        reply_to: oneshot::Sender<Result<(), GuardianError>>,
    },
    /// Request a new per-recording content key. Guardian generates a random DEK,
    /// persists the keyring, and returns the raw key bytes.
    StartRecording {
        recording_id: RecordingId,
        reply_to: oneshot::Sender<Result<[u8; 32], ShardError>>,
    },
    /// Like `StartRecording` but lets the caller pin per-recording policy
    /// (e.g. `publishable: false` to keep a sensitive recording local).
    /// The metadata entry is persisted before the key is returned.
    StartRecordingWithOptions {
        recording_id: RecordingId,
        options: RecordingOptions,
        reply_to: oneshot::Sender<Result<[u8; 32], ShardError>>,
    },
    /// Retrieve the content key for a recording (for playback decryption).
    ///
    /// Resolution chain: keyring (foreign + legacy own) → derived (own under
    /// the deterministic regime). Always returns `Some` under the v2
    /// regime; the `Option` is preserved for callers' historical
    /// vault_key-fallback paths but `None` is no longer emitted.
    GetContentKey {
        recording_id: RecordingId,
        reply_to: oneshot::Sender<Option<[u8; 32]>>,
    },
    /// List all recording IDs known to this node (completed + in-progress, excluding revoked).
    ListRecordings {
        reply_to: oneshot::Sender<Vec<RecordingId>>,
    },
    /// Debug-only: delete a recording's data without cryptographic revocation.
    DebugDeleteRecording {
        recording_id: RecordingId,
        reply_to: oneshot::Sender<Result<(), GuardianError>>,
    },
    /// Debug: return (shard_count, has_content_key) for a recording.
    DebugRecordingInfo {
        recording_id: RecordingId,
        reply_to: oneshot::Sender<(usize, bool)>,
    },
    /// Debug: list vault directory contents (vault_path, subdirs, .recording files).
    DebugVaultListing {
        reply_to: oneshot::Sender<(String, Vec<String>)>,
    },
    /// Revocation Replay: return all persisted revocation tokens for peer handshake.
    GetRevocationTokens {
        reply_to: oneshot::Sender<Vec<RevocationToken>>,
    },
    /// Persist the Bayesian PRNU posterior to the vault.
    /// Fire-and-forget from the capture path (every 100 frames).
    PersistPosterior(PrnuPosterior),
}

impl<J: TransientJournal> StorageActor<J> {
    pub async fn run(mut self, mut command_rx: mpsc::Receiver<StorageCommand>) {
        tracing::info!(target: "phalanx::storage", "StorageActor: Entering pure vault mode");
        self.bootstrap().await;

        let mut maintenance_timer = interval(Duration::from_millis(1000));

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => break,
                res = command_rx.recv() => {
                    match res {
                        Some(cmd) => self.handle_command(cmd).await,
                        None => {
                            tracing::info!(target: "phalanx::storage", "Sentinel dropped channel. Vault shutting down.");
                            break;
                        }
                    }
                }
                _ = maintenance_timer.tick() => {
                    self.replay_filter.rotate();
                    let _ = self.guardian.check_and_finalize_recording(self.current_tolerance).await;
                    // Mirror the ledger total into the gauge for the vitals
                    // task. Cheap: one ledger read + one atomic store per
                    // second. Mirror, not authoritative store — Guardian's
                    // ledger remains the source of truth.
                    self.used_bytes_gauge.store(
                        self.guardian.ledger.total_local_bytes(),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
            }
        }

        // Post-loop drain: after cancel fires, flush queued commands so
        // DrainForSalvage-style shutdown requests from MeshSentinel still
        // complete before the task exits.
        while let Ok(cmd) = command_rx.try_recv() {
            self.handle_command(cmd).await;
        }
    }

    async fn bootstrap(&mut self) {
        self.recover_reassembler_state().await;
        self.recover_revocations().await;
        self.load_keyring_and_logs().await;
        self.seed_replay_filter().await;
        self.cleanup_ghost_keys().await;
    }

    /// Hydrate the Reassembler state from the TransientJournal (WAL).
    async fn recover_reassembler_state(&mut self) {
        match self
            .reassembler
            .recover_from_journal(&mut self.journal)
            .await
        {
            Ok(()) => {
                tracing::info!(
                    target: "phalanx::storage",
                    active_recordings = self.reassembler.active_shards.len(),
                    "StorageActor: Bootstrap complete. State hydrated from WAL."
                );
            }
            Err(e) => {
                tracing::error!(target: "phalanx::storage", error = %e, "CRITICAL: Bootstrap recovery failed.");
            }
        }
    }

    /// Recover revoked recordings from journal and insert into guardian state.
    async fn recover_revocations(&mut self) {
        match self.journal.read_all_revocations().await {
            Ok(tokens) => {
                for token in &tokens {
                    self.guardian
                        .revoked_recordings
                        .insert(token.recording_id.clone());
                }
                if !tokens.is_empty() {
                    tracing::info!(
                        target: "phalanx::storage",
                        count = tokens.len(),
                        "Restored revoked recordings from journal"
                    );
                }
            }
            Err(e) => {
                tracing::error!(
                    target: "phalanx::storage",
                    error = %e,
                    "Failed to read revocations from journal"
                );
            }
        }
    }

    /// Load per-recording content keyring and hydrate recording logs from disk.
    async fn load_keyring_and_logs(&mut self) {
        if let Err(e) = self.guardian.load_keyring().await {
            tracing::error!(
                target: "phalanx::storage",
                error = %e,
                "Failed to load content keyring"
            );
        }

        // Per-recording policy metadata (e.g. `publishable`). Local-only;
        // a fresh-restored device starts with an empty map and every
        // recording reverts to default policy.
        if let Err(e) = self.guardian.load_recording_metadata().await {
            tracing::error!(
                target: "phalanx::storage",
                error = %e,
                "Failed to load recording metadata"
            );
        }

        // Rebuild in-memory indexes by scanning .recording files in the vault
        // directory. Without this, playback after an app restart finds no shards
        // (recording_logs starts empty).
        if let Err(e) = self.guardian.hydrate_recording_logs().await {
            tracing::error!(
                target: "phalanx::storage",
                error = %e,
                "Failed to hydrate recording logs from disk"
            );
        }
    }

    /// Seed the replay filter from recently persisted evidence hashes.
    ///
    /// Prevents post-crash replay attacks by pre-populating the Bloom filter
    /// with hashes from the most recent shards per recording.
    async fn seed_replay_filter(&mut self) {
        let seed_hashes = self.guardian.collect_recent_evidence_hashes(50).await;
        for hash in &seed_hashes {
            self.replay_filter.insert(hash);
        }
        if !seed_hashes.is_empty() {
            tracing::info!(
                target: "phalanx::storage",
                count = seed_hashes.len(),
                "C2: Replay filter seeded from persisted evidence"
            );
        }
    }

    /// Destroy content keys for revoked recordings that survived a partial crash.
    async fn cleanup_ghost_keys(&mut self) {
        let revoked: Vec<RecordingId> = self.guardian.revoked_recordings.iter().cloned().collect();
        let mut ghost_keys_cleaned = 0u32;
        for rid in &revoked {
            if self.guardian.destroy_content_key(rid) {
                ghost_keys_cleaned = ghost_keys_cleaned.saturating_add(1);
            }
        }
        if ghost_keys_cleaned > 0 {
            if let Err(e) = self.guardian.persist_keyring().await {
                tracing::error!(
                    target: "phalanx::storage",
                    error = %e,
                    "Failed to persist keyring after ghost key cleanup"
                );
            } else {
                tracing::info!(
                    target: "phalanx::storage",
                    count = ghost_keys_cleaned,
                    "Cleaned ghost content keys for revoked recordings"
                );
            }
        }
    }

    async fn handle_command(&mut self, cmd: StorageCommand) {
        match cmd {
            StorageCommand::Ingest {
                unit,
                reply_to,
                ttl,
            } => {
                self.current_tolerance = ttl;
                let result = self.handle_ingest(unit).await;
                let _ = reply_to.send(result);
            }
            StorageCommand::Retrieval {
                recording_id,
                owner_did,
                reply_to,
            } => {
                self.handle_retrieval(recording_id, owner_did, reply_to)
                    .await;
            }
            StorageCommand::GetShard {
                recording_id,
                sequence_id,
                reply_to,
            } => {
                let result = self
                    .guardian
                    .read_shard(&recording_id, sequence_id, None)
                    .await
                    .ok();
                let _ = reply_to.send(result);
            }
            StorageCommand::WriteShard { envelope, reply_to } => {
                let result = self.handle_write_shard(envelope).await;
                let _ = reply_to.send(result);
            }
            StorageCommand::IngestEnvelope {
                state,
                reply_to,
                ttl,
            } => {
                let _ = reply_to.send(self.guardian.ingest_envelope(state, ttl).await);
            }
            StorageCommand::EmergencySalvage(pending) => {
                self.handle_salvage(pending).await;
            }
            StorageCommand::Revoke { token, reply_to } => {
                let result = self.handle_revoke(token).await;
                let _ = reply_to.send(result);
            }
            StorageCommand::StartRecording {
                recording_id,
                reply_to,
            } => {
                let result = self
                    .handle_start_recording(&recording_id, RecordingOptions::default())
                    .await;
                let _ = reply_to.send(result);
            }
            StorageCommand::StartRecordingWithOptions {
                recording_id,
                options,
                reply_to,
            } => {
                let result = self.handle_start_recording(&recording_id, options).await;
                let _ = reply_to.send(result);
            }
            StorageCommand::GetContentKey {
                recording_id,
                reply_to,
            } => {
                // resolve_encryption_key always returns a key (keyring hit
                // or derived). We wrap in Some to preserve the existing
                // channel signature; callers that fell back to vault_key
                // on None are now dead-branch but still compile.
                let key = Some(
                    *self
                        .guardian
                        .resolve_encryption_key(&recording_id)
                        .as_bytes(),
                );
                let _ = reply_to.send(key);
            }
            StorageCommand::ListRecordings { reply_to } => {
                let ids = self.guardian.list_all_recordings();
                let _ = reply_to.send(ids);
            }
            StorageCommand::DebugDeleteRecording {
                recording_id,
                reply_to,
            } => {
                let result = self.guardian.debug_delete_recording(&recording_id).await;
                let _ = reply_to.send(result);
            }
            StorageCommand::DebugRecordingInfo {
                recording_id,
                reply_to,
            } => {
                let info = self.guardian.debug_recording_info(&recording_id);
                let _ = reply_to.send(info);
            }
            StorageCommand::DebugVaultListing { reply_to } => {
                self.handle_debug_vault_listing(reply_to).await;
            }
            StorageCommand::GetRevocationTokens { reply_to } => {
                let tokens = self
                    .journal
                    .read_all_revocations()
                    .await
                    .unwrap_or_default();
                let _ = reply_to.send(tokens);
            }
            StorageCommand::PersistPosterior(posterior) => {
                if let Err(e) = self.guardian.persist_prnu_posterior(&posterior).await {
                    tracing::warn!(
                        target: "phalanx::storage",
                        error = %e,
                        "Failed to persist PRNU posterior"
                    );
                }
            }
        }
    }

    async fn handle_debug_vault_listing(
        &mut self,
        reply_to: oneshot::Sender<(String, Vec<String>)>,
    ) {
        let vault_path = self.guardian.vault_path.clone();
        let mut entries = Vec::new();

        // Report recording_logs state via public API
        let log_recordings = self.guardian.list_recordings();
        entries.push(format!("RECORDING_LOGS: {} entries", log_recordings.len()));
        for rid in &log_recordings {
            let (shards, has_key) = self.guardian.debug_recording_info(rid);
            entries.push(format!(
                "  LOG: {} ({} shards, has_key={})",
                rid, shards, has_key
            ));
        }

        if let Ok(mut dir) = tokio::fs::read_dir(&vault_path).await {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let p = entry.path();
                let is_dir = p.is_dir();
                let name = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                if is_dir {
                    // Scan subdirectory for .recording files with sizes
                    let mut sub_files = Vec::new();
                    if let Ok(mut sub) = tokio::fs::read_dir(&p).await {
                        while let Ok(Some(sub_entry)) = sub.next_entry().await {
                            let fname = sub_entry.file_name().to_string_lossy().to_string();
                            let size = sub_entry.metadata().await.map(|m| m.len()).unwrap_or(0);
                            sub_files.push(format!("{}({}B)", fname, size));

                            // Read first 16 bytes of first .recording file for diagnosis
                            if fname.ends_with(".recording") && sub_files.len() == 1 {
                                let fpath = sub_entry.path();
                                match tokio::fs::read(&fpath).await {
                                    Ok(data) => {
                                        let preview: Vec<String> = data
                                            .iter()
                                            .take(16)
                                            .map(|b| format!("{b:02x}"))
                                            .collect();
                                        entries.push(format!(
                                            "RAW_BYTES({}): [{}] (total {} bytes)",
                                            fname,
                                            preview.join(" "),
                                            data.len()
                                        ));
                                    }
                                    Err(e) => {
                                        entries.push(format!("RAW_READ_ERR({}): {}", fname, e))
                                    }
                                }
                            }
                        }
                    }
                    entries.push(format!("DIR: {} -> [{}]", name, sub_files.join(", ")));
                } else {
                    entries.push(format!("FILE: {}", name));
                }
            }
        }
        let _ = reply_to.send((vault_path, entries));
    }

    /// Handles data ingestion purely from a forensic and storage perspective.
    async fn handle_ingest(
        &mut self,
        unit: ForensicUnit<ShardChunk, Verified>,
    ) -> Result<(), GuardianError> {
        // Storage pressure gate: reject when WAL/disk is near capacity (soft limit via integral)
        if self.system_governor.storage_scaler().0 < 0.05 {
            return Err(GuardianError::StorageFailure(
                "Storage pressure critical: WAL near capacity".into(),
            ));
        }

        // P6 FIX: Hard enforcement of max_storage_bytes.
        // The soft integral-based gate above can lag behind rapid ingestion bursts.
        // This hard check provides an absolute ceiling that cannot be exceeded.
        let current_storage = self.guardian.wal_bytes_estimate();
        let max_storage = self.config.storage.max_storage_bytes.as_u64();
        if current_storage >= max_storage {
            return Err(GuardianError::StorageFailure(format!(
                "P6: Hard storage limit reached ({} >= {} bytes)",
                current_storage, max_storage
            )));
        }

        let chunk = unit.unpack();

        // Foreign storage enforcement: reject foreign data when over the configured limit.
        let is_foreign = chunk.owner_did != self.guardian.local_did;
        if is_foreign {
            let foreign_total = self.guardian.ledger.total_foreign_bytes();
            let max_foreign = self.config.storage.max_foreign_storage_bytes.as_u64();
            if foreign_total >= max_foreign {
                tracing::warn!(
                    event = "foreign_storage_rejected",
                    foreign_bytes = foreign_total,
                    max_foreign_bytes = max_foreign,
                    owner_did = %chunk.owner_did,
                    "Foreign storage limit reached"
                );
                return Err(GuardianError::StorageFailure(format!(
                    "Foreign storage limit reached ({} >= {} bytes)",
                    foreign_total, max_foreign
                )));
            }

            // Per-owner quota: prevent a single foreign DID from monopolizing all foreign storage.
            let owner_bytes = self
                .guardian
                .ledger
                .foreign_bytes_for_owner(&chunk.owner_did);
            let max_per_owner = self.config.storage.max_foreign_per_owner_bytes.as_u64();
            if owner_bytes >= max_per_owner {
                tracing::warn!(
                    event = "per_owner_quota_rejected",
                    owner_did = %chunk.owner_did,
                    owner_bytes,
                    max_per_owner,
                    "Per-owner foreign storage quota exceeded"
                );
                return Err(GuardianError::StorageFailure(format!(
                    "Per-owner foreign quota exceeded for {} ({} >= {} bytes)",
                    chunk.owner_did, owner_bytes, max_per_owner
                )));
            }
        }

        // Track chunk size and owner DID for ledger accounting before consumption
        let chunk_bytes = chunk.data.len() as u64;
        let chunk_owner_did = chunk.owner_did.clone();

        let reassembly_result = self
            .reassembler
            .ingest_chunk(chunk, &mut self.journal)
            .await;

        if let Err(e) = self.journal.sync().await {
            tracing::error!(error = %e, "Forensics: Critical failure to sync WAL to disk");
        }

        // Update storage ledger (own vs foreign accounting)
        if reassembly_result.is_ok() {
            if is_foreign {
                self.guardian
                    .ledger
                    .record_foreign_ingestion(chunk_bytes, &chunk_owner_did);
            } else {
                self.guardian.ledger.record_own_ingestion(chunk_bytes);
            }
        }

        // Record storage pressure after WAL write
        self.system_governor.record_storage_pressure(
            self.guardian.wal_bytes_estimate(),
            self.config.storage.max_storage_bytes.as_u64(),
        );

        // Record memory pressure from reassembler buffers
        let buffer_bytes: usize = self
            .reassembler
            .active_shards
            .contexts
            .values()
            .map(|ctx| ctx.accumulator.accumulated_bytes())
            .sum();
        self.system_governor.record_memory_pressure(buffer_bytes);

        match reassembly_result {
            Ok(Some(envelope_state)) => {
                // 1. Disk first — persist to recording log before verification
                //
                // Ordering note (filter-check → disk → filter-insert → verify)
                // is deliberate. The replay filter is a DoS-mitigation
                // heuristic, not a cryptographic correctness gate — it
                // admits a ~1% false-positive rate per threat-model.md and
                // is seeded on boot from disk-persisted envelopes (C2 FIX,
                // `recording_log.rs::collect_recent_evidence_hashes`), which
                // themselves went through this same write-first-verify-later
                // contract. Populating the filter before `verify_envelope`
                // runs is consistent with that seeding semantics.
                //
                // Known false-positive surface: an attacker who scrapes an
                // honest envelope's bytes off the wire can retransmit them
                // with a mangled signature (same `evidence_hash`, since
                // hash = blake3(evidence) and ignores the signature field).
                // That poisons the filter with the victim's hash, causing
                // the honest copy to be rejected as a "replay" for at most
                // one bloom-rotation cycle. Blast radius is local-node only
                // — peers re-verify on receive, so gossip eventually
                // delivers the honest copy to everyone else, and the next
                // bloom rotation clears the poisoned entry here too.
                //
                // Do NOT reorder to verify-before-filter without updating
                // threat-model.md. Flipping it costs a full ed25519 verify
                // per duplicate-hash arrival on the hot path — the common
                // case for legitimate gossip (peers X and Y both forward
                // the same honest shard) — which was deemed unacceptable
                // during the C2 audit round.
                match &envelope_state {
                    EnvelopeState::Intact(envelope) => {
                        // Replay detection: reject evidence_hash seen recently.
                        if self.replay_filter.contains(&envelope.evidence_hash) {
                            tracing::warn!(
                                target: "phalanx::storage",
                                "Replay detected: evidence_hash recently ingested"
                            );
                            return Err(GuardianError::ReplayDetected(0));
                        }

                        self.guardian.append_shard(envelope).await?;
                        self.replay_filter.insert(&envelope.evidence_hash);
                        let recording_id = envelope.evidence.recording_id().clone();
                        // Publish gate: skip the mesh notify for recordings
                        // the operator marked local-only. Recordings without
                        // an explicit metadata entry default to publishable.
                        if self.guardian.is_recording_publishable(&recording_id) {
                            if let Some(ref tx) = self.commit_notify_tx {
                                let _ = tx.try_send(recording_id);
                            }
                        }
                    }
                }
                // 2. Verify in memory (data is already safely on disk)
                let result = self
                    .guardian
                    .ingest_envelope(envelope_state, self.current_tolerance)
                    .await;
                if let Err(ref e) = result {
                    tracing::warn!(
                        target: "phalanx::storage",
                        error = %e,
                        "Verification failed for persisted shard"
                    );
                }
                result
            }
            Ok(None) => {
                // Chunk accepted, but recording is still incomplete
                Ok(())
            }
            Err(e) => {
                // Cryptographic failure
                Err(GuardianError::VerificationFailed(e.to_string()))
            }
        }
    }

    /// Reads all shards for a recording from the recording log on disk.
    async fn handle_retrieval(
        &mut self,
        recording_id: RecordingId,
        owner_did: Option<phalanx_proto::identity::Did>,
        reply_to: oneshot::Sender<Vec<WitnessEnvelope>>,
    ) {
        let envelopes = self
            .guardian
            .read_all_shards(&recording_id, owner_did.as_ref())
            .await
            .unwrap_or_default();

        let _ = reply_to.send(envelopes);
    }

    /// Writes a single shard to the recording log, notifies DHT, and verifies in-memory.
    async fn handle_write_shard(&mut self, envelope: WitnessEnvelope) -> Result<(), GuardianError> {
        // Foreign recordings must have a keyring entry on first shard
        // arrival (their DEK is random — we cannot derive the foreign
        // owner's master). Own recordings are absent from the keyring by
        // design: their DEK is derived from `dek_master` on every read.
        // The own-vs-foreign branch is the load-bearing invariant for
        // `resolve_encryption_key` — if we mint a random DEK for an own
        // recording here, every subsequent read returns the wrong key.
        let rid = envelope.evidence.recording_id();
        let is_foreign = envelope.did != self.guardian.local_did;
        if is_foreign
            && self.guardian.get_content_key(rid).is_none()
            && !self.guardian.revoked_recordings.contains(rid)
        {
            self.guardian.mint_foreign_content_key(rid);
            self.guardian.persist_keyring().await?;
        }

        // 1. Disk first
        self.guardian.append_shard(&envelope).await?;
        let recording_id = envelope.evidence.recording_id().clone();
        // Publish gate (mirrors handle_ingest): skip the mesh notify for
        // recordings the operator marked local-only.
        if self.guardian.is_recording_publishable(&recording_id) {
            if let Some(ref tx) = self.commit_notify_tx {
                let _ = tx.try_send(recording_id);
            }
        }
        // 2. Verify in memory (data is already safely on disk)
        let result = self
            .guardian
            .ingest_envelope(EnvelopeState::Intact(envelope), self.current_tolerance)
            .await;
        if let Err(ref e) = result {
            tracing::warn!(
                target: "phalanx::storage",
                error = %e,
                "WriteShard: Verification failed for persisted shard"
            );
        }
        result
    }

    /// Cryptographic Forgetting: authorize and execute a recording revocation.
    async fn handle_revoke(&mut self, token: RevocationToken) -> Result<(), GuardianError> {
        let recording_id = token.recording_id.clone();

        // 1. Verify the token's self-contained signature
        phalanx_forensics::revocation::verify_revocation_token(&token).map_err(|e| {
            GuardianError::VerificationFailed(format!("Revocation token invalid: {e}"))
        })?;

        // 2. Look up any envelope to get the recording's embedded revocation key.
        //
        // NOTE (audit-closed): `read_all_shards` returns RAW envelopes without
        // re-running `verify_envelope`, and `.first()` picks an arbitrary shard.
        // This is safe because the cryptographic trust anchor is the BIP39
        // mnemonic held off-device by the recording author, NOT the on-disk
        // `revocation_key` field:
        //
        //   - `revocation_key` embedded in every envelope is a *public-key
        //     commitment* to a keypair derived from the author's BIP39 seed.
        //   - `verify_revocation_token` at step 1 checks the token's self-
        //     signature against that key. The matching private key is
        //     non-derivable from anything on the network — an attacker who
        //     injects a shard with a chosen `revocation_key` still cannot
        //     forge a token that verifies.
        //   - The step-2 equality check (`token.key == first.revocation_key`)
        //     is therefore a *consistency* gate, not the trust anchor. Even
        //     if `.first()` picks a poisoned shard, revocation only fires if
        //     the attacker *also* produces a token signed by the matching
        //     private key — which requires the BIP39 seed.
        //
        // Do NOT "harden" this by adding `verify_envelope` to the lookup —
        // the token gate already provides cryptographic authorization.
        // Previously flagged, investigated, closed. See audit trail in
        // threat-model.md §9 "Forced Evidence Retention."
        let envelopes = self
            .guardian
            .read_all_shards(&recording_id, None)
            .await
            .unwrap_or_default();

        if let Some(first) = envelopes.first() {
            // Authorize: token key must match the recording's embedded key
            phalanx_forensics::revocation::authorize_revocation(&token, &first.revocation_key)
                .map_err(|e| {
                    GuardianError::VerificationFailed(format!(
                        "Revocation authorization failed: {e}"
                    ))
                })?;
        } else if !self.guardian.has_recording(&recording_id) {
            // Unknown recording — cannot verify authorization.
            // Reject to prevent unauthorized cross-identity revocation.
            // Late-joining nodes discover revocations via DHT tombstone.
            return Err(GuardianError::VerificationFailed(
                "Cannot authorize revocation for unknown recording".into(),
            ));
        }
        // Recording exists locally (in logs or Crucible) but read_all_shards
        // returned empty (e.g., partially ingested). Honor with self-contained
        // signature as fallback.

        // 3. Execute the revocation
        self.guardian.revoke_recording(&recording_id).await?;

        // 4. Persist to journal for crash recovery
        if let Err(e) = self.journal.record_revocations(&[token]).await {
            tracing::error!(
                recording = %recording_id,
                error = %e,
                "Failed to persist revocation to journal"
            );
        }

        tracing::info!(
            recording = %recording_id,
            "Recording revoked — all evidence destroyed"
        );
        Ok(())
    }

    /// Derive (deterministically, from `dek_master`) the per-recording
    /// content key for a new own recording, and pin its policy metadata.
    ///
    /// The DEK is NOT written to the keyring — it's recomputable from the
    /// BIP39 phrase, which is what makes the recording mesh-recoverable
    /// after device loss. The keyring is reserved for foreign and legacy
    /// random-DEK recordings.
    ///
    /// `options` carries per-recording policy (currently `publishable`).
    /// Default options preserve the historical implicit-publish behaviour;
    /// the explicit-options API path lets the operator opt out per
    /// recording. The metadata entry is persisted *before* the key is
    /// returned so a crash between key derivation and the first commit
    /// does not leave a recording mis-classified as publishable.
    async fn handle_start_recording(
        &mut self,
        recording_id: &RecordingId,
        options: RecordingOptions,
    ) -> Result<[u8; 32], ShardError> {
        if self.guardian.revoked_recordings.contains(recording_id) {
            return Err(ShardError::RecordingRevoked);
        }
        let key = self.guardian.content_key_for(recording_id);

        self.guardian
            .set_recording_metadata(recording_id.clone(), options.into_metadata());
        self.guardian
            .persist_recording_metadata()
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        // PR C: catalog publishable recordings in the per-identity manifest
        // so a fresh-restored sentinel can enumerate what to fetch from the
        // mesh. Unpublishable recordings get no manifest entry — they're
        // not on the mesh, so their absence from the catalog is correct
        // and avoids leaking their existence in the published manifest.
        if options.publishable {
            self.append_manifest_entry(recording_id).await?;
        }

        tracing::info!(
            target: "phalanx::storage",
            recording = %recording_id,
            publishable = options.publishable,
            "Content key derived for new recording"
        );
        Ok(*key.as_bytes())
    }

    /// Append a `ManifestEntry` shard to this identity's deterministic
    /// manifest recording.
    ///
    /// The manifest's `RecordingId` is `derive_manifest_recording_id(
    /// dek_master)`; the per-recording AEAD key is the usual derive-path
    /// (no keyring entry). Each call:
    ///
    /// 1. Resolves `(next_seq, prev_hash)` from the manifest's recording
    ///    log (one disk read on subsequent calls; free on first call).
    /// 2. Builds and signs a `ManifestEntry` envelope.
    /// 3. Pins the manifest's `RecordingMetadata { publishable: true }`
    ///    explicitly — defensive against any future change to the
    ///    default-publishable semantics. The pin is idempotent.
    /// 4. Writes the envelope to disk via `append_shard` (bypasses the
    ///    Crucible reassembler — the manifest is a chain of independent
    ///    catalog facts, not media to reassemble; same pattern as
    ///    internally-generated `Evidence::Gap` shards).
    /// 5. Fires `commit_notify_tx` so MeshSentinel announces the new
    ///    manifest shard to the mesh.
    ///
    /// Errors propagate uniformly. A disk or signing failure here would
    /// equally block the child's first shard moments later, so there is
    /// no asymmetric "best-effort" failure mode worth special-casing.
    async fn append_manifest_entry(
        &mut self,
        child_recording_id: &RecordingId,
    ) -> Result<(), ShardError> {
        let manifest_id = self.guardian.manifest_recording_id();
        let (sequence_id, prev_hash) = self
            .guardian
            .manifest_chain_state()
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        let entry = ManifestEntry {
            timestamp: self.guardian.clock.now(),
            sequence_id,
            recording_id: manifest_id.clone(),
            child_recording_id: child_recording_id.clone(),
        };

        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::ManifestEntry(entry),
            &self.identity,
            self.identity.witness_id.clone(),
            prev_hash,
        )?;

        // Pin manifest's publishability explicitly. Idempotent — re-set
        // on every append so a missing or corrupted metadata file
        // recovers on the next start. The cost is one BTreeMap insert
        // per start_recording call.
        self.guardian.set_recording_metadata(
            manifest_id.clone(),
            RecordingOptions { publishable: true }.into_metadata(),
        );
        self.guardian
            .persist_recording_metadata()
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        self.guardian
            .append_shard(&envelope)
            .await
            .map_err(|e| ShardError::Io(format!("manifest append: {e}")))?;

        // Note: no ledger update. The storage ledger tracks
        // fountain-chunk bytes via `handle_ingest` only; shard-on-disk
        // writes (this path and `handle_write_shard`) intentionally skip
        // it. Adding `record_own_ingestion` here would over-count
        // manifest bytes relative to other shard writes.

        // Publish gate. We just pinned the manifest to publishable=true
        // above, so this branch is taken — but consult the gate
        // uniformly so future policy plumbing (operator override) is
        // honoured here too.
        if self.guardian.is_recording_publishable(&manifest_id) {
            if let Some(ref tx) = self.commit_notify_tx {
                let _ = tx.try_send(manifest_id);
            }
        }

        Ok(())
    }

    /// Persists network state to the WAL and salvages Guardian data.
    async fn handle_salvage(&mut self, pending: Vec<PendingEgress>) {
        tracing::warn!(target: "phalanx::storage", count = pending.len(), "Emergency salvage triggered.");
        if let Err(e) = self.journal.record_pending_egress(&pending).await {
            tracing::error!(target: "phalanx::storage", error = %e, "Failed to salvage pending egress to journal");
        }

        let _ = self.journal.sync().await;

        // CORRECTED: Uses Guardian::salvage
        if let Err(e) = self.guardian.salvage().await {
            tracing::error!(target: "phalanx::storage", error = %e, "Failed to salvage guardian");
        }
    }
}

pub struct NoOpJournal;
#[async_trait::async_trait]
impl TransientJournal for NoOpJournal {
    async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
        Ok(())
    }
    async fn sync(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        Ok(vec![])
    }
    async fn clear(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
    async fn record_pending_egress(
        &mut self,
        _pending: &[PendingEgress],
    ) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        Ok(vec![])
    }
    async fn record_workbench_state(&mut self, _: &[u8]) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError> {
        Ok(vec![])
    }
}
