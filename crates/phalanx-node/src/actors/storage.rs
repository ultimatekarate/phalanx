// crates/phalanx-node/src/actors/storage.rs
use crate::config::NodeConfig;
use crate::persistence::vault::Guardian;
use crate::vitals::{Homeostasis, SystemGovernor};
use phalanx_forensics::bloom::RotatingBloomFilter;
use phalanx_forensics::crucible::EvidenceExt;
use phalanx_forensics::prelude::*;
use phalanx_proto::evidence::EnvelopeState;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::prelude::{ShardChunk, ShardError};
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
    /// Fires after each successful shard write. MeshSentinel uses this for DHT announcements.
    pub commit_notify_tx: Option<mpsc::Sender<RecordingId>>,
    /// Replay detection: rotating Bloom filter for evidence_hash dedup.
    /// 1M bits per generation (~125KB × 2 = ~250KB fixed). Rotates on maintenance tick.
    pub replay_filter: RotatingBloomFilter,
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
}

impl<J: TransientJournal> StorageActor<J> {
    pub async fn run(mut self, mut command_rx: mpsc::Receiver<StorageCommand>) {
        tracing::info!(target: "phalanx::storage", "StorageActor: Entering pure vault mode");

        // Hydrate the Reassembler state from the TransientJournal (WAL)
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

        let mut maintenance_timer = interval(Duration::from_millis(1000));

        loop {
            tokio::select! {
                // FIX: Explicitly handle the None case to break the loop
                res = command_rx.recv() => {
                    match res {
                        Some(cmd) => match cmd {
                            StorageCommand::Ingest { unit, reply_to, ttl } => {
                                self.current_tolerance = ttl;
                                let result = self.handle_ingest(unit).await;
                                let _ = reply_to.send(result);
                            }
                            StorageCommand::Retrieval { recording_id, owner_did, reply_to } => {
                                self.handle_retrieval(recording_id, owner_did, reply_to).await;
                            }
                            StorageCommand::GetShard { recording_id, sequence_id, reply_to } => {
                                let result = self.guardian.read_shard(&recording_id, sequence_id, None).await.ok();
                                let _ = reply_to.send(result);
                            }
                            StorageCommand::WriteShard { envelope, reply_to } => {
                                let result = self.handle_write_shard(envelope).await;
                                let _ = reply_to.send(result);
                            }
                            StorageCommand::IngestEnvelope { state, reply_to, ttl } => {
                                let _ = reply_to.send(self.guardian.ingest_envelope(state, ttl).await);
                            }
                            StorageCommand::EmergencySalvage(pending) => {
                                // This handles the BrokenJournal error internally and continues
                                self.handle_salvage(pending).await;
                            }
                        },
                        None => {
                            tracing::info!(target: "phalanx::storage", "Sentinel dropped channel. Vault shutting down.");
                            break;
                        }
                    }
                }
                _ = maintenance_timer.tick() => {
                    self.replay_filter.rotate();
                    let _ = self.guardian.check_and_finalize_recording(self.current_tolerance).await;
                }
            }
        }
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
                        if let Some(ref tx) = self.commit_notify_tx {
                            let _ = tx.try_send(recording_id);
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
        // 1. Disk first
        self.guardian.append_shard(&envelope).await?;
        let recording_id = envelope.evidence.recording_id().clone();
        if let Some(ref tx) = self.commit_notify_tx {
            let _ = tx.try_send(recording_id);
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
