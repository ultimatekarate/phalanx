// crates/phalanx-node/src/actors/storage.rs
use crate::config::NodeConfig;
use crate::persistence::vault::Guardian;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_forensics::prelude::*;
use phalanx_proto::evidence::EnvelopeState;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::identity::VolleyId;
use phalanx_proto::prelude::{PendingEgress, ShardChunk, ShardError};
use phalanx_proto::storage::GuardianError;
use phalanx_proto::types::ForensicUnit;
use phalanx_proto::types::Verified;
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
    // REMOVED: forensic_tx, local_peer_id, ack_tx to ensure absolute isolation
}

pub enum StorageCommand {
    /// Pure ingestion. No routing logic or network ACKs.
    Ingest {
        unit: ForensicUnit<ShardChunk, Verified>,
        reply_to: oneshot::Sender<Result<(), GuardianError>>,
    },
    /// Pure retrieval. Returns raw envelopes directly from the vault.
    Retrieval {
        volley_id: VolleyId,
        reply_to: oneshot::Sender<Vec<WitnessEnvelope>>,
    },
    /// Single shard retrieval for local PlaybackCoordinator UI playback.
    GetShard {
        volley_id: VolleyId,
        sequence_id: StorageSequence,
        reply_to: oneshot::Sender<Option<WitnessEnvelope>>,
    },
    /// Direct envelope ingestion bypass (used internally by Guardian operations).
    IngestEnvelope {
        state: EnvelopeState,
        reply_to: oneshot::Sender<Result<(), GuardianError>>,
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
                    active_volleys = self.reassembler.active_shards.len(),
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
                            StorageCommand::Ingest { unit, reply_to } => {
                                let _ = reply_to.send(self.handle_ingest(unit).await);
                            }
                            StorageCommand::Retrieval { volley_id, reply_to } => {
                                self.handle_retrieval(volley_id, reply_to).await;
                            }
                            StorageCommand::GetShard { volley_id, sequence_id, reply_to } => {
                                let _ = reply_to.send(self.guardian.get_shard(&volley_id, sequence_id));
                            }
                            StorageCommand::IngestEnvelope { state, reply_to } => {
                                let _ = reply_to.send(self.guardian.ingest_envelope(state).await);
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
                    let _ = self.guardian.check_and_finalize_volley().await;
                }
            }
        }
    }

    /// Handles data ingestion purely from a forensic and storage perspective.
    async fn handle_ingest(
        &mut self,
        unit: ForensicUnit<ShardChunk, Verified>,
    ) -> Result<(), GuardianError> {
        let chunk = unit.unpack();

        let reassembly_result = self
            .reassembler
            .ingest_chunk(chunk, &mut self.journal)
            .await;

        if let Err(e) = self.journal.sync().await {
            tracing::error!(error = %e, "Forensics: Critical failure to sync WAL to disk");
        }

        match reassembly_result {
            Ok(Some(envelope_state)) => {
                // CORRECTED: Uses Guardian::ingest_envelope which takes EnvelopeState
                self.guardian.ingest_envelope(envelope_state).await
            }
            Ok(None) => {
                // Chunk accepted, but volley is still incomplete
                Ok(())
            }
            Err(e) => {
                // Cryptographic failure
                Err(GuardianError::VerificationFailed(e.to_string()))
            }
        }
    }

    /// Fetches all active shards for a specific volley without wrapping in network responses.
    async fn handle_retrieval(
        &self,
        volley_id: VolleyId,
        reply_to: oneshot::Sender<Vec<WitnessEnvelope>>,
    ) {
        // CORRECTED: Uses Guardian::get_active_volley_shards which returns an Option<&BTreeMap>
        let envelopes = self
            .guardian
            .get_active_volley_shards(&volley_id)
            .map(|map| map.values().cloned().collect())
            .unwrap_or_default();

        let _ = reply_to.send(envelopes);
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
}
