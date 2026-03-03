use phalanx_proto::prelude::*;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_forensics::prelude::*;
use std::time::{Duration};
use tokio::time::interval;
use crate::Guardian;
use crate::config::NodeConfig;
use tokio::sync::mpsc;

pub struct StorageActor<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub guardian: Guardian,
    pub journal: J,
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub forensic_tx: mpsc::Sender<(NetworkId, Did, GuardianError)>,
    pub local_peer_id: NetworkId,
}

pub enum StorageCommand {
    Ingest(ShardChunk, MeshTopic, NetworkId),
    Retrieval(RetrievalQuery),
    EmergencySalvage(Vec<PendingEgress>),
    GetShard {
        volley_id: VolleyId,
        sequence_id: StorageSequence,
        reply_to: tokio::sync::oneshot::Sender<Option<WitnessEnvelope>>,
    },
    IngestEnvelope(EnvelopeState),
}

impl<J: TransientJournal> StorageActor<J> {
    pub async fn run(mut self, mut command_rx: mpsc::Receiver<StorageCommand>) {
        tracing::info!("StorageActor: Entering forensic bootstrap phase");

        // PILLAR 2: Deterministic Recovery
        // Hydrate the Reassembler state from the TransientJournal (WAL) before opening the command gate.
        match self
            .reassembler
            .recover_from_journal(&mut self.journal, self.local_peer_id)
            .await
        {
            Ok(recovered_states) => {
                for state in recovered_states {
                    // Promote recovered envelopes to the Guardian for verification and Crucible processing.
                    if let Err(e) = self.guardian.ingest_envelope(state).await {
                        tracing::error!(error = %e, "Bootstrap: Guardian rejected recovered state");
                    }
                }
                tracing::info!(
                    active_volleys = self.reassembler.active_shards.len(),
                    "StorageActor: Bootstrap complete. State hydrated."
                );
            }
            Err(e) => {
                tracing::error!(error = %e, "CRITICAL: Bootstrap recovery failed. Starting with empty state.");
            }
        }

        let mut maintenance_timer = interval(Duration::from_millis(1000));

        loop {
            tokio::select! {
                Some(command) = command_rx.recv() => {
                    match command {
                        StorageCommand::Ingest(chunk, topic, peer_id) => {
                            self.process_incoming_chunk(chunk, topic, peer_id).await;
                        }

                        StorageCommand::IngestEnvelope(state) => {
                            // Manual or recovered envelope ingestion path.
                            if let Err(err) = self.guardian.ingest_envelope(state).await {
                                tracing::error!(error = %err, "Vault: Rejected explicit envelope ingestion");
                                let _ = self.forensic_tx.send((
                                    self.local_peer_id,
                                    self.identity.did.clone(),
                                    err
                                )).await;
                            }
                        }

                        StorageCommand::Retrieval(query) => {
                            // Delegate to specialized retrieval logic.
                            self.handle_retrieval_query(query).await;
                        }

                        StorageCommand::GetShard { volley_id, sequence_id, reply_to } => {
                            // Synchronous vault lookup for specific causality anchors.
                            let shard_opt = self.guardian.get_shard(&volley_id, sequence_id);
                            let _ = reply_to.send(shard_opt);
                        }

                        StorageCommand::EmergencySalvage(payload) => {
                            tracing::info!(count = payload.len(), "Pillar 1: Executing emergency salvage protocol");

                            // 1. Commit pending egress to WAL.
                            if let Err(e) = self.journal.record_pending_egress(&payload).await {
                                tracing::error!(error = %e, "Salvage: Failed to record pending egress to journal");
                            }

                            // 2. Force deterministic disk synchronization.
                            let _ = self.journal.sync().await;

                            // 3. Trigger Guardian-level salvage (Crucible flushing).
                            let _ = self.guardian.salvage().await;

                            tracing::info!("Salvage sequence complete. Terminating actor task.");
                            return;
                        }
                    }
                }

                _ = maintenance_timer.tick() => {
                    // Periodic Crucible maintenance: TTL checks and stale volley flushing.
                    if let Err(e) = self.guardian.check_and_finalize_volley().await {
                        tracing::warn!(error = %e, "Maintenance: Crucible cycle failed");
                    }
                }
            }
        }
    }

    async fn handle_retrieval_query(&self, query: RetrievalQuery) {
        let result = match self.guardian.get_active_volley_shards(&query.volley_id) {
            Some(shard_map) => Ok(shard_map.values().cloned().collect()),
            None => Ok(Vec::new()),
        };
        let _ = query.reply_to.send(result);
    }

    async fn process_incoming_chunk(
        &mut self,
        chunk: ShardChunk,
        topic: MeshTopic,
        peer_id: NetworkId,
    ) {
        let normalized_video = MeshTopic::new(self.config.network.video_topic.as_str());
        let normalized_audio = MeshTopic::new(self.config.network.audio_topic.as_str());

        if topic != normalized_video && topic != normalized_audio {
            tracing::warn!(target: "phalanx::forensics", ?topic, "Rejecting shard: Topic mismatch");
            return;
        }

        let chunk_owner_did = chunk.owner_did.clone();

        // Reassembler Stage
        let reassembly_result = self
            .reassembler
            .ingest_chunk(chunk, &mut self.journal)
            .await;

        if let Err(e) = self.journal.sync().await {
            error!(error = %e, "Forensics: Critical failure to sync WAL to disk");
        }

        match reassembly_result {
            Ok(Some(envelope_state)) => {
                tracing::info!(target: "phalanx::forensics", "Reassembly complete. Handing to Guardian.");

                // Reassembly complete. Proceed to Guardian validation.
                if let Err(err) = self.guardian.ingest_envelope(envelope_state).await {
                    tracing::error!(error = %err, "Forensics: Guardian rejected network envelope");

                    // Deterministic escalation to the Sentinel.
                    if let Err(e) = self.forensic_tx.send((peer_id, chunk_owner_did, err)).await {
                        tracing::error!(error = %e, "CRITICAL: Forensic channel disconnected");
                    }
                }
            }
            Ok(None) => {
                // If the test sends only 1 shard and expects an immediate signature failure,
                // but the reassembler thinks it needs more shards, it returns Ok(None).
                tracing::debug!(target: "phalanx::forensics", "Shard buffered. Volley incomplete.");
            }
            Err(err) => {
                // SHARD-LEVEL VIOLATION
                // If the signature mismatch is detected at the shard level (e.g., checksum fail),
                // we must escalate here or the test will time out.
                tracing::error!(target: "phalanx::forensics", error = %err, "Reassembler rejected shard. Escalating.");

                let forensic_err =
                    GuardianError::VerificationFailed(format!("Shard integrity: {}", err));
                let _ = self
                    .forensic_tx
                    .send((peer_id, chunk_owner_did, forensic_err))
                    .await;
            }
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
