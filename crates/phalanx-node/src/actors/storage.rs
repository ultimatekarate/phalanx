// crates/phalanx-node/src/actors/storage.rs
use crate::actors::retrieval::RetrievalQuery;
use crate::config::NodeConfig;
use crate::Guardian;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_forensics::prelude::*;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::storage::StorageAck;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;

pub struct StorageActor<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub guardian: Guardian,
    pub journal: J,
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub forensic_tx: mpsc::Sender<(NetworkId, Did, GuardianError)>,
    pub local_peer_id: NetworkId,
    pub ack_tx: mpsc::Sender<StorageAck>,
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

        // Hydrate the Reassembler state from the TransientJournal (WAL)
        // FIX: matched Ok(()) since recover_from_journal populates internal state
        match self
            .reassembler
            .recover_from_journal(&mut self.journal)
            .await
        {
            Ok(()) => {
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
                            if let Err(err) = self.guardian.ingest_envelope(state).await {
                                tracing::error!(error = %err, "Vault: Rejected explicit envelope ingestion");
                                let _ = self.forensic_tx.send((
                                    self.local_peer_id.clone(),
                                    self.identity.did.clone(),
                                    err
                                )).await;
                            }
                        }

                        StorageCommand::Retrieval(query) => {
                            self.handle_retrieval_query(query).await;
                        }

                        StorageCommand::GetShard { volley_id, sequence_id, reply_to } => {
                            let shard_opt = self.guardian.get_shard(&volley_id, sequence_id);
                            let _ = reply_to.send(shard_opt);
                        }

                        StorageCommand::EmergencySalvage(payload) => {
                            tracing::info!(count = payload.len(), "Pillar 1: Executing emergency salvage protocol");

                            if let Err(e) = self.journal.record_pending_egress(&payload).await {
                                tracing::error!(error = %e, "Salvage: Failed to record pending egress to journal");
                            }

                            let _ = self.journal.sync().await;
                            let _ = self.guardian.salvage().await;

                            tracing::info!("Salvage sequence complete. Terminating actor task.");
                            return;
                        }
                    }
                }

                _ = maintenance_timer.tick() => {
                    if let Err(e) = self.guardian.check_and_finalize_volley().await {
                        tracing::warn!(error = %e, "Maintenance: Crucible cycle failed");
                    }
                }
            }
        }
    }

    async fn handle_retrieval_query(&self, query: RetrievalQuery) {
        let result = match self
            .guardian
            .get_active_volley_shards(&query.request.volley_id)
        {
            Some(shard_map) => Ok(shard_map.values().cloned().collect()),
            None => Err(()),
        };

        // FIX: Mapped query result to expected VolleyResponse type
        let response = match result {
            Ok(envelopes) => VolleyResponse::Success(envelopes),
            Err(_) => VolleyResponse::NotFound,
        };

        let _ = query.reply_to.send(response);
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
            // CAUSAL LOOP: Release slot even on early rejection
            let _ = self
                .ack_tx
                .send(StorageAck::Failure(
                    ShardError::InvalidConfiguration("Topic mismatch".into()),
                    peer_id,
                ))
                .await;
            return;
        }

        let chunk_owner_did = chunk.owner_did.clone();

        let reassembly_result = self
            .reassembler
            .ingest_chunk(chunk, &mut self.journal)
            .await;

        if let Err(e) = self.journal.sync().await {
            tracing::error!(error = %e, "Forensics: Critical failure to sync WAL to disk");
        }

        match reassembly_result {
            Ok(Some(envelope_state)) => {
                tracing::info!(target: "phalanx::forensics", "Reassembly complete. Handing to Guardian.");

                if let Err(err) = self.guardian.ingest_envelope(envelope_state).await {
                    tracing::error!(error = %err, "Forensics: Guardian rejected network envelope");

                    if let Err(e) = self
                        .forensic_tx
                        .send((peer_id.clone(), chunk_owner_did, err))
                        .await
                    {
                        tracing::error!(error = %e, "CRITICAL: Forensic channel disconnected");
                    }
                }
            }
            Ok(None) => {
                tracing::debug!(target: "phalanx::forensics", "Shard buffered. Volley incomplete.");
            }
            Err(err) => {
                tracing::error!(target: "phalanx::forensics", error = %err, "Reassembler rejected shard. Escalating.");

                let forensic_err =
                    GuardianError::VerificationFailed(format!("Shard integrity: {}", err));
                let _ = self
                    .forensic_tx
                    .send((peer_id.clone(), chunk_owner_did, forensic_err))
                    .await;
            }
        }

        let _ = self
            .ack_tx
            .send(StorageAck::Success(VolleyId::new(""), peer_id.clone()))
            .await;
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
