use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Sleep;
use tracing::{debug, info};

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::base::types::{MeshTopic, PowerState, UnitInterval, VitalityRate};
use crate::primitives::identity::{NetworkId, PhalanxIdentity};
use crate::primitives::shards::{ShardChunk, ShardError, WitnessEnvelope};
use crate::storage::reassembler::{Reassembler, TransientJournal};
use crate::storage::vault::Guardian;
use crate::transport::health::{ControlMessage, HealthTracker};
use crate::transport::network_transport::NetworkTransport;
use crate::transport::protocol::VolleyResponse;

pub struct StorageActor<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub storage: Arc<RwLock<Guardian>>,
    pub journal: J,
    pub config: PhalanxConfig,
    pub identity: PhalanxIdentity,
    pub chunk_rx: mpsc::Receiver<(ShardChunk, MeshTopic, NetworkId)>,
    pub active_tasks_metric: Arc<AtomicUsize>,
    pub physics: PhalanxPhysics,
    pub local_peer_id: NetworkId,
}

impl<J: TransientJournal> StorageActor<J> {
    pub async fn run(mut self) {
        if let Err(err) = self.restore_state().await {
            tracing::error!(error = %err, "Failed to restore Crucible state from disk.");
        }

        let mut maintenance_timer = tokio::time::interval(Duration::from_secs(1));
        maintenance_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                // Handle incoming data
                chunk_payload = self.chunk_rx.recv() => {
                    match chunk_payload {
                        Some((chunk, topic, peer_id)) => {
                            info!("processing incoming chunk");
                            self.process_incoming_chunk(chunk, topic, peer_id).await;
                        }
                        None => {
                            // Channel closed: Trigger emergency salvage before actor death
                            info!("Chunk receiver closed. Commencing emergency salvage...");
                            let mut guardian = self.storage.write().await;
                            let _ = guardian.force_salvage_all();
                            return;
                        }
                    }
                }

                // Periodic maintenance
                _ = maintenance_timer.tick() => {
                    // 1. Flush stale volleys from the Crucible workbench
                    let mut guardian = self.storage.write().await;
                    if let Err(err) = guardian.check_and_finalize_volley() {
                        tracing::error!(error = %err, "Periodic finalization failed");
                    }
                    drop(guardian);

                    // 2. Periodic WAL snapshotting and metrics
                    if let Err(err) = self.snapshot_state().await {
                        tracing::error!(error = %err, "Freeze Protocol failed.");
                    }
                    self.update_metrics().await;
                }
            }
        }
    }

    async fn process_incoming_chunk(
        &mut self,
        chunk: ShardChunk,
        topic: MeshTopic,
        peer_id: NetworkId,
    ) {
        let envelope_opt = self
            .reassembler
            .ingest_chunk(
                chunk,
                &mut self.journal,
                &topic,
                &self.config,
                &self.identity,
                peer_id,
            )
            .await;

        match envelope_opt {
            Ok(Some(envelope)) => {
                let mut guardian_guard = self.storage.write().await;
                if let Err(err) = guardian_guard.ingest_envelope(envelope) {
                    tracing::error!(error = %err, "Vault rejected envelope");
                }
                drop(guardian_guard);
                self.update_metrics().await;
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(error = %err, "Reassembler rejected data chunk"),
        }
    }

    pub async fn restore_state(&mut self) -> Result<(), ShardError> {
        let recovered = self
            .reassembler
            .recover_from_journal(
                &mut self.journal,
                &self.config,
                &self.identity,
                self.local_peer_id,
            )
            .await?;

        let mut guardian = self.storage.write().await;
        for envelope in recovered {
            let _ = guardian.ingest_envelope(envelope);
        }
        info!("Crucible WAL replay complete.");
        Ok(())
    }

    pub async fn snapshot_state(&mut self) -> Result<(), ShardError> {
        if self.reassembler.crucible.contexts.is_empty() {
            self.journal
                .clear()
                .await
                .map_err(|e| ShardError::Io(std::io::Error::other(e.to_string())))?;
            debug!("Crucible state frozen and WAL compacted.");
        }
        Ok(())
    }

    async fn update_metrics(&self) {
        let storage_guard = self.storage.read().await;
        let active_contexts = storage_guard.crucible.contexts.len();
        self.active_tasks_metric
            .store(active_contexts, Ordering::Relaxed);
    }
}

pub struct StrongholdEngine<T: NetworkTransport, J: TransientJournal> {
    pub config: PhalanxConfig,
    pub identity: PhalanxIdentity,
    pub physics: PhalanxPhysics,
    pub network: T,
    pub chunk_tx: mpsc::Sender<(ShardChunk, MeshTopic, NetworkId)>,
    pub health_tracker: HealthTracker,
    pub power_state: PowerState,
    pub storage_load: Arc<AtomicUsize>,
    pub storage: Arc<RwLock<Guardian>>,
    pub _journal_phantom: std::marker::PhantomData<J>,
}

impl<T: NetworkTransport, J: TransientJournal + 'static> StrongholdEngine<T, J> {
    pub async fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        physics: PhalanxPhysics,
        network: T,
        journal: J,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let local_peer_id = identity.to_network_id();
        let (chunk_tx, chunk_rx) = mpsc::channel(1024);
        let storage_load = Arc::new(AtomicUsize::new(0));

        let guardian = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());
        let storage = Arc::new(RwLock::new(guardian));

        let actor = StorageActor {
            reassembler: Reassembler::new(),
            storage: Arc::clone(&storage),
            journal,
            config: config.clone(),
            identity: identity.clone(),
            chunk_rx,
            active_tasks_metric: Arc::clone(&storage_load),
            physics,
            local_peer_id,
        };

        tokio::spawn(async move { actor.run().await });

        Ok(Self {
            config,
            identity,
            physics,
            network,
            chunk_tx,
            health_tracker: HealthTracker::new(),
            power_state: PowerState::Normal,
            storage_load,
            storage,
            _journal_phantom: std::marker::PhantomData,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        info!(id = %self.identity.did, "Stronghold Engine active.");
        let mut heartbeat: Pin<Box<Sleep>> =
            Box::pin(tokio::time::sleep(Duration::from_millis(100)));

        loop {
            tokio::select! {
                Some(event) = self.network.next_event() => self.handle_network_event(event).await,
                () = &mut heartbeat => {
                    let next = self.pulse_vitality().await;
                    heartbeat.as_mut().reset((Instant::now() + next).into());
                }
            }
        }
    }

    async fn handle_network_event(&mut self, event: crate::transport::events::NetworkEvent) {
        match event {
            crate::transport::events::NetworkEvent::DataReceived {
                origin,
                topic,
                data,
            } => {
                if topic.as_str() == self.config.network.control_topic {
                    if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&data) {
                        self.health_tracker.register_activity(msg);
                    }
                } else if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&data) {
                    let _ = self.chunk_tx.try_send((chunk, topic, origin));
                }
            }
            crate::transport::events::NetworkEvent::RetrievalRequested {
                request,
                channel_id,
            } => {
                let guardian = self.storage.read().await;
                let response = match guardian.get_active_volley_shards(&request.locator.author) {
                    Some(data) => {
                        let filtered: Vec<WitnessEnvelope> = data
                            .values()
                            .filter(|e| e.evidence.volley_id() == &request.volley_id)
                            .cloned()
                            .collect();
                        if filtered.is_empty() {
                            VolleyResponse::NotFound
                        } else {
                            VolleyResponse::Success(filtered)
                        }
                    }
                    None => VolleyResponse::NotFound,
                };
                let _ = self.network.send_response(&channel_id, response).await;
            }
            _ => {}
        }
    }

    async fn pulse_vitality(&mut self) -> Duration {
        let load = UnitInterval::new(
            self.storage_load.load(Ordering::Relaxed) as f32 / self.config.storage.max_peers as f32,
        );
        let vitality = VitalityRate::calculate(&self.physics, self.power_state, load);
        let msg = ControlMessage {
            sender: self.identity.to_network_id(),
            load_factor: load.as_f32(),
            storage_remaining_mb: 10240,
            heartbeat_ms: vitality.as_u64(),
            is_leaf: self.power_state == PowerState::Leaf,
        };

        if let Ok(data) = postcard::to_stdvec(&msg) {
            let _ = self
                .network
                .publish(&self.config.network.control_topic, data)
                .await;
        }
        vitality.as_duration()
    }
}
