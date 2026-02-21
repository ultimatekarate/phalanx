use std::error::Error;
use std::path::Path;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};
use tokio::time::Sleep;
use tracing::{debug, info, warn};

use phalanx_core::{
    base::{
        config::{PhalanxConfig, PhalanxPhysics},
        types::{MeshTopic, PowerState, UnitInterval, VitalityRate},
    },
    primitives::identity::{NetworkId, PhalanxIdentity},
    primitives::shards::{ShardChunk, ShardError, WitnessEnvelope},
    security::{gate::ForensicGate, telemetry},
    storage::{
        journal::FileJournal, reassembler::Reassembler, reassembler::TransientJournal,
        vault::Guardian,
    },
    transport::events::NetworkEvent,
    transport::health::{ControlMessage, HealthTracker},
    transport::network_transport::NetworkTransport,
    transport::protocol::{VolleyRequest, VolleyResponse},
};

/// The Dedicated Storage Node.
pub struct StrongholdEngine<T: NetworkTransport, J: TransientJournal> {
    config: PhalanxConfig,
    identity: PhalanxIdentity,
    physics: PhalanxPhysics,
    network: T,
    chunk_tx: mpsc::Sender<(ShardChunk, MeshTopic, NetworkId)>,
    health_tracker: HealthTracker,
    power_state: PowerState,
    storage_load: Arc<AtomicUsize>,
    storage: Arc<RwLock<Guardian>>,
    _journal_phantom: std::marker::PhantomData<J>,
}

impl<T: NetworkTransport, J: TransientJournal + 'static> StrongholdEngine<T, J> {
    pub async fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        physics: PhalanxPhysics,
        network: T,
        journal: J,
    ) -> Result<Self, Box<dyn Error>> {
        let local_peer_id = identity.to_network_id();

        // 1. Storage Init
        let (chunk_tx, chunk_rx) = mpsc::channel(1024);
        let storage_load = Arc::new(AtomicUsize::new(0));
        let actor_load_metric = Arc::clone(&storage_load);

        let guardian = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());
        let shared_storage = Arc::new(RwLock::new(guardian));

        let storage_actor = StorageActor {
            reassembler: Reassembler::new(),
            storage: Arc::clone(&shared_storage),
            journal,
            config: config.clone(),
            identity: identity.clone(),
            chunk_rx,
            active_tasks_metric: actor_load_metric,
            physics: physics,
            local_peer_id,
        };

        tokio::spawn(async move {
            storage_actor.run().await;
        });

        Ok(Self {
            config,
            identity,
            physics,
            _journal_phantom: std::marker::PhantomData,
            network,
            chunk_tx,
            health_tracker: HealthTracker::new(),
            power_state: PowerState::Normal,
            storage_load,
            storage: shared_storage,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        info!(id = %self.identity.did, "Stronghold Engine active.");

        let mut heartbeat_timer: Pin<Box<Sleep>> =
            Box::pin(tokio::time::sleep(Duration::from_millis(100)));

        loop {
            tokio::select! {
                Some(event) = self.network.next_event() => {
                    self.handle_network_event(event).await;
                }
                () = &mut heartbeat_timer => {
                    let next_interval = self.pulse_vitality().await;
                    heartbeat_timer.as_mut().reset((Instant::now() + next_interval).into());
                }
            }
        }
    }

    async fn handle_network_event(&mut self, event: NetworkEvent) {
        match event {
            NetworkEvent::DataReceived {
                origin,
                topic,
                data,
            } => {
                self.handle_gossip(origin, topic, data);
            }
            NetworkEvent::RetrievalRequested {
                request,
                channel_id,
            } => {
                self.handle_retrieval_request(request, channel_id).await;
            }
            NetworkEvent::Shutdown => {
                info!("Shutdown signal received. Halting Stronghold Engine.");
            }
            _ => {}
        }
    }

    async fn handle_retrieval_request(&mut self, request: VolleyRequest, channel_id: String) {
        let volley_id = request.volley_id;
        let author_did = request.locator.author.clone();

        info!(
            target: "phalanx::egress",
            %volley_id,
            %author_did,
            "Processing mesh retrieval request"
        );

        let guardian = self.storage.read().await;

        let response = match guardian.get_active_volley_shards(&author_did) {
            Some(data) => {
                let filtered: Vec<WitnessEnvelope> = data
                    .values()
                    .filter(|e| e.evidence.volley_id() == &volley_id)
                    .cloned()
                    .collect();

                if filtered.is_empty() {
                    warn!(%volley_id, "Target volley found in index but contains no artifacts");
                    VolleyResponse::NotFound
                } else {
                    info!(%volley_id, count = filtered.len(), "Serving evidence unit to peer");
                    VolleyResponse::Success(filtered)
                }
            }
            None => {
                debug!(%author_did, "No records found for requested author");
                VolleyResponse::NotFound
            }
        };

        // Note: NetworkTransport must implement `send_response` to fulfill this request.
        let _ = self.network.send_response(&channel_id, response).await;
    }

    fn handle_gossip(&mut self, origin: NetworkId, topic: MeshTopic, data: Vec<u8>) {
        if topic.as_str() == self.config.network.control_topic {
            if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&data).gate(
                "ctrl_parse_fail",
                &origin,
                "Malformed heartbeat",
            ) {
                self.health_tracker.register_activity(msg);
            }
            return;
        }

        let chunk = match postcard::from_bytes::<ShardChunk>(&data).gate(
            "data_parse_fail",
            &origin,
            "Malformed data chunk",
        ) {
            Ok(c) => c,
            Err(_) => return,
        };

        if let Err(err) = self.chunk_tx.try_send((chunk, topic, origin)) {
            tracing::error!(
                error = %err,
                "StorageActor channel is full or closed. Data payload dropped."
            );
        }
    }

    async fn pulse_vitality(&mut self) -> Duration {
        let active_storage_tasks = self.storage_load.load(Ordering::Relaxed) as f32;
        let max_capacity = self.config.storage.max_peers as f32;
        let load = UnitInterval::new(active_storage_tasks / max_capacity);

        let vitality = VitalityRate::calculate(&self.physics, PowerState::Normal, load);
        let interval = vitality.as_duration();
        let sender_id = self.identity.to_network_id();

        let heartbeat_msg = ControlMessage {
            sender: sender_id,
            load_factor: load.as_f32(),
            storage_remaining_mb: 10240,
            heartbeat_ms: vitality.as_u64(),
            is_leaf: self.power_state == PowerState::Leaf,
        };

        if let Ok(data) = postcard::to_stdvec(&heartbeat_msg).gate(
            "heartbeat_enc_fail",
            &sender_id,
            "Failed to encode heartbeat",
        ) {
            let topic = &self.config.network.control_topic;
            let _ = self.network.publish(topic, data).await;
        }

        interval
    }
}

// =========================================================================
// STORAGE ACTOR
// =========================================================================

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

        let mut maintenance_timer = tokio::time::interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                Some((chunk, topic, peer_id)) = self.chunk_rx.recv() => {
                    let envelope_opt = self.reassembler.ingest_chunk(
                        chunk,
                        &mut self.journal,
                        &topic,
                        &self.config,
                        &self.identity,
                        peer_id,
                    ).await;

                    match envelope_opt {
                        Ok(Some(envelope)) => {
                            let mut guardian_guard = self.storage.write().await;
                            if let Err(err) = guardian_guard.ingest_envelope(envelope) {
                                tracing::error!(error = %err, "Vault rejected envelope");
                            }
                        }
                        Ok(None) => {},
                        Err(err) => {
                            tracing::warn!(error = %err, "Reassembler rejected data chunk");
                        }
                    }

                    let volleys_count = self.storage.read().await.active_volleys.len();
                    self.active_tasks_metric.store(
                        volleys_count,
                        Ordering::Relaxed
                    );
                }

                _ = maintenance_timer.tick() => {
                    if let Err(err) = self.snapshot_state().await {
                        tracing::error!(error = %err, "Freeze Protocol failed.");
                    }
                }
            }
        }
    }

    pub async fn restore_state(&mut self) -> Result<(), ShardError> {
        let recovered_envelopes = self
            .reassembler
            .recover_from_journal(
                &mut self.journal,
                &self.config,
                &self.identity,
                self.local_peer_id,
            )
            .await?;

        let mut guardian_guard = self.storage.write().await;
        for envelope in recovered_envelopes {
            let _ = guardian_guard.ingest_envelope(envelope);
        }

        info!("Crucible WAL replay complete.");
        Ok(())
    }

    pub async fn snapshot_state(&mut self) -> Result<(), ShardError> {
        let is_idle =
            self.reassembler.video_buffers.is_empty() && self.reassembler.audio_buffers.is_empty();

        if is_idle {
            self.journal.clear().await?;
            tracing::debug!("Crucible state frozen and WAL compacted.");
        }

        Ok(())
    }
}

// =========================================================================
// ENTRYPOINT
// =========================================================================

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    use libp2p::gossipsub;
    use phalanx_core::transport::libp2p_adapter::Libp2pAdapter;
    use phalanx_core::transport::swarm::{get_storage_key, load_swarm_key, setup_phalanx_swarm};

    let _guard = telemetry::init_observability();
    info!("Initializing PHALANX STRONGHOLD...");

    let config = PhalanxConfig::load("phalanx.toml")?;
    let (identity, _) = PhalanxIdentity::generate().map_err(|e| {
        tracing::error!(error = %e, "Engine boot aborted: Identity failure");
        e
    })?;

    let physics = PhalanxPhysics::default_wan();
    let local_peer_id = identity.to_network_id();

    let psk_path = Path::new("swarm.key");
    let psk = load_swarm_key(psk_path);

    // 1. Production Network Adapter Setup
    let libp2p_key = identity.to_libp2p_keypair();
    let mut swarm = setup_phalanx_swarm(libp2p_key, &config, &physics, psk)?;

    let storage_key = get_storage_key();
    swarm
        .behaviour_mut()
        .kademlia
        .start_providing(storage_key)?;

    let gossip = &mut swarm.behaviour_mut().gossipsub;
    gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.video_topic))?;
    gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.audio_topic))?;
    gossip.subscribe(&gossipsub::IdentTopic::new(&config.network.control_topic))?;

    let port = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "4001".to_string());
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{port}").parse()?)?;

    if let Some(query_id) = swarm.behaviour_mut().announce_stronghold(&local_peer_id) {
        info!(?query_id, "Stronghold role successfully announced to DHT.");
    }

    let network_adapter = Libp2pAdapter::new(swarm);
    let journal = FileJournal::new("crucible_wal.bin").await?;

    // 2. Engine Initialization
    let mut engine =
        StrongholdEngine::new(config, identity, physics, network_adapter, journal).await?;
    engine.run().await
}
