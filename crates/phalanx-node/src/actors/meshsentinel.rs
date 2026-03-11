// --- crates/phalanx-node/src/actors/meshsentinel.rs ---
use crate::actors::egress::{EgressActor, EgressCommand};
use crate::actors::ingestion::{IngestionActor, IngestionCommand};
use crate::actors::media_egress::MediaEgressActor;
use crate::actors::playback::PlaybackCoordinator;
use crate::actors::retrieval::{RetrievalActor, RetrievalCommand, TrustCommand};
use crate::actors::storage::NoOpJournal;
use crate::actors::storage::StorageCommand;
use crate::actors::trust_manager::TrustManager;
use crate::clock::TrustedClock;
use crate::config::NodeConfig;
use crate::identity::PhalanxNodeIdentityExt;
use crate::trust::ReputationProjection;
use crate::vitals::{
    FinalizationScale, HealthTracker, Homeostasis, IngestionScale, SystemGovernor,
};
use crate::Guardian;
use crate::{trust::TrustRegistry, StorageActor};
use phalanx_forensics::judge::IntegrityGate;
use phalanx_forensics::policy::{EgressGovernor, IngressGovernor, TrafficGovernor};
use phalanx_forensics::prelude::*;
use phalanx_proto::prelude::*;
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::{EgressPort, IngressPort};
use std::sync::Arc;

use tokio::sync::mpsc;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::time::CausalitySession;
use phalanx_proto::types::NodeMode;
use phalanx_proto::VolleyRequest;
use std::error::Error;
use tokio::task::JoinHandle;
use tokio::time::{interval, timeout, Duration};

/// A lightweight request broadcast to the mesh when a playback gap is detected.
#[derive(serde::Serialize, serde::Deserialize)]
struct ShardDiscoveryRequest {
    volley_id: VolleyId,
    sequence_id: StorageSequence,
}

pub struct SentinelDependencies<I: IngressPort, E: EgressPort, J: TransientJournal> {
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub ingress: I,
    pub egress: E,
    pub journal: J,
    pub trust_registry: Arc<tokio::sync::RwLock<TrustRegistry>>,
    pub reputation_cache: ReputationProjection,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    pub system_governor: Arc<SystemGovernor>,
}

pub struct MeshSentinel<I: IngressPort, E: EgressPort, J: TransientJournal> {
    pub trust_registry: Arc<tokio::sync::RwLock<TrustRegistry>>,
    pub reputation_cache: ReputationProjection,
    pub health_tracker: HealthTracker,
    pub mode: NodeMode,
    pub config: NodeConfig,
    pub identity: Arc<PhalanxIdentity>,
    pub clock: Arc<TrustedClock>,
    pub ingress: I,
    pub egress: E,
    pub seq_counter: u64,
    pub network_key: SymmetricKey,
    pub storage_task: JoinHandle<()>,
    pub storage_tx: mpsc::Sender<StorageCommand>,
    pub ingestion_tx: mpsc::Sender<IngestionCommand>,
    pub retrieval_tx: mpsc::Sender<RetrievalCommand>,
    pub egress_tx: mpsc::Sender<EgressCommand>,
    pub _journal_phantom: std::marker::PhantomData<J>,
    pub session: CausalitySession,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
    pub system_governor: Arc<SystemGovernor>,
}

impl<I: IngressPort, E: EgressPort + 'static, J: TransientJournal + Send + 'static>
    MeshSentinel<I, E, J>
{
    pub async fn new(mut deps: SentinelDependencies<I, E, J>) -> Result<Self, Box<dyn Error>> {
        let local_did = deps.identity.did.clone();
        let local_network_id = deps.identity.to_network_id();
        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&deps.config.storage.vault_path, &deps.config, local_did);
        let phys_capacity = deps.system_governor.config.pipeline_capacity();

        let (_video_tx_unused, video_rx) = mpsc::channel(deps.config.storage.max_video_buffer);
        let (_audio_tx_unused, audio_rx) = mpsc::channel(deps.config.storage.max_audio_buffer);

        // Vault Interface
        let (storage_tx, storage_rx) = mpsc::channel(phys_capacity);
        let ingress_governor = IngressGovernor::new(phys_capacity);
        let (egress_tx, egress_rx) = mpsc::channel(100);
        let (ingestion_tx, ingestion_rx) = mpsc::channel(phys_capacity);

        // Stateless Recovery: Pull salvaged egress from the journal
        let salvaged_queue = deps
            .journal
            .read_all_pending_egress()
            .await
            .unwrap_or_default();

        if !salvaged_queue.is_empty() {
            tracing::info!(
                count = salvaged_queue.len(),
                "Engine Bootstrap: Recovered salvaged egress records"
            );
        }

        // Vault instantiation (Pure IO configuration)
        let storage_actor = StorageActor {
            reassembler,
            guardian,
            journal: deps.journal,
            config: deps.config.clone(),
            identity: deps.identity.clone(),
            current_tolerance: Duration::from_millis(1000),
        };

        let storage_task = tokio::spawn(async move {
            storage_actor.run(storage_rx).await;
        });

        // Egress Actor instantiation
        let egress_actor = EgressActor::new(deps.egress.clone(), egress_rx, salvaged_queue);

        tokio::spawn(async move {
            egress_actor.run().await;
        });

        // Trust Manager Actor
        let (trust_tx, trust_rx) = mpsc::channel(100);
        let trust_manager = TrustManager::new(deps.trust_registry.clone(), trust_rx);
        tokio::spawn(trust_manager.run());

        // Retrieval Actor
        let (retrieval_tx, retrieval_rx) = mpsc::channel(100);
        let retrieval_actor = RetrievalActor::new(
            arc_identity.clone(),
            clock_handle.clone(),
            deps.system_governor.clone(),
            storage_tx.clone(),
            egress_tx.clone(),
            deps.trust_registry.clone(),
            trust_tx,
            retrieval_rx,
        );
        tokio::spawn(retrieval_actor.run());

        // Ingestion Actor
        let ingestion_actor = IngestionActor::new(
            deps.config.clone(),
            arc_identity.clone(),
            clock_handle.clone(),
            TrafficGovernor::new(),
            ingress_governor,
            deps.trust_registry.clone(),
            deps.reputation_cache.clone(),
            storage_tx.clone(),
            egress_tx.clone(),
            trust_tx.clone(),
            deps.system_governor.clone(),
            ingestion_rx,
        );
        tokio::spawn(ingestion_actor.run());

        // Media Egress Actor instantiation
        let media_actor = MediaEgressActor::new(
            deps.egress.clone(),
            video_rx,
            audio_rx,
            deps.config.network.video_topic.clone(),
            deps.config.network.audio_topic.clone(),
            local_network_id.clone(),
        );

        tokio::spawn(media_actor.run());

        let arc_identity = Arc::new(deps.identity.clone());
        let session = CausalitySession::new(arc_identity.clone(), local_network_id.clone());
        let raw_clock = TrustedClock::new();
        let clock_handle = Arc::new(raw_clock);

        Ok(Self {
            config: deps.config,
            identity: arc_identity,
            clock: clock_handle,
            ingress: deps.ingress,
            egress: deps.egress,
            trust_registry: deps.trust_registry,
            reputation_cache: deps.reputation_cache,
            health_tracker: HealthTracker::new(),
            mode: NodeMode::Standard,
            seq_counter: 0,
            network_key: SymmetricKey([0x42; 32]),
            storage_task,
            storage_tx,
            ingestion_tx,
            retrieval_tx,
            egress_tx,
            _journal_phantom: std::marker::PhantomData,
            session,
            discovery_rx: deps.discovery_rx,
            discovery_tx: deps.discovery_tx,
            system_governor: deps.system_governor,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_network_id = self.identity.to_network_id();
        let mut heartbeat_tick = interval(Duration::from_secs(1));

        let base_throttle = 5;
        loop {
            let scale: IngestionScale = self.system_governor.ingestion_scaler();

            tracing::error!(
                target: "siege_debug",
                scale = scale.0,
                "Loop tick: Checking network guard (Requires scale > 0.01)"
            );

            if scale.0 < 1.0 {
                let delay = scale.as_throttle_delay(base_throttle);
                tracing::trace!(target: "phalanx::metabolism", "Throttling loop for {}ms", delay.as_millis());
                tokio::time::sleep(delay).await;
            }

            tokio::select! {
                _ = heartbeat_tick.tick() => {
                    let load = 1.0 - self.system_governor.ingestion_scaler().0;
                    let storage = self.check_available_storage();

                    // The Sentinel asks the Tracker: "Is my metabolic drift significant?"
                    if self.health_tracker.should_broadcast_self(load as f32, storage) {
                        self.broadcast_metabolic_pulse().await?;
                    }
                }

                Some(event) = self.ingress.next_event(), if scale.0 > 0.01 => {
                    match event {
                        NetworkEvent::DataReceived { origin, topic, data } => {
                            let _ = self.ingestion_tx.try_send(IngestionCommand::ProcessChunk {
                                peer_id: origin,
                                data,
                                topic,
                            });
                        }
                        NetworkEvent::VolleyRequested { origin, request, channel_id } => {
                            let _ = self.retrieval_tx.send(
                                RetrievalCommand::SecureRetrieval {
                                    origin,
                                    request,
                                    channel_id,
                                }
                            ).await;
                        }
                        NetworkEvent::Shutdown => {
                            tracing::info!("Engine: Initiating emergency salvage");
                            let (tx, rx) = tokio::sync::oneshot::channel();
                            if self.egress_tx.send(EgressCommand::DrainForSalvage { reply_to: tx }).await.is_ok() {
                                if let Ok(payload) = timeout(Duration::from_millis(500), rx).await {
                                    let _ = self.storage_tx.send(StorageCommand::EmergencySalvage(payload.unwrap_or_default())).await;
                                }
                            }
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            break;
                        }
                        _ => {}
                    }
                }
                Some((volley_id, gap_sequence)) = self.discovery_rx.recv() => {
                    self.handle_gap_discovery(volley_id, gap_sequence).await;
                }
            }
        }
        Ok(())
    }

    async fn broadcast_metabolic_pulse(&mut self) -> Result<(), Box<dyn Error>> {
        // Capture the current "Breath" of the node
        let scale = self.system_governor.ingestion_scaler(); //

        // Map scale (1.0 = Empty) to load (0.0 = Busy)
        // If scale is 0.2 (80% throttled), load_factor is 0.8.
        let metabolic_load: f64 = 1.0 - scale.0;

        let message = ControlMessage {
            sender: self.identity.to_network_id(),
            load_factor: metabolic_load as f32,
            storage_remaining_mb: 10_000,
            heartbeat_ms: self.clock.now()?.0,
            is_leaf: self.mode == NodeMode::Leaf,
        };

        // Publish to the mesh control topic
        let topic = &self.config.network.control_topic;
        let data = postcard::to_allocvec(&message)?;

        self.egress.publish(topic, data).await?;

        Ok(())
    }

    fn check_available_storage(&self) -> u64 {
        // 1. Convert usize to u64 explicitly.
        // 'as u64' is safe here because usize is at most 64-bit on modern systems.
        let max_bytes = self.config.storage.max_storage_bytes.as_u64();

        // 2. TODO: In a production 'Mighty' node, you'd query the disk or the Guardian
        // for the actual used bytes. For now, we'll assume the vault is empty.
        let used_bytes = 0u64;

        // 3. Subtract and convert to MB (1024 * 1024 bytes)
        // saturating_sub ensures we never underflow if the disk is over-full
        max_bytes.saturating_sub(used_bytes) / (1024 * 1024)
    }

    pub async fn handle_gap_discovery(
        &mut self,
        volley_id: VolleyId,
        gap_sequence: StorageSequence,
    ) {
        tracing::info!(
            "Playback gap detected for Volley {:?} at sequence {}. Initiating mesh discovery.",
            volley_id,
            gap_sequence.0
        );

        let topic = MeshTopic::new("phalanx/discovery/1.0.0");
        let request = ShardDiscoveryRequest {
            volley_id,
            sequence_id: gap_sequence,
        };

        match postcard::to_allocvec(&request) {
            Ok(data) => {
                if let Err(e) = self.egress.publish(&topic, data).await {
                    tracing::error!("Failed to broadcast discovery request: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to serialize discovery request: {}", e),
        }
    }

    pub fn spawn_playback<S: PlaybackSink + 'static>(
        &self,
        volley_id: VolleyId,
        sink: S,
    ) -> tokio::task::JoinHandle<()> {
        let mut coordinator = PlaybackCoordinator::new(
            self.storage_tx.clone(),
            Some(self.network_key.clone()),
            sink,
            self.discovery_tx.clone(),
        );

        tokio::spawn(async move {
            if let Err(e) = coordinator.run(volley_id).await {
                tracing::error!("Playback Coordinator terminated with error: {:?}", e);
            }
        })
    }

    pub async fn dispatch_resilient_response(
        &mut self,
        channel_id: String,
        response: VolleyResponse,
    ) {
        let _ = self
            .egress_tx
            .send(EgressCommand::Dispatch {
                channel_id,
                response,
            })
            .await;
    }
}

// Ephemeral Bootstrap
impl<I: IngressPort, E: EgressPort + 'static> MeshSentinel<I, E, NoOpJournal> {
    pub async fn new_at_path(path: &str, ingress: I, egress: E) -> Result<Self, Box<dyn Error>> {
        let mut config = NodeConfig::default();
        config.storage.vault_path = path.to_string();
        let identity = PhalanxIdentity::new_ephemeral();
        let trust_registry_inner = TrustRegistry::build(&config).await;
        let trust_registry = Arc::new(tokio::sync::RwLock::new(trust_registry_inner));
        let reputation_cache = trust_registry.read().await.projection_handle();
        let (discovery_tx, discovery_rx) = mpsc::channel(100);

        let deps = SentinelDependencies {
            config,
            identity,
            ingress,
            egress,
            journal: NoOpJournal,
            trust_registry,
            reputation_cache,
            discovery_rx,
            discovery_tx,
            system_governor: Arc::new(SystemGovernor::new()),
        };

        Self::new(deps).await
    }
}
