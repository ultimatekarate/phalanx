// --- crates/phalanx-node/src/actors/meshsentinel.rs ---
use crate::actors::egress::{EgressActor, EgressCommand};
use crate::actors::ingestion::{IngestionActor, IngestionCommand};
use crate::actors::media_egress::MediaEgressActor;
use crate::actors::playback::PlaybackCoordinator;
use crate::actors::retrieval::{RetrievalActor, RetrievalCommand};

use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::TrustActor;
use crate::clock::TrustedClock;
use crate::config::NodeConfig;

use crate::vitals::{HealthTracker, SystemGovernor};
use crate::Guardian;
use crate::{trust::TrustRegistry, StorageActor};

use phalanx_forensics::policy::{IngressGovernor, TrafficGovernor};
use phalanx_forensics::prelude::*;
use phalanx_proto::prelude::*;
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::{EgressPort, IngressPort};
use std::sync::Arc;

use tokio::sync::mpsc;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::StorageSequence;
use std::error::Error;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration};

pub struct SentinelDependencies<I: IngressPort, E: EgressPort, J: TransientJournal> {
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub ingress: I,
    pub egress: E,
    pub journal: J,
    pub trust_registry: TrustRegistry,
    pub system_governor: Arc<SystemGovernor>,
}

pub struct MeshSentinel<I: IngressPort> {
    // Core router dependencies
    pub config: Arc<NodeConfig>,
    pub identity: Arc<PhalanxIdentity>,
    pub ingress: I,

    // For processing inbound control messages
    pub health_tracker: HealthTracker,

    // For the playback factory method
    pub storage_tx: mpsc::Sender<StorageCommand>,
    pub network_key: SymmetricKey,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,

    // Actor dispatch channels
    pub ingestion_tx: mpsc::Sender<IngestionCommand>,
    pub retrieval_tx: mpsc::Sender<RetrievalCommand>,
    pub egress_tx: mpsc::Sender<EgressCommand>,

    // Keep a reference to the storage task to ensure it's not dropped.
    pub storage_task: JoinHandle<()>,
}

impl<I: IngressPort> MeshSentinel<I> {
    pub async fn new<E, J>(mut deps: SentinelDependencies<I, E, J>) -> Result<Self, Box<dyn Error>>
    where
        E: EgressPort + 'static,
        J: TransientJournal + Send + 'static,
    {
        let local_did = deps.identity.did.clone();
        let local_network_id = deps.identity.to_network_id();
        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&deps.config.storage.vault_path, &deps.config, local_did);
        let phys_capacity = deps.system_governor.config.pipeline_capacity();

        let (_video_tx_unused, video_rx) = mpsc::channel(deps.config.storage.max_video_buffer);
        let (_audio_tx_unused, audio_rx) = mpsc::channel(deps.config.storage.max_audio_buffer);

        let (storage_tx, storage_rx) = mpsc::channel(phys_capacity);
        let (ingestion_tx, ingestion_rx) = mpsc::channel(phys_capacity);
        let ingress_governor = IngressGovernor::new(phys_capacity);
        let (egress_tx, egress_rx) = mpsc::channel(100);
        let (retrieval_tx, retrieval_rx) = mpsc::channel(100);
        let (trust_tx, trust_rx) = mpsc::channel(100);
        let (discovery_tx, _discovery_rx) = mpsc::channel(100);

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

        let arc_identity = Arc::new(deps.identity.clone());
        let raw_clock = TrustedClock::new();
        let clock_handle = Arc::new(raw_clock);

        // Trust Manager Actor
        let reputation_projection = deps.trust_registry.projection_handle();
        let trust_registry = deps.trust_registry;
        let trust_actor = TrustActor::new(trust_registry, trust_rx);
        tokio::spawn(trust_actor.run());

        let retrieval_actor = RetrievalActor::new(
            arc_identity.clone(),
            clock_handle.clone(),
            deps.system_governor.clone(),
            storage_tx.clone(),
            egress_tx.clone(),
            reputation_projection.clone(),
            trust_tx.clone(), // Pass the sender to the retrieval actor
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
            reputation_projection.clone(),
            storage_tx.clone(),
            egress_tx.clone(),
            trust_tx,
            deps.system_governor.clone(),
            ingestion_rx,
        );
        tokio::spawn(ingestion_actor.run());

        // Media Egress Actor instantiation
        let media_actor = MediaEgressActor::new(
            deps.egress.clone(),
            arc_identity.clone(),
            video_rx,
            audio_rx,
            deps.config.network.video_topic.clone(),
            deps.config.network.audio_topic.clone(),
            local_network_id.clone(),
        );

        tokio::spawn(media_actor.run());

        let config_arc = Arc::new(deps.config);

        Ok(Self {
            config: config_arc,
            identity: arc_identity,
            ingress: deps.ingress,
            health_tracker: HealthTracker::new(),
            network_key: SymmetricKey([0x42; 32]),
            storage_task,
            storage_tx,
            ingestion_tx,
            retrieval_tx,
            egress_tx,
            discovery_tx,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            tokio::select! {
                Some(event) = self.ingress.next_event() => {
                    match event {
                        NetworkEvent::DataReceived { origin, topic, data } => {
                            if topic.as_str() == self.config.network.control_topic.as_str() {
                                if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&data) {
                                    self.health_tracker.register_activity(msg);
                                }
                            } else {
                                // Apply backpressure. If the ingestion channel is full, drop the chunk.
                                if self.ingestion_tx.try_send(IngestionCommand::ProcessChunk {
                                    peer_id: origin,
                                    data,
                                    topic,
                                }).is_err() {
                                    tracing::warn!("Ingestion channel full, dropping chunk.");
                                }
                            }
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
            }
        }
        Ok(())
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
}
