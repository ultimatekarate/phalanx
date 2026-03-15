// --- crates/phalanx-node/src/actors/meshsentinel.rs ---
use crate::actors::egress::{EgressActor, EgressCommand};
use crate::actors::ingestion::{IngestionActor, IngestionCommand};
use crate::actors::media_egress::{MediaEgressActor, MediaEgressConfig};
use crate::actors::playback::PlaybackCoordinator;
use crate::actors::retrieval::{RetrievalActor, RetrievalCommand};

use crate::actors::storage::StorageCommand;
use crate::actors::trust_actor::{TrustActor, TrustCommand};
use crate::clock::TrustedClock;
use crate::config::NodeConfig;

use crate::vitals::{HealthTracker, Homeostasis, LifecycleEvent, SystemGovernor};
use crate::Guardian;
use crate::{trust::TrustRegistry, StorageActor};

use phalanx_forensics::policy::{IngressGovernor, TrafficGovernor};
use phalanx_forensics::prelude::*;
use phalanx_proto::prelude::*;
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::{EgressPort, IngressPort, LocalMeshPort};
use std::sync::Arc;

use tokio::sync::mpsc;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, StorageSequence, VideoShard};
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
    pub vault_key: SymmetricKey,
    /// Optional local mesh transport (BLE, WiFi Direct).
    /// Default: `None` (desktop/non-BLE platforms).
    /// When `Some`, MeshSentinel polls for local mesh events alongside network ingress.
    pub local_mesh: Option<Box<dyn LocalMeshPort>>,
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
    pub network_key: Arc<SymmetricKey>,
    pub discovery_tx: mpsc::Sender<(RecordingId, StorageSequence)>,

    // Homeostasis feedback
    pub system_governor: Arc<SystemGovernor>,

    // Actor dispatch channels
    pub ingestion_tx: mpsc::Sender<IngestionCommand>,
    pub retrieval_tx: mpsc::Sender<RetrievalCommand>,
    pub egress_tx: mpsc::Sender<EgressCommand>,

    // Keep a reference to the storage task to ensure it's not dropped.
    pub storage_task: JoinHandle<()>,

    // DHT: Receives notifications when StorageActor persists a shard.
    // Triggers `EgressCommand::AnnounceRecording` to announce the recording on the DHT.
    commit_notify_rx: mpsc::Receiver<RecordingId>,

    // DHT: Receives (recording_id, sequence_id) from PlaybackCoordinator when it
    // discovers missing shards. Triggers `EgressCommand::FindProviders`.
    discovery_rx: mpsc::Receiver<(RecordingId, StorageSequence)>,

    // Optional local mesh transport (BLE, WiFi Direct).
    // When available, the select! loop polls for local mesh events.
    local_mesh: Option<Box<dyn LocalMeshPort>>,

    // Lifecycle event receiver for mobile foreground/background transitions.
    // When a `Foregrounded` event arrives, immediately recalculate PowerState.
    // Desktop: always `None` (no foreground/background concept).
    lifecycle_rx: Option<tokio::sync::mpsc::Receiver<LifecycleEvent>>,

    // DHT: Provider discovery forwarding to the active PlaybackCoordinator.
    // Replaced with a fresh channel on each spawn_playback() call.
    providers_tx: mpsc::Sender<(RecordingId, Vec<NetworkId>)>,

    // Shield Wall: Trust channel for dispatching spectral anomaly offenses.
    pub trust_tx: mpsc::Sender<TrustCommand>,

    // Media capture channels — exposed for FFI frame injection.
    // Desktop sentinel ignores these; the FFI handle clones them for phalanx_push_video_frame().
    pub video_tx: mpsc::Sender<VideoShard>,
    pub audio_tx: mpsc::Sender<AudioShard>,
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
        let raw_clock = TrustedClock::new();
        let clock_handle = Arc::new(raw_clock);
        let guardian = Guardian::new(
            &deps.config.storage.vault_path,
            &deps.config,
            local_did,
            clock_handle.clone(),
            deps.vault_key.clone(),
        );
        let phys_capacity = deps.system_governor.config.pipeline_capacity();

        let (video_tx, video_rx) = mpsc::channel(deps.config.storage.max_video_buffer);
        let (audio_tx, audio_rx) = mpsc::channel(deps.config.storage.max_audio_buffer);

        let (storage_tx, storage_rx) = mpsc::channel(phys_capacity);
        let (ingestion_tx, ingestion_rx) = mpsc::channel(phys_capacity);
        let ingress_governor = IngressGovernor::new(phys_capacity);
        let (egress_tx, egress_rx) = mpsc::channel(100);
        let (retrieval_tx, retrieval_rx) = mpsc::channel(100);
        let (trust_tx, trust_rx) = mpsc::channel(100);
        let (discovery_tx, discovery_rx) = mpsc::channel(100);
        let (commit_notify_tx, commit_notify_rx) = mpsc::channel(100);

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
            system_governor: deps.system_governor.clone(),
            commit_notify_tx: Some(commit_notify_tx),
        };

        let storage_task = tokio::spawn(async move {
            storage_actor.run(storage_rx).await;
        });

        // Egress Actor instantiation
        let egress_actor = EgressActor::new(
            deps.egress.clone(),
            egress_rx,
            salvaged_queue,
            deps.system_governor.clone(),
        );

        tokio::spawn(async move {
            egress_actor.run().await;
        });

        let arc_identity = Arc::new(deps.identity.clone());

        // Trust Manager Actor
        let reputation_projection = deps.trust_registry.projection_handle();
        let trust_registry = deps.trust_registry;
        let trust_actor = TrustActor::new(trust_registry, trust_rx);
        tokio::spawn(trust_actor.run());

        let network_key = Arc::new(SymmetricKey([0x42; 32]));

        let retrieval_actor = RetrievalActor::new(
            arc_identity.clone(),
            clock_handle.clone(),
            deps.system_governor.clone(),
            storage_tx.clone(),
            egress_tx.clone(),
            reputation_projection.clone(),
            trust_tx.clone(), // Pass the sender to the retrieval actor
            network_key.clone(),
            retrieval_rx,
        );
        tokio::spawn(retrieval_actor.run());

        // Shield Wall: retain a trust_tx handle for spectral anomaly dispatch.
        let sentinel_trust_tx = trust_tx.clone();

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

        // Media Egress Actor instantiation — WAL-backed outbound queue for retry
        // with integral feedback: outbound queue pressure → w_integral → FPS self-regulation.
        let outbound_wal_dir =
            std::path::PathBuf::from(&deps.config.storage.vault_path).join("outbound_wal");
        let media_actor = MediaEgressActor::new(
            deps.egress.clone(),
            arc_identity.clone(),
            local_network_id.clone(),
            MediaEgressConfig {
                video_rx,
                audio_rx,
                video_topic: deps.config.network.video_topic.clone(),
                audio_topic: deps.config.network.audio_topic.clone(),
                symbol_size: deps.config.network.symbol_size,
                repair_ratio: deps.config.network.repair_ratio,
                wal_dir: outbound_wal_dir,
                system_governor: deps.system_governor.clone(),
                max_storage_bytes: deps.config.storage.max_storage_bytes.as_u64(),
            },
        )
        .await
        .expect("Failed to initialize MediaEgressActor outbound queue");

        tokio::spawn(media_actor.run());

        // Adaptive vitals polling — interval scales with PowerState.
        // Normal: 5s, Conserving: 15s, Leaf: 30s, Dormant: 60s.
        // Uses dynamic sleep instead of fixed interval to adapt each cycle.
        let vitals_governor = deps.system_governor.clone();
        tokio::spawn(async move {
            loop {
                let interval = vitals_governor.vitals_polling_interval();
                tokio::time::sleep(interval).await;
                vitals_governor.update_vitals();
            }
        });

        let config_arc = Arc::new(deps.config);

        if let Some(ref mesh) = deps.local_mesh {
            if mesh.is_available() {
                tracing::info!("Local mesh transport is AVAILABLE");
            } else {
                tracing::debug!("Local mesh transport provided but not available");
            }
        }

        // Extract lifecycle event receiver from hardware probe.
        // Mobile implementations push OS lifecycle callbacks into this channel.
        // Desktop (SysfsProbe) returns None.
        let lifecycle_rx = deps.system_governor.probe().lifecycle_events();

        // Placeholder providers_tx — replaced with a fresh channel on each spawn_playback() call.
        let (providers_tx, _) = mpsc::channel(1);

        Ok(Self {
            config: config_arc,
            identity: arc_identity,
            ingress: deps.ingress,
            health_tracker: HealthTracker::new(),
            system_governor: deps.system_governor.clone(),
            network_key: network_key.clone(),
            storage_task,
            storage_tx,
            ingestion_tx,
            retrieval_tx,
            egress_tx,
            discovery_tx,
            commit_notify_rx,
            discovery_rx,
            local_mesh: deps.local_mesh,
            lifecycle_rx,
            providers_tx,
            trust_tx: sentinel_trust_tx,
            video_tx,
            audio_tx,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            let should_shutdown = tokio::select! {
                Some(event) = self.ingress.next_event() => {
                    self.handle_network_event(event).await
                }

                // Poll local mesh transport for events (BLE, WiFi Direct).
                // When the local mesh is available, events are routed through the
                // same ingestion pipeline as network events.
                Some(local_event) = async {
                    match self.local_mesh.as_mut() {
                        Some(mesh) if mesh.is_available() => mesh.next_local_event().await,
                        _ => std::future::pending().await,
                    }
                } => {
                    tracing::debug!(event = "local_mesh_event", "Received event from local transport");
                    self.handle_network_event(local_event).await
                }

                // DHT: StorageActor persisted a shard — announce as provider.
                Some(recording_id) = self.commit_notify_rx.recv() => {
                    let _ = self.egress_tx
                        .send(EgressCommand::AnnounceRecording(recording_id))
                        .await;
                    false
                }

                // DHT: PlaybackCoordinator needs a missing shard — find providers.
                Some((recording_id, _sequence_id)) = self.discovery_rx.recv() => {
                    let _ = self.egress_tx
                        .send(EgressCommand::FindProviders(recording_id))
                        .await;
                    false
                }

                // Lifecycle events from mobile OS (foreground/background).
                // When the app transitions to foreground, immediately recalculate
                // PowerState and update vitals — don't wait for the polling tick.
                // This ensures capture resumes within milliseconds of foregrounding.
                // Desktop: lifecycle_rx is None, so this arm blocks via pending().
                Some(lifecycle_event) = async {
                    match self.lifecycle_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    match lifecycle_event {
                        LifecycleEvent::Foregrounded => {
                            tracing::info!(
                                event = "lifecycle_foregrounded",
                                "App foregrounded — immediate PowerState recalculation"
                            );
                            self.system_governor.update_vitals();
                        }
                        LifecycleEvent::Backgrounded => {
                            tracing::info!(
                                event = "lifecycle_backgrounded",
                                "App backgrounded — PowerState will transition to Dormant"
                            );
                            self.system_governor.update_vitals();
                        }
                    }
                    false // Never shutdown from lifecycle events
                }
            };

            if should_shutdown {
                break;
            }
        }
        Ok(())
    }

    /// Unified event handler for both network ingress and local mesh events.
    /// Returns `true` if the engine should shut down.
    async fn handle_network_event(&mut self, event: NetworkEvent) -> bool {
        match event {
            NetworkEvent::DataReceived {
                origin,
                topic,
                data,
            } => {
                // P5 FIX: Reject oversized messages before any processing.
                // This prevents memory amplification from messages that exceed
                // the configured chunk size, protecting the ingestion pipeline.
                if data.len() > self.config.network.max_chunk_size_bytes * 2 {
                    tracing::warn!(
                        size = data.len(),
                        limit = self.config.network.max_chunk_size_bytes * 2,
                        peer = %origin,
                        "P5: Oversized message rejected pre-queue"
                    );
                    return false;
                }

                // Record bandwidth pressure for every received message
                self.system_governor.record_bandwidth_pressure(data.len());

                if topic.as_str() == self.config.network.control_topic.as_str() {
                    if let Ok(msg) = phalanx_forensics::gate::unmarshal::<ControlMessage>(
                        &data,
                        "control_message",
                    ) {
                        let peer_id_for_spectral = msg.sender.clone();
                        self.health_tracker.register_activity(msg);

                        // Shield Wall: evaluate spectral consistency
                        if let Some(residual) =
                            self.health_tracker.spectral.evaluate(&peer_id_for_spectral)
                        {
                            if residual > self.health_tracker.spectral.anomaly_threshold {
                                // Drive peer toward decoupling via existing Volterra integral
                                self.system_governor.record_spectral_anomaly(
                                    &peer_id_for_spectral.to_string(),
                                    residual,
                                );

                                tracing::warn!(
                                    target: "phalanx::shield_wall",
                                    peer = %peer_id_for_spectral,
                                    residual = %residual,
                                    "SPECTRAL_ANOMALY_DETECTED"
                                );
                            }
                        }
                    }
                } else {
                    // Shield Wall: record data volume for spectral observation
                    self.health_tracker
                        .spectral
                        .record_data_received(origin.clone(), data.len());

                    // Bandwidth gate: reject at the edge when saturated
                    if self.system_governor.bandwidth_scaler().0 < 0.05 {
                        tracing::warn!(
                            size = data.len(),
                            peer = %origin,
                            "Bandwidth saturated, dropping chunk"
                        );
                    } else if self
                        .ingestion_tx
                        .try_send(IngestionCommand::ProcessChunk {
                            peer_id: origin,
                            data,
                            topic,
                        })
                        .is_err()
                    {
                        // Channel full — record memory pressure from the backlog
                        self.system_governor
                            .record_memory_pressure(self.config.network.max_chunk_size_bytes * 200);
                        tracing::warn!("Ingestion channel full, dropping chunk.");
                    }
                }
                false
            }

            // Record peer discovery source for connectivity detection.
            // Internet peers (Kademlia, Bootstrap) immediately mark internet as available.
            // mDNS peers increment local count. The 30s grace period in SystemGovernor
            // handles the transition to offline when only local peers remain.
            NetworkEvent::PeerDiscovered { peer, source } => {
                tracing::debug!(
                    event = "peer_discovered",
                    peer = %peer,
                    source = ?source,
                    "Peer discovered via {:?}",
                    source
                );
                self.system_governor.record_peer_discovery(source);
                // P12 FIX: Feed connection count into c_integral.
                self.system_governor.record_connection_gauge();
                false
            }

            NetworkEvent::RecordingRequested {
                origin,
                request,
                channel_id,
            } => {
                let _ = self
                    .retrieval_tx
                    .send(RetrievalCommand::SecureRetrieval {
                        origin,
                        request,
                        channel_id,
                    })
                    .await;
                false
            }

            // DHT: Providers discovered for a recording.
            // Filter out self (don't request shards from yourself), then forward to
            // PlaybackCoordinator which owns the auth context to construct retrieval requests.
            NetworkEvent::ProvidersDiscovered {
                recording_id,
                providers,
            } => {
                let local_id = self.identity.to_network_id();
                let remote_providers: Vec<_> =
                    providers.into_iter().filter(|p| *p != local_id).collect();
                if !remote_providers.is_empty() {
                    tracing::info!(
                        recording = %recording_id,
                        count = remote_providers.len(),
                        "DHT: Providers discovered for recording"
                    );
                    let _ = self.providers_tx.try_send((recording_id, remote_providers));
                }
                false
            }

            // DHT: Shards received from a peer — write each to the recording log.
            NetworkEvent::ShardResponseReceived { origin, envelopes } => {
                tracing::info!(
                    peer = %origin,
                    count = envelopes.len(),
                    "DHT: Shard response received"
                );
                for envelope in envelopes {
                    let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
                    let _ = self
                        .storage_tx
                        .send(StorageCommand::WriteShard {
                            envelope,
                            reply_to: reply_tx,
                        })
                        .await;
                }
                false
            }

            NetworkEvent::PeerDisconnected { peer } => {
                tracing::info!(
                    event = "peer_disconnected",
                    peer = %peer,
                    "Peer disconnected"
                );
                // Shield Wall: clean up spectral observation state for departed peer.
                self.health_tracker.spectral.remove_peer(&peer);
                // QUIC disconnects are always internet peers (not mDNS-local).
                self.system_governor.record_peer_departure(false);
                // P12 FIX: Update c_integral on disconnect.
                self.system_governor.record_connection_gauge();
                false
            }

            NetworkEvent::Shutdown => {
                tracing::info!("Engine: Initiating emergency salvage");
                let (tx, rx) = tokio::sync::oneshot::channel();
                if self
                    .egress_tx
                    .send(EgressCommand::DrainForSalvage { reply_to: tx })
                    .await
                    .is_ok()
                {
                    if let Ok(payload) = timeout(Duration::from_millis(500), rx).await {
                        let _ = self
                            .storage_tx
                            .send(StorageCommand::EmergencySalvage(
                                payload.unwrap_or_default(),
                            ))
                            .await;
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                true // Signal shutdown to the run loop
            }
        }
    }

    pub fn spawn_playback<S: PlaybackSink + 'static>(
        &mut self,
        recording_id: RecordingId,
        sink: S,
    ) -> tokio::task::JoinHandle<()> {
        // Fresh channel per playback session — only one active at a time.
        // Replacing providers_tx drops the old sender, signaling the previous
        // PlaybackCoordinator's providers_rx that no more data will arrive.
        let (providers_tx, providers_rx) = mpsc::channel(100);
        self.providers_tx = providers_tx;

        let mut coordinator = PlaybackCoordinator::new(
            self.storage_tx.clone(),
            self.egress_tx.clone(),
            Some((*self.network_key).clone()),
            sink,
            self.discovery_tx.clone(),
            providers_rx,
            self.identity.clone(),
        );

        tokio::spawn(async move {
            if let Err(e) = coordinator.run(recording_id).await {
                tracing::error!("Playback Coordinator terminated with error: {:?}", e);
            }
        })
    }
}
