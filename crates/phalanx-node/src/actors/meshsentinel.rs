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

use crate::trust::ReputationProjection;
use crate::vitals::canary::{CanaryMonitor, CanaryState};
use crate::vitals::{HealthTracker, Homeostasis, LifecycleEvent, SystemGovernor};
use crate::Guardian;
use crate::{trust::TrustRegistry, StorageActor};

use phalanx_forensics::eclipse::{self, EclipseProbe, MeshFingerprint};
use phalanx_forensics::policy::{IngressGovernor, TrafficGovernor};
use phalanx_forensics::prelude::*;
use phalanx_forensics::trust::{
    evaluate_reciprocity, PeerContribution, ReciprocityParams, ReciprocityVerdict,
};
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::network::{EgressPort, IngressPort, LocalMeshPort};
use phalanx_proto::prelude::*;
use phalanx_proto::storage::TransientJournal;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topology::{SubnetBucket, TransportClass};
use phalanx_proto::trust::Offense;
use phalanx_transport::identity_ext::Libp2pExt;
use std::sync::Arc;

use tokio::sync::mpsc;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, PrnuPosterior, StorageSequence, VideoShard};
use std::error::Error;
use std::sync::Mutex;
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
    /// Bayesian PRNU posterior — shared with the FFI capture path.
    /// MediaEgressActor reads this for luminance-conditioned provenance checks.
    pub prnu_posterior: Arc<Mutex<PrnuPosterior>>,
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

    // Eclipse remediation: topology-aware peer admission gate.
    topology_gate: TopologyGate,
    eclipse_probe: EclipseProbe,
    reputation: ReputationProjection,

    // E6: Peer discovery rate limiter — prevents CPU exhaustion from
    // burst PeerDiscovered floods. Resets each second.
    peer_discovery_count: u32,
    peer_discovery_window: std::time::Instant,

    /// Active recording ID, if any. Set by FFI when recording starts, cleared on stop.
    /// Used to capture ProximityWitness entries when LocalMesh peers are discovered.
    pub active_recording_id: Option<RecordingId>,
    /// Per-recording content key for the active recording (DEK for crypto-shredding).
    /// Set when recording starts (via StorageCommand::StartRecording), cleared on stop.
    pub active_recording_key: Option<[u8; 32]>,
    /// Watch channel sender for pushing per-recording content keys to MediaEgressActor.
    pub content_key_tx: tokio::sync::watch::Sender<Option<phalanx_proto::crypto::SymmetricKey>>,
    /// Proximity witnesses captured during the current recording.
    /// Flushed to the evidence pipeline when the recording ends.
    pub proximity_witnesses: Vec<phalanx_proto::corroboration::ProximityWitness>,
    /// Trusted clock for forensic timestamps.
    pub clock: Arc<TrustedClock>,

    // ── Silent Canary ──────────────────────────────────────────────────
    /// Lightweight peer identity cache: NetworkId → Did.
    /// Populated from WitnessEnvelope signatures during shard ingestion.
    /// MUST NEVER be persisted to disk — memory-only, dies with the process.
    peer_did_cache: std::collections::HashMap<NetworkId, Did>,
    /// Community-scoped dead man's switch. Monitors mesh presence of
    /// community peers during active recordings.
    pub canary: CanaryMonitor,
    /// Community IDs for canary key derivation. Snapshot taken at construction;
    /// only members who imported the community can derive the alert decryption key.
    community_ids: Vec<phalanx_proto::community::CommunityId>,

    // ── Revocation Replay ─────────────────────────────────────────────
    /// Peers we have already replayed revocation tokens to in this session.
    /// Prevents redundant gossipsub floods on peer reconnect.
    revocation_synced_peers: std::collections::HashSet<NetworkId>,

    // ── Reciprocity Floor ────────────────────────────────────────────
    /// First-seen timestamp (epoch seconds) per peer. Used to compute
    /// connection age for the reciprocity grace period.
    /// Never cleared on disconnect (prevents grace-period-reset attacks).
    /// Capped at 10,000 entries; oldest evicted on overflow.
    peer_first_seen: std::collections::HashMap<NetworkId, u64>,
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
            replay_filter: phalanx_forensics::bloom::RotatingBloomFilter::new(
                phalanx_forensics::bloom::RotatingBloomFilter::DEFAULT_CAPACITY,
            ),
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
            clock_handle.clone(),
        );

        tokio::spawn(async move {
            egress_actor.run().await;
        });

        let arc_identity = Arc::new(deps.identity.clone());

        // Trust Manager Actor
        let reputation_projection = deps.trust_registry.projection_handle();
        // Silent Canary: snapshot community IDs before moving the registry.
        let community_ids: Vec<_> = deps.trust_registry.communities.keys().copied().collect();
        let trust_registry = deps.trust_registry;
        let trust_actor = TrustActor::new(trust_registry, trust_rx);
        tokio::spawn(trust_actor.run());

        // Use the real vault_key — shards are encrypted with this key by MediaEgressActor.
        // The previous [0x42; 32] was a placeholder that caused silent decryption failures.
        let network_key = Arc::new(deps.vault_key.clone());

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
        // Per-recording content key watch channel: MeshSentinel → MediaEgressActor.
        // When a recording starts, the content key (DEK) is sent via this channel.
        // MediaEgressActor prefers the content key over vault_key for encryption.
        let (content_key_tx, content_key_rx) =
            tokio::sync::watch::channel::<Option<phalanx_proto::crypto::SymmetricKey>>(None);
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
                vault_key: deps.vault_key.clone(),
                content_key_rx,
                clock: clock_handle.clone(),
                prnu_posterior: deps.prnu_posterior.clone(),
                storage_tx: storage_tx.clone(),
            },
        )
        .await
        .map_err(|e| -> Box<dyn Error> {
            format!("Failed to initialize MediaEgressActor outbound queue: {e}").into()
        })?;

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
            topology_gate: TopologyGate::new(
                192, // total_capacity — matches libp2p connection limit
                SubnetQuota::DEFAULT,
                4, // max_anchors
            ),
            eclipse_probe: EclipseProbe::new(6), // 6 snapshots × 5min = 30min window
            reputation: reputation_projection.clone(),
            peer_discovery_count: 0,
            peer_discovery_window: std::time::Instant::now(),
            active_recording_id: None,
            active_recording_key: None,
            content_key_tx,
            proximity_witnesses: Vec::new(),
            clock: clock_handle.clone(),
            peer_did_cache: std::collections::HashMap::new(),
            canary: CanaryMonitor::new(2), // 2 consecutive stale ticks to confirm
            community_ids,
            revocation_synced_peers: std::collections::HashSet::new(),
            peer_first_seen: std::collections::HashMap::new(),
        })
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and timestamp arithmetic.
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        // Eclipse remediation: 5-minute tick for anchor promotion, eclipse detection, re-bootstrap.
        let mut topology_tick = tokio::time::interval(Duration::from_secs(300));
        topology_tick.tick().await; // Consume the immediate first tick

        loop {
            let should_shutdown = tokio::select! {
                Some(event) = self.ingress.next_event() => {
                    self.handle_network_event(event).await
                }

                // Poll local mesh transport for events (BLE, WiFi Direct).
                Some(local_event) = async {
                    match self.local_mesh.as_mut() {
                        Some(mesh) if mesh.is_available() => mesh.next_local_event().await,
                        _ => std::future::pending().await,
                    }
                } => {
                    tracing::debug!(event = "local_mesh_event", "Received event from local transport");
                    self.handle_network_event(local_event).await
                }

                Some(recording_id) = self.commit_notify_rx.recv() => {
                    self.handle_commit_notification(recording_id).await
                }

                Some((recording_id, _sequence_id)) = self.discovery_rx.recv() => {
                    self.handle_discovery_query(recording_id).await
                }

                Some(lifecycle_event) = async {
                    match self.lifecycle_rx.as_mut() {
                        Some(rx) => rx.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    self.handle_lifecycle_event(lifecycle_event)
                }

                _ = topology_tick.tick() => {
                    self.topology_maintenance_tick().await;
                    false
                }
            };

            if should_shutdown {
                break;
            }
        }
        Ok(())
    }

    /// DHT: StorageActor persisted a shard — announce as provider.
    async fn handle_commit_notification(&mut self, recording_id: RecordingId) -> bool {
        if let Err(e) = self
            .egress_tx
            .send(EgressCommand::AnnounceRecording(recording_id))
            .await
        {
            tracing::warn!("Failed to announce recording on DHT — egress channel closed: {e}");
        }
        false
    }

    /// DHT: PlaybackCoordinator needs a missing shard — find providers.
    async fn handle_discovery_query(&mut self, recording_id: RecordingId) -> bool {
        if let Err(e) = self
            .egress_tx
            .send(EgressCommand::FindProviders(recording_id))
            .await
        {
            tracing::warn!("Failed to find providers — egress channel closed: {e}");
        }
        false
    }

    /// Lifecycle events from mobile OS (foreground/background).
    /// Immediately recalculates PowerState so capture resumes within milliseconds.
    /// Desktop: lifecycle_rx is None, so this arm blocks via pending().
    fn handle_lifecycle_event(&self, event: LifecycleEvent) -> bool {
        match event {
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

    /// Unified event handler for both network ingress and local mesh events.
    /// Returns `true` if the engine should shut down.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and timestamp arithmetic.
    async fn handle_network_event(&mut self, event: NetworkEvent) -> bool {
        match event {
            NetworkEvent::DataReceived {
                origin,
                topic,
                data,
            } => {
                self.handle_data_received(origin, topic, data).await;
                false
            }
            NetworkEvent::PeerDiscovered {
                peer,
                source,
                bucket,
                transport,
            } => {
                self.handle_peer_discovered(peer, source, bucket, transport)
                    .await;
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
            NetworkEvent::ProvidersDiscovered {
                recording_id,
                providers,
            } => {
                self.handle_providers_discovered(recording_id, providers);
                false
            }
            NetworkEvent::ShardResponseReceived { origin, envelopes } => {
                self.handle_shard_response(origin, envelopes).await;
                false
            }
            NetworkEvent::PeerDisconnected { peer } => {
                self.handle_peer_disconnected(peer).await;
                false
            }
            NetworkEvent::BleAuthChallengeReceived { .. }
            | NetworkEvent::BleAuthResponseReceived { .. } => {
                tracing::debug!(
                    "BLE auth event received — handled by Flutter FFI, not MeshSentinel"
                );
                false
            }
            NetworkEvent::Shutdown => {
                self.handle_shutdown().await;
                true
            }
        }
    }

    // ── Event Handlers ──────────────────────────────────────────────────

    /// Handles incoming data: oversized message rejection, control message
    /// spectral analysis, and bandwidth-gated ingestion forwarding.
    #[allow(clippy::arithmetic_side_effects)] // Size comparisons and memory pressure recording.
    async fn handle_data_received(&mut self, origin: NetworkId, topic: MeshTopic, data: Vec<u8>) {
        // P5 FIX: Reject oversized messages before any processing.
        if data.len() > self.config.network.max_chunk_size_bytes * 2 {
            tracing::warn!(
                size = data.len(),
                limit = self.config.network.max_chunk_size_bytes * 2,
                peer = %origin,
                "P5: Oversized message rejected pre-queue"
            );
            return;
        }

        if topic.as_str() == self.config.network.control_topic.as_str() {
            self.handle_control_message(&data);
        } else if topic.as_str() == self.config.network.revocation_topic.as_str() {
            self.handle_revocation(origin, &data).await;
        } else {
            self.handle_data_chunk(origin, topic, data);
        }
    }

    fn handle_control_message(&mut self, data: &[u8]) {
        if let Ok(msg) =
            phalanx_forensics::gate::unmarshal::<ControlMessage>(data, "control_message")
        {
            let peer_id_for_spectral = msg.sender.clone();
            self.health_tracker.register_activity(msg);

            // Shield Wall: evaluate spectral consistency
            if let Some(residual) = self.health_tracker.spectral.evaluate(&peer_id_for_spectral) {
                if residual > self.health_tracker.spectral.anomaly_threshold {
                    self.system_governor
                        .record_spectral_anomaly(&peer_id_for_spectral.to_string(), residual);
                    tracing::warn!(
                        target: "phalanx::shield_wall",
                        peer = %peer_id_for_spectral,
                        residual = %residual,
                        "SPECTRAL_ANOMALY_DETECTED"
                    );
                }
            }
        }
    }

    #[allow(clippy::arithmetic_side_effects)] // Memory pressure arithmetic.
    fn handle_data_chunk(&mut self, origin: NetworkId, topic: MeshTopic, data: Vec<u8>) {
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
            self.system_governor
                .record_memory_pressure(self.config.network.max_chunk_size_bytes * 200);
            tracing::warn!("Ingestion channel full, dropping chunk.");
        }
    }

    /// Cryptographic Forgetting: process an inbound revocation token from gossipsub.
    async fn handle_revocation(&mut self, origin: NetworkId, data: &[u8]) {
        // 1. Deserialize
        let token: phalanx_proto::revocation::RevocationToken =
            match phalanx_forensics::gate::unmarshal_checked(data, "revocation_token") {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!(peer = %origin, error = %e, "Malformed revocation token");
                    return;
                }
            };

        // 2. Verify self-contained signature
        if let Err(e) = phalanx_forensics::revocation::verify_revocation_token(&token) {
            tracing::warn!(
                peer = %origin,
                recording = %token.recording_id,
                error = %e,
                "Invalid revocation token rejected"
            );
            return;
        }

        // 3. Forward to StorageActor for authorization and execution
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let recording_id = token.recording_id.clone();
        if self
            .storage_tx
            .send(StorageCommand::Revoke {
                token: token.clone(),
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            tracing::error!("Storage channel closed — cannot process revocation");
            return;
        }

        match reply_rx.await {
            Ok(Ok(())) => {
                tracing::info!(recording = %recording_id, "Revocation applied — propagating");
                // 4. Epidemic propagation: republish to gossipsub
                let _ = self
                    .egress_tx
                    .send(EgressCommand::PublishRevocation(token))
                    .await;
                // 5. Withdraw local DHT provider records
                let _ = self
                    .egress_tx
                    .send(EgressCommand::WithdrawProvider(recording_id))
                    .await;
            }
            Ok(Err(e)) => {
                tracing::warn!(recording = %recording_id, error = %e, "Revocation rejected");
            }
            Err(_) => {
                tracing::error!("Storage reply channel dropped during revocation");
            }
        }
    }

    /// Topology-aware peer admission with rate limiting, subnet diversity,
    /// IWFQ eviction, and proximity witness capture.
    #[allow(clippy::arithmetic_side_effects)] // Rate limit counter increment.
    async fn handle_peer_discovered(
        &mut self,
        peer: NetworkId,
        source: DiscoverySource,
        bucket: SubnetBucket,
        transport: TransportClass,
    ) {
        // E6: Per-second rate limit on peer discovery processing.
        const MAX_DISCOVERIES_PER_SECOND: u32 = 10;
        let now = std::time::Instant::now();
        if now.duration_since(self.peer_discovery_window) >= Duration::from_secs(1) {
            self.peer_discovery_count = 0;
            self.peer_discovery_window = now;
        }
        self.peer_discovery_count += 1;
        if self.peer_discovery_count > MAX_DISCOVERIES_PER_SECOND {
            tracing::debug!(
                event = "e6_rate_limit",
                peer = %peer,
                "E6: Peer discovery rate exceeded, dropping"
            );
            return;
        }

        // Topology-aware admission: check subnet diversity, transport quotas, IWFQ.
        let balance = self.compute_transport_balance();
        match self.topology_gate.try_admit(
            peer.clone(),
            TrustLevel::default(),
            bucket,
            transport,
            balance,
        ) {
            Ok((_ticket, evicted)) => {
                self.system_governor.record_peer_discovery(source);
                self.system_governor.record_connection_gauge();

                // Reciprocity floor: record first-seen time. or_insert() preserves
                // the original timestamp on reconnection (prevents grace-period-reset).
                {
                    const MAX_PEER_FIRST_SEEN: usize = 10_000;
                    if self.peer_first_seen.len() >= MAX_PEER_FIRST_SEEN
                        && !self.peer_first_seen.contains_key(&peer)
                    {
                        // Evict oldest entry to make room.
                        if let Some(oldest_peer) = self
                            .peer_first_seen
                            .iter()
                            .min_by_key(|(_, &ts)| ts)
                            .map(|(k, _)| k.clone())
                        {
                            self.peer_first_seen.remove(&oldest_peer);
                        }
                    }
                    let now_secs = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    self.peer_first_seen.entry(peer.clone()).or_insert(now_secs);
                }

                // Silent Canary: cancel any pending dark-peer confirmation.
                self.canary.on_peer_reconnected(&peer);

                // ProximityWitness capture: if recording and this is LocalMesh,
                // log the co-location event for the Corroboration Gate.
                if transport == TransportClass::LocalMesh {
                    if let Some(ref rec_id) = self.active_recording_id {
                        self.proximity_witnesses.push(
                            phalanx_proto::corroboration::ProximityWitness {
                                local_did: self.identity.did.clone(),
                                remote_did: phalanx_proto::identity::Did::new(peer.0.clone()),
                                recording_id: rec_id.clone(),
                                observed_at: self.clock.now().unwrap_or_default(),
                                transport,
                            },
                        );
                    }
                }

                // Replay persisted revocation tokens to newly-connected peers
                // so partitioned devices catch up on deletions they missed.
                if self.revocation_synced_peers.insert(peer.clone()) {
                    self.replay_revocation_tokens().await;
                }

                if let Some(evicted_peer) = evicted {
                    tracing::debug!(
                        event = "topology_eviction",
                        evicted = %evicted_peer,
                        newcomer = %peer,
                        "IWFQ: Evicted lower-trust peer to admit newcomer"
                    );
                    let _ = self
                        .egress_tx
                        .send(EgressCommand::DisconnectPeer(evicted_peer))
                        .await;
                }
            }
            Err(reason) => {
                tracing::debug!(
                    event = "topology_rejected",
                    peer = %peer,
                    reason = %reason,
                    "TopologyGate rejected peer"
                );
                let _ = self
                    .egress_tx
                    .send(EgressCommand::DisconnectPeer(peer))
                    .await;
            }
        }
    }

    /// Re-broadcast all persisted revocation tokens via gossipsub so that
    /// newly-connected (or previously-partitioned) peers catch up on deletions
    /// they missed while offline.
    async fn replay_revocation_tokens(&mut self) {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .storage_tx
            .send(StorageCommand::GetRevocationTokens { reply_to: reply_tx })
            .await
            .is_err()
        {
            return;
        }
        match reply_rx.await {
            Ok(tokens) if !tokens.is_empty() => {
                tracing::info!(
                    count = tokens.len(),
                    "Revocation replay: re-broadcasting to mesh"
                );
                for token in tokens {
                    let _ = self
                        .egress_tx
                        .send(EgressCommand::PublishRevocation(token))
                        .await;
                }
            }
            _ => {}
        }
    }

    /// DHT: Filter out self, forward remote providers to PlaybackCoordinator.
    fn handle_providers_discovered(
        &mut self,
        recording_id: RecordingId,
        providers: Vec<NetworkId>,
    ) {
        let local_id = self.identity.to_network_id();
        let remote_providers: Vec<_> = providers.into_iter().filter(|p| *p != local_id).collect();
        if !remote_providers.is_empty() {
            tracing::info!(
                recording = %recording_id,
                count = remote_providers.len(),
                "DHT: Providers discovered for recording"
            );
            let _ = self.providers_tx.try_send((recording_id, remote_providers));
        }
    }

    /// DHT: Write received shards to the recording log, awaiting each confirmation.
    async fn handle_shard_response(&mut self, origin: NetworkId, envelopes: Vec<WitnessEnvelope>) {
        tracing::info!(
            peer = %origin,
            count = envelopes.len(),
            "DHT: Shard response received"
        );
        for envelope in envelopes {
            // Silent Canary: populate peer DID cache and register contribution
            // for community peers during active recordings.
            self.register_canary_contribution(&origin, &envelope);

            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
            if let Err(e) = self
                .storage_tx
                .send(StorageCommand::WriteShard {
                    envelope,
                    reply_to: reply_tx,
                })
                .await
            {
                tracing::warn!("DHT shard write: storage channel closed: {e}");
                continue;
            }
            match reply_rx.await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::warn!("DHT shard write failed: {e}");
                }
                Err(_) => {
                    tracing::warn!("DHT shard write: storage actor dropped reply channel");
                }
            }
        }
    }

    async fn handle_peer_disconnected(&mut self, peer: NetworkId) {
        tracing::info!(
            event = "peer_disconnected",
            peer = %peer,
            "Peer disconnected"
        );
        self.topology_gate.demote_anchor(&peer);
        self.topology_gate.release(&peer);
        self.health_tracker.spectral.remove_peer(&peer);
        self.system_governor.record_peer_departure(false);
        self.system_governor.record_connection_gauge();

        // Silent Canary: mark peer as potentially dark. The canary only fires
        // after heartbeat staleness is confirmed (not on disconnect alone).
        if self.active_recording_id.is_some() && self.canary.is_active() {
            self.canary.on_peer_disconnected(&peer);

            // Check staleness immediately — the peer may already be stale.
            let physics = PhalanxPhysics::default();
            if self.health_tracker.is_peer_stale(&peer, &physics) {
                if let Some(state) = self.canary.on_peer_stale(&peer) {
                    self.handle_canary_alert(state).await;
                }
            }
        }
    }

    // ── Silent Canary: registration, escalation, and broadcast ──────────

    /// Update the peer DID cache and register a canary contribution if the
    /// peer is a verified community member with an active recording.
    fn register_canary_contribution(&mut self, origin: &NetworkId, envelope: &WitnessEnvelope) {
        use crate::trust::TrustOracle;
        use phalanx_forensics::crucible::EvidenceExt;
        use phalanx_proto::trust::TrustLevel;

        // Always populate the peer identity cache (memory-only).
        // R3-3 FIX: Cap cache size to prevent memory exhaustion from
        // an attacker sending shards with many distinct NetworkIds.
        const MAX_PEER_DID_CACHE: usize = 10_000;
        if self.peer_did_cache.len() >= MAX_PEER_DID_CACHE
            && !self.peer_did_cache.contains_key(origin)
        {
            tracing::debug!(
                target: "phalanx::mesh",
                "peer_did_cache at capacity, skipping new entry"
            );
        } else {
            self.peer_did_cache
                .insert(origin.clone(), envelope.did.clone());
        }

        // Only register canary contributions during an active recording.
        if self.active_recording_id.is_none() {
            return;
        }

        // Only watch community members (effective_trust >= Verified).
        let trust = self.reputation.effective_trust(&envelope.did);
        if trust < TrustLevel::Verified {
            return;
        }

        let recording_id = envelope.evidence.recording_id();
        self.canary
            .register_contribution(origin, &envelope.did, recording_id);
    }

    /// Dispatch canary escalation based on how many community peers remain.
    async fn handle_canary_alert(&mut self, state: CanaryState) {
        let (silent_peers, recordings_at_risk, peers_remaining) = match state {
            CanaryState::Alert {
                silent_peers,
                recordings_at_risk,
                peers_remaining,
            } => (silent_peers, recordings_at_risk, peers_remaining),
            CanaryState::Normal => return,
        };

        tracing::warn!(
            silent = silent_peers.len(),
            at_risk = recordings_at_risk.len(),
            remaining = peers_remaining,
            "Silent Canary: community peer(s) confirmed dark"
        );

        // Re-replicate dark peer's recordings via existing DHT infrastructure.
        for rid in &recordings_at_risk {
            let _ = self
                .egress_tx
                .send(EgressCommand::FindProviders(rid.clone()))
                .await;
        }

        if peers_remaining == 0 {
            // Local salvage — no peers left to distribute to.
            let _ = self
                .storage_tx
                .send(StorageCommand::EmergencySalvage(vec![]))
                .await;
        }

        // Broadcast encrypted canary alert to community members.
        self.broadcast_canary_alert(silent_peers.len()).await;
    }

    /// Encrypt and broadcast a canary alert. Only community members who
    /// imported the same community can derive the decryption key.
    async fn broadcast_canary_alert(&mut self, silent_count: usize) {
        let detected_at = self.clock.now().unwrap_or_default();
        // Mesh peer count is structurally bounded well below u32::MAX.
        #[allow(clippy::cast_possible_truncation)]
        let silent_count_u32 = silent_count as u32;
        let alert = phalanx_proto::network::CanaryAlert {
            silent_count: phalanx_proto::network::SilentCount(silent_count_u32),
            detected_at,
        };

        let plaintext = match postcard::to_allocvec(&alert) {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::warn!(error = %e, "Canary: failed to serialize alert");
                return;
            }
        };

        // Broadcast once per community (each derives its own canary key).
        for cid in &self.community_ids {
            let canary_key = SymmetricKey(blake3::derive_key(
                "phalanx.canary.v1.community-alert",
                &cid.0,
            ));

            let (nonce, ciphertext) =
                match phalanx_forensics::cryptography::encrypt_bytes(&canary_key, &plaintext) {
                    Ok(pair) => pair,
                    Err(e) => {
                        tracing::warn!(error = %e, "Canary: encryption failed");
                        continue;
                    }
                };

            let mut payload = nonce;
            payload.extend(ciphertext);

            let _ = self
                .egress_tx
                .send(EgressCommand::PublishMesh {
                    topic: MeshTopic::mesh(),
                    data: payload,
                })
                .await;
        }
    }

    async fn handle_shutdown(&mut self) {
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
    }

    pub async fn spawn_playback<V: PlaybackSink + 'static, A: PlaybackSink + 'static>(
        &mut self,
        recording_id: RecordingId,
        video_sink: V,
        audio_sink: A,
    ) -> tokio::task::JoinHandle<()> {
        // Fresh channel per playback session — only one active at a time.
        // Replacing providers_tx drops the old sender, signaling the previous
        // PlaybackCoordinator's providers_rx that no more data will arrive.
        let (providers_tx, providers_rx) = mpsc::channel(100);
        self.providers_tx = providers_tx;

        // Resolve per-recording content key for decryption.
        // Falls back to vault_key (network_key) for legacy recordings without content keys.
        let decryption_key = {
            let (tx, rx) = tokio::sync::oneshot::channel();
            let _ = self
                .storage_tx
                .send(StorageCommand::GetContentKey {
                    recording_id: recording_id.clone(),
                    reply_to: tx,
                })
                .await;
            match rx.await {
                Ok(Some(key_bytes)) => Some(phalanx_proto::crypto::SymmetricKey(key_bytes)),
                _ => Some((*self.network_key).clone()), // fallback for legacy
            }
        };

        let mut coordinator = PlaybackCoordinator::new(
            self.storage_tx.clone(),
            self.egress_tx.clone(),
            decryption_key,
            video_sink,
            audio_sink,
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

    // ── Eclipse Remediation ────────────────────────────────────────

    /// Derive dynamic transport balance from existing SystemGovernor signals.
    fn compute_transport_balance(&self) -> TransportBalance {
        if self.local_mesh.is_none() {
            return TransportBalance::new(0.1); // Minimum — no local mesh hardware
        }
        if !self.system_governor.internet_available() {
            return TransportBalance::new(0.4); // Shift toward local mesh when internet is down
        }
        TransportBalance::DEFAULT // 0.25 when both transports healthy
    }

    /// Periodic tick: anchor promotion, eclipse fingerprinting, re-bootstrap check.
    async fn topology_maintenance_tick(&mut self) {
        // 1. Anchor promotion: promote long-lived high-reputation peers.
        let peer_ids: Vec<NetworkId> = self.topology_gate.peer_ids().cloned().collect();
        for peer_id in &peer_ids {
            if self.topology_gate.is_anchored(peer_id) {
                continue;
            }
            let score = self.reputation.evaluate_reputation(peer_id);
            if let Some(proof) = AnchorEligible::try_from_score(score) {
                if self.topology_gate.promote_to_anchor(peer_id, proof) {
                    tracing::debug!(
                        event = "anchor_promoted",
                        peer = %peer_id,
                        score = score,
                        "Promoted peer to anchor status"
                    );
                }
            }
        }

        // 2. Eclipse fingerprinting: snapshot the current peer set topology.
        let mut peer_ids: Vec<&NetworkId> = self.health_tracker.heartbeats.keys().collect();
        let peer_set_hash = eclipse::hash_peer_set(&mut peer_ids);
        let peer_count = peer_ids.len();
        let subnet_distribution = self.topology_gate.subnet_counts().clone();

        let fingerprint = MeshFingerprint {
            peer_set_hash,
            peer_count,
            subnet_distribution,
            timestamp: MonotonicClock(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            ),
        };

        self.eclipse_probe.record(fingerprint);
        let risk = self.eclipse_probe.evaluate();

        match risk {
            EclipseRisk::Elevated => {
                self.system_governor.record_eclipse_impulse(5.0);
                tracing::warn!(
                    target: "phalanx::shield_wall",
                    event = "eclipse_risk_elevated",
                    peer_count = peer_count,
                    "Eclipse probe: ELEVATED risk — Sybil pressure injected"
                );
            }
            EclipseRisk::Critical => {
                self.system_governor.record_eclipse_impulse(20.0);
                tracing::warn!(
                    target: "phalanx::shield_wall",
                    event = "eclipse_risk_critical",
                    peer_count = peer_count,
                    "Eclipse probe: CRITICAL risk — Sybil pressure injected, triggering re-bootstrap"
                );

                // Record EclipseAttempt offense against concentrated-subnet peers.
                let _ = self
                    .trust_tx
                    .send(TrustCommand::RecordOffense {
                        did: self.identity.did.clone(), // Self-report — TrustActor handles routing
                        offense: Offense::EclipseAttempt,
                    })
                    .await;

                // Trigger re-bootstrap if peer count is below half capacity.
                if self.topology_gate.peer_count() < 96 {
                    let bootstrap_peers: Vec<String> = self
                        .config
                        .network
                        .bootstrap_peers
                        .iter()
                        .take(3)
                        .cloned()
                        .collect();
                    if !bootstrap_peers.is_empty() {
                        let _ = self
                            .egress_tx
                            .send(EgressCommand::ReBootstrap(bootstrap_peers))
                            .await;
                    }
                }
            }
            _ => {} // EclipseRisk::None — all clear
        }

        // 3. Reciprocity floor sweep: detect black hole peers.
        // Only active during recording — passive witnesses have nothing to forward.
        if self.active_recording_id.is_some() {
            let power_state = self.system_governor.current_power_state();
            // Don't judge peers when we're in Leaf/Dormant — we're not contributing enough ourselves.
            if !matches!(
                power_state,
                phalanx_proto::types::PowerState::Leaf | phalanx_proto::types::PowerState::Dormant
            ) {
                let params = ReciprocityParams::default();
                let mesh_peer_count = self.topology_gate.peer_count();
                let now_secs = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();

                let admitted_peers: Vec<NetworkId> =
                    self.topology_gate.peer_ids().cloned().collect();

                for peer_id in &admitted_peers {
                    let first_seen = self
                        .peer_first_seen
                        .get(peer_id)
                        .copied()
                        .unwrap_or(now_secs);
                    let connected_secs = now_secs.saturating_sub(first_seen);
                    let contribution = self.system_governor.peer_contribution_value(&peer_id.0);
                    let is_local_mesh = self
                        .topology_gate
                        .transport_class(peer_id)
                        .is_some_and(|tc| tc == TransportClass::LocalMesh);

                    let snapshot = PeerContribution {
                        connected_secs,
                        contribution_integral: contribution,
                        is_local_mesh,
                    };

                    if let ReciprocityVerdict::NonReciprocal { deficit } =
                        evaluate_reciprocity(&snapshot, &params, mesh_peer_count)
                    {
                        // Always: smooth reputation degradation via spectral anomaly.
                        self.system_governor
                            .record_spectral_anomaly(&peer_id.0, deficit * 5.0);

                        // Severe deficit + known DID → formal offense for blacklist escalation.
                        if deficit > 0.8 {
                            if let Some(did) = self.peer_did_cache.get(peer_id) {
                                let _ = self
                                    .trust_tx
                                    .send(TrustCommand::RecordOffense {
                                        did: did.clone(),
                                        offense: Offense::NonReciprocal,
                                    })
                                    .await;
                            }
                        }

                        tracing::debug!(
                            target: "phalanx::shield_wall",
                            event = "reciprocity_deficit",
                            peer = %peer_id,
                            deficit = deficit,
                            connected_secs = connected_secs,
                            "Black hole detection: peer below reciprocity floor"
                        );
                    }
                }
            }
        }

        // 4. Prune stale r_integrals entries (bounds memory for all namespaced keys).
        self.system_governor.prune_stale_integrals();
    }
}
