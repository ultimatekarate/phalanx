// --- crates/phalanx-node/src/actors/meshsentinel.rs ---
use crate::actors::playback::PlaybackCoordinator;
use crate::actors::storage::NoOpJournal;
use crate::actors::storage::StorageCommand;
use crate::clock::TrustedClock;
use crate::config::NodeConfig;
use crate::identity::PhalanxNodeIdentityExt;
use crate::state::SyncReputationCache;
use crate::vitals::{
    FinalizationScale, HealthTracker, Homeostasis, IngestionScale, SystemGovernor,
};
use crate::Guardian;
use crate::{trust::TrustRegistry, StorageActor};
use phalanx_forensics::judge::IntegrityGate;
use phalanx_forensics::policy::{EgressGovernor, IngressGovernor};
use phalanx_forensics::prelude::*;
use phalanx_forensics::ReputationGate;
use phalanx_proto::prelude::*;
use phalanx_proto::types::Unverified;
use std::sync::Arc;
use tokio::sync::mpsc;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::AudioShard;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::time::CausalitySession;
use phalanx_proto::trust::Offense;
use phalanx_proto::types::{ForensicUnit, NodeMode, TaskCost, Verified};
use phalanx_proto::VolleyRequest;
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::NetworkTransport;
use std::collections::VecDeque;
use std::error::Error;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

/// A lightweight request broadcast to the mesh when a playback gap is detected.
#[derive(serde::Serialize, serde::Deserialize)]
struct ShardDiscoveryRequest {
    volley_id: VolleyId,
    sequence_id: StorageSequence,
}

pub struct SentinelDependencies<T: NetworkTransport, J: TransientJournal> {
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub network: T,
    pub journal: J,
    pub trust_registry: TrustRegistry,
    pub reputation_cache: Arc<SyncReputationCache>,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    pub system_governor: Arc<SystemGovernor>,
}

pub struct MeshSentinel<T: NetworkTransport, J: TransientJournal> {
    pub trust_registry: TrustRegistry,
    pub reputation_cache: Arc<SyncReputationCache>,
    pub health_tracker: HealthTracker,
    pub governor: TrafficGovernor,
    pub mode: NodeMode,
    pub config: NodeConfig,
    pub identity: Arc<PhalanxIdentity>,
    pub clock: Arc<TrustedClock>,
    pub network: T,
    pub video_rx: mpsc::Receiver<VideoShard>,
    pub audio_rx: mpsc::Receiver<AudioShard>,
    pub seq_counter: u64,
    pub network_key: SymmetricKey,
    pub storage_task: JoinHandle<()>,
    pub storage_tx: mpsc::Sender<StorageCommand>,
    pub _journal_phantom: std::marker::PhantomData<J>,
    pub session: CausalitySession,
    pub pending_egress: VecDeque<PendingEgress>,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
    pub ingress_governor: IngressGovernor,
    pub system_governor: Arc<SystemGovernor>,
}

impl<T: NetworkTransport, J: TransientJournal + Send + 'static> MeshSentinel<T, J> {
    pub async fn new(mut deps: SentinelDependencies<T, J>) -> Result<Self, Box<dyn Error>> {
        let local_did = deps.identity.did.clone();
        let local_network_id = deps.identity.to_network_id();
        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&deps.config.storage.vault_path, &deps.config, local_did);

        let (_, video_rx) = mpsc::channel(deps.config.storage.max_video_buffer);
        let (_, audio_rx) = mpsc::channel(deps.config.storage.max_audio_buffer);

        // Vault Interface
        let (storage_tx, storage_rx) = mpsc::channel(10);
        let ingress_governor = IngressGovernor::new(10);

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
        };

        let storage_task = tokio::spawn(async move {
            storage_actor.run(storage_rx).await;
        });

        let arc_identity = Arc::new(deps.identity.clone());
        let session = CausalitySession::new(arc_identity.clone(), local_network_id.clone());
        let raw_clock = TrustedClock::new();
        let clock_handle = Arc::new(raw_clock);

        Ok(Self {
            config: deps.config,
            identity: arc_identity,
            clock: clock_handle,
            network: deps.network,
            trust_registry: deps.trust_registry,
            reputation_cache: deps.reputation_cache,
            health_tracker: HealthTracker::new(),
            governor: TrafficGovernor::new(),
            mode: NodeMode::Standard,
            video_rx,
            audio_rx,
            seq_counter: 0,
            network_key: SymmetricKey([0x42; 32]),
            storage_task,
            storage_tx,
            _journal_phantom: std::marker::PhantomData,
            session,
            pending_egress: VecDeque::from(salvaged_queue),
            discovery_rx: deps.discovery_rx,
            discovery_tx: deps.discovery_tx,
            ingress_governor,
            system_governor: deps.system_governor,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_network_id = self.identity.to_network_id();
        let mut retry_tick = interval(Duration::from_millis(500));

        let base_throttle = 5;
        loop {
            let scale: IngestionScale = self.system_governor.ingestion_scaler();

            if scale.0 < 1.0 {
                let delay = scale.as_throttle_delay(base_throttle);
                tracing::trace!(target: "phalanx::metabolism", "Throttling loop for {}ms", delay.as_millis());
                tokio::time::sleep(delay).await;
            }

            tokio::select! {
                _ = retry_tick.tick() => { self.process_pending_egress().await; }
                Some(event) = self.network.next_event(), if scale.0 > 0.01 => {
                    match event {
                        NetworkEvent::DataReceived { origin, topic, data } => {
                            let start = tokio::time::Instant::now();
                            self.handle_network_ingress(origin, &data, topic).await;
                            self.system_governor.record_pressure(start.elapsed());
                        }
                        NetworkEvent::VolleyRequested { origin, request, channel_id } => {
                            self.execute_secure_retrieval(origin, request, channel_id, &local_network_id).await;
                        }
                        NetworkEvent::Shutdown => {
                            tracing::info!("Engine: Initiating emergency salvage");
                            let payload = self.pending_egress.drain(..).collect();
                            let _ = self.storage_tx.send(StorageCommand::EmergencySalvage(payload)).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            break;
                        }
                        _ => {}
                    }
                }
                Some(shard) = self.video_rx.recv() => {
                    self.process_media_egress(Evidence::Video(shard), &local_network_id).await;
                }
                Some(shard) = self.audio_rx.recv() => {
                    self.process_media_egress(Evidence::Audio(shard), &local_network_id).await;
                }
                Some((volley_id, gap_sequence)) = self.discovery_rx.recv() => {
                    self.handle_gap_discovery(volley_id, gap_sequence).await;
                }
            }
        }
        Ok(())
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
                if let Err(e) = self.network.publish(&topic, data).await {
                    tracing::error!("Failed to broadcast discovery request: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to serialize discovery request: {}", e),
        }
    }

    async fn process_media_egress(&mut self, evidence: Evidence, _local_id: &NetworkId) {
        let topic = match &evidence {
            Evidence::Video(_) => &self.config.network.video_topic,
            Evidence::Audio(_) => &self.config.network.audio_topic,
            Evidence::Gap(_) | Evidence::Handover(_) => {
                tracing::warn!("Unexpected evidence type for media egress");
                return;
            }
        };

        match postcard::to_allocvec(&evidence) {
            Ok(data) => {
                if let Err(e) = self.network.publish(topic, data).await {
                    tracing::error!("Failed to publish media egress: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to serialize media evidence: {}", e),
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

    /// Handles outbound data requests from the mesh, applying integrity and policy gates.
    async fn execute_secure_retrieval(
        &mut self,
        origin: NetworkId,
        request: VolleyRequest,
        channel_id: String,
        local_id: &NetworkId,
    ) {
        let io_scale: FinalizationScale = self.system_governor.finalization_scaler();

        // If the disk/IO integral is too high, we shed the load
        if io_scale.0 < 0.2 {
            tracing::warn!("I/O Digestion integral saturated. Shedding retrieval request.");
            return;
        }

        // 1. EARLY RESOURCE SHEDDING (Physical Gate)
        if !self.system_governor.check_permission(TaskCost::Heavy) {
            tracing::warn!(target: "phalanx::egress", "Retrieval rejected: System thermal/battery limits exceeded");
            self.dispatch_resilient_response(channel_id, VolleyResponse::Unauthorized)
                .await;
            return;
        }

        // 2. PRIVACY GATE
        if PhalanxNodeIdentityExt::verify_retrieval_auth(&*self.identity, &request).is_err() {
            tracing::warn!(peer = %origin, volley = %request.volley_id, "Privacy Gate: Unauthorized retrieval attempt blocked");
            self.trust_registry
                .record_offense(&request.target_did, Offense::InvalidSignature, &self.clock)
                .await;
            self.dispatch_resilient_response(channel_id, VolleyResponse::Unauthorized)
                .await;
            return;
        }

        // 3. FETCH FROM PURE VAULT
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if self
            .storage_tx
            .send(StorageCommand::Retrieval {
                volley_id: request.volley_id.clone(),
                reply_to: reply_tx,
            })
            .await
            .is_err()
        {
            self.dispatch_resilient_response(channel_id, VolleyResponse::NotFound)
                .await;
            return;
        }

        let raw_envelopes = reply_rx.await.unwrap_or_default();

        // 4. INTEGRITY & POLICY GATES
        let mut sealed_units = Vec::new();
        let current_stress = self.system_governor.current_stress();
        let target_trust = self.trust_registry.check_trust(&request.target_did);
        let now = PhalanxTimestamp::now();

        for env in raw_envelopes {
            // Safe extraction of sequence_id for logging
            let sequence_id = match &env.evidence {
                Evidence::Video(shard) => shard.sequence_id,
                Evidence::Audio(shard) => shard.sequence_id,
                Evidence::Gap(gap) => gap.start_seq,
                Evidence::Handover(_) => StorageSequence(0),
            };

            // GATE 3: Cryptographic Integrity Validation (Data-at-rest becoming Data-in-motion)
            if let Ok(valid_env) = env.check_integrity(local_id, now, 10_000, None) {
                // GATE 4: Typestate Promotion via Egress Policy
                let unit = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(valid_env);

                if let Ok(sealed) = EgressGovernor::authorize(unit, &target_trust, &current_stress)
                {
                    sealed_units.push(sealed);
                } else {
                    tracing::warn!(seq = %sequence_id, "Egress denied by policy");
                }
            } else {
                tracing::error!(seq = %sequence_id, "CRITICAL: Integrity validation failed for local vault data");
            }
        }

        // 5. DISPATCH TO NETWORK
        let response = if sealed_units.is_empty() {
            VolleyResponse::NotFound
        } else {
            VolleyResponse::Success(sealed_units)
        };

        self.dispatch_resilient_response(channel_id, response).await;
    }

    async fn process_pending_egress(&mut self) {
        let now = PhalanxTimestamp::now();
        let mut retry_queue = VecDeque::new();

        while let Some(mut pending) = self.pending_egress.pop_front() {
            if pending.next_attempt > now {
                retry_queue.push_back(pending);
                continue;
            }

            match self
                .network
                .send_response(&pending.channel_id, pending.response.clone())
                .await
            {
                Ok(_) => {
                    tracing::info!(channel = %pending.channel_id, "Redelivery successful");
                }
                Err(_) => {
                    pending.attempt_count += 1;
                    if pending.attempt_count < 3 {
                        let delay = Duration::from_millis(500 * (2u64.pow(pending.attempt_count)));
                        pending.next_attempt =
                            PhalanxTimestamp::from_millis(now.0 + delay.as_millis() as u64);
                        retry_queue.push_back(pending);
                    }
                }
            }
        }
        self.pending_egress = retry_queue;
    }

    pub async fn dispatch_resilient_response(
        &mut self,
        channel_id: String,
        response: VolleyResponse,
    ) {
        if self
            .network
            .send_response(&channel_id, response.clone())
            .await
            .is_err()
        {
            tracing::warn!(channel = %channel_id, "Response dispatch failed, queuing for retry");
            self.pending_egress.push_back(PendingEgress {
                channel_id,
                response,
                attempt_count: 1,
                next_attempt: PhalanxTimestamp::from_millis(PhalanxTimestamp::now().0 + 1000),
            });
        }
    }

    pub async fn handle_forensic_violation(
        &mut self,
        peer_id: NetworkId,
        owner_did: Did,
        err: GuardianError,
    ) {
        let offense = match err {
            GuardianError::VerificationFailed(_) | GuardianError::InvalidSignature(_) => {
                Some(Offense::InvalidSignature)
            }
            GuardianError::QuotaExceeded(_) => Some(Offense::QuotaExceeded),
            GuardianError::ReplayDetected(_) => Some(Offense::ReplayAttack),

            GuardianError::AmbiguousOwnership => {
                tracing::debug!(%peer_id, "Dropping ambiguous shard without penalty");
                None
            }
            // NEW: Route severe Guardian errors to high-penalty Trust Offenses
            GuardianError::PolicyViolation(_) => Some(Offense::IdentityTheft),
            GuardianError::ChainIntegrityViolation(_) => Some(Offense::ProtocolViolation),

            // Catch-all for any other unforeseen forensic crimes
            _ => Some(Offense::ProtocolViolation),
        };

        if let Some(offense_type) = offense {
            self.trust_registry
                .record_offense(&owner_did, offense_type, &self.clock)
                .await;

            let score = self.trust_registry.evaluate_reputation(&peer_id);
            if let Ok(mut cache) = self.reputation_cache.scores.write() {
                cache.insert(peer_id.clone(), score);
            }

            if self.trust_registry.is_blacklisted(&owner_did) {
                tracing::warn!(
                    %peer_id,
                    %owner_did,
                    "CRITICAL: Peer blacklisted. Severing connection."
                );
                self.network.ban_peer(&peer_id).await;
            }
        }
    }

    /// Handles inbound data from the wire, applying routing and ingress quotas before hitting the vault.
    pub async fn handle_network_ingress(
        &mut self,
        peer_id: NetworkId,
        data: &[u8],
        topic: MeshTopic,
    ) {
        // 1. TOPIC ROUTING (Edge Filtering)
        let topic_str = topic.as_str();
        if topic_str != self.config.network.video_topic
            && topic_str != self.config.network.audio_topic
        {
            tracing::warn!("Sentinel dropped chunk: Invalid topic {}", topic_str);
            return;
        }

        if !self
            .governor
            .should_accept(&peer_id, &self.identity.to_network_id())
        {
            return;
        }

        match postcard::from_bytes::<ShardChunk>(data) {
            Ok(raw_chunk) => {
                let unverified = ForensicUnit::<_, Unverified>::new(raw_chunk);

                let sender_did = unverified.data.owner_did.clone();

                if !self.system_governor.is_peer_coupled(&peer_id.to_string())
                    || self.trust_registry.is_blacklisted(&sender_did)
                {
                    self.network.ban_peer(&peer_id).await;
                    return;
                }

                let tolerance = self.system_governor.temporal_tolerance();
                let now_ms = self
                    .clock
                    .now()
                    .unwrap_or_else(|_| unverified.data.timestamp);

                let shard_timestamp = unverified.data.timestamp;

                // Saturating sub to prevent underflow if clocks are slightly out of sync
                let age = Duration::from_millis(now_ms.0.saturating_sub(shard_timestamp.0));

                if age > tolerance {
                    tracing::warn!(
                        peer = %peer_id,
                        age_ms = %age.as_millis(),
                        tolerance_ms = %tolerance.as_millis(),
                        "Frame rejected: Exceeds dynamic temporal tolerance"
                    );
                    self.ingress_governor.release_slot(&peer_id);
                    return;
                }

                // 2. RESOURCE QUOTAS (IWFQ Allocation)
                let trust_level = self.trust_registry.check_trust(&sender_did);
                let stress = self.system_governor.current_stress();

                match self
                    .ingress_governor
                    .try_allocate(peer_id.clone(), trust_level, stress)
                {
                    Ok(Some(evicted_peer)) => {
                        tracing::warn!(%evicted_peer, "Preempted IWFQ slot for higher-trust peer");
                        self.network.ban_peer(&evicted_peer).await;
                    }
                    Ok(None) => {}    // Slot granted
                    Err(_) => return, // Silent drop (Backpressure)
                }

                let verified_unit = ForensicUnit::<_, Verified>::new_verified(unverified.unpack());

                // 3. DISPATCH TO PURE VAULT
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                if let Err(err) = self
                    .storage_tx
                    .send(StorageCommand::Ingest {
                        unit: verified_unit,
                        reply_to: reply_tx,
                    })
                    .await
                {
                    tracing::error!(error = %err, "CRITICAL: Failed to route chunk to vault");
                    self.ingress_governor.release_slot(&peer_id);
                    return;
                }

                // 4. VAULT RESPONSE & CAUSAL BACKPRESSURE RELEASE
                match reply_rx.await {
                    Ok(Ok(())) => {
                        self.ingress_governor.release_slot(&peer_id);
                    }
                    Ok(Err(guardian_error)) => {
                        // THE FIX: If storage detects a crime, the Sentinel must punish it.
                        self.handle_forensic_violation(peer_id.clone(), sender_did, guardian_error)
                            .await;
                        self.ingress_governor.release_slot(&peer_id);
                    }
                    Err(_) => {
                        self.ingress_governor.release_slot(&peer_id);
                    }
                }
            }
            Err(err) => {
                tracing::warn!(peer = %peer_id, error = %err, "Dropped malformed payload at edge");
            }
        }
    }
}

// Ephemeral Bootstrap
impl<T: NetworkTransport> MeshSentinel<T, NoOpJournal> {
    pub async fn new_at_path(path: &str, network: T) -> Result<Self, Box<dyn Error>> {
        let mut config = NodeConfig::default();
        config.storage.vault_path = path.to_string();
        let identity = PhalanxIdentity::new_ephemeral();
        let trust_registry = TrustRegistry::build(&config).await;
        let (discovery_tx, discovery_rx) = mpsc::channel(100);

        let deps = SentinelDependencies {
            config,
            identity,
            network,
            journal: NoOpJournal,
            trust_registry,
            reputation_cache: Arc::new(SyncReputationCache::default()),
            discovery_rx,
            discovery_tx,
            system_governor: Arc::new(SystemGovernor::new()),
        };

        Self::new(deps).await
    }
}
