// --- crates/phalanx-node/src/actors/meshsentinel.rs ---
use crate::actors::egress::{EgressActor, EgressCommand};
use crate::actors::media_egress::MediaEgressActor;
use crate::actors::playback::PlaybackCoordinator;
use crate::actors::storage::NoOpJournal;
use crate::actors::storage::StorageCommand;
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
use phalanx_forensics::policy::{EgressGovernor, IngressGovernor};
use phalanx_forensics::prelude::*;
use phalanx_forensics::ReputationGate;
use phalanx_proto::prelude::*;
use phalanx_proto::types::Unverified;
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::{EgressPort, IngressPort};
use std::sync::Arc;

use tokio::sync::mpsc;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::time::CausalitySession;
use phalanx_proto::trust::Offense;
use phalanx_proto::types::{ForensicUnit, NodeMode, TaskCost, Verified};
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
    pub trust_registry: TrustRegistry,
    pub reputation_cache: ReputationProjection,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    pub system_governor: Arc<SystemGovernor>,
}

pub struct MeshSentinel<I: IngressPort, E: EgressPort, J: TransientJournal> {
    pub trust_registry: TrustRegistry,
    pub reputation_cache: ReputationProjection,
    pub health_tracker: HealthTracker,
    pub governor: TrafficGovernor,
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
    pub egress_tx: mpsc::Sender<EgressCommand>,
    pub _journal_phantom: std::marker::PhantomData<J>,
    pub session: CausalitySession,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
    pub ingress_governor: IngressGovernor,
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
            governor: TrafficGovernor::new(),
            mode: NodeMode::Standard,
            seq_counter: 0,
            network_key: SymmetricKey([0x42; 32]),
            storage_task,
            storage_tx,
            egress_tx,
            _journal_phantom: std::marker::PhantomData,
            session,
            discovery_rx: deps.discovery_rx,
            discovery_tx: deps.discovery_tx,
            ingress_governor,
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
                            self.handle_network_ingress(origin, &data, topic).await;
                        }
                        NetworkEvent::VolleyRequested { origin, request, channel_id } => {
                            self.execute_secure_retrieval(origin, request, channel_id, &local_network_id).await;
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
                .record_offense(
                    &request.target_did,
                    Offense::InvalidSignature,
                    self.clock.as_ref(),
                )
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
                .record_offense(&owner_did, offense_type, self.clock.as_ref())
                .await;

            if self.trust_registry.is_blacklisted(&owner_did) {
                tracing::warn!(
                    %peer_id,
                    %owner_did,
                    "CRITICAL: Peer blacklisted. Severing connection."
                );
                self.egress.ban_peer(&peer_id).await;
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
        if topic_str != self.config.network.video_topic.as_str()
            && topic_str != self.config.network.audio_topic.as_str()
        {
            tracing::warn!("Sentinel dropped chunk: Invalid topic {}", topic_str);
            return;
        }

        let topic = &self.config.network.control_topic;
        if topic_str == topic.as_str() {
            match postcard::from_bytes::<ControlMessage>(data) {
                Ok(msg) => {
                    // Update our medical records for this peer
                    self.health_tracker.register_activity(msg);
                    return; // Control messages don't go to the Vault
                }
                Err(e) => {
                    tracing::warn!(peer = %peer_id, "Malformed control message: {}", e);
                    return;
                }
            }
        }

        if !self
            .governor
            .should_accept(&peer_id, &self.identity.to_network_id())
        {
            return;
        }

        // START THE METABOLIC CLOCK IMMEDIATELY
        let start_cpu = tokio::time::Instant::now();

        match postcard::from_bytes::<ShardChunk>(data) {
            Ok(raw_chunk) => {
                let unverified = ForensicUnit::<_, Unverified>::new(raw_chunk);
                let sender_did = unverified.data.owner_did.clone();

                // 1. IMMUNE INTEGRAL FILTER
                if !self.system_governor.is_peer_coupled(&peer_id.to_string())
                    || self.trust_registry.is_blacklisted(&sender_did)
                {
                    self.egress.ban_peer(&peer_id).await;
                    return;
                }

                // 2. THE ELASTIC GATE (FEEDBACK REQUIRED)
                let shard_birth = unverified.data.timestamp;
                let now_ms = self.clock.now().unwrap_or(shard_birth);
                let age = Duration::from_millis(now_ms.0.saturating_sub(shard_birth.0));

                // CRITICAL: Feed the Latency Integral before checking tolerance!
                self.system_governor.record_latency_pressure(age);

                let tolerance = self.system_governor.temporal_tolerance();

                tracing::error!(
                    target: "siege_debug",
                    peer = %peer_id,
                    age_ms = age.as_millis(),
                    tolerance_ms = tolerance.as_millis(),
                    "Evaluating Temporal Gate"
                );

                if age > tolerance {
                    tracing::warn!(peer = %peer_id, age = ?age, tol = ?tolerance, "Dropped: Stale Shard");
                    return; // Guard will release slot if we had one
                }

                // 3. RESOURCE ALLOCATION (IWFQ)
                let trust_level = self.trust_registry.check_trust(&sender_did);
                let stress = self.system_governor.current_stress();
                match self
                    .ingress_governor
                    .try_allocate(peer_id.clone(), trust_level, stress)
                {
                    Ok(Some(evicted)) => {
                        self.egress.ban_peer(&evicted).await;
                    }
                    Ok(None) => {}
                    Err(_) => {
                        tracing::error!(target: "siege_debug", "INGRESS GOVERNOR FULL! Dropping {}", peer_id);
                        return;
                    }
                }

                // CREATE A RAII GUARD: Automatically releases the slot when this scope ends
                let _slot_guard = SlotGuard::new(&mut self.ingress_governor, peer_id.clone());

                // 4. VAULT DISPATCH
                let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
                let verified_unit = ForensicUnit::<_, Verified>::new_verified(unverified.unpack());

                tracing::error!(target: "siege_debug", "Sending to Vault. Channel Capacity: {}", self.storage_tx.capacity());

                if self
                    .storage_tx
                    .send(StorageCommand::Ingest {
                        unit: verified_unit,
                        reply_to: reply_tx,
                        ttl: tolerance,
                    })
                    .await
                    .is_err()
                {
                    tracing::error!("Vault disconnected");
                    return;
                }

                // 5. CAUSAL WAIT
                let vault_response = reply_rx.await;

                // releases the borrow on self.ingress_governor so we can use `self` again.
                drop(_slot_guard);

                match vault_response {
                    Ok(Ok(())) => {
                        self.system_governor
                            .record_peer_evidence(&peer_id.to_string(), true);
                    }
                    Ok(Err(guardian_error)) => {
                        tracing::warn!(
                            target: "siege_debug",
                            peer = %peer_id,
                            error = ?guardian_error,
                            "Vault rejected ingress payload"
                        );
                        self.system_governor
                            .record_peer_evidence(&peer_id.to_string(), false);
                        // Now this call is allowed because the guard is gone.
                        self.handle_forensic_violation(peer_id, sender_did, guardian_error)
                            .await;
                    }
                    _ => {}
                }
            }
            Err(err) => tracing::warn!(error = %err, "Malformed payload"),
        }

        // RECORD TOTAL METABOLIC COST (Including deserialization)
        self.system_governor
            .record_metabolic_pressure(start_cpu.elapsed());
    }
}

/// RAII Guard to ensure IngressGovernor slots are released even on early returns.
struct SlotGuard<'a> {
    governor: &'a mut IngressGovernor,
    peer_id: NetworkId,
}

impl<'a> SlotGuard<'a> {
    fn new(governor: &'a mut IngressGovernor, peer_id: NetworkId) -> Self {
        Self { governor, peer_id }
    }
}

impl<'a> Drop for SlotGuard<'a> {
    fn drop(&mut self) {
        // This is the "Magic": No matter how handle_network_ingress exits,
        // this line runs, preventing "Zombie Slots" from clogging the node.
        self.governor.release_slot(&self.peer_id);
    }
}

// Ephemeral Bootstrap
impl<I: IngressPort, E: EgressPort + 'static> MeshSentinel<I, E, NoOpJournal> {
    pub async fn new_at_path(path: &str, ingress: I, egress: E) -> Result<Self, Box<dyn Error>> {
        let mut config = NodeConfig::default();
        config.storage.vault_path = path.to_string();
        let identity = PhalanxIdentity::new_ephemeral();
        let trust_registry = TrustRegistry::build(&config).await;
        let reputation_cache = trust_registry.projection_handle();
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
