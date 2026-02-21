use crate::security::trust::TrustRegistry;

use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, span, Level};

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::base::types::{
    ByteCapacity, MeshTopic, NodeMode, PowerState, TrafficGovernor, UnitInterval, VitalityRate,
};
use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use crate::primitives::shards::ShardChunk;
use crate::primitives::shards::ShardError;
use crate::primitives::time::TrustedClock;
use crate::security::e2ee::SymmetricKey;
use crate::security::ingress::IngressOrchestrator;
use crate::security::telemetry::{ChaosMode, DiscoverySource, NodeRole, SimEvent};
use crate::storage::reassembler::{Reassembler, TransientJournal};
use crate::storage::vault::Guardian;
use crate::transport::health::HealthTracker;

// INTEGRATING SECURITY GATES
use crate::security::gate::{ForensicGate, PrivacyGate, WitnessGate};

use crate::primitives::shards::{create_video_shard, Evidence, ShardId, StorageSequence, VolleyId};

// =========================================================================================
//  POLYFILL: Simulation Journal
// =========================================================================================

pub struct SimJournal;
#[async_trait::async_trait]
impl TransientJournal for SimJournal {
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
}

// =========================================================================================
//  INFRASTRUCTURE: The Harness
// =========================================================================================

pub struct SimulationHarness {
    pub nodes: Arc<RwLock<HashMap<Did, mpsc::Sender<SimEvent>>>>,
    pub broadcast_channel: mpsc::Sender<(Did, NetworkId, SimEvent)>,
    pub telemetry_tx: mpsc::Sender<SimEvent>,
    pub config: PhalanxConfig,
    pub identity_registry: Arc<RwLock<HashMap<Did, NetworkId>>>,
    pub physics: PhalanxPhysics,
}

impl SimulationHarness {
    #[must_use]
    pub fn init_mesh(
        config: PhalanxConfig,
        physics: PhalanxPhysics,
    ) -> (Self, mpsc::Receiver<SimEvent>) {
        let (broadcast_tx, broadcast_rx) = mpsc::channel(1024);
        let (telemetry_tx, telemetry_rx) = mpsc::channel(4096);
        let nodes = Arc::new(RwLock::new(HashMap::new()));

        let harness = Self {
            nodes: nodes.clone(),
            identity_registry: Arc::new(RwLock::new(HashMap::new())),
            broadcast_channel: broadcast_tx,
            telemetry_tx: telemetry_tx.clone(),
            config,
            physics,
        };

        let nodes_ref = nodes;
        let telemetry_tap = telemetry_tx;

        tokio::spawn(async move {
            Self::run_mesh_relay(nodes_ref, broadcast_rx, telemetry_tap).await;
        });

        (harness, telemetry_rx)
    }

    pub async fn resolve_did(&self, did: &Did) -> Option<NetworkId> {
        self.identity_registry.read().await.get(did).copied()
    }

    pub async fn inject_chaos(&self, target_did: &Did, mode: ChaosMode) {
        let target_network_id_opt = self.resolve_did(target_did).await;

        if let Some(target_network_id) = target_network_id_opt {
            if let Some(tx) = self.nodes.read().await.get(target_did) {
                info!(target: "phalanx::chaos", node=%target_did, ?mode, "Injecting Chaos Event");
                let event = SimEvent::ChaosUpdate {
                    target: target_network_id,
                    mode,
                };
                let _ = tx.send(event).await;
            }
        } else {
            error!(target: "phalanx::chaos", node=%target_did, "Failed to resolve DID to NetworkId for Chaos injection.");
        }
    }

    pub async fn spawn_node(&mut self, name: &str, role: NodeRole) -> Did {
        let (identity, _) = match PhalanxIdentity::generate() {
            Ok(res) => res,
            Err(e) => {
                error!(
                    node = %name,
                    error = %e,
                    "CRITICAL: Failed to generate node identity. Aborting spawn."
                );
                return Did::default();
            }
        };
        let node_did = identity.did.clone();
        let network_id = NetworkId::random();

        let (node_tx, node_rx) = mpsc::channel::<SimEvent>(100);

        {
            self.identity_registry
                .write()
                .await
                .insert(node_did.clone(), network_id);
            self.nodes.write().await.insert(node_did.clone(), node_tx);
        }

        info!(node = %name, ?role, "Initializing Node Actor");

        let _ = self
            .broadcast_channel
            .send((
                node_did.clone(),
                network_id,
                SimEvent::PeerDiscovered {
                    peer: network_id,
                    role,
                    source: DiscoverySource::Bootstrap,
                },
            ))
            .await;

        let sim_config = SimConfig {
            name: name.to_string(),
            identity,
            network_id,
            role,
            config: self.config.clone(),
            physics: self.physics,
        };

        let actor = SimNode::new(
            sim_config,
            self.broadcast_channel.clone(),
            self.telemetry_tx.clone(),
        )
        .await;

        tokio::spawn(async move {
            actor.run(node_rx).await;
        });

        node_did
    }

    async fn run_mesh_relay(
        nodes: Arc<RwLock<HashMap<Did, mpsc::Sender<SimEvent>>>>,
        mut relay_rx: mpsc::Receiver<(Did, NetworkId, SimEvent)>,
        telemetry_tx: mpsc::Sender<SimEvent>,
    ) {
        while let Some((_sender_did, _sender_peer, event)) = relay_rx.recv().await {
            let _ = telemetry_tx.try_send(event.clone());

            let current_nodes = nodes.read().await;
            for node_tx in current_nodes.values() {
                let _ = node_tx.send(event.clone()).await;
            }
        }
    }

    pub async fn broadcast(&self, sender_did: &Did, event: SimEvent) {
        let network_id = self
            .resolve_did(sender_did)
            .await
            .unwrap_or_else(NetworkId::random);

        let _ = self
            .broadcast_channel
            .send((sender_did.clone(), network_id, event))
            .await;
    }
}

// =========================================================================================
//  LOGIC: The Node Actor
// =========================================================================================

pub struct SimConfig {
    pub name: String,
    pub identity: PhalanxIdentity,
    pub network_id: NetworkId,
    pub role: NodeRole,
    pub config: PhalanxConfig,
    pub physics: PhalanxPhysics,
}

struct SimNode {
    name: String,
    identity: PhalanxIdentity,
    network_id: NetworkId,
    role: NodeRole,

    reassembler: Reassembler,
    storage: Guardian,
    config: PhalanxConfig,
    physics: PhalanxPhysics,
    health_tracker: HealthTracker,
    governor: TrafficGovernor,
    mode: NodeMode,

    chaos_mode: ChaosMode,
    known_strongholds: Vec<NetworkId>,

    seq_counter: StorageSequence,
    staged_bytes: ByteCapacity,
    start_time: std::time::Instant,

    broadcast_tx: mpsc::Sender<(Did, NetworkId, SimEvent)>,
    telemetry_tx: mpsc::Sender<SimEvent>,

    network_key: SymmetricKey,
    trust_registry: TrustRegistry,
    clock: TrustedClock,
}

impl SimNode {
    async fn new(
        sim_config: SimConfig,
        broadcast_tx: mpsc::Sender<(Did, NetworkId, SimEvent)>,
        telemetry_tx: mpsc::Sender<SimEvent>,
    ) -> Self {
        let reassembler = Reassembler::new();

        let vault_path = format!("sim_vault/{}", sim_config.name);
        let storage = Guardian::new(
            &vault_path,
            &sim_config.config,
            sim_config.identity.did.clone(),
        );

        let mut trust_config = PhalanxConfig::default();
        trust_config.storage.vault_path = vault_path.to_string();
        let trust_registry = TrustRegistry::build(&trust_config).await;

        let clock = TrustedClock::new();

        Self {
            name: sim_config.name,
            identity: sim_config.identity,
            network_id: sim_config.network_id,
            role: sim_config.role,
            config: sim_config.config,
            physics: sim_config.physics,
            reassembler,
            storage,
            health_tracker: HealthTracker::new(),
            governor: TrafficGovernor::new(),
            mode: NodeMode::Standard,
            chaos_mode: ChaosMode::Stable,
            known_strongholds: Vec::new(),
            seq_counter: StorageSequence::default(),
            staged_bytes: ByteCapacity::default(),
            start_time: std::time::Instant::now(),
            broadcast_tx,
            telemetry_tx,
            network_key: SymmetricKey([0x42; 32]),
            trust_registry,
            clock,
        }
    }

    async fn run(mut self, mut rx: mpsc::Receiver<SimEvent>) {
        let span = span!(Level::INFO, "sim_node", node = %self.name, network_id = %self.network_id);
        let _enter = span.enter();
        info!("Actor Loop Started");

        let mut cleanup_tick = tokio::time::interval(self.physics.shard_timeout());
        let mut data_tick = tokio::time::interval(Duration::from_millis(100));
        let mut physics_tick = tokio::time::interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                _ = physics_tick.tick() => {
                    self.step_physics().await;
                }
                _ = data_tick.tick() => {
                    if self.role != NodeRole::Stronghold {
                        self.step_traffic().await;
                    }
                }
                _ = cleanup_tick.tick() => {
                    // Legacy manual state pruning logic removed.
                    // Crucible flush protocols manage state transitions inherently.
                }
                Some(event) = rx.recv() => {
                    self.handle_event(event).await;
                }
            }
        }
    }

    async fn step_physics(&mut self) {
        if matches!(self.chaos_mode, ChaosMode::Hyperactive) {
            self.physics.apply_system_load(UnitInterval::new(0.95));
        } else {
            self.physics.apply_system_load(UnitInterval::new(0.10));
        }

        let vitality =
            VitalityRate::calculate(&self.physics, PowerState::Normal, UnitInterval::new(0.10));

        if let ChaosMode::PacketLoss(prob) = self.chaos_mode {
            if rand::rng().random_range(0.0..1.0) < prob {
                return;
            }
        }

        let event = SimEvent::Heartbeat {
            origin: self.network_id,
            uptime: self.start_time.elapsed().as_secs(),
            health: vitality,
        };

        let _ = self
            .broadcast_tx
            .send((self.identity.did.clone(), self.network_id, event))
            .await;
    }

    async fn step_traffic(&mut self) {
        let spawn_chance = if matches!(self.chaos_mode, ChaosMode::Hyperactive) {
            0.9
        } else {
            0.3
        };

        if rand::rng().random_range(0.0..1.0) < spawn_chance {
            self.seq_counter += 1;
            let frames = vec![vec![1; 512]];
            let shard_id = ShardId(self.seq_counter.0);

            let shard_result =
                create_video_shard(frames, self.seq_counter, 30, VolleyId::new("sim_volley")).gate(
                    "sim_gen_err",
                    &self.network_id,
                    "Video generation failed",
                );

            if let Ok(shard) = shard_result {
                let chunks_result = Evidence::Video(shard)
                    .safeguard(&self.network_key)
                    .and_then(|ev| ev.seal(&self.identity, self.network_id))
                    .map(|mut envelope| {
                        if matches!(self.chaos_mode, ChaosMode::Hyperactive) {
                            if let Evidence::Video(ref mut v) = envelope.evidence {
                                v.fps = 145;
                            }
                        }
                        envelope
                    })
                    .and_then(|env| {
                        env.chunkify(shard_id).gate(
                            "sim_chunk_err",
                            &self.network_id,
                            "Discretization failed",
                        )
                    });

                if let Ok(chunks) = chunks_result {
                    if let Some(first_chunk) = chunks.first() {
                        let event = SimEvent::ShardPublished {
                            origin: self.network_id,
                            chunk: first_chunk.clone(),
                        };

                        let _ = self
                            .broadcast_tx
                            .send((self.identity.did.clone(), self.network_id, event))
                            .await;
                    }
                }
            }
        }
    }

    async fn handle_event(&mut self, event: SimEvent) {
        if let ChaosMode::HighLatency(ms) = self.chaos_mode {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }

        match event {
            SimEvent::Shutdown => std::process::exit(0),

            SimEvent::ChaosUpdate { target, mode } => {
                if target == self.network_id {
                    self.chaos_mode = mode;
                }
            }

            SimEvent::ShardPublished { origin, chunk }
            | SimEvent::ChunkIngested { origin, chunk } => {
                if origin != self.network_id {
                    self.process_inbound_chunk(origin, chunk).await;
                }
            }

            SimEvent::PeerDiscovered { peer, role, .. } => {
                if peer != self.network_id
                    && role == NodeRole::Stronghold
                    && !self.known_strongholds.contains(&peer)
                {
                    self.known_strongholds.push(peer);
                    debug!("Registered Stronghold: {}", peer);
                }
            }

            SimEvent::SystemStressUpdate(interval) => {
                self.physics.apply_system_load(interval);
            }

            _ => {}
        }
    }

    async fn process_inbound_chunk(
        &mut self,
        origin: NetworkId,
        chunk: crate::primitives::shards::ShardChunk,
    ) {
        let size = chunk.data.len() as u64;
        let topic = MeshTopic::new("sim_topic");
        let sender_did = chunk.owner_did.clone();

        // 1. Allocate Parameter Objects
        let ctx = crate::security::ingress::IngressContext {
            config: &self.config,
            identity: &self.identity,
            network_id: self.network_id,
            clock: &self.clock,
            governor: &self.governor,
            mode: self.mode,
        };

        let mut journal = SimJournal;

        let mut pipeline = crate::security::ingress::SecurityPipeline {
            reassembler: &mut self.reassembler,
            guardian: &mut self.storage,
            trust_registry: &mut self.trust_registry,
            health_tracker: &mut self.health_tracker,
            journal: &mut journal,
        };

        // 2. Execute Shared Orchestration
        let orchestration_result =
            IngressOrchestrator::process_chunk(chunk, &topic, &ctx, &mut pipeline).await;

        // 3. Handle Simulation-Specific Telemetry
        match orchestration_result {
            Ok(Some(_finalized_size)) => {
                let _ = self.telemetry_tx.try_send(SimEvent::ShardProcessed {
                    peer_id: origin,
                    byte_size: ByteCapacity(size),
                });

                if self.role == NodeRole::Guardian && origin != self.network_id {
                    let _ = self.telemetry_tx.try_send(SimEvent::OffloadComplete {
                        origin,
                        target: self.network_id,
                        size: ByteCapacity(size),
                    });
                }

                if self.role == NodeRole::Guardian {
                    self.staged_bytes += size;
                    let threshold = ByteCapacity(4096 * 5);

                    if self.staged_bytes > threshold && !self.known_strongholds.is_empty() {
                        let target_idx = rand::rng().random_range(0..self.known_strongholds.len());
                        if let Some(target) = self.known_strongholds.get(target_idx).cloned() {
                            let _ = self.telemetry_tx.try_send(SimEvent::OffloadComplete {
                                origin: self.network_id,
                                target,
                                size: self.staged_bytes,
                            });
                            self.staged_bytes = ByteCapacity::default();
                        }
                    }
                }
            }
            Ok(None) => {}
            Err(crate::security::ingress::IngressError::Blacklisted(_)) => {
                let _ = self.telemetry_tx.try_send(SimEvent::AttackAttemptBlocked {
                    attacker: origin,
                    target: self.network_id,
                    reason: "Preemptive Gate: Peer is blacklisted".to_string(),
                });
            }
            Err(e) => {
                self.trust_registry
                    .record_offense(
                        &sender_did,
                        crate::security::trust::Offense::ReplayAttack,
                        &self.clock,
                    )
                    .await;

                let send_result = self
                    .telemetry_tx
                    .send(SimEvent::AttackAttemptBlocked {
                        attacker: origin,
                        target: self.network_id,
                        reason: format!("Trust Threshold Breached: {}", e),
                    })
                    .await;

                if let Err(err) = send_result {
                    tracing::error!(
                        target: "phalanx::telemetry",
                        "CRITICAL: Failed to emit AttackAttemptBlocked event. Telemetry receiver dropped: {}",
                        err
                    );
                }
            }
        }
    }
}
