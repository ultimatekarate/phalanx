use rand::Rng;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, info, span, Level};

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::base::types::{ByteCapacity, PowerState, UnitInterval, VitalityRate};
use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use crate::security::sentinel::{ControlMessage, Sentinel};
use crate::security::telemetry::{ChaosMode, DiscoverySource, NodeRole, SimEvent};
use crate::storage::vault::Guardian;

use crate::primitives::shards::{
    chunkify, create_video_shard, ChunkType, Evidence, ShardId, StorageSequence, WitnessEnvelope,
};

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

        let nodes_ref = nodes.clone();
        let telemetry_tap = telemetry_tx.clone();

        // Spawn the "Ether" (Network Relay)
        tokio::spawn(async move {
            Self::run_mesh_relay(nodes_ref, broadcast_rx, telemetry_tap).await;
        });

        (harness, telemetry_rx)
    }

    pub async fn resolve_did(&self, did: &Did) -> Option<NetworkId> {
        self.identity_registry.read().await.get(did).cloned()
    }

    pub async fn inject_chaos(&self, target_did: &Did, mode: ChaosMode) {
        if let Some(tx) = self.nodes.read().await.get(target_did) {
            info!(target: "phalanx::chaos", node=%target_did, ?mode, "Injecting Chaos Event");
            let _ = tx.send(SimEvent::ChaosUpdate(mode)).await;
        }
    }

    pub async fn spawn_node(&mut self, name: &str, role: NodeRole) -> Did {
        let (identity, _) = PhalanxIdentity::generate();
        let node_did = identity.did.clone();
        let network_id = NetworkId::random();

        let (node_tx, node_rx) = mpsc::channel::<SimEvent>(100);

        // Register Node in the "Ether"
        {
            self.identity_registry
                .write()
                .await
                .insert(node_did.clone(), network_id);
            self.nodes.write().await.insert(node_did.clone(), node_tx);
        }

        info!(node = %name, ?role, "Initializing Node Actor");

        // Broadcast Presence
        let _ = self
            .broadcast_channel
            .send((
                node_did.clone(),
                network_id,
                SimEvent::PeerDiscovered {
                    peer: network_id,
                    role,
                    source: DiscoverySource::Identify,
                },
            ))
            .await;

        // [REFACTOR] Configuration Object Construction
        let sim_config = SimConfig {
            name: name.to_string(),
            identity,
            network_id,
            role,
            config: self.config.clone(),
            physics: self.physics, // Copy trait assumed for PhalanxPhysics
        };

        // Instantiate the Actor
        let actor = SimNode::new(
            sim_config,
            self.broadcast_channel.clone(),
            self.telemetry_tx.clone(),
        );

        // Run the Actor
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
        while let Some((sender_did, _sender_peer, event)) = relay_rx.recv().await {
            // Tap into the stream for the Dashboard
            let _ = telemetry_tx.try_send(event.clone());

            // Forward to all other nodes
            let current_nodes = nodes.read().await;
            for (did, node_tx) in current_nodes.iter() {
                if did != &sender_did {
                    let _ = node_tx.send(event.clone()).await;
                }
            }
        }
    }

    pub async fn broadcast(&self, sender_did: &Did, event: SimEvent) {
        // Try to resolve the NetworkId, or use a random one if this is an
        // external/unregistered actor (like a test attacker).
        let network_id = self
            .resolve_did(sender_did)
            .await
            .unwrap_or_else(NetworkId::random);

        // Send to the relay channel, which distributes to all active actors.
        let _ = self
            .broadcast_channel
            .send((sender_did.clone(), network_id, event))
            .await;
    }
}

// =========================================================================================
//  LOGIC: The Node Actor
// =========================================================================================

/// Configuration container for initializing a `SimNode`.
/// Encapsulates static properties to satisfy `clippy::too_many_arguments`.
pub struct SimConfig {
    pub name: String,
    pub identity: PhalanxIdentity,
    pub network_id: NetworkId,
    pub role: NodeRole,
    pub config: PhalanxConfig,
    pub physics: PhalanxPhysics,
}

struct SimNode {
    // Identity
    name: String,
    identity: PhalanxIdentity,
    network_id: NetworkId,
    role: NodeRole,

    // Subsystems
    sentinel: Sentinel,
    storage: Guardian,
    config: PhalanxConfig,
    physics: PhalanxPhysics,

    // Internal State
    chaos_mode: ChaosMode,
    known_strongholds: Vec<NetworkId>,
    seq_counter: u64,
    staged_bytes: u64,

    // Communications
    broadcast_tx: mpsc::Sender<(Did, NetworkId, SimEvent)>,
    telemetry_tx: mpsc::Sender<SimEvent>,
}

impl SimNode {
    /// Spawns a new actor representing a single node in the network simulation.
    fn new(
        sim_config: SimConfig,
        broadcast_tx: mpsc::Sender<(Did, NetworkId, SimEvent)>,
        telemetry_tx: mpsc::Sender<SimEvent>,
    ) -> Self {
        let sentinel = Sentinel::new(&sim_config.config);
        let storage = Guardian::new(
            &format!("sim_vault/{}", sim_config.name),
            &sim_config.config,
            sim_config.identity.did.clone(),
        );

        Self {
            name: sim_config.name,
            identity: sim_config.identity,
            network_id: sim_config.network_id,
            role: sim_config.role,
            config: sim_config.config,
            physics: sim_config.physics,
            sentinel,
            storage,
            chaos_mode: ChaosMode::Stable,
            known_strongholds: Vec::new(),
            seq_counter: 0,
            staged_bytes: 0,
            broadcast_tx,
            telemetry_tx,
        }
    }

    async fn run(mut self, mut rx: mpsc::Receiver<SimEvent>) {
        let span = span!(Level::INFO, "sim_node", node = %self.name, network_id = %self.network_id);
        let _enter = span.enter();
        info!("Actor Loop Started");

        let mut cleanup_tick = tokio::time::interval(self.physics.shard_timeout());
        let mut data_tick = tokio::time::interval(Duration::from_millis(100));
        let mut physics_tick = tokio::time::interval(Duration::from_millis(500)); // Slower heartbeat

        loop {
            // Apply Chaos Load
            if matches!(self.chaos_mode, ChaosMode::Hyperactive) {
                self.physics.artificial_load = 0.95;
            }

            tokio::select! {
                // 1. Vitality & Heartbeats
                _ = physics_tick.tick() => {
                    self.step_physics().await;
                }

                // 2. Traffic Generation (Normal & Chaos)
                _ = data_tick.tick() => {
                    if self.role != NodeRole::Stronghold {
                        self.step_traffic().await;
                    }
                }

                // 3. Maintenance
                _ = cleanup_tick.tick() => {
                    self.sentinel.prune_stale_buffers(&self.config, &self.physics);
                    self.storage.archive_stale_sessions(self.physics.shard_timeout());
                }

                // 4. Message Handling
                Some(event) = rx.recv() => {
                    self.handle_event(event).await;
                }
            }
        }
    }

    // --- BEHAVIORS ---

    async fn step_physics(&mut self) {
        // Calculate Load
        let micro_load =
            self.storage.micro_layer.len() as f32 / (self.config.storage.max_peers * 5) as f32;
        let macro_load =
            self.storage.macro_layer.len() as f32 / self.config.storage.max_peers as f32;
        let total_raw_load = micro_load + macro_load + self.physics.artificial_load;
        let load = UnitInterval::new(total_raw_load);

        let vitality = VitalityRate::calculate(&self.physics, PowerState::Normal, load);
        let interval = vitality.as_duration();

        // Chaos: Packet Loss
        if let ChaosMode::PacketLoss(prob) = self.chaos_mode {
            if rand::rng().random_range(0.0..1.0) < prob {
                return; // Simulate dropped heartbeat
            }
        }

        // Broadcast Heartbeat
        let mut msg = ControlMessage {
            sender: self.network_id,
            load_factor: load.as_f32(),
            storage_remaining_mb: 1024,
            heartbeat_ms: interval.as_millis() as u64,
            is_leaf: false,
        };

        if matches!(self.chaos_mode, ChaosMode::Byzantine) {
            msg.storage_remaining_mb = 99999999;
        }

        if let Ok(data) = postcard::to_stdvec(&msg) {
            let event = SimEvent::Heartbeat {
                origin: self.network_id,
                payload: data,
            };
            let _ = self
                .broadcast_tx
                .send((self.identity.did.clone(), self.network_id, event))
                .await;
        }
    }

    async fn step_traffic(&mut self) {
        let spawn_chance = if matches!(self.chaos_mode, ChaosMode::Hyperactive) {
            0.5
        } else {
            0.1
        };

        if rand::rng().random_range(0.0..1.0) < spawn_chance {
            self.seq_counter += 1;
            let frames = vec![vec![1; 512]];

            // 1. Create Valid Data (FPS 30)
            let shard = create_video_shard(
                frames,
                StorageSequence(self.seq_counter as u32),
                30,
                "sim_volley".into(),
            );

            // 2. Sign it (Locks signature to 30 FPS)
            let mut envelope =
                WitnessEnvelope::new(Evidence::Video(shard), &self.identity, self.network_id);

            // 3. TAMPER (Chaos Logic)
            // Modify data AFTER signing to trigger invalid signature detection at the receiver
            if matches!(self.chaos_mode, ChaosMode::Hyperactive) {
                if let Evidence::Video(ref mut v) = envelope.evidence {
                    v.fps = 145;
                }
            }

            // 4. Chunkify & Broadcast
            if let Ok(data) = postcard::to_stdvec(&envelope) {
                let chunks = chunkify(
                    ShardId(self.seq_counter as u32),
                    data,
                    4096,
                    self.identity.did.clone(),
                    ChunkType::Witnessed,
                );
                let event = SimEvent::ChunkIngested {
                    origin: self.network_id,
                    chunk: chunks[0].clone(),
                };
                let _ = self
                    .broadcast_tx
                    .send((self.identity.did.clone(), self.network_id, event))
                    .await;
            }
        }
    }

    async fn handle_event(&mut self, event: SimEvent) {
        // Chaos: High Latency
        if let ChaosMode::HighLatency(ms) = self.chaos_mode {
            tokio::time::sleep(Duration::from_millis(ms)).await;
        }

        match event {
            SimEvent::Shutdown => std::process::exit(0),

            SimEvent::ChaosUpdate(mode) => {
                self.chaos_mode = mode;
                // Note: We don't need to adjust tickers here anymore, logic handles it naturally
            }

            SimEvent::ChunkIngested { origin, chunk } => {
                if origin != self.network_id {
                    self.process_inbound_chunk(origin, chunk).await;
                }
            }

            SimEvent::PeerDiscovered { peer, role, .. } => {
                // Register Strongholds for Offloading
                if role == NodeRole::Stronghold && !self.known_strongholds.contains(&peer) {
                    self.known_strongholds.push(peer);
                    debug!("Registered Stronghold: {}", peer);
                }
            }

            SimEvent::Heartbeat { payload, .. } => {
                if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&payload) {
                    self.sentinel.health_tracker.register_activity(msg);
                }
            }

            // Ignored Events
            SimEvent::ShardProcessed { .. } => {}
            SimEvent::CrucibleFinalized { .. } => {}
            SimEvent::AttackAttemptBlocked { .. } => {}
            SimEvent::OffloadComplete { .. } => {}
            SimEvent::SystemStressUpdate(interval) => {
                self.physics.apply_system_load(interval);
            }
        }
    }

    async fn process_inbound_chunk(
        &mut self,
        origin: NetworkId,
        chunk: crate::primitives::shards::ShardChunk,
    ) {
        // 1. Snapshot Reputation
        let was_blacklisted = self
            .storage
            .peer_registry
            .get(&chunk.owner_did)
            .is_some_and(|r| r.is_blacklisted);
        let pre_sigs = self
            .storage
            .peer_registry
            .get(&chunk.owner_did)
            .map_or(0, |r| r.invalid_sigs);

        // 2. Ingest (Triggering Guardian Logic)
        self.storage.ingest_chunk(chunk.clone(), false);

        // 3. Inspect Result
        let current_rep = self.storage.peer_registry.get(&chunk.owner_did);
        let is_blacklisted = current_rep.is_some_and(|r| r.is_blacklisted);
        let post_sigs = current_rep.map_or(0, |r| r.invalid_sigs);

        // 4. Report Defense
        if is_blacklisted {
            let _ = self.telemetry_tx.try_send(SimEvent::AttackAttemptBlocked {
                attacker: origin,
                reason: if !was_blacklisted {
                    "Vampire Attack: BANNED".into()
                } else {
                    "Traffic Shedding: Blacklisted Peer".into()
                },
            });
        } else if post_sigs > pre_sigs {
            let _ = self.telemetry_tx.try_send(SimEvent::AttackAttemptBlocked {
                attacker: origin,
                reason: format!("Vampire Signature Detected (Penalty {}/5)", post_sigs),
            });
        } else {
            // Valid Data
            let size = chunk.data.len() as u64;
            let _ = self.telemetry_tx.try_send(SimEvent::ShardProcessed {
                peer_id: origin,
                byte_size: ByteCapacity(size),
            });

            // 5. OFFLOAD LOGIC (Guardians Only)
            if self.role == NodeRole::Guardian {
                self.staged_bytes += size;
                const OFFLOAD_THRESHOLD: u64 = 4096 * 5;

                if self.staged_bytes > OFFLOAD_THRESHOLD && !self.known_strongholds.is_empty() {
                    let target_idx = rand::rng().random_range(0..self.known_strongholds.len());
                    let target = self.known_strongholds[target_idx];

                    let _ = self.telemetry_tx.try_send(SimEvent::OffloadComplete {
                        origin: self.network_id,
                        target,
                        size: ByteCapacity(self.staged_bytes),
                    });

                    self.staged_bytes = 0;
                }
            }
        }
    }
}
