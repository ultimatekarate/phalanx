use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, span, Level};
use std::sync::Arc;
use std::time::Duration;
use rand::Rng; 

use crate::primitives::identity::{PhalanxIdentity, Did, NetworkId};
use crate::security::sentinel::{Sentinel, ControlMessage};
use crate::base::types::{ByteCapacity, PowerState, UnitInterval, VitalityRate};
use crate::storage::vault::Guardian;
use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::security::telemetry::{SimEvent, ChaosMode}; 

// --- NEW IMPORTS REQUIRED FOR ATTACK GENERATION ---
use crate::primitives::shards::{create_video_shard, WitnessEnvelope, Evidence, chunkify, StorageSequence, ShardId, ChunkType};

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
        physics: PhalanxPhysics
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
            physics
        };

        let nodes_ref = nodes.clone();
        let telemetry_tap = telemetry_tx.clone();
        
        tokio::spawn(async move {
            Self::run_mesh_relay(nodes_ref, broadcast_rx, telemetry_tap).await;
        });

        (harness, telemetry_rx)
    }

    pub async fn resolve_did(&self, did: &Did) -> Option<NetworkId> {
        let map = self.identity_registry.read().await;
        map.get(did).cloned()
    }
    
    async fn run_mesh_relay(
        nodes: Arc<RwLock<HashMap<Did, mpsc::Sender<SimEvent>>>>, 
        mut relay_rx: mpsc::Receiver<(Did, NetworkId, SimEvent)>,
        telemetry_tx: mpsc::Sender<SimEvent> 
    ) {
        while let Some((sender_did, _sender_peer, event)) = relay_rx.recv().await {
            let _ = telemetry_tx.try_send(event.clone());

            let current_nodes = nodes.read().await;
            for (did, node_tx) in current_nodes.iter() {
                if did != &sender_did {
                    let _ = node_tx.send(event.clone()).await;
                }
            }
        }
    }

    pub async fn stop_node(&mut self, did: &Did) {
        let mut nodes_guard = self.nodes.write().await;
        if let Some(tx) = nodes_guard.remove(did) {
            let _ = tx.send(SimEvent::Shutdown).await;
            warn!(node_did = %did, "Node stopped manually via harness");
        }
    }

    pub async fn inject_chaos(&self, target_did: &Did, mode: ChaosMode) {
        let nodes = self.nodes.read().await;
        if let Some(tx) = nodes.get(target_did) {
            info!(target: "phalanx::chaos", node=%target_did, ?mode, "Injecting Chaos Event");
            let _ = tx.send(SimEvent::ChaosUpdate(mode)).await;
        }
    }

    pub async fn lookup_did(&self, network_id: &NetworkId) -> Option<Did> {
        let registry = self.identity_registry.read().await;
        registry.iter()
            .find(|(_, net_id)| *net_id == network_id)
            .map(|(did, _)| did.clone())
    }

    pub async fn spawn_node(&mut self, name: &str) -> Did {
        let name_owned = name.to_string();
        let (identity, _) = PhalanxIdentity::generate();
        let node_did = identity.did.clone();
        let return_did = node_did.clone();
        let node_network_id = NetworkId::random();
        
        let (node_tx, mut node_rx) = mpsc::channel::<SimEvent>(100);

        let registry_clone = Arc::clone(&self.identity_registry);
        let broadcast_tx = self.broadcast_channel.clone();
        let telemetry_tx = self.telemetry_tx.clone(); 
        
        let config = self.config.clone();
        let mut physics = self.physics.clone(); 

        {
            let mut peer_guard = self.identity_registry.write().await;
            peer_guard.insert(node_did.clone(), node_network_id);
            let mut nodes_guard = self.nodes.write().await;
            nodes_guard.insert(node_did.clone(), node_tx);
        }
        
        info!(node = %name_owned, "Initializing Guardian");

        let mut sentinel = Sentinel::new(&config);
        let mut storage = Guardian::new(&format!("sim_vault/{}", name), &config, identity.did.clone());

        tokio::spawn(async move {
            let span = span!(Level::INFO, "sim_node", node = %name_owned, network_id = %node_network_id);
            let _enter = span.enter();
            info!("Virtual node loop started");

            let mut chaos_mode = ChaosMode::Stable;
            let mut cleanup_tick = tokio::time::interval(physics.shard_timeout());
            let mut data_tick = tokio::time::interval(Duration::from_millis(100));
            // Track sequences for our generated data
            let mut seq_counter = 0; 

            loop {
                if matches!(chaos_mode, ChaosMode::Hyperactive) {
                    physics.artificial_load = 0.95; 
                }

                let micro_load = storage.micro_layer.len() as f32 / (config.storage.max_peers * 5) as f32;
                let macro_load = storage.macro_layer.len() as f32 / config.storage.max_peers as f32;
                let total_raw_load = micro_load + macro_load + physics.artificial_load;
                let load = UnitInterval::new(total_raw_load);
                let vitality = VitalityRate::calculate(&physics, PowerState::Normal, load);
                let current_interval = vitality.as_duration();

                tokio::select! {
                    _ = tokio::time::sleep(current_interval)=> {
                        let drop_packet = if let ChaosMode::PacketLoss(prob) = chaos_mode {
                            rand::rng().random_range(0.0..1.0) < prob
                        } else { false };

                        if !drop_packet {
                            let mut msg = ControlMessage {
                                sender: node_network_id,
                                load_factor: load.as_f32(),
                                storage_remaining_mb: 1024,
                                heartbeat_ms: current_interval.as_millis() as u64,
                                is_leaf: false
                            };
                            
                            if matches!(chaos_mode, ChaosMode::Byzantine) {
                                msg.storage_remaining_mb = 99999999; 
                            }

                            if let Ok(data) = postcard::to_stdvec(&msg) {
                                let event = SimEvent::Heartbeat { 
                                    origin: node_network_id, 
                                    payload: data 
                                };
                                let _ = broadcast_tx.send((node_did.clone(), node_network_id, event)).await;
                            }
                        }
                    }

                    // --- UPDATED TRAFFIC GENERATOR ---
                    _ = data_tick.tick() => {
                        let spawn_chance = if matches!(chaos_mode, ChaosMode::Hyperactive) { 
                            0.5 // High chance for Vampire Mode
                        } else { 
                            0.1 // Low chance for Normal Mode
                        };

                        if rand::rng().random_range(0.0..1.0) < spawn_chance {
                            seq_counter += 1;
                            let frames = vec![vec![1; 512]]; 
                            
                            // 1. Create the shard
                            let shard = create_video_shard(
                                frames, 
                                StorageSequence(seq_counter), 
                                30, 
                                "sim_volley".into()
                            );
                            
                             // Wrap in Envelope (Signed by THIS node)
                            let mut envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, node_network_id);
                            
                            // 2. Poison the data AFTER it has been signed.
                            if matches!(chaos_mode, ChaosMode::Hyperactive) {
                                if let Evidence::Video(ref mut v) = envelope.evidence { 
                                     v.fps = 145; // The signature expects 30, finds 145 -> REJECT!
                                }
                            }
                             // 3. Chunkify & BROADCAST
                             // Use large chunk size (4096) to force immediate reassembly at receiver
                            if let Ok(data) = postcard::to_stdvec(&envelope) {
                                let chunks = chunkify(
                                    ShardId(seq_counter), 
                                    data, 
                                    4096, 
                                    node_did.clone(), 
                                    ChunkType::Witnessed
                                );

                                 // Broadcast triggers 'ChunkIngested' on other nodes
                                let event = SimEvent::ChunkIngested { 
                                    origin: node_network_id, 
                                    chunk: chunks[0].clone() 
                                };
                                
                                let _ = broadcast_tx.send((node_did.clone(), node_network_id, event)).await;
                            }
                        }
                    }

                    _ = cleanup_tick.tick() => {
                        sentinel.prune_stale_buffers(&config, &physics);
                        storage.archive_stale_sessions(physics.shard_timeout());
                    }

                    Some(event) = node_rx.recv() => {
                        if let ChaosMode::HighLatency(ms) = chaos_mode {
                            tokio::time::sleep(Duration::from_millis(ms)).await;
                        }

                        match event {
                            SimEvent::Shutdown => break,
                            
                            SimEvent::ChaosUpdate(new_mode) => {
                                chaos_mode = new_mode;
                                if matches!(chaos_mode, ChaosMode::Hyperactive) {
                                    data_tick = tokio::time::interval(Duration::from_millis(10)); 
                                } else {
                                    data_tick = tokio::time::interval(Duration::from_millis(100));
                                }
                            }

                            SimEvent::ChunkIngested { origin, chunk } => {
                                if origin == node_network_id {
                                    // Keep this empty to handle log spam.
                                } else {
                                    // Inbound (Foreign) - DEFENSE LOGIC
                                    
                                    // 1. Snapshot Reputation
                                    let was_blacklisted = storage.peer_registry.get(&chunk.owner_did)
                                        .map_or(false, |r| r.is_blacklisted);
                                    let pre_sigs = storage.peer_registry.get(&chunk.owner_did)
                                        .map_or(0, |r| r.invalid_sigs);

                                    // 2. Ingest (Triggering Guardian Logic in vault.rs)
                                    storage.ingest_chunk(chunk.clone(), false);

                                    // 3. Inspect Result
                                    let current_rep = storage.peer_registry.get(&chunk.owner_did);
                                    let is_blacklisted = current_rep.map_or(false, |r| r.is_blacklisted);
                                    let post_sigs = current_rep.map_or(0, |r| r.invalid_sigs);

                                    // 4. Report Defense
                                    if is_blacklisted {
                                         let _ = telemetry_tx.try_send(SimEvent::AttackAttemptBlocked {
                                            attacker: origin,
                                            reason: if !was_blacklisted { 
                                                "Vampire Attack: Signature Threshold Exceeded (BANNED)".into() 
                                            } else { 
                                                "Traffic Shedding: Blacklisted Peer".into() 
                                            },
                                        });
                                    } else if post_sigs > pre_sigs {
                                        // Penalty applied, but not yet banned
                                        let _ = telemetry_tx.try_send(SimEvent::AttackAttemptBlocked {
                                            attacker: origin,
                                            reason: format!("Vampire Signature Detected (Penalty {}/5)", post_sigs),
                                        });
                                    } else {
                                        // Success
                                        let _ = telemetry_tx.try_send(SimEvent::ShardProcessed { 
                                            peer_id: origin, 
                                            byte_size: ByteCapacity(chunk.data.len() as u64) 
                                        });
                                    }
                                }
                            }
                            
                            SimEvent::Heartbeat { origin: _source_peer, payload: data } => {
                                if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&data) {
                                    sentinel.health_tracker.register_activity(msg);
                                }
                            }
                            SimEvent::PeerDiscovered { peer, source: _ } => {
                                let registry_read = registry_clone.read().await;
                                let found_did = registry_read.iter()
                                    .find(|(_, net_id)| **net_id == peer)
                                    .map(|(d, _)| d.clone());
                                drop(registry_read);

                                if let Some(did) = found_did {
                                    let mut write_guard = registry_clone.write().await;
                                    write_guard.insert(did, peer); 
                                }
                            }
                            SimEvent::ShardProcessed { .. } => {}
                            SimEvent::CrucibleFinalized { .. } => { }
                            SimEvent::AttackAttemptBlocked { .. } => {}
                            SimEvent::SystemStressUpdate(interval) => {
                                physics.apply_system_load(interval);
                            }
                        }
                    }
                }
            }
        });

        return_did
    }

    pub async fn broadcast(&self, sender_did: &Did, event: SimEvent) {
        let nodes_guard = self.nodes.read().await;
        for (did, tx) in nodes_guard.iter() {
            if did != sender_did {
                let _ = tx.send(event.clone()).await;
            }
        }
    }

    pub async fn record_ingestion(&self, peer: NetworkId, bytes: ByteCapacity) {
        let event = SimEvent::ShardProcessed {
            peer_id: peer,
            byte_size: bytes,
        };
        self.publish_to_dashboard(event).await;
    }

    pub async fn publish_to_dashboard(&self, event: SimEvent) {
        if let Err(e) = self.telemetry_tx.try_send(event) {
            tracing::warn!(target: "phalanx::sim", error = %e, "Telemetry channel dropped.");
        }
    }
}