use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, debug, span, Level};
use std::sync::Arc;
use std::time::Duration; // Added Duration
// rand is likely available via your transitive dependencies (ed25519-dalek/sntpc)
// If this fails, add `rand = "0.8"` to crates/phalanx-core/Cargo.toml
use rand::Rng; 

use crate::primitives::identity::{PhalanxIdentity, Did, NetworkId};
use crate::security::sentinel::{Sentinel, ControlMessage};
use crate::base::types::{ByteCapacity, PowerState, UnitInterval, VitalityRate};
use crate::storage::vault::Guardian;
use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::security::telemetry::{SimEvent}; 

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

        // SPAWN RELAY (The Network Tap)
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
            // TAP: Mirror network traffic to dashboard
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
        
        // IMPORTANT: Clone the telemetry handle so the node can talk to the dashboard directly
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

            let mut cleanup_tick = tokio::time::interval(physics.shard_timeout());
            
            // NEW: Traffic Generator Tick (Simulate Video Recording)
            let mut data_tick = tokio::time::interval(Duration::from_millis(100));

            loop {
                // Vitality Logic
                let micro_load = storage.micro_layer.len() as f32 / (config.storage.max_peers * 5) as f32;
                let macro_load = storage.macro_layer.len() as f32 / config.storage.max_peers as f32;
                let total_raw_load = micro_load + macro_load + physics.artificial_load;
                let load = UnitInterval::new(total_raw_load);
                let vitality = VitalityRate::calculate(&physics, PowerState::Normal, load);
                let current_interval = vitality.as_duration();

                tokio::select! {
                    // 1. Heartbeat
                    _ = tokio::time::sleep(current_interval)=> {
                        let msg = ControlMessage {
                            sender: node_network_id,
                            load_factor: load.as_f32(),
                            storage_remaining_mb: 1024,
                            heartbeat_ms: current_interval.as_millis() as u64,
                            is_leaf: false
                        };
                        if let Ok(data) = postcard::to_stdvec(&msg) {
                            let event = SimEvent::Heartbeat { 
                                origin: node_network_id, 
                                payload: data 
                            };
                            let _ = broadcast_tx.send((node_did.clone(), node_network_id, event)).await;
                        }
                    }

                    // 2. Traffic Generation (The "Noise" Maker)
                    _ = data_tick.tick() => {
                        // 10% chance per tick to generate a shard
                        if rand::rng().random_range(0.0..1.0) < 0.1 {
                             let size = ByteCapacity(1024 * rand::rng().random_range(10..100)); // 10KB-100KB

                             // Report "Work Done" to Dashboard
                            let _ = telemetry_tx.try_send(SimEvent::ShardProcessed { 
                                peer_id: node_network_id, 
                                byte_size: size 
                            });

                            debug!("Generated simulated video shard of size {:?}", size);
                        }
                    }

                    // 3. Maintenance
                    _ = cleanup_tick.tick() => {
                        sentinel.prune_stale_buffers(&config, &physics);
                        storage.archive_stale_sessions(physics.shard_timeout());
                    }

                    // 4. Inbox
                    Some(event) = node_rx.recv() => {
                        match event {
                            SimEvent::Shutdown => break,
                            
                            SimEvent::ChunkIngested { origin, chunk } => {
                                if origin == node_network_id {
                                    if let Some(envelope) = sentinel.process_chunk(chunk, &config.network.video_topic, &config, &identity, node_network_id) {
                                        let _ = storage.ingest_envelope(envelope);
                                        // If we ingest real data, report it too
                                        let _ = telemetry_tx.try_send(SimEvent::ShardProcessed { 
                                            peer_id: node_network_id, 
                                            byte_size: ByteCapacity(1024) 
                                        });
                                    }
                                } else {
                                    storage.ingest_chunk(chunk, false);
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
                            
                            SimEvent::ShardProcessed { peer_id: _, byte_size: _ } => {
                                // Already handled by the sender/generator
                            }

                            SimEvent::CrucibleFinalized { volley_id: _ } => { }

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

    // ... broadcast, record_ingestion, publish_to_dashboard methods remain as helpers ...
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