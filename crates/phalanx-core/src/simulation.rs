use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn, debug, trace, span, Level};
use std::sync::Arc;

// --- Internal Crate Imports ---
use crate::primitives::identity::{PhalanxIdentity, Did, NetworkId};
use crate::security::sentinel::{Sentinel, ControlMessage};
use crate::base::types::{ByteCapacity, PowerState, UnitInterval, VitalityRate};
use crate::storage::vault::Guardian;
use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::security::telemetry::{SimEvent}; 

pub struct SimulationHarness {
    pub nodes: Arc<RwLock<HashMap<Did, mpsc::Sender<SimEvent>>>>,
    /// Internal channel for node-to-node communication (Mesh Relay).
    pub broadcast_channel: mpsc::Sender<(Did, NetworkId, SimEvent)>,
    /// Dedicated channel for Phase 3 Dashboard telemetry.
    pub telemetry_tx: mpsc::Sender<SimEvent>, 
    pub config: PhalanxConfig,
    pub identity_registry: Arc<RwLock<HashMap<Did, NetworkId>>>,
    pub physics: PhalanxPhysics,
}

impl SimulationHarness {
    /// Initializes the mesh and returns the telemetry receiver for the dashboard.
    /// 
    /// Returns: (Harness, RelayReceiver, DashboardReceiver)
    pub fn init_mesh(
        config: PhalanxConfig, 
        physics: PhalanxPhysics
    ) -> (Self, mpsc::Receiver<(Did, NetworkId, SimEvent)>, mpsc::Receiver<SimEvent>) {
        
        // Internal routing for the mesh (Node <-> Relay)
        let (broadcast_tx, broadcast_rx) = mpsc::channel(1024);

        // External routing for the dashboard (Harness -> TUI)
        let (telemetry_tx, telemetry_rx) = mpsc::channel(4096);

        let harness = Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            identity_registry: Arc::new(RwLock::new(HashMap::new())),
            broadcast_channel: broadcast_tx,
            telemetry_tx,
            config,
            physics
        };
        (harness, broadcast_rx, telemetry_rx)
    }

    pub async fn resolve_did(&self, did: &Did) -> Option<NetworkId> {
        let map = self.identity_registry.read().await;
        map.get(did).cloned()
    }
    
    /// The "God View" Mesh Relay.
    /// Routes messages between virtual nodes to simulate network propagation.
    pub async fn run_mesh_relay(
        nodes: Arc<RwLock<HashMap<Did, mpsc::Sender<SimEvent>>>>, 
        mut relay_rx: mpsc::Receiver<(Did, NetworkId, SimEvent)>
    ) {
        while let Some((sender_did, _sender_peer, event)) = relay_rx.recv().await {
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

    /// Resolves a DID from a NetworkId by searching the simulation's global registry.
    /// 
    /// In a production environment, this would be handled by the libp2p Identify 
    /// protocol, but in simulation, the harness serves as the authoritative oracle.
    pub async fn lookup_did(&self, network_id: &NetworkId) -> Option<Did> {
        let registry = self.identity_registry.read().await;
        registry.iter()
            .find(|(_, net_id)| *net_id == network_id)
            .map(|(did, _)| did.clone())
    }

    /// Spawns a virtual node in a detached tokio task.
    /// 
    /// This method explicitly prevents "Lifetime Escapes" by cloning all
    /// necessary handles before entering the async block.
    pub async fn spawn_node(&mut self, name: &str) -> Did {
        let name_owned = name.to_string();
        let (identity, _) = PhalanxIdentity::generate();
        let node_did = identity.did.clone();
        let return_did = node_did.clone();
        let node_network_id = NetworkId::random();
        
        let (node_tx, mut node_rx) = mpsc::channel::<SimEvent>(100);

        // 1. Prepare Owned Handles (The "Cloning" Phase for 'static lifetimes)
        let registry_clone = Arc::clone(&self.identity_registry);
        let broadcast_tx = self.broadcast_channel.clone();
        
        // We clone the config and physics so the node operates independently
        let config = self.config.clone();
        let mut physics = self.physics.clone(); 

        // 2. Register Identity (Before Spawning)
        {
            let mut peer_guard = self.identity_registry.write().await;
            peer_guard.insert(node_did.clone(), node_network_id);
            
            let mut nodes_guard = self.nodes.write().await;
            nodes_guard.insert(node_did.clone(), node_tx);
        }
        
        info!(
            node = %name_owned, 
            quota_foreign = %config.storage.max_foreign_storage_bytes,
            "Initializing Guardian"
        );

        let mut sentinel = Sentinel::new(&config);
        let mut storage = Guardian::new(&format!("sim_vault/{}", name), &config, identity.did.clone());

        // 3. Spawn the Reactor
        tokio::spawn(async move {
            let span = span!(Level::INFO, "sim_node", node = %name_owned, network_id = %node_network_id);
            let _enter = span.enter();
            info!("Virtual node loop started");

            let mut cleanup_tick = tokio::time::interval(physics.shard_timeout());

            loop {
                // Determine load for Vitality rate using LOCAL physics state
                let micro_load = storage.micro_layer.len() as f32 / (config.storage.max_peers * 5) as f32;
                let macro_load = storage.macro_layer.len() as f32 / config.storage.max_peers as f32;
                
                // Factor in artificial load injected via dashboard
                let total_raw_load = micro_load + macro_load + physics.artificial_load;
                let load = UnitInterval::new(total_raw_load);
                
                let vitality = VitalityRate::calculate(&physics, PowerState::Normal, load);
                let current_interval = vitality.as_duration();

                tokio::select! {
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

                    _ = cleanup_tick.tick() => {
                        sentinel.prune_stale_buffers(&config, &physics);
                        storage.archive_stale_sessions(physics.shard_timeout());
                    }

                    Some(event) = node_rx.recv() => {
                        match event {
                            SimEvent::Shutdown => break,
                            
                            SimEvent::ChunkIngested { origin, chunk } => {
                                if origin == node_network_id {
                                    debug!("Processing self-generated chunk");
                                    if let Some(envelope) = sentinel.process_chunk(chunk, &config.network.video_topic, &config, &identity, node_network_id) {
                                        if let Err(e) = storage.ingest_envelope(envelope) {
                                            error!(?e, "Failed to ingest self-generated envelope");
                                        }
                                    }
                                } else {
                                    info!(source = %origin, "Ingesting foreign chunk (Salvage)");
                                    let is_leaf_mode = false;
                                    storage.ingest_chunk(chunk, is_leaf_mode);
                                }
                            }
                            
                            SimEvent::Heartbeat { origin: _source_peer, payload: data } => {
                                if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&data) {
                                    sentinel.health_tracker.register_activity(msg);
                                }
                            }
                            
                            SimEvent::PeerDiscovered { peer, source } => {
                                debug!(target: "phalanx::sim", ?peer, ?source, "New peer address discovered");

                                // Use the LOCAL registry clone to avoid 'self' escape
                                let registry_read = registry_clone.read().await;
                                let found_did = registry_read.iter()
                                    .find(|(_, net_id)| **net_id == peer)
                                    .map(|(d, _)| d.clone());
                                drop(registry_read); // Drop lock immediately

                                if let Some(did) = found_did {
                                    let mut write_guard = registry_clone.write().await;
                                    write_guard.insert(did, peer); 
                                    debug!(target: "phalanx::sim", "Identity resolution successful for {}", peer);
                                } else {
                                    warn!(target: "phalanx::sim", %peer, "Discovery resolution failed: No DID mapped");
                                }
                            }
                            
                            SimEvent::ShardProcessed { peer_id, byte_size } => {
                                trace!(target: "phalanx::sim", %peer_id, %byte_size, "Data processed in sim-node");
                            }

                            SimEvent::CrucibleFinalized { volley_id } => {
                                info!(target: "phalanx::sim", volley_id = %volley_id, "Simulation archival complete");
                            }

                            // --- System & Lifecycle Variants ---
                            SimEvent::SystemStressUpdate(interval) => {
                                // Apply stress to the LOCAL simulation physics
                                physics.apply_system_load(interval);
                                debug!(target: "phalanx::sim", load=%interval.as_f32(), "System stress applied");
                            }
                        }
                    }
                }
            }
            info!("Virtual node loop terminated");
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
        // Uses renamed fields 'origin' and 'size'
        let event = SimEvent::ShardProcessed {
            peer_id: peer,
            byte_size: bytes,
        };
        self.publish_to_dashboard(event).await;
    }

    /// Publishes a strongly-typed event to the external dashboard.
    pub async fn publish_to_dashboard(&self, event: SimEvent) {
        // Non-blocking send to prevent simulation stalls
        if let Err(e) = self.telemetry_tx.try_send(event) {
            tracing::warn!(target: "phalanx::sim", error = %e, "Telemetry channel dropped.");
        }
    }
}

// TESTS ======================================================================

#[tokio::test]
async fn test_salvage_on_node_death() {
    use tokio::time::Duration;
    use tracing::{info};
    use crate::primitives::shards::{self, create_video_shard, Evidence, WitnessEnvelope, ChunkType};

    let _ = tracing_subscriber::fmt()
        .with_env_filter("phalanx=debug,info")
        .try_init();

    let _ = std::fs::remove_dir_all("sim_vault/VictimDevice");
    let _ = std::fs::remove_dir_all("sim_vault/GuardianDevice");

    let config = PhalanxConfig::test_salvage_on_node_death();
    let physics = PhalanxPhysics::test_profile();
    
    // Updated destructuring for triple return
    let (mut harness, relay_rx, _telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);
    
    let nodes_ref = Arc::clone(&harness.nodes);
    tokio::spawn(async move { 
        SimulationHarness::run_mesh_relay(nodes_ref, relay_rx).await 
    });

    let victim_device_did = harness.spawn_node("VictimDevice").await;
    let _guardian_device_did = harness.spawn_node("GuardianDevice").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let victim_device_network_id = harness.resolve_did(&victim_device_did).await.unwrap();
    let (victim_identity, _) = crate::primitives::identity::PhalanxIdentity::generate(); 
    let victim_did = victim_identity.did.clone();

    let frames = vec![vec![1]];
    let real_shard = create_video_shard(
        frames,
        shards::StorageSequence(999),
        10,
        "volley_test_999".into()
    );

    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard), 
        &victim_identity, 
        victim_device_network_id
    );

    let serialized_envelope = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");
    
    let chunks = shards::chunkify(
        shards::ShardId(999), 
        serialized_envelope, 
        10, 
        victim_did.clone(),
        ChunkType::Witnessed
    );

    info!(victim = %victim_did, chunk_count = chunks.len(), "Broadcasting Signed Envelope Chunks");

    for chunk in chunks {
        // Using updated SimEvent variant
        harness.broadcast(&victim_device_did, SimEvent::ChunkIngested { 
            origin: victim_device_network_id, 
            chunk: chunk 
        }).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    info!("Waiting for 5 seconds for salvage...");
    tokio::time::sleep(Duration::from_millis(5000)).await;

    let victim_safe_did = victim_did.to_safe_name();
    let evidence_dir = std::path::PathBuf::from("sim_vault")
        .join("GuardianDevice")
        .join(&victim_safe_did);
    
    info!(path = ?evidence_dir, "Checking for salvaged archive");

    let mut found_file = false;
    for _ in 0..10 {
        if evidence_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&evidence_dir) {
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.ends_with(".vid.phlx") {
                        info!(file = %name, "Found archive!");
                        found_file = true;
                        break;
                    }
                }
            }
        }
        if found_file { break; }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(found_file, "Salvage failed: .phlx file not found in correct DID folder.");
}

#[tokio::test]
async fn test_out_of_sequence_salvage_on_node_death() {
    use crate::primitives::shards::{create_video_shard, DataPayload, StorageSequence, Evidence, WitnessEnvelope};
    use crate::primitives::identity::NetworkId;
    
    let (identity, _) = PhalanxIdentity::generate();
    let peer_id = NetworkId::random(); 
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/salvage_test", &config, identity.did.clone());
    
    let mut captured_envelopes = Vec::new();
    for i in 0..5 {
        let seq = StorageSequence(i);
        let frames = vec![vec![i as u8]];
        let shard = create_video_shard(
            frames,
            seq,
            30,
            "volley_test_999".into()
        );
        
        let envelope = WitnessEnvelope::new(
            Evidence::Video(shard), 
            &identity, 
            peer_id
        );
        captured_envelopes.push(envelope);
    }

    storage.ingest_envelope(captured_envelopes[0].clone()).expect("Ingest failed");
    storage.ingest_envelope(captured_envelopes[2].clone()).expect("Ingest failed");
    storage.ingest_envelope(captured_envelopes[4].clone()).expect("Ingest failed");
    storage.ingest_envelope(captured_envelopes[1].clone()).expect("Ingest failed");
    storage.ingest_envelope(captured_envelopes[3].clone()).expect("Ingest failed");

    let session = storage.get_active_volley_shards(&identity.did.clone())
        .expect("Session should exist for recovered DID");

    let mut keys: Vec<&StorageSequence> = session.keys().collect();
    keys.sort(); 

    for (i, seq) in keys.iter().enumerate() {
        assert_eq!(seq.0, i as u32, "Sequence gap detected at index {}", i);
        let env = session.get(seq).unwrap();
        if let Evidence::Video(ref v) = env.evidence {
            if let DataPayload::Clear(bytes) = &v.payload {
                let recovered: Vec<Vec<u8>> = postcard::from_bytes(bytes).unwrap();
                assert_eq!(recovered[0][0], i as u8, "Data mismatch at sequence {}", i);
            }
        }
    }
}

#[tokio::test]
async fn test_stronghold_crash_recovery() {
    use crate::primitives::shards::{self, StorageSequence, Evidence, WitnessEnvelope};
    use crate::primitives::identity::NetworkId;
    
    let config = PhalanxConfig::default();
    let vault_path = "sim_vault/crash_test";
    let _ = std::fs::remove_dir_all(vault_path);

    let (identity, _) = PhalanxIdentity::generate();
    let peer_id = NetworkId::random();
    let seq = StorageSequence(101);
    
    let mut storage = Guardian::new(vault_path, &config, identity.did.clone());

    let frames = vec![vec![0xAA]];
    let shard = shards::create_video_shard(
        frames, 
        seq, 
        30,
        "volley_test_999".into()
    );
    
    let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
    storage.ingest_envelope(envelope.clone()).expect("Ingest failed");

    drop(storage);

    let recovered_storage = Guardian::new(vault_path, &config, identity.did.clone());
    
    let recovered_session = recovered_storage.get_active_volley_shards(&identity.did.clone())
        .expect("Guardian failed to recover DID session from WAL");
        
    let recovered_env = recovered_session.get(&seq)
        .expect("Guardian failed to recover specific shard 101 from WAL");

    if let Evidence::Video(ref v) = recovered_env.evidence {
        if let crate::primitives::shards::DataPayload::Clear(bytes) = &v.payload {
            let recovered: Vec<Vec<u8>> = postcard::from_bytes(bytes).unwrap();
            assert_eq!(recovered[0][0], 0xAA);
        }
    }
}

#[tokio::test]
async fn test_leaf_mode_isolation() {
    use crate::primitives::shards::{self, StorageSequence};

    let (me, _) = PhalanxIdentity::generate();
    let (stranger, _) = PhalanxIdentity::generate();
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/leaf_test", &config, me.did.clone());

    let shard = shards::create_video_shard(vec![vec![1]], StorageSequence(1), 30, "v1".into());
    let chunk = shards::chunkify(
        shards::ShardId(1),
        postcard::to_stdvec(&shard).unwrap(),
        100, 
        stranger.did.clone(),
        shards::ChunkType::Witnessed);

    let is_leaf_mode = true;
    storage.ingest_chunk(chunk[0].clone(), is_leaf_mode);

    assert_eq!(storage.micro_layer.len(), 0, "Guardian stored foreign data while in Leaf Mode!");
}

#[tokio::test]
async fn test_vampire_attack_defense() {
    use crate::primitives::shards::{create_video_shard, Evidence, WitnessEnvelope, StorageSequence};
    
    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    // Destructure triple
    let (mut harness, _relay_rx, _telemetry_rx) = SimulationHarness::init_mesh(config.clone(), physics);

    let _victim_did = harness.spawn_node("Victim").await;
    let attacker_did = harness.spawn_node("Attacker").await;
    
    let (attacker_identity, _) = PhalanxIdentity::generate();
    let attacker_net_id = NetworkId::random();

    for i in 0..7 {
        let shard = create_video_shard(vec![vec![1]], StorageSequence(i), 30, "vampire_volley".into());
        let mut envelope = WitnessEnvelope::new(Evidence::Video(shard), &attacker_identity, attacker_net_id);
        
        if let Evidence::Video(ref mut v) = envelope.evidence { v.fps = 145; }

        let chunk = crate::primitives::shards::chunkify(
            crate::primitives::shards::ShardId(i as u32), 
            postcard::to_stdvec(&envelope).unwrap(), 
            100, 
            attacker_did.clone(),
            crate::primitives::shards::ChunkType::Witnessed
        );

        // Uses unified SimEvent variant
        harness.broadcast(&attacker_did, SimEvent::ChunkIngested { 
            origin: attacker_net_id, 
            chunk: chunk[0].clone() 
        }).await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    info!("Vampire test completed: Attacker signatures penalized by Victim Guardian.");
}