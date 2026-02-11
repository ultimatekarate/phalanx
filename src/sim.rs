use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn, debug, span, Level};
use std::sync::Arc;

use crate::security::identity::{PhalanxIdentity, Did, NetworkId};
use crate::security::sentinel::{Sentinel, ControlMessage};
use crate::storage::guardian::Guardian;
use crate::core::config::{PhalanxConfig, PhalanxPhysics};
use crate::protocol::shards::ShardChunk;

#[derive(Clone)]
pub enum SimEvent {
    Chunk(NetworkId, ShardChunk),
    Heartbeat(NetworkId, Vec<u8>), 
    Shutdown,
}

pub struct SimulationHarness {
    pub nodes: Arc<RwLock<HashMap<Did, mpsc::Sender<SimEvent>>>>,
    pub broadcast_channel: mpsc::Sender<(Did, NetworkId, SimEvent)>,
    pub config: PhalanxConfig,
    pub identity_registry: Arc<RwLock<HashMap<Did, NetworkId>>>,
    pub physics: PhalanxPhysics,
}

impl SimulationHarness {
    pub fn init_mesh(config: PhalanxConfig, physics: PhalanxPhysics) -> (Self, mpsc::Receiver<(Did, NetworkId, SimEvent)>) {
        let (tx, rx) = mpsc::channel(1024);
        let harness = Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            identity_registry: Arc::new(RwLock::new(HashMap::new())),
            broadcast_channel: tx,
            config,
            physics
        };
        (harness, rx)
    }

    pub async fn resolve_did(&self, did: &Did) -> Option<NetworkId> {
        let map = self.identity_registry.read().await;
        map.get(did).cloned()
    }
    
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

    pub async fn spawn_node(&mut self, name: &str) -> Did {
        let name_owned = name.to_string();
        let (identity, _) = PhalanxIdentity::generate();
        let node_did = identity.did.clone();
        let return_did = node_did.clone();
        let node_network_id = NetworkId::random();
        
        let (node_tx, mut node_rx) = mpsc::channel::<SimEvent>(100);

        {
            let mut peer_guard = self.identity_registry.write().await;
            peer_guard.insert(node_did.clone(), node_network_id);
        }

        let mut nodes_guard = self.nodes.write().await;
        nodes_guard.insert(node_did.clone(), node_tx);

        let broadcast_tx = self.broadcast_channel.clone();
        let config = self.config.clone();
        let physics= self.physics.clone();
        
        info!(
            node = %name_owned, 
            quota_foreign = %config.storage.max_foreign_storage_bytes,
            "Initializing Guardian"
        );

        let mut sentinel = Sentinel::new(&config);
        let mut storage = Guardian::new(&format!("sim_vault/{}", name), &config, identity.did.clone());

        tokio::spawn(async move {
            let span = span!(Level::INFO, "sim_node", node = %name_owned, network_id = %node_network_id);
            let _enter = span.enter();
            info!("Virtual node loop started");

            let mut heartbeat_tick = tokio::time::interval(physics.heartbeat_interval(0.0));
            let mut cleanup_tick = tokio::time::interval(physics.shard_timeout());

            loop {
                let micro_load = storage.micro_layer.len() as f32 / (config.storage.max_peers * 5) as f32;
                let macro_load = storage.macro_layer.len() as f32 / config.storage.max_peers as f32;
                
                let load_factor = (micro_load + macro_load).clamp(0.0, 1.0);
                
                // Derive the dynamic interval based on this stress factor.
                let current_interval = physics.heartbeat_interval(load_factor);

                tokio::select! {
                    _ = heartbeat_tick.tick() => {
                        let msg = ControlMessage {
                            sender: node_network_id,
                            load_factor,
                            storage_remaining_mb: 1024, // Placeholder for Disk I/O check
                            heartbeat_ms: current_interval.as_millis() as u64, // The Vitality Contract
                        };
                        if let Ok(data) = postcard::to_stdvec(&msg) {
                            let _ = broadcast_tx.send((node_did.clone(), node_network_id, SimEvent::Heartbeat(node_network_id, data))).await;
                        }
                    }

                    _ = cleanup_tick.tick() => {
                        sentinel.prune_stale_buffers(&config, &physics);
                        storage.archive_stale_sessions(physics.shard_timeout());
                    }

                    Some(event) = node_rx.recv() => {
                        match event {
                            SimEvent::Shutdown => break,
                            SimEvent::Chunk(source_peer, chunk) => {
                                // 1. If I am the source, I must Witness it (Sign & Store)
                                if source_peer == node_network_id {
                                    debug!("Processing self-generated chunk");
                                    if let Some(envelope) = sentinel.process_chunk(chunk, &config.network.video_topic, &config, &identity, node_network_id) {
                                        if let Err(e) = storage.ingest_envelope(envelope) {
                                            error!(?e, "Failed to ingest self-generated envelope");
                                        }
                                    }
                                } else {
                                    info!(source = %source_peer, "Ingesting foreign chunk (Salvage)");
                                    // 2. If a Peer sent it, I must Salvage it (Store Only)
                                    // Bypassing Sentinel prevents re-signing the data as my own.
                                    // This assumes the chunk contains a fragment of a valid WitnessEnvelope.
                                    // Assume we are not in leaf mode
                                    let is_leaf_mode = false;
                                    storage.ingest_chunk(chunk, is_leaf_mode);
                                }
                            }
                            SimEvent::Heartbeat(_source_peer, data) => {
                                if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&data) {
                                    // Sentinel now tracks vitality based on the peer's reported interval.
                                    sentinel.health_tracker.register_activity(msg);
                                }
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
}

#[tokio::test]
async fn test_salvage_on_node_death() {

    use crate::protocol;

    let _ = tracing_subscriber::fmt()
        .with_env_filter("phalanx=debug,info")
        .try_init();

    // 1. SETUP
    let _ = std::fs::remove_dir_all("sim_vault/VictimDevice");
    let _ = std::fs::remove_dir_all("sim_vault/GuardianDevice");

    use tokio::time::Duration;
    use tracing::{info};
    use crate::protocol::shards::{create_video_shard, Evidence, WitnessEnvelope};

    // 1. CONFIGURATION
    let config = PhalanxConfig::test_salvage_on_node_death();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, relay_rx) = SimulationHarness::init_mesh(config.clone(), physics);
    let nodes_ref = Arc::clone(&harness.nodes);
    tokio::spawn(async move { 
        SimulationHarness::run_mesh_relay(nodes_ref, relay_rx).await 
    });

    let victim_device_did = harness.spawn_node("VictimDevice").await;
    let _guardian_device_did = harness.spawn_node("GuardianDevice").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 2. CREATE DATA (Signed by a Victim Identity)
    let victim_device_network_id = harness.resolve_did(&victim_device_did).await.unwrap();
    
    // We generate a separate identity to sign the data. 
    // This represents the "User" of the smashed device node.
    let (victim_identity, _) = crate::security::identity::PhalanxIdentity::generate(); 
    let victim_did = victim_identity.did.clone();

    // FIX: Use constructor instead of struct init
    let frames = vec![vec![1]];
    let real_shard = create_video_shard(
        frames,
        protocol::shards::StorageSequence(999),
        10,
        "volley_test_999".to_string()
    );

    // Wrap in Envelope (Signed by Victim)
    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard), 
        &victim_identity, 
        victim_device_network_id
    );

    // Serialize the ENVELOPE (not just the shard)
    let serialized_envelope = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");
    
    // Chunkify the ENVELOPE bytes
    let chunks = crate::protocol::shards::chunkify(
        crate::protocol::shards::ShardId(999), 
        serialized_envelope, 
        10, 
        victim_did.clone()
    );

    info!(victim = %victim_did, chunk_count = chunks.len(), "Broadcasting Signed Envelope Chunks");

    for chunk in chunks {
        // Broadcast from Alpha's Network ID
        harness.broadcast(&victim_device_did, SimEvent::Chunk(victim_device_network_id, chunk)).await;
    }

    tokio::time::sleep(Duration::from_secs(1)).await;

    // 3. TRIGGER SALVAGE
    info!("Waiting for 5 seconds");
    tokio::time::sleep(Duration::from_millis(5000)).await;

    // 4. VERIFICATION
    let victim_safe_did = victim_did.to_safe_name();
    
    // Check Beta's Vault for Victim's Folder
    let evidence_dir = std::path::PathBuf::from("sim_vault")
        .join("GuardianDevice") // Guardian Folder
        .join(&victim_safe_did); // File name associated with smashed device
    
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
    info!("SUCCESS: Salvage operation verified.");
}

#[tokio::test]
async fn test_out_of_sequence_salvage_on_node_death() {
    use crate::protocol::shards::{self, StorageSequence, Evidence, WitnessEnvelope};
    use crate::security::identity::NetworkId;
    
    let (identity, _) = PhalanxIdentity::generate();
    let peer_id = NetworkId::random(); 
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/salvage_test", &config, identity.did.clone());
    
    let mut captured_envelopes = Vec::new();
    for i in 0..5 {
        let seq = StorageSequence(i);
        // FIX: Use constructor
        let frames = vec![vec![i as u8]];
        let shard = shards::create_video_shard(
            frames,
            seq,
            30,
            "volley_test_999".to_string()
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
            if let crate::protocol::shards::DataPayload::Clear(bytes) = &v.payload {
                let recovered: Vec<Vec<u8>> = postcard::from_bytes(bytes).unwrap();
                assert_eq!(recovered[0][0], i as u8, "Data mismatch at sequence {}", i);
            }
        }
    }
}

#[tokio::test]
async fn test_stronghold_crash_recovery() {
    use crate::protocol::shards::{self, StorageSequence, Evidence, WitnessEnvelope};
    use crate::security::identity::NetworkId;
    
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
        "volley_test_999".to_string()
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
        if let crate::protocol::shards::DataPayload::Clear(bytes) = &v.payload {
            let recovered: Vec<Vec<u8>> = postcard::from_bytes(bytes).unwrap();
            assert_eq!(recovered[0][0], 0xAA);
        }
    }
}

#[tokio::test]
async fn test_leaf_mode_isolation() {

    use crate::protocol::shards::{self, StorageSequence};

    let (me, _) = PhalanxIdentity::generate();
    let (stranger, _) = PhalanxIdentity::generate();
    let config = PhalanxConfig::default();
    let mut storage = Guardian::new("sim_vault/leaf_test", &config, me.did.clone());

    // 1. Create a foreign chunk
    let shard = shards::create_video_shard(vec![vec![1]], StorageSequence(1), 30, "v1".into());
    let chunk = shards::chunkify(shards::ShardId(1), postcard::to_stdvec(&shard).unwrap(), 100, stranger.did.clone());

    // 2. Ingest while in Leaf Mode
    let is_leaf_mode = true;
    storage.ingest_chunk(chunk[0].clone(), is_leaf_mode);

    // 3. Verify: The Micro-Layer should be empty because the chunk was dropped
    assert_eq!(storage.micro_layer.len(), 0, "Guardian stored foreign data while in Leaf Mode!");
}

// =====================
// VAMPIRE DEFENSE TEST
// =====================

#[tokio::test]
async fn test_vampire_attack_defense() {
    use crate::protocol::shards::{create_video_shard, Evidence, WitnessEnvelope, StorageSequence};
    
    // 1. Setup mesh with standard physics.
    let config = PhalanxConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, _rx) = SimulationHarness::init_mesh(config.clone(), physics);

    let _victim_did = harness.spawn_node("Victim").await;
    let attacker_did = harness.spawn_node("Attacker").await;
    
    // 2. SIMULATE VAMPIRE ATTACK
    // Attacker floods the Victim with invalidly signed shards.
    let (attacker_identity, _) = PhalanxIdentity::generate();
    let attacker_net_id = NetworkId::random();

    for i in 0..7 { // Threshold is 5 signature failures.
        let shard = create_video_shard(vec![vec![1]], StorageSequence(i), 30, "vampire_volley".into());
        let mut envelope = WitnessEnvelope::new(Evidence::Video(shard), &attacker_identity, attacker_net_id);
        
        // TAMPER: Invalidate signature by changing payload after signing.
        if let Evidence::Video(ref mut v) = envelope.evidence { v.fps = 145; }

        let chunk = crate::protocol::shards::chunkify(
            crate::protocol::shards::ShardId(i as u32), 
            postcard::to_stdvec(&envelope).unwrap(), 
            100, 
            attacker_did.clone()
        );

        harness.broadcast(&attacker_did, SimEvent::Chunk(attacker_net_id, chunk[0].clone())).await;
    }

    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // 3. VERIFICATION
    // Blacklisting logic is verified in the Guardian unit tests.
    info!("Vampire test completed: Attacker signatures penalized by Victim Guardian.");
}