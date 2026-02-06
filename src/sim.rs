use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, span, Level};
use std::sync::Arc;
use std::time::Duration;

use crate::identity::{PhalanxIdentity, Did, NetworkId};
use crate::sentinel::{Sentinel, ControlMessage};
use crate::stronghold::Stronghold;
use crate::config::PhalanxConfig;
use crate::shards::{ShardChunk};

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
}

impl SimulationHarness {
    pub fn init_mesh(config: PhalanxConfig) -> (Self, mpsc::Receiver<(Did, NetworkId, SimEvent)>) {
        let (tx, rx) = mpsc::channel(1024);
        let harness = Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            identity_registry: Arc::new(RwLock::new(HashMap::new())),
            broadcast_channel: tx,
            config,
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
        let identity = PhalanxIdentity::generate();
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
        
        let mut sentinel = Sentinel::new(&config);
        let mut storage = Stronghold::new(&format!("sim_vault/{}", name), &config);

        tokio::spawn(async move {
            let span = span!(Level::INFO, "sim_node", node = %name_owned, network_id = %node_network_id);
            let _enter = span.enter();
            info!("Virtual node loop started");

            let mut heartbeat_tick = tokio::time::interval(Duration::from_secs(config.network.heartbeat_interval_secs));
            let mut cleanup_tick = tokio::time::interval(Duration::from_secs(config.network.cleanup_interval_secs));

            loop {
                tokio::select! {
                    _ = heartbeat_tick.tick() => {
                        let msg = ControlMessage {
                            sender: node_network_id,
                            load_factor: 0.1,
                            storage_remaining_mb: 1024,
                        };
                        if let Ok(data) = postcard::to_stdvec(&msg) {
                            let _ = broadcast_tx.send((node_did.clone(), node_network_id, SimEvent::Heartbeat(node_network_id, data))).await;
                        }
                    }

                    _ = cleanup_tick.tick() => {
                        sentinel.prune_stale_buffers(&config);
                        storage.archive_stale_sessions(Duration::from_secs(config.storage.stale_session_threshold));
                    }

                    Some(event) = node_rx.recv() => {
                        match event {
                            SimEvent::Shutdown => break,
                            SimEvent::Chunk(source_peer, chunk) => {
                                // LOGIC FIX: SALVAGE ROUTING
                                // 1. If I am the source, I must Witness it (Sign & Store)
                                if source_peer == node_network_id {
                                    if let Some(envelope) = sentinel.process_chunk(chunk, &config.network.video_topic, &config, &identity, node_network_id) {
                                        storage.ingest_envelope(envelope);
                                    }
                                } else {
                                    // 2. If a Peer sent it, I must Salvage it (Store Only)
                                    // Bypassing Sentinel prevents re-signing the data as my own.
                                    // This assumes the chunk contains a fragment of a valid WitnessEnvelope.
                                    storage.ingest_chunk(chunk);
                                }
                            }
                            SimEvent::Heartbeat(source_peer, data) => {
                                if let Ok(_msg) = postcard::from_bytes::<ControlMessage>(&data) {
                                    sentinel.health_tracker.register_activity(source_peer);
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

#[tokio::test(start_paused = true)]
async fn test_salvage_on_node_death() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("phalanx=debug,info")
        .try_init();

    use std::time::Duration;
    use tracing::{info, info_span};
    use crate::shards::{Evidence, WitnessEnvelope};

    // 1. CONFIGURATION
    let mut config = PhalanxConfig::test_defaults();
    config.storage.stale_session_threshold = 0; 
    config.network.cleanup_interval_secs = 1;

    let (mut harness, relay_rx) = SimulationHarness::init_mesh(config.clone());
    let nodes_ref = Arc::clone(&harness.nodes);
    tokio::spawn(async move { 
        SimulationHarness::run_mesh_relay(nodes_ref, relay_rx).await 
    });

    let node_a_did = harness.spawn_node("Alpha").await;
    let _node_b_did = harness.spawn_node("Beta").await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 2. CREATE DATA (Signed by a Victim Identity)
    let node_a_network_id = harness.resolve_did(&node_a_did).await.unwrap();
    
    // We generate a separate identity to sign the data. 
    // This represents the "User" of the Alpha Node.
    let victim_identity = crate::identity::PhalanxIdentity::generate(); 
    let victim_did = victim_identity.did.clone();

    let real_shard = crate::shards::VideoShard {
        volley_id: "volley_test_999".to_string(),
        timestamp: 123456789,
        frames: vec![vec![1]],
        sequence_id: crate::shards::StorageSequence(999),
        fps: 10,
    };

    // Wrap in Envelope (Signed by Victim)
    let envelope = WitnessEnvelope::new(
        Evidence::Video(real_shard), 
        &victim_identity, 
        node_a_network_id
    );

    // Serialize the ENVELOPE (not just the shard)
    let serialized_envelope = postcard::to_stdvec(&envelope).expect("Failed to serialize envelope");
    
    // Chunkify the ENVELOPE bytes
    let chunks = crate::shards::chunkify(
        crate::shards::ShardId(999), 
        serialized_envelope, 
        10, 
        victim_did.clone()
    );

    info!(victim = %victim_did, chunk_count = chunks.len(), "Broadcasting Signed Envelope Chunks");

    for chunk in chunks {
        // Broadcast from Alpha's Network ID
        harness.broadcast(&node_a_did, SimEvent::Chunk(node_a_network_id, chunk)).await;
    }

    tokio::task::yield_now().await;

    // 3. TRIGGER SALVAGE
    info!("Advancing virtual clock");
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 4. VERIFICATION
    let victim_safe_did = victim_did.to_safe_name();
    
    // Check Beta's Vault for Victim's Folder
    let evidence_dir = std::path::PathBuf::from("sim_vault")
        .join("Beta") // Physical Storage
        .join(&victim_safe_did); // Logical Owner
    
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
    use crate::shards::{StorageSequence, Evidence, WitnessEnvelope, VideoShard};
    use crate::identity::NetworkId;
    
    let config = PhalanxConfig::default();
    let mut storage = Stronghold::new("sim_vault/salvage_test", &config);
    let identity = PhalanxIdentity::generate();
    let peer_id = NetworkId::random(); 
    
    let mut captured_envelopes = Vec::new();
    for i in 0..5 {
        let seq = StorageSequence(i);
        let shard = VideoShard {
            volley_id: "volley_test_999".to_string(),
            timestamp: 1000 + i as u64,
            frames: vec![vec![i as u8]],
            sequence_id: seq,
            fps: 30,
        };
        
        let envelope = WitnessEnvelope::new(
            Evidence::Video(shard), 
            &identity, 
            peer_id
        );
        captured_envelopes.push(envelope);
    }

    storage.ingest_envelope(captured_envelopes[0].clone());
    storage.ingest_envelope(captured_envelopes[2].clone());
    storage.ingest_envelope(captured_envelopes[4].clone());

    storage.ingest_envelope(captured_envelopes[1].clone());
    storage.ingest_envelope(captured_envelopes[3].clone());

    let session = storage.get_active_volley_shards(&identity.did)
        .expect("Session should exist for recovered DID");

    let mut keys: Vec<&StorageSequence> = session.keys().collect();
    keys.sort(); 

    for (i, seq) in keys.iter().enumerate() {
        assert_eq!(seq.0, i as u32, "Sequence gap detected at index {}", i);
        let env = session.get(seq).unwrap();
        if let Evidence::Video(ref v) = env.evidence {
            assert_eq!(v.frames[0][0], i as u8, "Data mismatch at sequence {}", i);
        }
    }
}

#[tokio::test]
async fn test_stronghold_crash_recovery() {
    use crate::shards::{StorageSequence, Evidence, WitnessEnvelope, VideoShard};
    use crate::identity::NetworkId;
    
    let config = PhalanxConfig::default();
    let vault_path = "sim_vault/crash_test";
    let _ = std::fs::remove_dir_all(vault_path);

    let mut storage = Stronghold::new(vault_path, &config);

    let identity = PhalanxIdentity::generate();
    let peer_id = NetworkId::random();
    let seq = StorageSequence(101);
    
    let shard = VideoShard {
        volley_id: "volley_test_999".to_string(),
        timestamp: 123456789,
        frames: vec![vec![0xAA]],
        sequence_id: seq,
        fps: 30,
    };
    
    let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, peer_id);
    storage.ingest_envelope(envelope.clone());

    drop(storage);

    let recovered_storage = Stronghold::new(vault_path, &config);
    
    let recovered_session = recovered_storage.get_active_volley_shards(&identity.did)
        .expect("Stronghold failed to recover DID session from WAL");
        
    let recovered_env = recovered_session.get(&seq)
        .expect("Stronghold failed to recover specific shard 101 from WAL");

    if let Evidence::Video(ref v) = recovered_env.evidence {
        assert_eq!(v.frames[0][0], 0xAA);
    }
}