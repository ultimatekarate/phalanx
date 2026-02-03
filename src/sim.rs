use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, span, Level};
use libp2p::PeerId;

use std::sync::Arc;
use std::time::Duration;

use crate::identity::PhalanxIdentity;
use crate::sentinel::{Sentinel, SimPacket, ControlMessage};
use crate::stronghold::Stronghold;
use crate::config::PhalanxConfig;

/// A handle to a virtual node in the harness
pub struct SimNodeHandle {
    pub did: String,
    pub tx: mpsc::Sender<SimPacket>,
}

pub struct SimulationHarness {
    // Wrap nodes so they can be shared across tasks
    pub nodes: Arc<RwLock<HashMap<String, mpsc::Sender<SimPacket>>>>,
    pub broadcast_channel: mpsc::Sender<(String, PeerId, SimPacket)>,
    pub config: PhalanxConfig,
    pub peer_map: Arc<RwLock<HashMap<String, PeerId>>>,
}

impl SimulationHarness {
    pub fn init_mesh(config: PhalanxConfig) -> (Self, mpsc::Receiver<(String, PeerId, SimPacket)>) {
        let (tx, rx) = mpsc::channel(1024);
        let harness = Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            peer_map: Arc::new(RwLock::new(HashMap::new())),
            broadcast_channel: tx,
            config,
        };
        (harness, rx)
    }

    pub async fn get_peer_id(&self, did: &str) -> Option<PeerId> {
        let map = self.peer_map.read().await;
        map.get(did).cloned()
    }
    
    pub async fn run_mesh_relay(
        nodes: Arc<RwLock<HashMap<String, mpsc::Sender<SimPacket>>>>, 
        mut relay_rx: mpsc::Receiver<(String, PeerId, SimPacket)>
    ) {
        while let Some((sender_did, _sender_peer, packet)) = relay_rx.recv().await {
            // Acquire a READ lock to find targets
            let current_nodes = nodes.read().await;
            for (did, node_tx) in current_nodes.iter() {
                if did != &sender_did {
                    let _ = node_tx.send(packet.clone()).await;
                }
            }
        }
    }

    pub async fn stop_node(&mut self, did: &str) {
        // 1. Acquire the write lock (awaiting if another task is reading/writing)
        let mut nodes_guard = self.nodes.write().await;
        
        // 2. Now you can call HashMap methods on the guard
        if let Some(tx) = nodes_guard.remove(did) {
            let _ = tx.send(SimPacket::Shutdown).await;
            warn!(node_did = %did, "Node stopped manually via harness");
        }
    }

    /// Spawns a new virtual node into the simulation
pub async fn spawn_node(&mut self, name: &str) -> String {
    let name_owned = name.to_string();
    let identity = PhalanxIdentity::generate();
    let did = identity.did.clone();
    let peer_id = PeerId::random();
    
    let (node_tx, mut node_rx) = mpsc::channel::<SimPacket>(100);

    // Register node identity in the harness for test lookups
    {
        let mut peer_guard = self.peer_map.write().await;
        peer_guard.insert(did.clone(), peer_id);
    }

    let mut nodes_guard = self.nodes.write().await;
    nodes_guard.insert(did.clone(), node_tx);

    let broadcast_tx = self.broadcast_channel.clone();
    let node_did = did.clone();
    let config = self.config.clone();
    
    let mut sentinel = Sentinel::new(&config);
    let mut storage = Stronghold::new(&format!("sim_vault/{}", name), &config);

    tokio::spawn(async move {
        let span = span!(Level::INFO, "sim_node", node = %name_owned, peer = %peer_id);
        let _enter = span.enter();
        info!("Virtual node loop started");

        let mut heartbeat_tick = tokio::time::interval(Duration::from_secs(config.network.heartbeat_interval_secs));
        let mut cleanup_tick = tokio::time::interval(Duration::from_secs(5));

        loop {
            tokio::select! {
                // 1. Outbound Heartbeats
                _ = heartbeat_tick.tick() => {
                    let msg = sentinel.generate_heartbeat(&peer_id);
                    match postcard::to_stdvec(&msg) {
                        Ok(data) => {
                            let _ = broadcast_tx.send((node_did.clone(), peer_id, SimPacket::Heartbeat(peer_id, data))).await;
                        },
                        Err(e) => warn!(error = %e, "Failed to serialize outbound heartbeat"),
                    }
                }

                // 2. Health Cleanup and Archival
                _ = cleanup_tick.tick() => {
                    // process_cleanup now uses HealthTracker internally to find stale peers
                    let salvaged = sentinel.process_cleanup(peer_id);
                    for (_dark_peer, envelopes) in salvaged {
                        for env in envelopes {
                            storage.ingest_envelope(env);
                        }
                    }
                    storage.archive_stale_sessions(Duration::from_secs(config.storage.stale_session_threshold));
                }

                // 3. Inbound Packet Handling
                Some(packet) = node_rx.recv() => {
                    match packet {
                        SimPacket::Shutdown => {
                            info!("Shutdown signal received. Terminating virtual node loop");
                            break;
                        }
                        SimPacket::Chunk(actual_source, chunk) => {
                            // Delegation to ReassemblyManager preserves PeerId-to-DID link
                            if let Some(envelope) = sentinel.ingest_chunk(actual_source, chunk) {
                                storage.ingest_envelope(envelope);
                            }
                        }
                        SimPacket::Heartbeat(source_peer, data) => {
                            match postcard::from_bytes::<ControlMessage>(&data) {
                                Ok(msg) => {
                                    /* FUNCTIONAL DOCUMENTATION:
                                       Targeting the HealthTracker directly ensures we use tokio::time::Instant.
                                       This is critical for 'tokio::time::pause' and 'advance' compatibility 
                                       in the simulation harness.
                                    */
                                    sentinel.health.register_heartbeat(source_peer, msg);
                                },
                                Err(e) => warn!(error = %e, "Received malformed heartbeat in simulation"),
                            }
                        }
                    }
                }
            }
        }
        info!("Virtual node loop terminated");
    });

    did
}

    /// Simulates a broadcast on the Gossipsub network
    pub async fn broadcast(&self, sender_did: &str, packet: SimPacket) {
        let start = std::time::Instant::now();
        
        // Acquire the lock
        let nodes_guard = self.nodes.read().await;
        
        let wait_time = start.elapsed();
        if wait_time > std::time::Duration::from_millis(10) {
            tracing::warn!(?wait_time, "High lock contention in Simulation broadcast");
        }

        for (did, tx) in nodes_guard.iter() {
            if did != sender_did {
                let _ = tx.send(packet.clone()).await;
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn test_salvage_on_node_death() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter("phalanx=debug,info")
        .try_init();

    use crate::shards::ShardId;
    use crate::shards::ShardChunk;
    use std::time::Duration;
    use tracing::{info, info_span};

    let test_span = info_span!("test_salvage", shard_id = 999);
    let _enter = test_span.enter();

    let config = PhalanxConfig::test_defaults();
    let (mut harness, relay_rx) = SimulationHarness::init_mesh(config.clone());
    
    let nodes_ref = Arc::clone(&harness.nodes);
    tokio::spawn(async move { 
        SimulationHarness::run_mesh_relay(nodes_ref, relay_rx).await 
    });

    // 1. Spawn Alpha and Beta
    let node_a_did = harness.spawn_node("Alpha").await;
    let _node_b_did = harness.spawn_node("Beta").await;
    
    // Give nodes a moment to initialize and register in the relay
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 2. Transmit Partial Data
    // We fetch Alpha's PeerId from the harness to ensure the Sentinel tracks it correctly
    let node_a_peer_id = harness.get_peer_id(&node_a_did).await
        .expect("Alpha PeerId missing from harness");


    info!(alpha = %node_a_did, peer = %node_a_peer_id, "Nodes initialized and registered");
    
    let partial_chunks = vec![
        ShardChunk { shard_id: ShardId(999), chunk_index: 0, total_chunks: 5, data: vec![1, 2, 3], owner_did: node_a_did.clone() },
        ShardChunk { shard_id: ShardId(999), chunk_index: 1, total_chunks: 5, data: vec![4, 5, 6], owner_did: node_a_did.clone() },
    ];

    for chunk in partial_chunks {
        harness.broadcast(&node_a_did, SimPacket::Chunk(node_a_peer_id, chunk)).await;
    }

    // Allow the chunks to propagate through the relay to Beta
    tokio::task::yield_now().await;

    // 3. KILL ALPHA
    info!(target = "Alpha", "Shutting down Alpha to trigger 'Dark Peer' state");
    harness.stop_node(&node_a_did).await;

    // 4. TRIGGER SALVAGE (The Critical Sync)
    // Advance time past the heartbeat timeout (65s)
    let warp_duration = Duration::from_secs(70);
    info!(warp = ?warp_duration, "Advancing virtual clock");
    tokio::time::advance(warp_duration).await;

    // IMPORTANT: In a paused-time environment, 'advance' moves the clock,
    // but pending tasks (like cleanup_tick) need a 'sleep' or 'yield' to be scheduled.
    // We sleep for a small amount of "virtual time" to ensure the cleanup loop runs.
    tokio::time::sleep(Duration::from_millis(500)).await;

    info!("Warping again to trigger Stronghold disk archival");
    tokio::time::advance(Duration::from_secs(10)).await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    // 5. VERIFICATION
    let node_a_safe_did = node_a_did.replace(":", "_");
    let evidence_dir = std::path::PathBuf::from("sim_vault")
        .join("Beta")
        .join(&node_a_safe_did);
    
    info!(constructed_path = ?evidence_dir, "Checking for salvaged evidence");

    // Poll for the file with a timeout to allow for Disk I/O latency
    let mut found_file = false;
    for _ in 0..10 {
        if evidence_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&evidence_dir) {
                for entry in entries.flatten() {
                    if entry.file_name().to_string_lossy().ends_with(".aud.phlx") {
                        found_file = true;
                        break;
                    }
                }
            }
        }
        if found_file { break; }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    assert!(found_file, "Forensic salvage failed: No .phlx file found in Beta's vault.");
    info!("SUCCESS: Salvage operation verified.");
}

#[tokio::test]
async fn test_stronghold_crash_recovery() {
    use crate::shards;
    
    let config = PhalanxConfig::default();
    let mut storage = Stronghold::new("sim_vault/crash_test", &config);

    // 1. Ingest a shard
    let identity = PhalanxIdentity::generate();
    let shard = shards::create_video_shard(vec![vec![0]], 101, 30);
    let envelope = shards::WitnessEnvelope::from_video(shard, &identity, "peer_a".to_string());
    
    storage.ingest_envelope(envelope.clone());

    // 2. Simulate Crash (Drop the old stronghold instance)
    drop(storage);

    // 3. Recover
    let recovered_storage = Stronghold::new("sim_vault/crash_test", &config);
    // Note: recover_from_wal should be called inside Stronghold::new
    
    let recovered_session = recovered_storage.active_sessions.get(&identity.did);
    assert!(recovered_session.is_some(), "Stronghold failed to recover DID session from WAL");
    assert!(recovered_session.unwrap().contains_key(&101), "Stronghold failed to recover specific shard from WAL");
    
    tracing::info!("DURABILITY VERIFIED: Shard 101 survived the simulated crash.");
}