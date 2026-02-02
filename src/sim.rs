use std::collections::HashMap;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn, span, Level};
use libp2p::PeerId;

use std::sync::Arc;

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
}

impl SimulationHarness {
    pub fn init_mesh(config: PhalanxConfig) -> (Self, mpsc::Receiver<(String, PeerId, SimPacket)>) {
        let (tx, rx) = mpsc::channel(1024);
        let harness = Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            broadcast_channel: tx,
            config,
        };
        (harness, rx)
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


        let mut nodes_guard = self.nodes.write().await;
        nodes_guard.insert(did.clone(), node_tx);

        let broadcast_tx = self.broadcast_channel.clone();
        let node_did = did.clone();
        let config = self.config.clone();
        
        // Initialize the domain modules
        let mut sentinel = Sentinel::new(&config);
        let mut storage = Stronghold::new(&format!("sim_vault/{}", name), &config);

        tokio::spawn(async move {
            // INSTRUMENTATION: Every log in this task is context-aware
            let span = span!(Level::INFO, "sim_node", node = %name_owned, peer = %peer_id);
            let _enter = span.enter();
            info!("Virtual node initialized");

            let mut heartbeat_tick = tokio::time::interval(std::time::Duration::from_secs(config.network.heartbeat_interval_secs));
            let mut cleanup_tick = tokio::time::interval(std::time::Duration::from_secs(5));

            loop {
                tokio::select! {
                    // 1. Emit Heartbeat
                    _ = heartbeat_tick.tick() => {
                        let msg = sentinel.generate_heartbeat(&peer_id);
                        if let Ok(data) = postcard::to_stdvec(&msg) {
                            let _ = broadcast_tx.send((node_did.clone(), peer_id, SimPacket::Heartbeat(peer_id, data))).await;
                        }
                    }

                    // 2. Periodic Maintenance (Cleanup & Salvage)
                    _ = cleanup_tick.tick() => {
                        let salvaged = sentinel.process_cleanup(peer_id);
                        for (_dark_peer, envelopes) in salvaged {
                            for env in envelopes {
                                storage.ingest_envelope(env);
                            }
                        }
                        storage.archive_stale_sessions(std::time::Duration::from_secs(config.storage.stale_session_threshold));
                    }

                    // 3. Packet Processing
                    Some(packet) = node_rx.recv() => {
                        match packet {
                            SimPacket::Shutdown => {
                                info!("Shutdown signal received.");
                                break;
                            }
                            SimPacket::Chunk(chunk) => {
                                // Manual ingestion for simulation (bypassing SwarmEvent)
                                if let Some(envelope) = sentinel.ingest_chunk(peer_id, chunk) {
                                    storage.ingest_envelope(envelope);
                                }
                            }
                            SimPacket::Heartbeat(source_peer, data) => {
                                if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&data) {
                                    sentinel.register_sim_heartbeat(source_peer, msg);
                                }
                            }
                        }
                    }
                }
            }
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

#[tokio::test]
async fn test_salvage_on_node_death() {
    use std::time::Duration;
    use crate::shards::ShardChunk;

    // 1. Setup with sane defaults
    let config = PhalanxConfig::default(); 
    let (mut harness, relay_rx) = SimulationHarness::init_mesh(config.clone());
    
    // Share the nodes map with the relay
    let nodes_ref = Arc::clone(&harness.nodes);
    tokio::spawn(async move { 
        SimulationHarness::run_mesh_relay(nodes_ref, relay_rx).await 
    });

    let node_a_did = harness.spawn_node("Alpha").await;
    let _node_b_did = harness.spawn_node("Beta").await;

    // Allow time for virtual node loops to initialize
    tokio::time::sleep(Duration::from_secs(1)).await;

    // 2. Node A starts sending a shard but "crashes" after 2 chunks
    let test_shard_id = 999;
    let partial_chunks = vec![
        ShardChunk { shard_id: test_shard_id, chunk_index: 0, total_chunks: 5, data: vec![1, 2, 3] },
        ShardChunk { shard_id: test_shard_id, chunk_index: 1, total_chunks: 5, data: vec![4, 5, 6] },
    ];

    for chunk in partial_chunks {
        harness.broadcast(&node_a_did, SimPacket::Chunk(chunk)).await;
    }

    // 3. Trigger "Node Death"
    tracing::info!("Node Alpha going dark...");
    harness.stop_node(&node_a_did).await;

    // 4. Wait for Node Beta to timeout Node Alpha and run its cleanup tick
    // This must be longer than config.network.pulse_timeout_secs
    let wait_time = config.network.pulse_timeout_secs + 2;
    tracing::info!("Waiting {}s for salvage timeout...", wait_time);
    tokio::time::sleep(Duration::from_secs(wait_time)).await;

    // 5. VERIFICATION: Check Node Beta's vault
    // Note: Node Beta's vault is at "sim_vault/Beta" based on our spawn_node logic
    let vault_path = std::path::PathBuf::from("sim_vault/Beta");
    
    // We expect to find a file in the directory named after Node A's DID
    let node_a_safe_did = node_a_did.replace(":", "_");
    let evidence_dir = vault_path.join(node_a_safe_did);

    assert!(evidence_dir.exists(), "Beta should have created a directory for Alpha's evidence");

    let mut found_salvage = false;
    if let Ok(entries) = std::fs::read_dir(evidence_dir) {
        for entry in entries.flatten() {
            let filename = entry.file_name().to_string_lossy().to_string();
            if filename.contains("session") && filename.contains(".phlx") {
                found_salvage = true;
                let metadata = entry.metadata().unwrap();
                assert!(metadata.len() > 0, "Salvaged file should not be empty");
                tracing::info!(file = %filename, size = %metadata.len(), "FORENSIC SUCCESS: Salvaged shard found in Beta's vault.");
            }
        }
    }

    assert!(found_salvage, "Node Beta failed to salvage the partial shard from Node Alpha");
}