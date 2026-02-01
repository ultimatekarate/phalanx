use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{info, warn, span, Level};
use crate::shards::{WitnessEnvelope, ShardChunk};
use crate::identity::PhalanxIdentity;
use crate::sentinel::Sentinel;
use crate::stronghold::Stronghold;
use crate::config::PhalanxConfig;

/// Packets sent over the simulated mesh
#[derive(Clone)]
pub enum SimPacket {
    Chunk(ShardChunk),
    Heartbeat(PeerId, Vec<u8>), // Serialized ControlMessage
}

/// A handle to a virtual node in the harness
pub struct SimNodeHandle {
    pub did: String,
    pub tx: mpsc::Sender<(String, SimPacket)>, // Send to node
}

pub struct SimulationHarness {
    pub nodes: HashMap<String, mpsc::Sender<SimPacket>>,
    pub broadcast_channel: mpsc::Sender<(String, SimPacket)>,
    pub config: PhalanxConfig,
}

impl SimulationHarness {
    pub fn new(config: PhalanxConfig) -> Self {
        Self {
            nodes: HashMap::new(),
            config,
        }
    }

    pub fn init_mesh(config: PhalanxConfig) -> (Self, mpsc::Receiver<(String, SimPacket)>) {
        let (tx, rx) = mpsc::channel(1024);
        let harness = Self {
            nodes: HashMap::new(),
            broadcast_channel: tx,
            config,
        };
        (harness, rx)
    }

    pub async fn run_mesh_relay(&mut self, mut relay_rx: mpsc::Receiver<(String, PeerId, SimPacket)>) {
        while let Some((sender_did, sender_peer, packet)) = relay_rx.recv().await {
            for (did, node_tx) in &self.nodes {
                // Don't echo back to the sender
                if did != &sender_did {
                    let _ = node_tx.send(packet.clone()).await;
                }
            }
        }
    }

    /// Spawns a new virtual node into the simulation
    pub async fn spawn_node(&mut self, name: &str) -> String {
        let identity = PhalanxIdentity::generate();
        let did = identity.did.clone();
        let (node_tx, mut node_rx) = mpsc::channel::<SimPacket>(100);
        let peer_id = libp2p::PeerId::random();

        self.nodes.insert(did.clone(), node_tx);

        let broadcast_tx = self.broadcast_channel.clone();
        let node_did = did.clone();
        
        let mut sentinel = Sentinel::new(&self.config);
        let mut storage = Stronghold::new(&format!("sim_vault/{}", name));
        
        // The Virtual Node Loop
        tokio::spawn(async move {
            let _span = span!(Level::INFO, "sim_node", node = name, did = %node_did, peer = %peer_id).entered();
            info!("Virtual node started");

            // Heartbeat interval (defaulting to 30s if not specified in config)
            let mut heartbeat_tick = tokio::time::interval(std::time::Duration::from_secs(30));

            loop {
                tokio::select! {
                    // 1. Outgoing Heartbeat Emission
                    _ = heartbeat_tick.tick() => {
                        let msg = crate::sentinel::ControlMessage {
                            sender: node_did.clone(),
                            load_factor: 0.0,
                            is_on_battery: false,
                            storage_remaining_mb: 5000,
                        };
                        
                        if let Ok(data) = postcard::to_stdvec(&msg) {
                            let _ = broadcast_tx.send((node_did.clone(), peer_id, SimPacket::Heartbeat(peer_id, data))).await;
                        }
                    }

                    // 2. Incoming Packet Processing
                    Some(packet) = node_rx.recv() => {
                        match packet {
                            SimPacket::Chunk(chunk) => {
                                if let Some(envelope) = sentinel.ingest_chunk(chunk) {
                                    storage.ingest_envelope(envelope);
                                }
                            }
                            SimPacket::Heartbeat(data) => {
                                if let Ok(msg) = postcard::from_bytes::<crate::sentinel::ControlMessage>(&data) {
                                    // In simulation, we map heartbeats to a generic PeerId for tracking
                                    sentinel.register_sim_heartbeat(peer_id, msg);
                                    
                                    tracing::debug!(
                                        sender_did = %node_did, 
                                        "Simulated heartbeat processed"
                                    );
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
        for (did, tx) in &self.nodes {
            if did != sender_did {
                let _ = tx.send(packet.clone()).await;
            }
        }
    }
}