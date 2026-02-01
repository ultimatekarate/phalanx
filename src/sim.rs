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
    Heartbeat(Vec<u8>), // Serialized ControlMessage
}

/// A handle to a virtual node in the harness
pub struct SimNodeHandle {
    pub did: String,
    pub tx: mpsc::Sender<(String, SimPacket)>, // Send to node
}

pub struct SimulationHarness {
    pub nodes: HashMap<String, mpsc::Sender<SimPacket>>,
    pub config: PhalanxConfig,
}

impl SimulationHarness {
    pub fn new(config: PhalanxConfig) -> Self {
        Self {
            nodes: HashMap::new(),
            config,
        }
    }

    /// Spawns a new virtual node into the simulation
    pub async fn spawn_node(&mut self, name: &str) -> String {
        let identity = PhalanxIdentity::generate();
        let did = identity.did.clone();
        let (node_tx, mut node_rx) = mpsc::channel::<SimPacket>(100);
        
        self.nodes.insert(did.clone(), node_tx);
        
        let mut sentinel = Sentinel::new(&self.config);
        let mut storage = Stronghold::new(&format!("sim_vault/{}", name));
        
        // The Virtual Node Loop
        tokio::spawn(async move {
            let _span = span!(Level::INFO, "sim_node", node = name, did = %did).entered();
            info!("Virtual node started");

            while let Some(packet) = node_rx.recv().await {
                match packet {
                    SimPacket::Chunk(chunk) => {
                        if let Some(envelope) = sentinel.ingest_chunk(chunk) {
                            storage.ingest_envelope(envelope);
                        }
                    }
                    SimPacket::Heartbeat(data) => {
                        // Simulated heartbeat logic
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