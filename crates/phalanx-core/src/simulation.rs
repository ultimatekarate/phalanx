use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::base::engine::PhalanxEngine;
use crate::base::types::MeshTopic;
use crate::primitives::identity::{Did, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{ShardChunk, ShardError};
use crate::security::telemetry::{ChaosMode, NodeRole, SimEvent};
use crate::storage::reassembler::TransientJournal;
use crate::transport::events::NetworkEvent;
use crate::transport::mock::MockTransport;

// =========================================================================================
//  POLYFILL: Simulation Journal
// =========================================================================================

pub struct SimJournal;

#[async_trait::async_trait]
impl TransientJournal for SimJournal {
    async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
        Ok(())
    }
    async fn sync(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        Ok(vec![])
    }
    async fn clear(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
}

// =========================================================================================
//  INFRASTRUCTURE: The Hexagonal Simulation Harness
// =========================================================================================

pub struct SimulationHarness {
    pub config: PhalanxConfig,
    pub physics: PhalanxPhysics,
    pub telemetry_tx: mpsc::Sender<SimEvent>,
    pub identity_registry: Arc<RwLock<HashMap<Did, NetworkId>>>,

    // The routing table for the Mock Transport adapters.
    // Driving this directly simulates incoming network sockets.
    pub ingress_routes: Arc<RwLock<HashMap<Did, mpsc::Sender<NetworkEvent>>>>,
    pub chaos_registry: Arc<RwLock<HashMap<Did, ChaosMode>>>,
}

impl SimulationHarness {
    #[must_use]
    pub fn init_mesh(
        config: PhalanxConfig,
        physics: PhalanxPhysics,
    ) -> (Self, mpsc::Receiver<SimEvent>) {
        let (telemetry_tx, telemetry_rx) = mpsc::channel(4096);

        let harness = Self {
            config,
            physics,
            telemetry_tx,
            identity_registry: Arc::new(RwLock::new(HashMap::new())),
            ingress_routes: Arc::new(RwLock::new(HashMap::new())),
            chaos_registry: Arc::new(RwLock::new(HashMap::new())),
        };

        (harness, telemetry_rx)
    }

    pub async fn resolve_did(&self, did: &Did) -> Option<NetworkId> {
        self.identity_registry.read().await.get(did).copied()
    }

    pub async fn inject_chaos(&self, target_did: &Did, mode: ChaosMode) {
        let mut registry = self.chaos_registry.write().await;
        registry.insert(target_did.clone(), mode);
        info!(target: "phalanx::chaos", node=%target_did, ?mode, "Chaos parameters updated for node traffic");
    }

    /// Spawns an actual PhalanxEngine backed by the MockTransport adapter.
    pub async fn spawn_node(&mut self, name: &str, _role: NodeRole) -> Option<Did> {
        // 1. Establish Domain Identity
        let identity_result = PhalanxIdentity::generate();
        let (identity, _) = match identity_result {
            Ok(res) => res,
            Err(e) => {
                error!(node = %name, error = %e, "Failed to generate node identity.");
                return None;
            }
        };

        let node_did = identity.did.clone();
        let network_id = identity.to_network_id();

        self.identity_registry
            .write()
            .await
            .insert(node_did.clone(), network_id);

        info!(node = %name, %network_id, "Initializing Production Engine on Mock Adapter");

        // 2. Establish Mock Transport Port (The Adapter)
        let (ingress_tx, ingress_rx) = mpsc::channel::<NetworkEvent>(4096);
        let (egress_tx, mut egress_rx) = mpsc::channel::<(MeshTopic, Vec<u8>)>(4096);
        let transport = MockTransport::new(ingress_rx, Some(egress_tx))
            .with_telemetry(network_id, self.telemetry_tx.clone());

        self.ingress_routes
            .write()
            .await
            .insert(node_did.clone(), ingress_tx);

        // 3. Initialize the Actual Production Engine
        let engine_result =
            PhalanxEngine::new(self.config.clone(), identity, transport, SimJournal);

        let mut engine = match engine_result {
            Ok(e) => e,
            Err(err) => {
                error!(error = %err, "Critical: PhalanxEngine failed to initialize.");
                return None;
            }
        };

        // 4. Detach Engine Execution
        tokio::spawn(async move {
            if let Err(e) = engine.run().await {
                error!(error = %e, "Simulation node engine terminated unexpectedly.");
            }
        });

        // 5. Wire Mesh Routing (Egress -> Ingress)
        let routing_table = Arc::clone(&self.ingress_routes);
        let source_did = node_did.clone();
        let source_network_id = network_id;
        let chaos_registry = Arc::clone(&self.chaos_registry);

        tokio::spawn(async move {
            while let Some((topic, data)) = egress_rx.recv().await {
                let current_chaos = chaos_registry
                    .read()
                    .await
                    .get(&source_did)
                    .cloned()
                    .unwrap_or(ChaosMode::Stable);

                // Network Chaos Emulation: Packet Loss
                if let ChaosMode::PacketLoss(prob) = current_chaos {
                    // Quick probabilistic drop logic without importing rand directly here
                    let drop = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .subsec_nanos()
                        % 100
                        < (prob * 100.0) as u32;
                    if drop {
                        warn!(%source_network_id, "Packet dropped due to chaos emulation");
                        continue;
                    }
                }

                // Emulate Network Discovery/Gossip Propagation
                let payload_event = NetworkEvent::DataReceived {
                    origin: source_network_id,
                    topic,
                    data,
                };

                let routes = routing_table.read().await;
                for (target_did, target_tx) in routes.iter() {
                    // Prevent echoing to self
                    if target_did != &source_did {
                        if let Err(err) = target_tx.send(payload_event.clone()).await {
                            error!(error = %err, %target_did, "Mesh routing failure in harness");
                        }
                    }
                }
            }
        });

        Some(node_did)
    }

    /// Facilitates direct event injection (e.g., Byzantine attack tests)
    pub async fn inject_event(&self, target: &Did, event: NetworkEvent) -> Result<(), String> {
        let routes = self.ingress_routes.read().await;
        if let Some(tx) = routes.get(target) {
            tx.send(event).await.map_err(|e| e.to_string())
        } else {
            Err("Target node not found in simulation routing table".into())
        }
    }

    pub async fn advance_mesh_time(&self, duration: std::time::Duration) {
        tracing::info!(
            target: "phalanx::simulation",
            dilation_ms = duration.as_millis(),
            "Advancing virtual mesh clock to trigger actor heartbeats"
        );

        // Advance the internal timer wheel
        tokio::time::advance(duration).await;

        // Force the executor to poll the waking background tasks,
        // ensuring the StorageActor's `select!` macro processes the tick.
        tokio::task::yield_now().await;
    }
}
