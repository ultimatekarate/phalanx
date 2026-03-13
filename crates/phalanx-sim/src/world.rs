// crates/phalanx-sim/src/world.rs
//
// The "Ether": Shared state where simulated nodes meet.
// Holds the in-memory mesh topology, virtual transport channels between nodes,
// and the chaos injection state for each link.

use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{Did, MeshTopic};
use phalanx_proto::telemetry::ChaosMode;
use std::collections::HashMap;
use tokio::sync::mpsc;
use tracing::{debug, warn};

/// Shared simulation state: identity registry, ingress routing table, and chaos config.
///
/// All fields are accessed through `Arc<tokio::sync::RwLock<SimulationWorld>>` by the
/// harness and each node's `SimEgress`. Using `tokio::sync::RwLock` (not `parking_lot`)
/// because `route_publish()` calls `ingress_tx.send().await` inside the lock.
pub struct SimulationWorld {
    /// Maps each node's DID to its ingress channel sender.
    /// Used by `route_publish()` to forward data to all other nodes.
    pub ingress_routes: HashMap<Did, mpsc::Sender<NetworkEvent>>,

    /// Maps each node's DID to its forensic NetworkId.
    /// Used by `resolve_did()` and for constructing `DataReceived` events.
    pub identity_map: HashMap<Did, NetworkId>,

    /// Per-node chaos mode. Defaults to `ChaosMode::Stable` when absent.
    /// Checked during `route_publish()` to apply packet loss, byzantine failure, etc.
    pub chaos_registry: HashMap<Did, ChaosMode>,
}

impl SimulationWorld {
    /// Create a new empty simulation world.
    pub fn new() -> Self {
        Self {
            ingress_routes: HashMap::new(),
            identity_map: HashMap::new(),
            chaos_registry: HashMap::new(),
        }
    }

    /// Register a node in the simulation world.
    /// Called by `SimulationHarness::spawn_node()` after identity generation.
    pub fn register_node(
        &mut self,
        did: Did,
        network_id: NetworkId,
        ingress_tx: mpsc::Sender<NetworkEvent>,
    ) {
        self.identity_map.insert(did.clone(), network_id);
        self.ingress_routes.insert(did, ingress_tx);
    }

    /// Look up a node's NetworkId by its DID.
    pub fn lookup_network_id(&self, did: &Did) -> Option<NetworkId> {
        self.identity_map.get(did).cloned()
    }

    /// Route a publish to all other nodes in the mesh, applying chaos filtering.
    ///
    /// This emulates gossipsub propagation: the source node publishes data on a topic,
    /// and all other nodes receive it as a `NetworkEvent::DataReceived`.
    ///
    /// Chaos filtering is applied based on the **source** node's chaos mode:
    /// - `Stable` / `Hyperactive`: normal delivery
    /// - `PacketLoss(prob)`: probabilistic drop (0.0 = no loss, 1.0 = total loss)
    /// - `Byzantine`: all publishes silently dropped (simulates total network partition)
    /// - `HighLatency(_)`: delivered normally (latency is handled at the clock level)
    pub async fn route_publish(
        &self,
        source_did: &Did,
        source_network_id: NetworkId,
        topic: MeshTopic,
        data: Vec<u8>,
    ) -> Result<(), String> {
        let chaos_mode = self
            .chaos_registry
            .get(source_did)
            .cloned()
            .unwrap_or(ChaosMode::Stable);

        match chaos_mode {
            ChaosMode::Byzantine => {
                debug!(
                    source = %source_network_id,
                    "Byzantine chaos: all publishes dropped"
                );
                return Ok(());
            }
            ChaosMode::PacketLoss(prob) => {
                if rand::random::<f32>() < prob {
                    debug!(
                        source = %source_network_id,
                        probability = prob,
                        "Chaos packet loss: message dropped"
                    );
                    return Ok(());
                }
            }
            _ => {} // Stable, HighLatency, Hyperactive: deliver normally
        }

        let event = NetworkEvent::DataReceived {
            origin: source_network_id.clone(),
            topic,
            data,
        };

        for (target_did, target_tx) in &self.ingress_routes {
            // Don't echo back to source
            if target_did == source_did {
                continue;
            }

            if let Err(e) = target_tx.send(event.clone()).await {
                warn!(
                    source = %source_network_id,
                    target = %target_did,
                    error = %e,
                    "Mesh routing failure: target node's ingress channel closed"
                );
            }
        }

        Ok(())
    }
}

impl Default for SimulationWorld {
    fn default() -> Self {
        Self::new()
    }
}
