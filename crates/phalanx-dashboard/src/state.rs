use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

use phalanx_core::primitives::identity::NetworkId;
use phalanx_core::security::telemetry::{ChaosMode, NodeRole, SimEvent};

use crate::widgets::{TrafficVector, VectorStyle};

pub struct ActiveVector {
    pub origin: NetworkId,
    pub target: NetworkId,
    pub timestamp: Instant,
    pub style: VectorStyle,
}

pub struct DashboardMetrics {
    pub total_bytes_processed: u64,
}

pub struct DashboardState {
    pub active_peers: HashMap<NetworkId, Instant>,
    pub node_modes: HashMap<NetworkId, ChaosMode>,
    pub node_roles: HashMap<NetworkId, NodeRole>,
    pub active_vectors: Vec<ActiveVector>,
    pub logs: VecDeque<String>, // Migrated to VecDeque for O(1) front insertions
    pub metrics: DashboardMetrics,
    pub current_scenario: String,
    pub is_running: bool,
}

impl DashboardState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            active_peers: HashMap::new(),
            node_modes: HashMap::new(),
            node_roles: HashMap::new(),
            active_vectors: Vec::new(),
            logs: VecDeque::with_capacity(51), // Pre-allocated to prevent reallocation
            metrics: DashboardMetrics {
                total_bytes_processed: 0,
            },
            current_scenario: "Stable".to_string(),
            is_running: true,
        }
    }

    pub fn push_log(&mut self, message: String) {
        self.logs.push_front(message); // O(1) shift
        if self.logs.len() > 50 {
            self.logs.pop_back(); // O(1) prune
        }
    }

    pub fn tick_maintenance(&mut self) {
        let now = Instant::now();

        // Prune stale visual vectors
        self.active_vectors
            .retain(|v| now.duration_since(v.timestamp) < Duration::from_secs(2));

        // Prune stale peer indicators
        self.active_peers
            .retain(|_, last_seen| now.duration_since(*last_seen) < Duration::from_secs(10));
    }

    pub fn ingest_telemetry(&mut self, event: SimEvent) {
        match event {
            SimEvent::AttackAttemptBlocked {
                attacker,
                target,
                reason,
            } => {
                self.push_log(format!(
                    "[DEFENSE] {} blocked {}: {}",
                    target, attacker, reason
                ));

                if let Some(existing) = self.active_vectors.iter_mut().find(|v| {
                    v.origin == attacker && v.target == target && v.style == VectorStyle::Attack
                }) {
                    existing.timestamp = Instant::now();
                } else {
                    self.active_vectors.push(ActiveVector {
                        origin: attacker,
                        target,
                        timestamp: Instant::now(),
                        style: VectorStyle::Attack,
                    });
                }
            }
            SimEvent::ChunkIngested { origin, chunk } => {
                let size = chunk.data.len() as u64;
                self.metrics.total_bytes_processed += size;

                // Extract target from the chunk's destination mapping (contextual based on your mesh routing)
                // Defaulting to Guardian for UI visualization purposes
                let target = chunk
                    .owner_did
                    .to_string()
                    .parse::<NetworkId>()
                    .unwrap_or(origin);
                let target_role = self.node_roles.get(&target).unwrap_or(&NodeRole::Guardian);

                if *target_role == NodeRole::Stronghold {
                    self.push_log(format!(
                        "[ARCHIVE] {} -> {}: {} bytes",
                        origin, target, size
                    ));
                }

                if let Some(existing) = self.active_vectors.iter_mut().find(|v| {
                    v.origin == origin && v.target == target && v.style == VectorStyle::Standard
                }) {
                    existing.timestamp = Instant::now();
                } else {
                    self.active_vectors.push(ActiveVector {
                        origin,
                        target,
                        timestamp: Instant::now(),
                        style: VectorStyle::Standard,
                    });
                }
            }
            SimEvent::PeerDiscovered { peer, role, .. } => {
                self.active_peers.insert(peer, Instant::now());
                self.node_roles.insert(peer, role);
            }
            SimEvent::Shutdown => {
                self.push_log("Simulated Node Shutdown Detected".to_string());
            }
            _ => {
                // Not everything goes in the dashboard.
            }
        }
    }

    #[must_use]
    pub fn generate_widget_vectors(&self) -> Vec<TrafficVector> {
        self.active_vectors
            .iter()
            .map(|v| TrafficVector {
                from: v.origin,
                to: v.target,
                age_seconds: v.timestamp.elapsed().as_secs_f32(),
                style: match v.style {
                    VectorStyle::Standard => VectorStyle::Standard,
                    VectorStyle::Attack => VectorStyle::Attack,
                },
            })
            .collect()
    }
}
