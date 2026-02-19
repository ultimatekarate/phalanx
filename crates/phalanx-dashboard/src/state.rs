// crates/phalanx-dashboard/src/state.rs

use std::collections::HashMap;
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
    pub logs: Vec<String>,
    pub metrics: DashboardMetrics,
    pub current_scenario: String,
    pub is_running: bool,
}

impl DashboardState {
    pub fn new() -> Self {
        Self {
            active_peers: HashMap::new(),
            node_modes: HashMap::new(),
            node_roles: HashMap::new(),
            active_vectors: Vec::new(),
            logs: Vec::new(),
            metrics: DashboardMetrics {
                total_bytes_processed: 0,
            },
            current_scenario: "Stable".to_string(),
            is_running: true,
        }
    }

    pub fn tick_maintenance(&mut self) {
        let retention_threshold = Duration::from_secs(2);
        self.active_vectors
            .retain(|vector| vector.timestamp.elapsed() < retention_threshold);
    }

    pub fn push_log(&mut self, message: String) {
        self.logs.insert(0, message);
        if self.logs.len() > 50 {
            self.logs.truncate(50);
        }
    }

    pub fn ingest_telemetry(&mut self, event: SimEvent) {
        match event {
            SimEvent::Heartbeat { origin, .. } => {
                self.active_peers.insert(origin, Instant::now());
            }
            SimEvent::PeerDiscovered { peer, role, .. } => {
                self.node_roles.insert(peer, role);
                self.active_peers.insert(peer, Instant::now());
            }
            SimEvent::ShardProcessed { peer_id, byte_size } => {
                self.metrics.total_bytes_processed += byte_size.as_u64();
                self.active_peers.insert(peer_id, Instant::now());
            }
            SimEvent::AttackAttemptBlocked {
                attacker,
                target,
                reason,
            } => {
                self.push_log(format!("[DEFENSE] {} -> {}: {}", attacker, target, reason));
                self.active_vectors.push(ActiveVector {
                    origin: attacker,
                    target, // Use the extracted target
                    timestamp: Instant::now(),
                    style: VectorStyle::Attack,
                });
            }
            SimEvent::OffloadComplete {
                origin,
                target,
                size,
            } => {
                let target_role = self.node_roles.get(&target).unwrap_or(&NodeRole::Guardian);

                if *target_role == NodeRole::Stronghold {
                    self.push_log(format!(
                        "[ARCHIVE] {} -> {}: {} bytes",
                        origin,
                        target,
                        size.as_u64()
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
            _ => {}
        }
    }

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