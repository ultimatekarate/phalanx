use crate::base::config::PhalanxPhysics;
use crate::base::types::{PowerState, UnitInterval, VitalityRate};
use crate::primitives::identity::NetworkId;
use std::collections::HashMap;
use tokio::time::Instant;

// =====================
// HEALTH & CAPACITY
// =====================
/// Tracks peer vitality and their reported resource availability.
pub struct HealthTracker {
    pub heartbeats: HashMap<NetworkId, Instant>,
    pub capacities: HashMap<NetworkId, ControlMessage>,
    pub peer_contracts: HashMap<NetworkId, VitalityRate>,
}

impl HealthTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            heartbeats: HashMap::new(),
            capacities: HashMap::new(),
            peer_contracts: HashMap::new(),
        }
    }

    pub fn register_activity(&mut self, msg: ControlMessage) {
        let peer_id = msg.sender;
        self.heartbeats.insert(peer_id, Instant::now());
        self.peer_contracts
            .insert(peer_id, VitalityRate::new(msg.heartbeat_ms));
        self.capacities.insert(peer_id, msg);
    }

    #[must_use]
    pub fn is_peer_stale(&self, peer_id: &NetworkId, physics: &PhalanxPhysics) -> bool {
        let last_time = match self.heartbeats.get(peer_id) {
            Some(t) => t,
            None => return true,
        };

        // Use the peer's reported interval, or fall back to physics default if unknown
        let default_load_factor = 0.0;
        let contract = self
            .peer_contracts
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| {
                VitalityRate::calculate(
                    physics,
                    PowerState::Normal,
                    UnitInterval::new(default_load_factor),
                )
            });

        // Apply physics jitter_factor to allow for network variance
        let grace_period = contract.as_duration() * physics.jitter_factor as u32;

        last_time.elapsed() > grace_period
    }
}

/// Standard default method.
impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlMessage {
    pub sender: NetworkId,
    pub load_factor: f32,
    pub storage_remaining_mb: u64,
    pub heartbeat_ms: u64,
    pub is_leaf: bool,
}
