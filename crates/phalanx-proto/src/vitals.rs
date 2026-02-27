// crates/phalanx-proto/src/vitals.rs
use crate::identity::NetworkId;
use serde::{Deserialize, Serialize};

/// The heartbeat of the Phalanx network.
/// Broadcasted to coordinate load-balancing and peer vitality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    pub sender: NetworkId,
    pub load_factor: f32,
    pub storage_remaining_mb: u64,
    pub heartbeat_ms: u64,
    pub is_leaf: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatInterval(pub u64);

impl HeartbeatInterval {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}
