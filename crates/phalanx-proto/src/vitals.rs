// crates/phalanx-proto/src/vitals.rs
use crate::identity::MeshAddress;
use serde::{Deserialize, Serialize};

/// The heartbeat of the Phalanx network.
/// Broadcasted to coordinate load-balancing and peer vitality.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    pub sender: MeshAddress,
    pub load_factor: f32,
    pub storage_remaining_mb: u64,
    pub heartbeat_ms: u64,
    pub is_leaf: bool,
    /// Tier 2 Shield Wall: optional integral state summary for spectral
    /// consistency verification.  Nodes that omit this field are still
    /// checked via Tier 1 behavioral signals (heartbeat jitter, throughput).
    #[serde(default)]
    pub integral_summary: Option<[f32; 8]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeartbeatInterval(pub u64);

impl HeartbeatInterval {
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}
