// crates/phalanx-proto/src/vitals.rs
use serde::{Deserialize, Serialize};
use crate::identity::NetworkId;

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