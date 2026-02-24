// crates/phalanx-core/src/primitives/network.rs

use serde::{Serialize, Deserialize};
use crate::primitives::shards::{ShardId, ShardGapReport};
use crate::primitives::identity::Did;

/// The "Help" signal sent over the mesh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRequest {
    /// The gap report identifying exactly what is missing
    pub report: ShardGapReport,
    /// The DID of the node asking for help (for routing/trust)
    pub requester: Did,
}