use crate::prelude::{MeshTopic, NetworkId};
use crate::retrieval::VolleyRequest;
use crate::telemetry::DiscoverySource;

pub const RETRIEVAL_PROTOCOL_ID: &str = "/phalanx/retrieval/1.0.0";
pub const DISCOVERY_TOPIC_ID: &str = "/phalanx/discovery/1.0.0";

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    DataReceived {
        origin: NetworkId,
        topic: MeshTopic,
        data: Vec<u8>,
    },
    /// A new peer was discovered on the mesh.
    /// `source` indicates HOW it was discovered — mDNS (local) vs Kademlia/Bootstrap (internet).
    /// The MeshSentinel uses this to track internet connectivity.
    PeerDiscovered {
        peer: NetworkId,
        source: DiscoverySource,
    },
    VolleyRequested {
        origin: NetworkId,
        request: VolleyRequest,
        channel_id: String,
    },
    Shutdown,
}
