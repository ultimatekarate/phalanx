use crate::prelude::{MeshTopic, NetworkId};
use crate::retrieval::VolleyRequest;

pub const RETRIEVAL_PROTOCOL_ID: &str = "/phalanx/retrieval/1.0.0";
pub const DISCOVERY_TOPIC_ID: &str = "/phalanx/discovery/1.0.0";

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    DataReceived {
        origin: NetworkId,
        topic: MeshTopic,
        data: Vec<u8>,
    },
    PeerDiscovered(NetworkId),
    VolleyRequested {
        origin: NetworkId,
        request: VolleyRequest,
        channel_id: String,
    },
    Shutdown,
}
