use crate::prelude::{MeshTopic, NetworkId};
use crate::retrieval::VolleyRequest;

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
