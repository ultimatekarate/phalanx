// crates/phalanx-transport/src/signaling.rs
use phalanx_proto::{MeshTopic, NetworkId};

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    DataReceived {
        origin: NetworkId,
        topic: MeshTopic,
        data: Vec<u8>,
    },
    PeerConnected(NetworkId),
    PeerDisconnected(NetworkId),
    TransmissionError(String),
}