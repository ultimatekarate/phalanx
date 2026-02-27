#[derive(Debug, Clone)]
pub enum NetworkEvent {
    DataReceived {
        origin: NetworkId,
        topic: MeshTopic,
        data: Vec<u8>,
    },
    PeerDiscovered(NetworkId),
    RetrievalRequested {
        origin: NetworkId,
        request: VolleyRequest,
        channel_id: String,
    },
    Shutdown,
}
