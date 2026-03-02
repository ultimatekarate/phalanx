use libp2p::PeerId;
use phalanx_proto::identity::NetworkId;
use std::str::FromStr;

#[async_trait]
pub trait TransportAdapter: Send + Sync {
    /// Broadcast data to all peers subscribed to a topic.
    async fn publish(&self, topic: MeshTopic, data: Vec<u8>) -> Result<(), TransportError>;

    /// Send data directly to a specific peer.
    async fn send_direct(&self, target: &NetworkId, data: Vec<u8>) -> Result<(), TransportError>;

    /// Provides the stream of incoming network events (messages, peer joins, etc.)
    fn ingress_stream(&self) -> mpsc::Receiver<NetworkEvent>;
}

pub struct PeerMapper;

impl PeerMapper {
    /// Translates a physical PeerId into a forensic NetworkId.
    pub fn to_network_id(peer_id: &PeerId) -> NetworkId {
        NetworkId(peer_id.to_base58())
    }

    /// Translates a forensic NetworkId back into a physical PeerId.
    pub fn from_network_id(network_id: &NetworkId) -> Result<PeerId, String> {
        PeerId::from_str(&network_id.0).map_err(|error| error.to_string())
    }
}
