use crate::base::types::MeshTopic;
use crate::primitives::identity::NetworkId;
use crate::transport::events::NetworkEvent;
use async_trait::async_trait;

#[async_trait]
pub trait NetworkTransport: Send + 'static {
    /// Pushes a payload out to the mesh
    async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String>;

    /// Pulls the next parsed event from the underlying network implementation
    async fn next_event(&mut self) -> Option<NetworkEvent>;

    /// Drops a peer from the routing table (used by the TrustRegistry)
    async fn ban_peer(&mut self, peer: &NetworkId);
}
