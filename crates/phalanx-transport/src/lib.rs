// crates/phalanx-transport/src/lib.rs
pub mod adapters;
pub mod routing;
pub mod signaling;

use async_trait::async_trait;
use phalanx_proto::{MeshTopic, NetworkId};
use crate::signaling::NetworkEvent;

#[async_trait]
pub trait TransportAdapter: Send + Sync {
    /// Send a Noun (data) across a Preposition (target/topic).
    async fn send(&self, target: &NetworkId, topic: MeshTopic, data: Vec<u8>) -> Result<(), TransportError>;
    
    /// The stream of incoming Prepositional signals.
    async fn ingress_stream(&self) -> tokio::sync::mpsc::Receiver<NetworkEvent>;
}


#[async_trait]
pub trait NetworkTransport: Send + 'static {
    /// Pushes a payload out to the mesh
    async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String>;

    /// Pulls the next parsed event from the underlying network implementation
    async fn next_event(&mut self) -> Option<NetworkEvent>;

    /// Drops a peer from the routing table (used by the TrustRegistry)
    async fn ban_peer(&mut self, peer: &NetworkId);

    /// Fulfills a pending network retrieval request
    async fn send_response(
        &mut self,
        channel_id: &str,
        response: VolleyResponse,
    ) -> Result<(), String>;
}