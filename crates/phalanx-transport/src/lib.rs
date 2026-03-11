// crates/phalanx-transport/src/lib.rs

// 1. EXTERNAL DEPENDENCIES
use async_trait::async_trait; // THE MISSING PIECE
use libp2p::PeerId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::*; // Pulls in MeshTopic, VolleyResponse, NetworkEvent
use std::str::FromStr;
use tokio::sync::mpsc; // FIX: Corrected from 'use crate::mpsc'

// 2. MODULE REGISTRY
pub mod adapters {
    pub mod kademlia;
    pub mod libp2p;
    pub mod mock;
    pub mod quic;
}

pub mod behaviour;
pub mod builder;
pub mod codec;
pub mod events;
pub mod identity_ext;
pub mod io;
pub mod kademlia;
pub mod retrieval;
pub mod routing {
    pub mod governor;
    pub mod table;
}
pub mod signaling;

#[cfg(test)]
pub mod mock;

// 3. THE TRANSPORT ADAPTER (THE PRIMARY INTERFACE)
// This is what the MeshSentinel/Node uses to interact with the mesh.
#[async_trait]
pub trait TransportAdapter: Send + Sync {
    /// Broadcast data to all peers subscribed to a topic.
    async fn publish(&self, topic: MeshTopic, data: Vec<u8>) -> Result<(), TransportError>;

    /// Send data directly to a specific peer.
    async fn send_direct(&self, target: &NetworkId, data: Vec<u8>) -> Result<(), TransportError>;

    /// Provides the stream of incoming network events (messages, peer joins, etc.)
    fn ingress_stream(&self) -> mpsc::Receiver<NetworkEvent>;

    /// Sever the connection and block a peer.
    async fn ban_peer(&self, peer: &NetworkId) -> Result<(), TransportError>;
}

// 3b. THE NETWORK TRANSPORT (THE NARRATOR'S INTERFACE)
// This is the mutable, event-driven trait consumed by the MeshSentinel actor loop.
// MockTransport and FailingTransport implement this for simulation.
#[async_trait]
pub trait NetworkTransport: Send {
    /// Publish data to all subscribers of a topic.
    async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String>;

    /// Poll for the next inbound network event.
    async fn next_event(&mut self) -> Option<NetworkEvent>;

    /// Ban a peer by its forensic NetworkId.
    async fn ban_peer(&mut self, peer: &NetworkId);

    /// Send a response to a specific retrieval channel.
    async fn send_response(
        &mut self,
        channel_id: &str,
        response: VolleyResponse,
    ) -> Result<(), String>;
}

// NEW: Discrete ports for Actor-based architecture

#[async_trait]
pub trait IngressPort: Send {
    async fn next_event(&mut self) -> Option<NetworkEvent>;
}

#[async_trait]
pub trait EgressPort: Send + Sync + Clone {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String>;
    async fn ban_peer(&self, peer: &NetworkId);
    async fn send_response(&self, channel_id: &str, response: VolleyResponse)
        -> Result<(), String>;
}

// 4. THE PEER MAPPER (THE TRANSLATOR)
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

// 5. ERROR TYPES
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Network failure: {0}")]
    Network(String),

    #[error("Serialization failure: {0}")]
    Serialization(String),

    #[error("Protocol violation: {0}")]
    Protocol(String),

    #[error("Internal violation: {0}")]
    Internal(String),
}

// 6. THE PRELUDE (GATEWAY FOR OTHER CRATES)
pub mod prelude {
    pub use crate::adapters::libp2p::Libp2pAdapter;
    pub use crate::EgressPort;
    pub use crate::IngressPort;
    pub use crate::NetworkTransport;
    pub use crate::PeerMapper;
    pub use crate::TransportAdapter;
    pub use crate::TransportError;
}
