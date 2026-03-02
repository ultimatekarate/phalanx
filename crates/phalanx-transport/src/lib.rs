// crates/phalanx-transport/src/lib.rs
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::*;
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

/// The Transport Prelude: Interface for the MeshSentinel to the physical wire.
pub mod prelude {
    pub use crate::adapters::libp2p::Libp2pAdapter;
    pub use crate::NetworkTransport;
    pub use crate::TransportError;
}

#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    #[error("Network failure: {0}")]
    Network(String),

    #[error("Serialization failure: {0}")]
    Serialization(String),

    #[error("Protocol violation: {0}")]
    Protocol(String),
}

/// The Mouth: Defines the physical interaction with the data mesh.
/// Note: Native async is utilized here to avoid BoxFuture overhead.
pub trait NetworkTransport: Send + Sync + 'static {
    /// Pushes a payload out to the mesh (Gossipsub/Broadcast).
    async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), TransportError>;

    /// Pulls the next parsed forensic event from the physical layer.
    async fn next_event(&mut self) -> Option<NetworkEvent>;

    /// Explicitly blacklists a peer in the physical routing tables.
    async fn ban_peer(&mut self, peer: &NetworkId);

    /// Fulfills a Direct-Request (Request/Response) interaction.
    async fn send_response(
        &mut self,
        channel_id: &str,
        response: VolleyResponse,
    ) -> Result<(), TransportError>;
}
