// crates/phalanx-transport/src/lib.rs

// EXTERNAL DEPENDENCIES
use libp2p::PeerId;
use std::str::FromStr;

// MODULE REGISTRY
pub mod adapters {
    pub mod libp2p;
    pub mod local_mesh;
    pub mod mock;
}

pub mod behaviour;
pub mod builder;
pub mod codec;
pub mod config;
pub mod counting;
pub mod dht;
pub mod events;
pub mod factory;
pub mod identity_ext;
pub mod kademlia;
pub mod routing;

// THE PEER MAPPER (THE TRANSLATOR)
pub struct PeerMapper;

impl PeerMapper {
    /// Translates a libp2p `PeerId` into a domain-typed `MeshAddress`.
    /// This is the canonical Post Office translation at the libp2p boundary
    /// per `linguistic-code-model.md` §IV.1.
    pub fn to_mesh_address(peer_id: &PeerId) -> phalanx_proto::identity::MeshAddress {
        phalanx_proto::identity::MeshAddress(peer_id.to_base58())
    }

    /// Translates a `MeshAddress` back into a libp2p `PeerId`.
    /// Returns an error if the address is not a valid PeerId base58 multihash.
    pub fn from_mesh_address(
        address: &phalanx_proto::identity::MeshAddress,
    ) -> Result<PeerId, String> {
        PeerId::from_str(&address.0).map_err(|error| error.to_string())
    }
}

// THE PRELUDE (GATEWAY FOR OTHER CRATES)
// Capability contracts (EgressPort, IngressPort, etc.) live in phalanx_proto::network.
// Import them directly: use phalanx_proto::network::{EgressPort, IngressPort, ...};
pub mod prelude {
    pub use crate::PeerMapper;
    pub use crate::adapters::libp2p::{Libp2pEgress, Libp2pIngress};
    pub use crate::config::MeshTransportConfig;
    pub use crate::factory::{build_mesh_transport, build_mesh_transport_with_store};
    pub use crate::identity_ext::Libp2pExt;
}
