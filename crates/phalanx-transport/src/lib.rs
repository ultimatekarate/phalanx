// crates/phalanx-transport/src/lib.rs

// EXTERNAL DEPENDENCIES
use async_trait::async_trait;
use libp2p::PeerId;
use phalanx_proto::network::{IngressPort, NetworkEvent};
use phalanx_proto::prelude::*; // Pulls in MeshTopic, NetworkId
use std::str::FromStr;

// MODULE REGISTRY
pub mod adapters {
    pub mod libp2p;
    pub mod local_mesh;
    pub mod mock;
    pub mod quic;
}

pub mod behaviour;
pub mod builder;
pub mod codec;
pub mod config;
pub mod dht;
pub mod events;
pub mod factory;
pub mod identity_ext;
pub mod io;
pub mod kademlia;
pub mod routing;

/// Combines two `IngressPort` streams into one via `tokio::select!`.
///
/// A Stronghold running both the libp2p swarm and the QuicAdapter creates a
/// `MergedIngress` so `MeshSentinel` sees a single unified event stream.
pub struct MergedIngress<A: IngressPort, B: IngressPort> {
    a: A,
    b: B,
}

impl<A: IngressPort, B: IngressPort> MergedIngress<A, B> {
    pub fn new(a: A, b: B) -> Self {
        Self { a, b }
    }
}

#[async_trait]
impl<A: IngressPort, B: IngressPort> IngressPort for MergedIngress<A, B> {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        tokio::select! {
            ev = self.a.next_event() => ev,
            ev = self.b.next_event() => ev,
        }
    }
}

// THE PEER MAPPER (THE TRANSLATOR)
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

#[cfg(test)]
mod merged_ingress_tests {
    use super::*;
    use phalanx_proto::identity::NetworkId;
    use tokio::sync::mpsc;

    /// A trivial IngressPort backed by an mpsc receiver.
    struct ChanIngress(mpsc::Receiver<NetworkEvent>);

    #[async_trait]
    impl IngressPort for ChanIngress {
        async fn next_event(&mut self) -> Option<NetworkEvent> {
            self.0.recv().await
        }
    }

    #[tokio::test]
    async fn merged_ingress_interleaves_both_sources() {
        let (tx_a, rx_a) = mpsc::channel(8);
        let (tx_b, rx_b) = mpsc::channel(8);

        let mut merged = MergedIngress::new(ChanIngress(rx_a), ChanIngress(rx_b));

        // Send one event from each source.
        let peer_b = NetworkId("libp2p-peer".into());

        tx_a.send(NetworkEvent::Shutdown).await.unwrap();
        tx_b.send(NetworkEvent::PeerDiscovered {
            peer: peer_b.clone(),
            source: phalanx_proto::telemetry::DiscoverySource::Quic,
            bucket: phalanx_proto::topology::SubnetBucket::from_ipv4_prefix(127, 0),
            transport: phalanx_proto::topology::TransportClass::Internet,
        })
        .await
        .unwrap();

        // We should receive both, order is non-deterministic.
        let e1 = merged.next_event().await.expect("event 1");
        let e2 = merged.next_event().await.expect("event 2");

        let mut saw_shutdown = false;
        let mut saw_peer = false;
        for ev in [&e1, &e2] {
            match ev {
                NetworkEvent::Shutdown => saw_shutdown = true,
                NetworkEvent::PeerDiscovered { .. } => saw_peer = true,
                _ => panic!("unexpected event variant"),
            }
        }
        assert!(saw_shutdown, "missing Shutdown from source A");
        assert!(saw_peer, "missing PeerDiscovered from source B");
    }

    #[tokio::test]
    async fn merged_ingress_returns_none_when_both_closed() {
        let (tx_a, rx_a) = mpsc::channel::<NetworkEvent>(1);
        let (tx_b, rx_b) = mpsc::channel::<NetworkEvent>(1);

        let mut merged = MergedIngress::new(ChanIngress(rx_a), ChanIngress(rx_b));

        // Drop both senders.
        drop(tx_a);
        drop(tx_b);

        assert!(merged.next_event().await.is_none());
    }
}

// THE PRELUDE (GATEWAY FOR OTHER CRATES)
// Capability contracts (EgressPort, IngressPort, etc.) live in phalanx_proto::network.
// Import them directly: use phalanx_proto::network::{EgressPort, IngressPort, ...};
pub mod prelude {
    pub use crate::adapters::libp2p::{Libp2pEgress, Libp2pIngress};
    pub use crate::adapters::quic::{
        QuicAdapter, QuicClientConfig, QuicEgress, QuicIngress, QuicServerConfig,
    };
    pub use crate::config::MeshTransportConfig;
    pub use crate::factory::{build_mesh_transport, build_mesh_transport_with_store};
    pub use crate::identity_ext::Libp2pExt;
    pub use crate::MergedIngress;
    pub use crate::PeerMapper;
}
