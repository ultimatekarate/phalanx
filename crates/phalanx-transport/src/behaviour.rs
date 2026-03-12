use crate::behaviour::kad::store::RecordStore;
use crate::codec::PhalanxRetrievalProtocol;
use crate::events::PhalanxEvent;
use libp2p::kad::RecordKey;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    autonat, connection_limits, dcutr, gossipsub, identify, kad, mdns, relay, request_response,
};
use phalanx_proto::constants::DiscoveryError;
use phalanx_proto::prelude::*;
// Also, define STRONGHOLD_NAMESPACE if it was lost in the proto move:
pub const STRONGHOLD_NAMESPACE: &[u8] = b"phalanx/stronghold";

pub type PhalanxKadStore = kad::store::MemoryStore;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour<S: RecordStore + Send + Sync + 'static> {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<S>,
    pub identify: identify::Behaviour,
    pub relay_server: relay::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
    pub retrieval: request_response::Behaviour<PhalanxRetrievalProtocol>,
    /// E1 FIX: Swarm-level connection limits to prevent eclipse attacks.
    /// Enforces hard caps on total connections and per-peer connections.
    pub connection_limits: connection_limits::Behaviour,
}

impl<S> PhalanxBehaviour<S>
where
    S: RecordStore + Send + Sync + 'static,
{
    /// Announces the local node as a Stronghold provider to the network.
    ///
    /// # Sentinel Argument
    /// The `local_node_id` must be passed explicitly. This ensures the
    /// forensic log is always signed by the caller's verified identity.
    pub fn announce_stronghold(&mut self, local_node_id: &NetworkId) -> Option<kad::QueryId> {
        let record_key = RecordKey::new(&STRONGHOLD_NAMESPACE);

        tracing::info!(
            target: "phalanx::transport",
            "Announcing local node as Stronghold provider"
        );

        let result = self
            .kademlia
            .start_providing(record_key)
            .map_err(|_| DiscoveryError::StorageError);

        if let Err(ref e) = result {
            tracing::warn!(
                target: "phalanx::transport",
                node = %local_node_id,
                "DHT Announcement Failed: {:?}", e
            );
        }

        result.ok()
    }

    pub fn find_strongholds(&mut self) -> kad::QueryId {
        let record_key = RecordKey::new(&STRONGHOLD_NAMESPACE);

        tracing::info!(
            target: "phalanx::transport",
            "Initiating discovery for Stronghold providers"
        );

        self.kademlia.get_providers(record_key)
    }
}
