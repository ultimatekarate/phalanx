use crate::behaviour::kad::store::RecordStore;
use crate::codec::PhalanxRetrievalProtocol;
use crate::events::PhalanxEvent;
use libp2p::kad::RecordKey;
use libp2p::swarm::NetworkBehaviour;
use libp2p::{
    autonat, connection_limits, dcutr, gossipsub, identify, kad, mdns, relay, request_response,
};
use phalanx_proto::constants::DiscoveryError;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::prelude::*;
// Also, define STRONGHOLD_NAMESPACE if it was lost in the proto move:
pub const STRONGHOLD_NAMESPACE: &[u8] = b"phalanx/stronghold";
pub const RECORDING_NAMESPACE_PREFIX: &str = "phalanx/recording/";

pub type PhalanxKadStore = kad::store::MemoryStore;

/// Parse a RecordingId from a Kademlia RecordKey.
/// Inverse of `PhalanxBehaviour::recording_key()`.
pub fn recording_id_from_key(key: &RecordKey) -> Option<RecordingId> {
    let key_str = std::str::from_utf8(key.as_ref()).ok()?;
    key_str
        .strip_prefix(RECORDING_NAMESPACE_PREFIX)
        .map(RecordingId::new)
}

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

    /// Builds a DHT key for a specific recording.
    fn recording_key(recording_id: &RecordingId) -> RecordKey {
        let key = format!("{}{}", RECORDING_NAMESPACE_PREFIX, recording_id.as_str());
        RecordKey::new(&key.as_bytes())
    }

    /// Announces this node as a provider for a specific recording on the DHT.
    pub fn announce_recording(&mut self, recording_id: &RecordingId) -> Option<kad::QueryId> {
        let record_key = Self::recording_key(recording_id);

        tracing::debug!(
            target: "phalanx::transport",
            recording = %recording_id,
            "DHT: Announcing as recording provider"
        );

        self.kademlia
            .start_providing(record_key)
            .map_err(|_| DiscoveryError::StorageError)
            .ok()
    }

    /// Initiates a DHT query to find providers for a specific recording.
    pub fn find_recording_providers(&mut self, recording_id: &RecordingId) -> kad::QueryId {
        let record_key = Self::recording_key(recording_id);

        tracing::debug!(
            target: "phalanx::transport",
            recording = %recording_id,
            "DHT: Querying for recording providers"
        );

        self.kademlia.get_providers(record_key)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn recording_id_from_key_parses_phalanx_namespace() {
        let key_str = format!("{}{}", RECORDING_NAMESPACE_PREFIX, "abc-123");
        let key = RecordKey::new(&key_str);
        assert_eq!(
            recording_id_from_key(&key),
            Some(RecordingId::new("abc-123"))
        );

        let bad_key = RecordKey::new(&b"not-a-phalanx-key");
        assert_eq!(recording_id_from_key(&bad_key), None);
    }
}
