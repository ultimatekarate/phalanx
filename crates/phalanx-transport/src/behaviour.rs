#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<PhalanxKadStore>,
    pub identify: identify::Behaviour,
    pub relay_server: relay::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
    pub retrieval: request_response::Behaviour<PhalanxRetrievalProtocol>,
}

impl PhalanxBehaviour {
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

        self.kademlia
            .start_providing(record_key)
            .map_err(|_| DiscoveryError::StorageError)
            .gate(
                "dht_announce_fail",
                local_node_id,
                "DHT Announcement Failed",
            )
            .ok()
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
