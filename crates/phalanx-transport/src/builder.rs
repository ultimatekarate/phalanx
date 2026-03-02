use futures::future::Either;
use libp2p::{
    autonat, core::upgrade::Version, dcutr, gossipsub, identify, identity::Keypair, kad, mdns,
    noise, pnet, relay, request_response, tcp, yamux, PeerId, StreamProtocol, Transport,
};
use std::error::Error;
use std::time::Duration;

use crate::behaviour::PhalanxBehaviour;

use phalanx_proto::{
    constants::RETRIEVAL_PROTOCOL_ID,
    types::{PhalanxPhysics, PowerState, UnitInterval, VitalityRate},
    // Note: VitalityRate and UnitInterval must be imported from the appropriate proto/domain module
};

/// Constructs the foundational transport stack for the node.
pub fn build_base_transport(
    local_key: &Keypair,
    psk: Option<pnet::PreSharedKey>,
) -> Result<
    libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn Error>,
> {
    let noise_config = noise::Config::new(local_key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    let yamux_config = yamux::Config::default();

    let base_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let dns_transport = libp2p::dns::tokio::Transport::system(base_transport)?;

    type RawStream = libp2p::tcp::tokio::TcpStream;
    type EncryptedStream = libp2p::pnet::PnetOutput<RawStream>;

    let transport = if let Some(key) = psk {
        let pnet_config = pnet::PnetConfig::new(key);
        dns_transport
            .and_then(move |socket, _| pnet_config.handshake(socket))
            .map(|stream, _| Either::<EncryptedStream, RawStream>::Left(stream))
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .boxed()
    } else {
        dns_transport
            .map(|stream, _| Either::<EncryptedStream, RawStream>::Right(stream))
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .boxed()
    };

    Ok(transport)
}

/// Instantiates the composite network behaviour logic.
pub fn build_behaviour<S>(
    local_key: &Keypair,
    max_chunk_size_bytes: usize,
    protocol_version: String,
    physics: &PhalanxPhysics,
    relay_client: relay::client::Behaviour,
    mut kademlia: kad::Behaviour<S>,
) -> Result<PhalanxBehaviour, Box<dyn Error>>
where
    S: kad::store::RecordStore + Send + Sync + 'static,
{
    let local_peer_id = local_key.public().to_peer_id();

    // Calculate gossipsub heartbeat based on physics simulation state
    // Note: Requires VitalityRate and UnitInterval definitions to compile properly
    let gossip_heartbeat =
        VitalityRate::calculate(physics, PowerState::Normal, UnitInterval::new(0.0)).as_duration();

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub::ConfigBuilder::default()
            .heartbeat_interval(gossip_heartbeat)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .max_transmit_size(max_chunk_size_bytes * 2)
            .build()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?,
    )?;

    kademlia.set_mode(Some(kad::Mode::Server));

    let identify =
        identify::Behaviour::new(identify::Config::new(protocol_version, local_key.public()));

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
    let relay_server = relay::Behaviour::new(local_peer_id, relay::Config::default());
    let dcutr = dcutr::Behaviour::new(local_peer_id);
    let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());

    let retrieval_config =
        request_response::Config::default().with_request_timeout(Duration::from_secs(20));

    // Map string constant to typed StreamProtocol
    let retrieval_protocol = StreamProtocol::try_from_owned(RETRIEVAL_PROTOCOL_ID.to_string())?;

    let retrieval = request_response::Behaviour::new(
        [(retrieval_protocol, request_response::ProtocolSupport::Full)],
        retrieval_config,
    );

    Ok(PhalanxBehaviour {
        gossipsub,
        mdns,
        kademlia,
        identify,
        relay_server,
        relay_client,
        dcutr,
        autonat,
        retrieval,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::identity::NetworkId;
    use libp2p::identity::Keypair;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    struct MockEvaluator;

    impl PeerEvaluator for MockEvaluator {
        fn evaluate_reputation(&self, _peer_id: &NetworkId) -> f32 {
            1.0 // Baseline neutral for tests
        }
    }

    fn get_test_config() -> (PhalanxConfig, PhalanxPhysics) {
        let config = PhalanxConfig::default();
        let physics = PhalanxPhysics::default_wan();
        (config, physics)
    }

    fn generate_test_identity() -> Keypair {
        Keypair::generate_ed25519()
    }

    #[test]
    fn test_swarm_key_io_roundtrip() {
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("swarm.key");
        let path_str = file_path.to_str().unwrap();

        generate_swarm_key(path_str).expect("Failed to generate swarm key");
        assert!(file_path.exists());

        let loaded_key = load_swarm_key(&file_path);
        assert!(
            loaded_key.is_some(),
            "Should successfully load generated key"
        );

        let corrupt_path = dir.path().join("corrupt.key");
        let mut f = File::create(&corrupt_path).unwrap();
        f.write_all(b"short_key").unwrap();

        let loaded_corrupt = load_swarm_key(&corrupt_path);
        assert!(
            loaded_corrupt.is_none(),
            "Should reject key with invalid length"
        );
    }

    #[tokio::test]
    async fn test_behaviour_initialization() {
        let keypair = generate_test_identity();
        let (config, physics) = get_test_config();
        let local_peer_id = keypair.public().to_peer_id();

        // Setup ephemeral RedbStore for testing
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_dht.redb");
        let local_network_id = NetworkId::from(local_peer_id);
        let store = RedbStore::new(&db_path, local_network_id, Arc::new(MockEvaluator)).unwrap();

        let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad::Config::default());

        let (_, relay_client_behaviour) = relay::client::new(local_peer_id);

        // Pass the constructed kademlia
        let result = build_behaviour(
            &keypair,
            &config,
            &physics,
            relay_client_behaviour,
            kademlia,
        );

        assert!(
            result.is_ok(),
            "PhalanxBehaviour should initialize with valid config"
        );
    }

    #[test]
    fn test_stronghold_announcement_query_generation() {
        let keypair = generate_test_identity();
        let (config, physics) = get_test_config();
        let local_peer_id = keypair.public().to_peer_id();
        let network_id = NetworkId::from(local_peer_id); // Explicit ID
        let temp_dir = tempdir().unwrap();
        let db_path = temp_dir.path().join("test_dht.redb");
        let local_network_id = NetworkId::from(local_peer_id);
        let store = RedbStore::new(&db_path, local_network_id, Arc::new(MockEvaluator)).unwrap();

        let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad::Config::default());

        let (_, relay_client_behaviour) = relay::client::new(local_peer_id);
        let mut behaviour = build_behaviour(
            &keypair,
            &config,
            &physics,
            relay_client_behaviour,
            kademlia,
        )
        .expect("Setup failed");

        // Verify that the announcement returns a valid QueryId
        let result = behaviour.announce_stronghold(&network_id);
        assert!(
            result.is_some(),
            "Announce stronghold should succeed in a clean memory store"
        );
    }
}
