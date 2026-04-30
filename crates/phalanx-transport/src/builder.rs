use crate::builder::kad::store::RecordStore;
use crate::counting::{CountingMuxer, IoCounters};
use futures::future::Either;
use libp2p::{
    autonat, connection_limits, core::upgrade::Version, dcutr, gossipsub, identify,
    identity::Keypair, kad, mdns, noise, pnet, relay, request_response, tcp, yamux, PeerId,
    StreamProtocol, Transport,
};
use std::error::Error;
use std::time::Duration;

use crate::behaviour::PhalanxBehaviour;

use phalanx_proto::{
    network::RETRIEVAL_PROTOCOL_ID,
    types::{PhalanxPhysics, VitalityRate},
};

#[derive(Default)]
pub struct TransportConfig {
    pub listening_port: u16,
    pub bootstrap_peers: Vec<String>,
}

/// Constructs the QUIC transport — the primary transport for the swarm.
///
/// QUIC provides native TLS 1.3 encryption and stream multiplexing, replacing
/// the TCP + Noise + Yamux stack. Connection migration across network transitions
/// (WiFi → cellular) is handled transparently by the protocol.
pub fn build_quic_transport(
    local_key: &Keypair,
    counters: &IoCounters,
) -> Result<
    libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn Error>,
> {
    let quic_config = libp2p::quic::Config::new(local_key);
    let transport = libp2p::quic::tokio::Transport::new(quic_config);
    let counters = counters.clone();

    Ok(transport
        .map(move |(peer_id, muxer), _| {
            let inner = libp2p::core::muxing::StreamMuxerBox::new(muxer);
            let counting = CountingMuxer::wrap(inner, &counters);
            (peer_id, libp2p::core::muxing::StreamMuxerBox::new(counting))
        })
        .boxed())
}

/// Constructs the TCP fallback transport for environments where UDP is blocked.
///
/// Uses the classic TCP + Noise + Yamux stack with optional PSK for private networks.
/// This is the secondary transport — QUIC is preferred when available.
pub fn build_tcp_fallback(
    local_key: &Keypair,
    psk: Option<pnet::PreSharedKey>,
    counters: &IoCounters,
) -> Result<
    libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>,
    Box<dyn Error>,
> {
    type RawStream = libp2p::tcp::tokio::TcpStream;
    type EncryptedStream = libp2p::pnet::PnetOutput<RawStream>;

    let counters = counters.clone();

    if let Some(key) = psk {
        // PSK path: requires DNS transport for hostname resolution
        let noise_config = noise::Config::new(local_key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let yamux_config = yamux::Config::default();
        let base_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        let dns_transport = libp2p::dns::tokio::Transport::system(base_transport)?;
        let pnet_config = pnet::PnetConfig::new(key);
        Ok(dns_transport
            .and_then(move |socket, _| pnet_config.handshake(socket))
            .map(|stream, _| Either::<EncryptedStream, RawStream>::Left(stream))
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .map(move |(peer_id, muxer), _| {
                let boxed = libp2p::core::muxing::StreamMuxerBox::new(muxer);
                let counting = CountingMuxer::wrap(boxed, &counters);
                (peer_id, libp2p::core::muxing::StreamMuxerBox::new(counting))
            })
            .boxed())
    } else {
        // No-PSK path: try DNS, fall back to plain TCP.
        // Android lacks /etc/resolv.conf so DNS transport init fails.
        // All Phalanx multiaddrs use IP addresses, so DNS isn't needed.
        let base_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
        match libp2p::dns::tokio::Transport::system(base_transport) {
            Ok(dns_transport) => {
                let noise_config = noise::Config::new(local_key)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let yamux_config = yamux::Config::default();
                Ok(dns_transport
                    .map(|stream, _| Either::<EncryptedStream, RawStream>::Right(stream))
                    .upgrade(Version::V1)
                    .authenticate(noise_config)
                    .multiplex(yamux_config)
                    .timeout(Duration::from_secs(20))
                    .map(move |(peer_id, muxer), _| {
                        let boxed = libp2p::core::muxing::StreamMuxerBox::new(muxer);
                        let counting = CountingMuxer::wrap(boxed, &counters);
                        (peer_id, libp2p::core::muxing::StreamMuxerBox::new(counting))
                    })
                    .boxed())
            }
            Err(e) => {
                tracing::warn!(target: "phalanx::transport", "DNS transport unavailable ({e}), falling back to plain TCP");
                let plain_tcp = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
                let noise_config = noise::Config::new(local_key)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let yamux_config = yamux::Config::default();
                Ok(plain_tcp
                    .upgrade(Version::V1)
                    .authenticate(noise_config)
                    .multiplex(yamux_config)
                    .timeout(Duration::from_secs(20))
                    .map(move |(peer_id, muxer), _| {
                        let boxed = libp2p::core::muxing::StreamMuxerBox::new(muxer);
                        let counting = CountingMuxer::wrap(boxed, &counters);
                        (peer_id, libp2p::core::muxing::StreamMuxerBox::new(counting))
                    })
                    .boxed())
            }
        }
    }
}

/// Instantiates the composite network behaviour logic.
pub fn build_behaviour<S>(
    local_key: &Keypair,
    max_chunk_size_bytes: usize,
    protocol_version: String,
    physics: &PhalanxPhysics,
    relay_client: relay::client::Behaviour,
    mut kademlia: kad::Behaviour<S>,
) -> Result<PhalanxBehaviour<S>, Box<dyn Error>>
where
    S: RecordStore + Send + Sync + 'static,
{
    let local_peer_id = local_key.public().to_peer_id();

    // Calculate gossipsub heartbeat based on physics simulation state
    let gossip_heartbeat = VitalityRate::new(physics.tau_rtt).as_duration();

    // Multiplier is a small constant; overflow not reachable in practice.
    #[allow(clippy::arithmetic_side_effects)]
    let gossip_max_transmit = max_chunk_size_bytes * 2;
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(gossip_heartbeat)
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(gossip_max_transmit)
        .build()
        .map_err(std::io::Error::other)?;

    let mut gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )?;

    // E2 FIX: Enable gossipsub peer scoring to penalize misbehaving peers.
    // Without scoring, an attacker can flood the mesh with invalid messages
    // and gossipsub has no mechanism to deprioritize them.
    let peer_score_params = gossipsub::PeerScoreParams {
        // Decay scoring data slowly (retain misbehaviour memory)
        decay_interval: Duration::from_secs(60),
        decay_to_zero: 0.01,
        // IP colocation penalty: penalize multiple peers from same IP
        ip_colocation_factor_weight: -5.0,
        ip_colocation_factor_threshold: 3.0,
        ..Default::default()
    };

    let peer_score_thresholds = gossipsub::PeerScoreThresholds {
        gossip_threshold: -100.0,
        publish_threshold: -200.0,
        graylist_threshold: -400.0,
        ..Default::default()
    };

    gossipsub
        .with_peer_score(peer_score_params, peer_score_thresholds)
        .map_err(std::io::Error::other)?;

    kademlia.set_mode(Some(kad::Mode::Server));

    let identify =
        identify::Behaviour::new(identify::Config::new(protocol_version, local_key.public()));

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
    // N2 FIX: Configure relay with explicit circuit and reservation limits.
    // Default relay config allows unbounded reservations, enabling resource exhaustion.
    let relay_config = relay::Config {
        max_reservations: 64,
        max_reservations_per_peer: 4,
        max_circuits: 128,
        max_circuits_per_peer: 4,
        ..relay::Config::default()
    };
    let relay_server = relay::Behaviour::new(local_peer_id, relay_config);
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

    // E1/E5 FIX: Connection limits to prevent eclipse attacks.
    // Caps the total number of established connections and per-peer connections.
    // max_established_per_peer prevents a single PeerId from opening many connections.
    let connection_limits = connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_established(Some(192))
            .with_max_established_incoming(Some(128))
            .with_max_established_outgoing(Some(64))
            .with_max_established_per_peer(Some(4))
            .with_max_pending_incoming(Some(64))
            .with_max_pending_outgoing(Some(32)),
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
        connection_limits,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use crate::builder::pnet::PreSharedKey;
    use libp2p::identity::Keypair;
    use libp2p::kad::store::MemoryStore;
    use phalanx_proto::prelude::*;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;
    use tempfile::tempdir;

    fn generate_test_identity() -> Keypair {
        Keypair::generate_ed25519()
    }
    pub fn generate_swarm_key(path: &str) -> std::io::Result<()> {
        use rand::RngCore;
        use std::fs;
        let mut key = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        fs::write(path, key)
    }

    pub fn load_swarm_key(path: &Path) -> Option<PreSharedKey> {
        match fs::read(path) {
            Ok(bytes) => {
                if bytes.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&bytes);
                    Some(PreSharedKey::new(arr))
                } else {
                    tracing::error!(
                        "Swarm key at {:?} is corrupt (wrong length). Ignoring.",
                        path
                    );
                    None
                }
            }
            Err(_) => None,
        }
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
    async fn test_pure_transport_initialization() {
        let keypair = generate_test_identity();
        let physics = PhalanxPhysics::default_wan();
        let local_peer_id = keypair.public().to_peer_id();

        // STRICT BOUNDARY: Use libp2p's built-in MemoryStore.
        let store = MemoryStore::new(local_peer_id);
        let kademlia = libp2p::kad::Behaviour::with_config(
            local_peer_id,
            store,
            libp2p::kad::Config::default(),
        );
        let (_, relay_client_behaviour) = libp2p::relay::client::new(local_peer_id);

        let result = build_behaviour(
            &keypair,
            1024 * 1024,                       // ARG 2: max_chunk_size_bytes
            "/phalanx/test/1.0.0".to_string(), // ARG 3: protocol_version
            &physics,                          // ARG 4: physics
            relay_client_behaviour,            // ARG 5: relay_client
            kademlia,                          // ARG 6: kademlia
        );
        assert!(
            result.is_ok(),
            "Unit: Pure transport behaviour failed to initialize"
        );
    }

    #[tokio::test]
    async fn test_stronghold_announcement_query_generation() {
        let keypair = generate_test_identity();
        let physics = PhalanxPhysics::default_wan();

        let local_peer_id = keypair.public().to_peer_id();
        let network_id = MeshAddress::new(local_peer_id.to_string());

        // STRICT BOUNDARY: Use MemoryStore to isolate transport testing
        let store = MemoryStore::new(local_peer_id);
        let kademlia = libp2p::kad::Behaviour::with_config(
            local_peer_id,
            store,
            libp2p::kad::Config::default(),
        );
        let (_, relay_client_behaviour) = libp2p::relay::client::new(local_peer_id);

        let mut behaviour = build_behaviour(
            &keypair,
            1024 * 1024,                       // ARG 2: max_chunk_size_bytes
            "/phalanx/test/1.0.0".to_string(), // ARG 3: protocol_version
            &physics,                          // ARG 4: physics
            relay_client_behaviour,            // ARG 5: relay_client
            kademlia,                          // ARG 6: kademlia
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
