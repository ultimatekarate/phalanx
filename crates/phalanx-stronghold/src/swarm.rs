// crates/phalanx-stronghold/src/swarm.rs
//
// Swarm setup for the Stronghold daemon. Mirrors the node's orchestrator
// but uses MemoryStore for the DHT (no redb dependency).
//
// Hands layer — owns transport initialization.

use std::error::Error;
use std::time::Duration;

use async_trait::async_trait;
use libp2p::{
    core::upgrade::Version, identity::Keypair, kad, noise, relay, yamux, Multiaddr, StreamProtocol,
    Swarm, SwarmBuilder, Transport,
};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::types::PhalanxPhysics;
use phalanx_transport::builder::{build_behaviour, build_quic_transport, build_tcp_fallback};
use phalanx_transport::prelude::Libp2pAdapter;
use phalanx_transport::{IngressPort, TransportAdapter};
use tokio::sync::mpsc;

use crate::config::NetworkConfig;

/// Set up a libp2p swarm for the Stronghold.
///
/// Uses `MemoryStore` for the Kademlia DHT — the Stronghold doesn't need
/// persistent DHT records (it discovers peers, doesn't serve them).
pub fn setup_stronghold_swarm(
    local_key: Keypair,
    network_config: &NetworkConfig,
) -> Result<
    Swarm<phalanx_transport::behaviour::PhalanxBehaviour<kad::store::MemoryStore>>,
    Box<dyn Error>,
> {
    let local_peer_id = local_key.public().to_peer_id();
    tracing::info!(peer_id = %local_peer_id, "Stronghold: initializing swarm");

    let physics = PhalanxPhysics::default_wan();
    let protocol_version = "/phalanx/1.0.0".to_string();
    let max_chunk_size_bytes = 8192;

    // Kademlia with in-memory store (no redb needed)
    let protocol_str = format!("/phalanx/kad/{}", protocol_version);
    let kad_protocol = StreamProtocol::try_from_owned(protocol_str)?;
    let mut kad_config = kad::Config::new(kad_protocol);
    kad_config.set_replication_factor(std::num::NonZeroUsize::new(20).expect("non-zero"));
    kad_config.set_query_timeout(Duration::from_secs(30));
    kad_config.set_record_ttl(Some(Duration::from_secs(3600)));
    kad_config.set_provider_record_ttl(Some(Duration::from_secs(3600)));
    let memory_store = kad::store::MemoryStore::new(local_peer_id);
    let kademlia = kad::Behaviour::with_config(local_peer_id, memory_store, kad_config);

    // Relay client
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);

    // Transport composition: QUIC primary, TCP fallback
    let quic_transport = build_quic_transport(&local_key)?;
    let tcp_fallback = build_tcp_fallback(&local_key, None)?;
    let behaviour = build_behaviour(
        &local_key,
        max_chunk_size_bytes,
        protocol_version,
        &physics,
        relay_client,
        kademlia,
    )?;

    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|_key| quic_transport)?
        .with_other_transport(|_key| tcp_fallback)?
        .with_other_transport(|key| {
            let noise_config = noise::Config::new(key)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
            let yamux_config = yamux::Config::default();
            Ok(relay_transport
                .upgrade(Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux_config))
        })?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c: libp2p::swarm::Config| {
            c.with_idle_connection_timeout(Duration::from_secs(60))
                .with_max_negotiating_inbound_streams(128)
        })
        .build();

    // Listen on configured addresses
    for addr in &network_config.listen_addresses {
        if let Ok(multiaddr) = addr.parse::<Multiaddr>() {
            swarm.listen_on(multiaddr)?;
            tracing::info!(address = %addr, "Stronghold: listening");
        }
    }

    // Subscribe to gossipsub topics
    let topics = [&network_config.video_topic, &network_config.audio_topic];
    for topic in topics {
        let ident = libp2p::gossipsub::IdentTopic::new(topic.to_string());
        if let Err(e) = swarm.behaviour_mut().gossipsub.subscribe(&ident) {
            tracing::warn!(topic = %topic, error = %e, "Stronghold: failed to subscribe");
        } else {
            tracing::info!(topic = %topic, "Stronghold: subscribed");
        }
    }

    // Dial bootstrap peers
    for peer_addr in &network_config.bootstrap_peers {
        if let Ok(multiaddr) = peer_addr.parse::<Multiaddr>() {
            if let Err(e) = swarm.dial(multiaddr) {
                tracing::warn!(addr = %peer_addr, error = %e, "Stronghold: failed to dial bootstrap");
            }
        }
    }

    Ok(swarm)
}

/// Thin ingress wrapper around `mpsc::Receiver<NetworkEvent>`.
/// Bridges the Libp2pAdapter's ingress stream to the `IngressPort` trait
/// consumed by `StrongholdSentinel`.
pub struct StrongholdIngress {
    rx: mpsc::Receiver<NetworkEvent>,
}

impl StrongholdIngress {
    pub fn from_adapter(adapter: &Libp2pAdapter) -> Self {
        Self {
            rx: adapter.ingress_stream(),
        }
    }
}

#[async_trait]
impl IngressPort for StrongholdIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.rx.recv().await
    }
}
