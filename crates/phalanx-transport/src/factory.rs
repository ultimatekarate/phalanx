// crates/phalanx-transport/src/factory.rs
//
// Mesh transport factory. Encapsulates ALL libp2p swarm construction so
// that consumers (phalanx-node, phalanx-stronghold) never import libp2p.

use std::time::Duration;

use libp2p::kad::store::RecordStore;
use libp2p::{
    Multiaddr, StreamProtocol, SwarmBuilder, Transport, core::upgrade::Version, kad, noise, pnet,
    relay, yamux,
};
use phalanx_proto::identity::PhalanxIdentity;

use crate::adapters::libp2p::{Libp2pAdapter, Libp2pEgress, Libp2pIngress};
use crate::builder::{build_behaviour, build_quic_transport, build_tcp_fallback};
use crate::config::MeshTransportConfig;
use crate::counting::IoCounters;
use crate::identity_ext::Libp2pExt;
use phalanx_proto::network::TransportError;

/// Build a complete mesh transport with an ephemeral (in-memory) DHT store.
///
/// Use this for nodes that don't need persistent DHT records (e.g. Stronghold).
pub fn build_mesh_transport(
    identity: &PhalanxIdentity,
    config: &MeshTransportConfig,
) -> Result<(Libp2pIngress, Libp2pEgress), TransportError> {
    let local_key = identity.to_libp2p_keypair();
    let local_peer_id = local_key.public().to_peer_id();

    let store = kad::store::MemoryStore::new(local_peer_id);
    build_mesh_transport_inner(local_key, store, config)
}

/// Build a complete mesh transport with a custom DHT record store.
///
/// Use this for nodes that need persistent DHT records (e.g. Node with RedbStore).
pub fn build_mesh_transport_with_store<S>(
    identity: &PhalanxIdentity,
    store: S,
    config: &MeshTransportConfig,
) -> Result<(Libp2pIngress, Libp2pEgress), TransportError>
where
    S: RecordStore + Send + Sync + 'static,
{
    let local_key = identity.to_libp2p_keypair();
    build_mesh_transport_inner(local_key, store, config)
}

fn build_mesh_transport_inner<S>(
    local_key: libp2p::identity::Keypair,
    store: S,
    config: &MeshTransportConfig,
) -> Result<(Libp2pIngress, Libp2pEgress), TransportError>
where
    S: RecordStore + Send + Sync + 'static,
{
    let local_peer_id = local_key.public().to_peer_id();

    // ── PSK validation ───────────────────────────────────────
    let psk = config.psk.map(pnet::PreSharedKey::new);
    if config.require_psk && psk.is_none() {
        return Err(TransportError::Protocol(
            "require_psk is set but no Pre-Shared Key was provided. \
            The node cannot start without transport-layer encryption."
                .to_string(),
        ));
    }

    // ── Kademlia ─────────────────────────────────────────────
    let protocol_str = format!("/phalanx/kad/{}", config.protocol_version);
    let kad_protocol = StreamProtocol::try_from_owned(protocol_str)
        .map_err(|e| TransportError::Protocol(e.to_string()))?;
    let mut kad_config = kad::Config::new(kad_protocol);
    // 20 is non-zero — if config provides 0, fall back to the default.
    let replication = std::num::NonZeroUsize::new(config.kademlia_replication_factor)
        .or_else(|| std::num::NonZeroUsize::new(20))
        .ok_or_else(|| {
            TransportError::Protocol("default replication factor is zero".to_string())
        })?;
    kad_config.set_replication_factor(replication);
    kad_config.set_query_timeout(Duration::from_secs(config.kademlia_query_timeout_secs));
    kad_config.set_record_ttl(Some(Duration::from_secs(config.kademlia_record_ttl_secs)));
    kad_config.set_provider_record_ttl(Some(Duration::from_secs(config.kademlia_record_ttl_secs)));
    if config.kademlia_filter_both {
        kad_config.set_record_filtering(kad::StoreInserts::FilterBoth);
    }
    let kademlia = kad::Behaviour::with_config(local_peer_id, store, kad_config);

    // ── Relay ────────────────────────────────────────────────
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);

    // ── I/O counters ──────────────────────────────────────────
    let io_counters = if config.adapter.enable_io_log {
        IoCounters::with_io_log()
    } else {
        IoCounters::new()
    };

    // ── Transport composition ────────────────────────────────
    let quic_transport = build_quic_transport(&local_key, &io_counters)
        .map_err(|e| TransportError::Network(e.to_string()))?;
    let tcp_fallback = build_tcp_fallback(&local_key, psk, &io_counters)
        .map_err(|e| TransportError::Network(e.to_string()))?;

    let behaviour = build_behaviour(
        &local_key,
        config.max_chunk_size_bytes,
        config.protocol_version.clone(),
        &config.physics,
        relay_client,
        kademlia,
    )
    .map_err(|e| TransportError::Internal(e.to_string()))?;

    // ── Swarm assembly ───────────────────────────────────────
    let idle_timeout = Duration::from_secs(config.idle_timeout_secs);

    // Connection limits are currently hardcoded in build_behaviour().
    // These config fields are reserved for future per-deployment tuning.
    let _ = (
        config.max_established,
        config.max_established_incoming,
        config.max_established_per_peer,
    );

    let mut swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_other_transport(|_key| quic_transport)
        .map_err(|e| TransportError::Network(format!("QUIC transport: {e}")))?
        .with_other_transport(|_key| tcp_fallback)
        .map_err(|e| TransportError::Network(format!("TCP transport: {e}")))?
        .with_other_transport({
            let relay_counters = io_counters.clone();
            move |key| {
                let noise_config = noise::Config::new(key)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                let yamux_config = yamux::Config::default();
                Ok(relay_transport
                    .upgrade(Version::V1)
                    .authenticate(noise_config)
                    .multiplex(yamux_config)
                    .map(move |(peer_id, muxer), _| {
                        let boxed = libp2p::core::muxing::StreamMuxerBox::new(muxer);
                        let counting = crate::counting::CountingMuxer::wrap(boxed, &relay_counters);
                        (peer_id, libp2p::core::muxing::StreamMuxerBox::new(counting))
                    }))
            }
        })
        .map_err(|e| TransportError::Network(format!("Relay transport: {e}")))?
        .with_behaviour(|_| behaviour)
        .map_err(|e| TransportError::Internal(format!("Behaviour: {e}")))?
        .with_swarm_config(|c: libp2p::swarm::Config| {
            c.with_idle_connection_timeout(idle_timeout)
                .with_max_negotiating_inbound_streams(128)
        })
        .build();

    // ── Swarm activation ─────────────────────────────────────

    // Listen on configured addresses
    for addr in &config.listen_addresses {
        let multiaddr: Multiaddr = addr.parse().map_err(|e| {
            TransportError::Protocol(format!("Invalid listen address '{addr}': {e}"))
        })?;
        swarm
            .listen_on(multiaddr)
            .map_err(|e| TransportError::Network(format!("Listen failed on '{addr}': {e}")))?;
        tracing::info!(target: "phalanx::factory", address = %addr, "Listening");
    }

    // Subscribe to gossipsub topics
    for topic in &config.subscribe_topics {
        let ident = libp2p::gossipsub::IdentTopic::new(topic.to_string());
        swarm
            .behaviour_mut()
            .gossipsub
            .subscribe(&ident)
            .map_err(|e| TransportError::Protocol(format!("Subscribe to '{topic}' failed: {e}")))?;
        tracing::info!(target: "phalanx::factory", topic = %topic, "Subscribed");
    }

    // Dial bootstrap peers
    for peer_addr in &config.bootstrap_peers {
        if let Ok(multiaddr) = peer_addr.parse::<Multiaddr>() {
            if let Err(e) = swarm.dial(multiaddr) {
                tracing::warn!(target: "phalanx::factory", error = %e, addr = %peer_addr, "Failed to dial bootstrap peer");
            }
        }
    }

    // ── Adapter creation ─────────────────────────────────────
    let (ingress, egress) = Libp2pAdapter::from_swarm(swarm, config.adapter.clone(), io_counters);

    Ok((ingress, egress))
}
