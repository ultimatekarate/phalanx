use crate::behaviour::{recording_id_from_key, PhalanxBehaviour};
use crate::counting::IoCounters;
use crate::events::PhalanxEvent;
use crate::PeerMapper;
use async_trait::async_trait;
use futures::StreamExt; // Required to bring StreamExt::select_next_some into scope
use libp2p::kad;
use libp2p::kad::store::RecordStore;
use libp2p::swarm::Swarm;
use libp2p::swarm::SwarmEvent;
use libp2p::PeerId;
use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::TransportError;
use phalanx_proto::network::{EgressPort, IngressPort, NetworkEvent};
use phalanx_proto::retrieval::RecordingResponse;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::topology::{SubnetBucket, TransportClass};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::Instant;

pub enum TransportCommand {
    Publish(MeshTopic, Vec<u8>),
    SendDirect(NetworkId, Vec<u8>),
    Ban(NetworkId),
    AnnounceRecording(phalanx_proto::identity::RecordingId),
    FindRecordingProviders(phalanx_proto::identity::RecordingId),
    /// Eclipse remediation: re-dial bootstrap peers and trigger Kademlia random walk.
    ReBootstrap(Vec<String>),
}

#[derive(Clone)]
pub struct Libp2pAdapter {
    command_tx: mpsc::Sender<TransportCommand>,
    // Arc<Mutex<>> ensures the Receiver can be extracted safely across threads
    event_rx_factory: Arc<Mutex<Option<mpsc::Receiver<NetworkEvent>>>>,
    /// Monotonically increasing count of dropped transport events.
    /// Read by MeshSentinel on maintenance ticks to feed connection pressure
    /// into the Volterra homeostasis integral.
    pub dropped_event_count: Arc<AtomicU64>,
    /// Monotonically increasing count of swarm wake events (every
    /// `swarm.select_next_some()` return). Negligible overhead — always active.
    pub swarm_wake_count: Arc<AtomicU64>,
    /// Optional per-wake timestamp log. None in production, Some when
    /// `AdapterConfig::enable_wake_log` is true (benchmarks).
    swarm_wake_log: Option<Arc<Mutex<Vec<Instant>>>>,
    /// Socket-level I/O counters. Every byte read/written on any substream
    /// is tracked here. Always active — ~1ns overhead per I/O op.
    pub io_counters: IoCounters,
}

/// Extract a `SubnetBucket` from a libp2p `Multiaddr`.
///
/// IPv4: uses first two octets as a /16 prefix bucket.
/// IPv6: hashes the first 6 bytes of the address into a two-byte bucket.
/// Fallback: hashes the raw Multiaddr bytes.
fn extract_subnet_bucket(addr: &libp2p::Multiaddr) -> SubnetBucket {
    use libp2p::multiaddr::Protocol;
    for proto in addr.iter() {
        match proto {
            Protocol::Ip4(ipv4) => {
                let octets = ipv4.octets();
                return SubnetBucket::from_ipv4_prefix(octets[0], octets[1]);
            }
            Protocol::Ip6(ipv6) => {
                let octets = ipv6.octets();
                return SubnetBucket::from_ipv6_prefix(&octets[..6]);
            }
            _ => continue,
        }
    }
    // Fallback: hash the raw Multiaddr bytes
    SubnetBucket::from_ipv6_prefix(addr.to_vec().as_slice())
}

pub fn translate_swarm_event(event: SwarmEvent<PhalanxEvent>) -> Option<NetworkEvent> {
    match event {
        SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(libp2p::gossipsub::Event::Message {
            propagation_source,
            message,
            ..
        })) => Some(NetworkEvent::DataReceived {
            origin: PeerMapper::to_network_id(&propagation_source),
            topic: MeshTopic::new(message.topic.as_str()),
            data: message.data,
        }),
        SwarmEvent::Behaviour(PhalanxEvent::Retrieval(
            libp2p::request_response::Event::Message {
                peer,
                message:
                    libp2p::request_response::Message::Request {
                        request_id,
                        request,
                        ..
                    },
                ..
            },
        )) => Some(NetworkEvent::RecordingRequested {
            origin: PeerMapper::to_network_id(&peer),
            request,
            channel_id: request_id.to_string(),
        }),
        // mDNS discovery → PeerDiscovered (vitals tracking)
        SwarmEvent::Behaviour(PhalanxEvent::Mdns(libp2p::mdns::Event::Discovered(peers))) => peers
            .first()
            .map(|(peer_id, addr)| NetworkEvent::PeerDiscovered {
                peer: PeerMapper::to_network_id(peer_id),
                source: DiscoverySource::Mdns,
                bucket: extract_subnet_bucket(addr),
                transport: TransportClass::from_discovery_source(DiscoverySource::Mdns),
            }),
        // DHT: Kademlia provider discovery results → ProvidersDiscovered
        SwarmEvent::Behaviour(PhalanxEvent::Kademlia(kad::Event::OutboundQueryProgressed {
            result:
                kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders {
                    key,
                    providers,
                })),
            ..
        })) => {
            let Some(recording_id) = recording_id_from_key(&key) else {
                tracing::warn!(
                    target: "phalanx::transport",
                    "DHT: Could not parse recording_id from provider key"
                );
                return None;
            };
            let providers: Vec<_> = providers.iter().map(PeerMapper::to_network_id).collect();
            Some(NetworkEvent::ProvidersDiscovered {
                recording_id,
                providers,
            })
        }
        // DHT: Request-response shard retrieval responses → ShardResponseReceived
        SwarmEvent::Behaviour(PhalanxEvent::Retrieval(
            libp2p::request_response::Event::Message {
                peer,
                message: libp2p::request_response::Message::Response { response, .. },
                ..
            },
        )) => match response {
            RecordingResponse::Success(sealed_units) => {
                let envelopes = sealed_units.into_iter().map(|u| u.unpack()).collect();
                Some(NetworkEvent::ShardResponseReceived {
                    origin: PeerMapper::to_network_id(&peer),
                    envelopes,
                })
            }
            other => {
                tracing::debug!(
                    target: "phalanx::transport",
                    response = ?other,
                    "DHT: Non-success retrieval response"
                );
                None
            }
        },
        _ => None, // Safely ignore background noise like DHT pings
    }
}

/// H3 FIX: Configurable event channel capacity and per-peer rate limits.
#[derive(Clone)]
pub struct AdapterConfig {
    /// Event channel capacity (default: 2048)
    pub event_channel_capacity: usize,
    /// Max events per peer per second before dropping (default: 100)
    pub max_events_per_peer_per_sec: u64,
    /// When Some, the swarm event loop sleeps for this duration between poll
    /// bursts. None means continuous polling (default). This is the production
    /// mechanism for power-state-dependent cadencing.
    pub poll_cadence: Option<Duration>,
    /// When true, the adapter records timestamps for every swarm wake into a
    /// shared log. Intended for benchmarks only — not for production use.
    pub enable_wake_log: bool,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            event_channel_capacity: 2048,
            max_events_per_peer_per_sec: 100,
            poll_cadence: None,
            enable_wake_log: false,
        }
    }
}

impl Libp2pAdapter {
    /// Initializes the Actor Pattern.
    /// The Swarm is moved into a detached Tokio task to preserve thread safety (Sync).
    pub fn new<S>(swarm: Swarm<PhalanxBehaviour<S>>) -> Self
    where
        S: RecordStore + Send + Sync + 'static,
    {
        Self::with_config(swarm, AdapterConfig::default(), IoCounters::new())
    }

    #[allow(clippy::arithmetic_side_effects)] // Counter increments — overflow not reachable in practice.
    pub fn with_config<S>(
        mut swarm: Swarm<PhalanxBehaviour<S>>,
        config: AdapterConfig,
        io_counters: IoCounters,
    ) -> Self
    where
        S: RecordStore + Send + Sync + 'static,
    {
        let (command_tx, mut command_rx) = mpsc::channel::<TransportCommand>(128);
        let (_event_tx, event_rx) = mpsc::channel::<NetworkEvent>(config.event_channel_capacity);
        let max_per_sec = config.max_events_per_peer_per_sec;
        let dropped_counter = Arc::new(AtomicU64::new(0));
        let dropped_counter_task = dropped_counter.clone();

        let wake_counter = Arc::new(AtomicU64::new(0));
        let wake_counter_task = wake_counter.clone();

        let wake_log: Option<Arc<Mutex<Vec<Instant>>>> = if config.enable_wake_log {
            Some(Arc::new(Mutex::new(Vec::new())))
        } else {
            None
        };
        let wake_log_task = wake_log.clone();

        let poll_cadence = config.poll_cadence;

        tokio::spawn(async move {
            // H3 FIX: Per-peer rate limiting state
            let mut peer_event_counts: HashMap<PeerId, (u64, Instant)> = HashMap::new();
            let mut dropped_events: u64 = 0;

            // Shared closure-like helper: process a single swarm event.
            // Extracted as a macro to avoid borrow-checker issues with `swarm`.
            macro_rules! handle_command {
                ($command_option:expr) => {
                    match $command_option {
                        Some(TransportCommand::Publish(topic, data)) => {
                            let ident_topic = libp2p::gossipsub::IdentTopic::new(topic.to_string());
                            if let Err(publish_error) = swarm.behaviour_mut().gossipsub.publish(ident_topic, data) {
                                tracing::error!(
                                    target: "phalanx::transport",
                                    "Gossipsub publish failed for topic {}: {:?}",
                                    topic,
                                    publish_error
                                );
                            }
                        }
                        Some(TransportCommand::SendDirect(target, data)) => {
                            match PeerMapper::from_network_id(&target) {
                                Ok(peer_id) => {
                                    if !swarm.is_connected(&peer_id) {
                                        tracing::warn!(
                                            target: "phalanx::transport",
                                            "Rejecting SendDirect to unconnected peer: {}",
                                            target.0,
                                        );
                                    } else {
                                        match postcard::from_bytes::<phalanx_proto::retrieval::RecordingRequest>(&data) {
                                            Ok(request) => {
                                                swarm.behaviour_mut().retrieval.send_request(&peer_id, request);
                                            }
                                            Err(decode_error) => {
                                                tracing::error!(
                                                    target: "phalanx::transport",
                                                    "Failed to decode RecordingRequest for {}: {:?}",
                                                    target.0,
                                                    decode_error
                                                );
                                            }
                                        }
                                    }
                                }
                                Err(mapping_error) => {
                                    tracing::error!(
                                        target: "phalanx::transport",
                                        "Cannot route direct message; invalid NetworkId {}: {}",
                                        target.0,
                                        mapping_error
                                    );
                                }
                            }
                        }
                        Some(TransportCommand::Ban(peer)) => {
                            match PeerMapper::from_network_id(&peer) {
                                Ok(peer_id) => {
                                    let _ = swarm.disconnect_peer_id(peer_id);
                                    tracing::info!(
                                        target: "phalanx::transport",
                                        "Administratively disconnected peer: {}",
                                        peer.0
                                    );
                                }
                                Err(mapping_error) => {
                                    tracing::error!(
                                        target: "phalanx::transport",
                                        "Ban failed; invalid NetworkId {}: {}",
                                        peer.0,
                                        mapping_error
                                    );
                                }
                            }
                        }
                        Some(TransportCommand::AnnounceRecording(recording_id)) => {
                            swarm.behaviour_mut().announce_recording(&recording_id);
                        }
                        Some(TransportCommand::FindRecordingProviders(recording_id)) => {
                            swarm.behaviour_mut().find_recording_providers(&recording_id);
                        }
                        Some(TransportCommand::ReBootstrap(peers)) => {
                            for addr_str in &peers {
                                if let Ok(addr) = addr_str.parse::<libp2p::Multiaddr>() {
                                    if let Err(e) = swarm.dial(addr.clone()) {
                                        tracing::warn!(
                                            addr = %addr_str,
                                            error = %e,
                                            "ReBootstrap: failed to dial bootstrap peer"
                                        );
                                    } else {
                                        tracing::debug!(addr = %addr_str, "ReBootstrap: dialing bootstrap peer");
                                    }
                                }
                            }
                            let random_peer = libp2p::PeerId::random();
                            swarm.behaviour_mut().kademlia.get_closest_peers(random_peer);
                            tracing::info!(bootstrap_count = peers.len(), "ReBootstrap: initiated");
                        }
                        None => {} // Channel dropped — handled at call site
                    }
                };
            }

            macro_rules! handle_swarm_event {
                ($swarm_event:expr) => {{
                    let swarm_event = $swarm_event;

                    // Instrument: count every swarm wake
                    wake_counter_task.fetch_add(1, Ordering::Relaxed);
                    if let Some(ref log) = wake_log_task {
                        if let Ok(mut guard) = log.lock() {
                            guard.push(Instant::now());
                        }
                    }

                    // Internal swarm wiring: discovered mDNS peers → Kademlia routing table
                    if let SwarmEvent::Behaviour(PhalanxEvent::Mdns(
                        libp2p::mdns::Event::Discovered(ref peers)
                    )) = swarm_event {
                        for (peer_id, addr) in peers {
                            swarm.behaviour_mut().kademlia.add_address(peer_id, addr.clone());
                        }
                    }

                    // H3 FIX: Extract source peer for rate limiting
                    let source_peer = match &swarm_event {
                        SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(
                            libp2p::gossipsub::Event::Message { propagation_source, .. }
                        )) => Some(*propagation_source),
                        SwarmEvent::Behaviour(PhalanxEvent::Retrieval(
                            libp2p::request_response::Event::Message { peer, .. }
                        )) => Some(*peer),
                        _ => None,
                    };

                    // Per-peer rate limiting
                    let rate_ok = if let Some(peer) = source_peer {
                        let now = Instant::now();
                        let entry = peer_event_counts
                            .entry(peer)
                            .or_insert((0, now));

                        if now.duration_since(entry.1).as_secs() >= 1 {
                            entry.0 = 0;
                            entry.1 = now;
                        }

                        entry.0 += 1;
                        entry.0 <= max_per_sec
                    } else {
                        true
                    };

                    if rate_ok {
                        if let Some(network_event) = translate_swarm_event(swarm_event) {
                            if _event_tx.try_send(network_event).is_err() {
                                dropped_events += 1;
                                dropped_counter_task.store(dropped_events, Ordering::Relaxed);
                                if dropped_events % 100 == 1 {
                                    tracing::warn!(
                                        target: "phalanx::transport",
                                        total_dropped = dropped_events,
                                        "Event channel full, dropping events"
                                    );
                                }
                            }
                        }
                    } else if let Some(peer) = source_peer {
                        dropped_events += 1;
                        dropped_counter_task.store(dropped_events, Ordering::Relaxed);
                        if dropped_events % 100 == 1 {
                            tracing::warn!(
                                target: "phalanx::transport",
                                peer = %peer,
                                total_dropped = dropped_events,
                                "Per-peer rate limit exceeded, dropping event"
                            );
                        }
                    }
                }};
            }

            if let Some(cadence) = poll_cadence {
                // ── Cadenced polling: drain pending events, then sleep ──
                loop {
                    // Drain phase: process all pending events with a short timeout
                    loop {
                        tokio::select! {
                            biased;
                            command_option = command_rx.recv() => {
                                if command_option.is_none() {
                                    return; // Channel dropped; shutdown
                                }
                                handle_command!(command_option);
                            }
                            swarm_event = swarm.select_next_some() => {
                                handle_swarm_event!(swarm_event);
                            }
                            _ = tokio::time::sleep(Duration::from_millis(100)) => {
                                break; // No more pending events
                            }
                        }
                    }
                    // Sleep phase: wait for the configured cadence
                    tokio::time::sleep(cadence).await;
                }
            } else {
                // ── Continuous polling (original behaviour) ──
                loop {
                    tokio::select! {
                        command_option = command_rx.recv() => {
                            if command_option.is_none() {
                                break; // Channel dropped; initiate actor shutdown
                            }
                            handle_command!(command_option);
                        },
                        swarm_event = swarm.select_next_some() => {
                            handle_swarm_event!(swarm_event);
                        }
                    }
                }
            }
        });

        Self {
            command_tx,
            event_rx_factory: Arc::new(Mutex::new(Some(event_rx))),
            dropped_event_count: dropped_counter,
            swarm_wake_count: wake_counter,
            swarm_wake_log: wake_log,
            io_counters,
        }
    }

    /// Factory constructor: returns `(Libp2pIngress, Libp2pEgress)` port objects directly,
    /// avoiding the Mutex one-shot pattern.
    pub fn from_swarm<S>(
        swarm: Swarm<PhalanxBehaviour<S>>,
        config: AdapterConfig,
        io_counters: IoCounters,
    ) -> (Libp2pIngress, Libp2pEgress)
    where
        S: RecordStore + Send + Sync + 'static,
    {
        let adapter = Self::with_config(swarm, config, io_counters);
        // Safety: from_swarm is called once immediately after construction, so the
        // Mutex cannot be poisoned and the receiver is guaranteed to be present.
        #[allow(clippy::expect_used)]
        let receiver = adapter
            .event_rx_factory
            .lock()
            .expect("Mutex poisoned in Libp2pAdapter::from_swarm")
            .take()
            .expect("Receiver already consumed");
        (
            Libp2pIngress {
                ingress_rx: receiver,
            },
            Libp2pEgress { adapter },
        )
    }
}

impl Libp2pAdapter {
    pub async fn publish(&self, topic: MeshTopic, data: Vec<u8>) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::Publish(topic, data))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }

    pub async fn send_direct(
        &self,
        target: &NetworkId,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::SendDirect(target.clone(), data))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }

    pub async fn ban_peer(&self, peer: &NetworkId) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::Ban(peer.clone()))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }

    pub async fn announce_recording(
        &self,
        recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::AnnounceRecording(recording_id.clone()))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }

    pub async fn find_providers(
        &self,
        recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::FindRecordingProviders(
                recording_id.clone(),
            ))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }

    /// Eclipse remediation: re-dial bootstrap peers and trigger Kademlia random walk.
    pub async fn rebootstrap(&self, peers: &[String]) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::ReBootstrap(peers.to_vec()))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }
}

// --- Port Objects ---

pub struct Libp2pIngress {
    ingress_rx: mpsc::Receiver<NetworkEvent>,
}

#[async_trait]
impl IngressPort for Libp2pIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.ingress_rx.recv().await
    }
}

#[derive(Clone)]
pub struct Libp2pEgress {
    adapter: Libp2pAdapter,
}

impl Libp2pEgress {
    pub fn dropped_event_count(&self) -> Arc<AtomicU64> {
        self.adapter.dropped_event_count.clone()
    }

    /// Returns the shared swarm wake counter. Every call to
    /// `swarm.select_next_some()` increments this counter.
    pub fn swarm_wake_count(&self) -> Arc<AtomicU64> {
        self.adapter.swarm_wake_count.clone()
    }

    /// Returns the per-wake timestamp log, if enabled via
    /// `AdapterConfig::enable_wake_log`.
    pub fn swarm_wake_log(&self) -> Option<Arc<Mutex<Vec<Instant>>>> {
        self.adapter.swarm_wake_log.clone()
    }

    /// Returns the shared counter of bytes sent at the socket level.
    pub fn socket_bytes_sent(&self) -> Arc<AtomicU64> {
        self.adapter.io_counters.bytes_sent.clone()
    }

    /// Returns the shared counter of bytes received at the socket level.
    pub fn socket_bytes_received(&self) -> Arc<AtomicU64> {
        self.adapter.io_counters.bytes_received.clone()
    }

    /// Returns the shared counter of socket-level I/O operations
    /// (each `poll_read` or `poll_write` that transfers bytes).
    pub fn socket_io_ops(&self) -> Arc<AtomicU64> {
        self.adapter.io_counters.io_ops.clone()
    }
}

#[async_trait]
impl EgressPort for Libp2pEgress {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        self.adapter
            .publish(topic.clone(), data)
            .await
            .map_err(|e| e.to_string())
    }

    async fn ban_peer(&self, peer: &NetworkId) {
        if let Err(e) = self.adapter.ban_peer(peer).await {
            tracing::error!(target: "phalanx::transport", "Failed to ban peer {}: {}", peer.0, e);
        }
    }

    async fn send_response(
        &self,
        _channel_id: &str,
        _response: RecordingResponse,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn announce_recording(
        &self,
        recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), String> {
        self.adapter
            .announce_recording(recording_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn find_providers(
        &self,
        recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), String> {
        self.adapter
            .find_providers(recording_id)
            .await
            .map_err(|e| e.to_string())
    }

    async fn send_request(
        &self,
        target: &NetworkId,
        request: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        let data = postcard::to_allocvec(&request).map_err(|e| e.to_string())?;
        self.adapter
            .send_direct(target, data)
            .await
            .map_err(|e| e.to_string())
    }

    async fn rebootstrap(&self, peers: &[String]) -> Result<(), String> {
        self.adapter
            .rebootstrap(peers)
            .await
            .map_err(|e| e.to_string())
    }
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
    use libp2p::swarm::{ConnectionId, SwarmEvent};
    use libp2p::PeerId;
    use phalanx_proto::network::NetworkEvent;

    // Mock behaviour event for testing purposes
    enum MockBehaviourEvent {
        MessageReceived { source: PeerId, payload: Vec<u8> },
    }

    impl Into<NetworkEvent> for MockBehaviourEvent {
        fn into(self) -> NetworkEvent {
            match self {
                MockBehaviourEvent::MessageReceived { source, payload } => {
                    NetworkEvent::DataReceived {
                        origin: NetworkId(source.to_string()),
                        topic: MeshTopic::new("test_topic"),
                        data: payload,
                    }
                }
            }
        }
    }

    fn translate_mock_event(event: SwarmEvent<MockBehaviourEvent>) -> Option<NetworkEvent> {
        match event {
            SwarmEvent::Behaviour(b) => Some(b.into()),
            _ => None,
        }
    }

    #[test]
    fn test_ignores_internal_libp2p_noise() {
        let peer = PeerId::random();
        let event: SwarmEvent<MockBehaviourEvent> = SwarmEvent::ConnectionEstablished {
            peer_id: peer,
            connection_id: ConnectionId::new_unchecked(1),
            endpoint: libp2p::core::ConnectedPoint::Dialer {
                address: "/ip4/127.0.0.1/tcp/0".parse().unwrap(),
                role_override: libp2p::core::Endpoint::Dialer,
                port_use: libp2p::core::transport::PortUse::New,
            },
            num_established: std::num::NonZeroU32::new(1).unwrap(),
            concurrent_dial_errors: None,
            established_in: std::time::Duration::from_millis(10),
        };

        // We only care about data, not raw TCP connection events
        assert!(translate_mock_event(event).is_none());
    }

    #[test]
    fn test_translates_valid_payload() {
        let peer = PeerId::random();
        let payload = b"forensic_evidence_chunk".to_vec();

        let event = SwarmEvent::Behaviour(MockBehaviourEvent::MessageReceived {
            source: peer,
            payload: payload.clone(),
        });

        let translated =
            translate_mock_event(event).expect("Should translate valid behaviour event");

        // Match against your actual NetworkEvent variants
        match translated {
            NetworkEvent::DataReceived { origin, data, .. } => {
                assert_eq!(origin.0, peer.to_string());
                assert_eq!(data, payload);
            }
            _ => panic!("Translated to wrong NetworkEvent variant"),
        }
    }
}
