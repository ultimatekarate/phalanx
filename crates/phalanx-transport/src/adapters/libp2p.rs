use crate::behaviour::{recording_id_from_key, PhalanxBehaviour};
use crate::counting::{IoCounters, IoLogEntry};
use crate::events::PhalanxEvent;
use crate::PeerMapper;
use async_trait::async_trait;
use futures::StreamExt; // Required to bring StreamExt::select_next_some into scope
use libp2p::kad;
use libp2p::kad::store::RecordStore;
use libp2p::swarm::Swarm;
use libp2p::swarm::SwarmEvent;
use libp2p::PeerId;
use phalanx_proto::identity::MeshAddress;
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
    SendDirect(MeshAddress, Vec<u8>),
    Ban(MeshAddress),
    AnnounceRecording(phalanx_proto::identity::RecordingId),
    FindRecordingProviders(phalanx_proto::identity::RecordingId),
    /// Eclipse remediation: re-dial bootstrap peers and trigger Kademlia random walk.
    ReBootstrap(Vec<String>),
    /// Reply to a previously-received `Message::Request` identified by `channel_id`.
    /// The actor looks up the captured `ResponseChannel` and calls
    /// `swarm.behaviour_mut().retrieval.send_response(...)`.
    SendResponse(String, RecordingResponse),
}

/// Per-protocol wake attribution. Each field is a handle to a shared atomic
/// counter; clones share state. Always-on — 12 atomic increments per wake
/// have negligible cost. Operational type (not a Dictionary Noun) per the
/// Linguistic Model; lives in phalanx-transport.
///
/// Sum of all 12 counters equals `Libp2pAdapter::swarm_wake_count` (up to small
/// read-races). Diverges loudly if a new `SwarmEvent` variant goes unclassified
/// in the `handle_swarm_event!` match.
#[derive(Clone, Debug, Default)]
pub struct ProtocolWakeCounters {
    pub gossipsub: Arc<AtomicU64>,
    pub kademlia: Arc<AtomicU64>,
    pub mdns: Arc<AtomicU64>,
    pub identify: Arc<AtomicU64>,
    pub autonat: Arc<AtomicU64>,
    pub dcutr: Arc<AtomicU64>,
    pub relay_server: Arc<AtomicU64>,
    pub relay_client: Arc<AtomicU64>,
    pub retrieval: Arc<AtomicU64>,
    /// ConnectionEstablished / ConnectionClosed / IncomingConnection / Dialing / *Error
    pub connection: Arc<AtomicU64>,
    /// NewListenAddr / ExpiredListenAddr / ListenerClosed / ListenerError
    pub listener: Arc<AtomicU64>,
    /// NewExternalAddr* and any future SwarmEvent variants not otherwise classified.
    pub other: Arc<AtomicU64>,
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
    /// Per-protocol wake attribution. Always active.
    pub protocol_wakes: ProtocolWakeCounters,
    /// Gauge: count of `TransportCommand`s sent but not yet consumed. Saturates
    /// at the command-channel capacity (hardcoded 2048 today; see the
    /// `mpsc::channel::<TransportCommand>(2048)` call in `with_config`). This is
    /// a *gauge*, not a total — it decrements after each `command_rx.recv()`.
    pub outbound_queue_depth: Arc<AtomicU64>,
    /// Monotonically increasing count of `gossipsub.publish()` calls that
    /// returned an error (e.g. `InsufficientPeers`, `MessageTooLarge`). The
    /// `Egress::publish()` API reports these only via `tracing::error!`, so
    /// tests with no subscriber installed lose them. This counter gives a
    /// programmatic signal that the swarm task rejected a published message.
    pub gossipsub_publish_errors: Arc<AtomicU64>,
    /// Monotonically increasing count of retrieval responses that could not
    /// be delivered. Three failure modes contribute:
    /// 1. `send_response` called with an unknown `channel_id` (already
    ///    responded, or the entry was evicted by GC after the 20s libp2p
    ///    request-response timeout).
    /// 2. The 30s GC sweep evicted entries whose requesters never received
    ///    a reply (the `RecordingRequested` event was queued but no upstream
    ///    actor produced a `RecordingResponse` in time).
    /// 3. libp2p's `request_response::Behaviour::send_response` returned
    ///    `Err` because the peer disconnected before we could deliver.
    pub response_channels_lost: Arc<AtomicU64>,
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
            origin: PeerMapper::to_mesh_address(&propagation_source),
            topic: MeshTopic::new(message.topic.as_str()),
            data: message.data,
        }),
        // Note: `Message::Request` is intentionally NOT handled here. The
        // actor at `with_config` intercepts that variant before this function
        // sees it, so it can capture the `ResponseChannel` (which has no public
        // constructor and can't be carried around inside a pure function).
        // mDNS discovery → PeerDiscovered (vitals tracking)
        SwarmEvent::Behaviour(PhalanxEvent::Mdns(libp2p::mdns::Event::Discovered(peers))) => peers
            .first()
            .map(|(peer_id, addr)| NetworkEvent::PeerDiscovered {
                peer: PeerMapper::to_mesh_address(peer_id),
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
            let providers: Vec<_> = providers.iter().map(PeerMapper::to_mesh_address).collect();
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
                    origin: PeerMapper::to_mesh_address(&peer),
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
    /// When true, the shared `IoCounters::io_log` is initialized to `Some` so
    /// every socket-level read/write appends a timestamped `IoLogEntry`.
    /// Benchmarks only — not production.
    pub enable_io_log: bool,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            event_channel_capacity: 2048,
            max_events_per_peer_per_sec: 100,
            poll_cadence: None,
            enable_wake_log: false,
            enable_io_log: false,
        }
    }
}

/// Per-peer event rate limiter with a 1-second sliding window.
///
/// Each peer tracks `(count, window_start)`. Calls within 1 second of the
/// window start increment the count; once `max_per_sec` is exceeded in a
/// window, subsequent calls return `false` until the window resets. The
/// clock is injected so unit tests can advance time deterministically.
struct PerPeerRateLimiter {
    counts: HashMap<PeerId, (u64, Instant)>,
    max_per_sec: u64,
}

impl PerPeerRateLimiter {
    fn new(max_per_sec: u64) -> Self {
        Self {
            counts: HashMap::new(),
            max_per_sec,
        }
    }

    fn should_accept(&mut self, peer: PeerId, now: Instant) -> bool {
        let entry = self.counts.entry(peer).or_insert((0, now));
        if now.duration_since(entry.1).as_secs() >= 1 {
            entry.0 = 0;
            entry.1 = now;
        }
        entry.0 += 1;
        entry.0 <= self.max_per_sec
    }
}

/// Time-keyed store keyed by string IDs. Entries older than `timeout` are
/// dropped on `evict_expired(now)`. The clock is injected so unit tests can
/// drive eviction deterministically. Generic over `T` so tests can use any
/// stub value (the production type `ResponseChannel<RecordingResponse>` has no
/// public constructor).
struct TimedStore<T> {
    entries: HashMap<String, (T, Instant)>,
    timeout: Duration,
}

impl<T> TimedStore<T> {
    fn new(timeout: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            timeout,
        }
    }

    fn insert(&mut self, key: String, value: T, now: Instant) {
        self.entries.insert(key, (value, now));
    }

    fn take(&mut self, key: &str) -> Option<T> {
        self.entries.remove(key).map(|(v, _)| v)
    }

    /// Drop entries inserted more than `timeout` ago. Returns the count evicted.
    fn evict_expired(&mut self, now: Instant) -> usize {
        let timeout = self.timeout;
        let before = self.entries.len();
        self.entries
            .retain(|_, (_, inserted_at)| now.duration_since(*inserted_at) < timeout);
        before - self.entries.len()
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
        let (command_tx, mut command_rx) = mpsc::channel::<TransportCommand>(2048);
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

        let protocol_wakes = ProtocolWakeCounters::default();
        let protocol_wakes_task = protocol_wakes.clone();

        let outbound_queue_depth = Arc::new(AtomicU64::new(0));
        let outbound_queue_depth_task = outbound_queue_depth.clone();
        let gossipsub_publish_errors = Arc::new(AtomicU64::new(0));
        let gossipsub_publish_errors_task = gossipsub_publish_errors.clone();
        let response_channels_lost = Arc::new(AtomicU64::new(0));
        let response_channels_lost_task = response_channels_lost.clone();

        let poll_cadence = config.poll_cadence;

        tokio::spawn(async move {
            // H3 FIX: Per-peer rate limiting state
            let mut rate_limiter = PerPeerRateLimiter::new(max_per_sec);
            let mut dropped_events: u64 = 0;
            // Channel store for inbound retrieval requests. Keys are
            // `request_id.to_string()`, matching the `channel_id` we hand out
            // upstream as part of `NetworkEvent::RecordingRequested`. Entries
            // expire after 30s — comfortably past libp2p's 20s
            // request-response timeout (set in builder.rs).
            let mut response_channels: TimedStore<
                libp2p::request_response::ResponseChannel<RecordingResponse>,
            > = TimedStore::new(Duration::from_secs(30));
            let mut last_gc = Instant::now();

            // Shared closure-like helper: process a single swarm event.
            // Extracted as a macro to avoid borrow-checker issues with `swarm`.
            macro_rules! handle_command {
                ($command_option:expr) => {
                    match $command_option {
                        Some(TransportCommand::Publish(topic, data)) => {
                            let ident_topic = libp2p::gossipsub::IdentTopic::new(topic.to_string());
                            if let Err(publish_error) = swarm.behaviour_mut().gossipsub.publish(ident_topic, data) {
                                gossipsub_publish_errors_task.fetch_add(1, Ordering::Relaxed);
                                tracing::error!(
                                    target: "phalanx::transport",
                                    "Gossipsub publish failed for topic {}: {:?}",
                                    topic,
                                    publish_error
                                );
                            }
                        }
                        Some(TransportCommand::SendDirect(target, data)) => {
                            match PeerMapper::from_mesh_address(&target) {
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
                                        "Cannot route direct message; invalid MeshAddress {}: {}",
                                        target.0,
                                        mapping_error
                                    );
                                }
                            }
                        }
                        Some(TransportCommand::Ban(peer)) => {
                            match PeerMapper::from_mesh_address(&peer) {
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
                                        "Ban failed; invalid MeshAddress {}: {}",
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
                        Some(TransportCommand::SendResponse(channel_id, response)) => {
                            // Amortized GC at the natural traffic point.
                            response_channels.evict_expired(Instant::now());
                            match response_channels.take(&channel_id) {
                                Some(channel) => {
                                    if swarm
                                        .behaviour_mut()
                                        .retrieval
                                        .send_response(channel, response)
                                        .is_err()
                                    {
                                        response_channels_lost_task
                                            .fetch_add(1, Ordering::Relaxed);
                                        tracing::warn!(
                                            target: "phalanx::transport",
                                            channel_id = %channel_id,
                                            "send_response failed: channel closed before reply"
                                        );
                                    }
                                }
                                None => {
                                    response_channels_lost_task.fetch_add(1, Ordering::Relaxed);
                                    tracing::warn!(
                                        target: "phalanx::transport",
                                        channel_id = %channel_id,
                                        "send_response: unknown channel_id (already responded, or expired)"
                                    );
                                }
                            }
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

                    // Per-protocol wake attribution. Borrows swarm_event; value
                    // is still consumed by translate_swarm_event below.
                    let protocol_counter: &Arc<AtomicU64> = match &swarm_event {
                        SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(_))   => &protocol_wakes_task.gossipsub,
                        SwarmEvent::Behaviour(PhalanxEvent::Mdns(_))        => &protocol_wakes_task.mdns,
                        SwarmEvent::Behaviour(PhalanxEvent::Kademlia(_))    => &protocol_wakes_task.kademlia,
                        SwarmEvent::Behaviour(PhalanxEvent::Identify(_))    => &protocol_wakes_task.identify,
                        SwarmEvent::Behaviour(PhalanxEvent::Autonat(_))     => &protocol_wakes_task.autonat,
                        SwarmEvent::Behaviour(PhalanxEvent::Dcutr(_))       => &protocol_wakes_task.dcutr,
                        SwarmEvent::Behaviour(PhalanxEvent::RelayServer(_)) => &protocol_wakes_task.relay_server,
                        SwarmEvent::Behaviour(PhalanxEvent::RelayClient(_)) => &protocol_wakes_task.relay_client,
                        SwarmEvent::Behaviour(PhalanxEvent::Retrieval(_))   => &protocol_wakes_task.retrieval,
                        SwarmEvent::ConnectionEstablished { .. }
                        | SwarmEvent::ConnectionClosed { .. }
                        | SwarmEvent::IncomingConnection { .. }
                        | SwarmEvent::IncomingConnectionError { .. }
                        | SwarmEvent::OutgoingConnectionError { .. }
                        | SwarmEvent::Dialing { .. }                        => &protocol_wakes_task.connection,
                        SwarmEvent::NewListenAddr { .. }
                        | SwarmEvent::ExpiredListenAddr { .. }
                        | SwarmEvent::ListenerClosed { .. }
                        | SwarmEvent::ListenerError { .. }                  => &protocol_wakes_task.listener,
                        _                                                    => &protocol_wakes_task.other,
                    };
                    protocol_counter.fetch_add(1, Ordering::Relaxed);

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

                    // Per-peer rate limiting (single Instant::now() reused for GC below)
                    let now = Instant::now();
                    let rate_ok = match source_peer {
                        Some(peer) => rate_limiter.should_accept(peer, now),
                        None => true,
                    };

                    // Periodic GC of expired response channels. Runs at most once
                    // per 30s (libp2p's request-response timeout is 20s, so any
                    // entry past 30s is guaranteed dead from libp2p's perspective).
                    if now.duration_since(last_gc) >= Duration::from_secs(30) {
                        let evicted = response_channels.evict_expired(now);
                        if evicted > 0 {
                            response_channels_lost_task
                                .fetch_add(evicted as u64, Ordering::Relaxed);
                        }
                        last_gc = now;
                    }

                    // Pre-process: capture the ResponseChannel from inbound Request
                    // events before translate_swarm_event consumes the SwarmEvent.
                    // Only capture if the event will actually be delivered upstream
                    // (rate-limit ok AND event_tx not full); otherwise the channel
                    // would leak in our map until GC.
                    let (network_event, channel_to_insert) = match swarm_event {
                        SwarmEvent::Behaviour(PhalanxEvent::Retrieval(
                            libp2p::request_response::Event::Message {
                                peer,
                                message:
                                    libp2p::request_response::Message::Request {
                                        request_id,
                                        request,
                                        channel,
                                    },
                                ..
                            },
                        )) => {
                            let channel_id = request_id.to_string();
                            let event = NetworkEvent::RecordingRequested {
                                origin: PeerMapper::to_mesh_address(&peer),
                                request,
                                channel_id: channel_id.clone(),
                            };
                            (Some(event), Some((channel_id, channel)))
                        }
                        other => (translate_swarm_event(other), None),
                    };

                    if rate_ok {
                        if let Some(network_event) = network_event {
                            match _event_tx.try_send(network_event) {
                                Ok(()) => {
                                    if let Some((id, channel)) = channel_to_insert {
                                        response_channels.insert(id, channel, now);
                                    }
                                }
                                Err(_) => {
                                    dropped_events += 1;
                                    dropped_counter_task
                                        .store(dropped_events, Ordering::Relaxed);
                                    if dropped_events % 100 == 1 {
                                        tracing::warn!(
                                            target: "phalanx::transport",
                                            total_dropped = dropped_events,
                                            "Event channel full, dropping events"
                                        );
                                    }
                                    // channel_to_insert drops here — the
                                    // ResponseChannel sender closes, libp2p's
                                    // requester-side fires a timeout. Correct
                                    // behavior under backpressure.
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
                                outbound_queue_depth_task.fetch_sub(1, Ordering::Relaxed);
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
                            outbound_queue_depth_task.fetch_sub(1, Ordering::Relaxed);
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
            protocol_wakes,
            outbound_queue_depth,
            gossipsub_publish_errors,
            response_channels_lost,
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
        self.outbound_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.command_tx
            .send(TransportCommand::Publish(topic, data))
            .await
            .map_err(|_| {
                self.outbound_queue_depth.fetch_sub(1, Ordering::Relaxed);
                TransportError::Internal("Sentinel connection lost".into())
            })
    }

    pub async fn send_direct(
        &self,
        target: &MeshAddress,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        self.outbound_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.command_tx
            .send(TransportCommand::SendDirect(target.clone(), data))
            .await
            .map_err(|_| {
                self.outbound_queue_depth.fetch_sub(1, Ordering::Relaxed);
                TransportError::Internal("Sentinel connection lost".into())
            })
    }

    pub async fn ban_peer(&self, peer: &MeshAddress) -> Result<(), TransportError> {
        self.outbound_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.command_tx
            .send(TransportCommand::Ban(peer.clone()))
            .await
            .map_err(|_| {
                self.outbound_queue_depth.fetch_sub(1, Ordering::Relaxed);
                TransportError::Internal("Sentinel connection lost".into())
            })
    }

    pub async fn announce_recording(
        &self,
        recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), TransportError> {
        self.outbound_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.command_tx
            .send(TransportCommand::AnnounceRecording(recording_id.clone()))
            .await
            .map_err(|_| {
                self.outbound_queue_depth.fetch_sub(1, Ordering::Relaxed);
                TransportError::Internal("Sentinel connection lost".into())
            })
    }

    pub async fn find_providers(
        &self,
        recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), TransportError> {
        self.outbound_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.command_tx
            .send(TransportCommand::FindRecordingProviders(
                recording_id.clone(),
            ))
            .await
            .map_err(|_| {
                self.outbound_queue_depth.fetch_sub(1, Ordering::Relaxed);
                TransportError::Internal("Sentinel connection lost".into())
            })
    }

    /// Reply to a previously-received `RecordingRequested` event, identified by
    /// the `channel_id` that was delivered with the inbound event. Best-effort:
    /// returns `Ok(())` once the command is enqueued; failures inside the actor
    /// (unknown channel_id, libp2p response channel expired) are surfaced via
    /// the `response_channels_lost` counter, not the return value.
    ///
    /// Calling this twice with the same `channel_id` is safe — the second call
    /// is a no-op that increments the lost-counter.
    pub async fn send_response(
        &self,
        channel_id: &str,
        response: RecordingResponse,
    ) -> Result<(), TransportError> {
        self.outbound_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.command_tx
            .send(TransportCommand::SendResponse(
                channel_id.to_string(),
                response,
            ))
            .await
            .map_err(|_| {
                self.outbound_queue_depth.fetch_sub(1, Ordering::Relaxed);
                TransportError::Internal("Sentinel connection lost".into())
            })
    }

    /// Eclipse remediation: re-dial bootstrap peers and trigger Kademlia random walk.
    pub async fn rebootstrap(&self, peers: &[String]) -> Result<(), TransportError> {
        self.outbound_queue_depth.fetch_add(1, Ordering::Relaxed);
        self.command_tx
            .send(TransportCommand::ReBootstrap(peers.to_vec()))
            .await
            .map_err(|_| {
                self.outbound_queue_depth.fetch_sub(1, Ordering::Relaxed);
                TransportError::Internal("Sentinel connection lost".into())
            })
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

    /// Returns a handle to the per-protocol wake counters. Clones of
    /// `ProtocolWakeCounters` share the underlying atomics with the adapter
    /// (12 `Arc::clone` bumps per call; only invoke at sample boundaries).
    pub fn protocol_wakes(&self) -> ProtocolWakeCounters {
        self.adapter.protocol_wakes.clone()
    }

    /// Returns the shared gauge of unconsumed outbound `TransportCommand`s.
    /// Saturates at the command-channel capacity (hardcoded 2048).
    pub fn outbound_queue_depth(&self) -> Arc<AtomicU64> {
        self.adapter.outbound_queue_depth.clone()
    }

    /// Returns the monotonic count of failed `gossipsub.publish()` calls in
    /// the swarm task. These errors (e.g. `InsufficientPeers`) are otherwise
    /// only surfaced via `tracing::error!`, which is lost in tests that
    /// don't install a subscriber.
    pub fn gossipsub_publish_errors(&self) -> Arc<AtomicU64> {
        self.adapter.gossipsub_publish_errors.clone()
    }

    /// Returns the monotonic count of retrieval responses that could not be
    /// delivered: unknown `channel_id`, GC eviction past libp2p's
    /// request-response timeout, or `request_response::Behaviour::send_response`
    /// returning `Err` because the peer disconnected.
    pub fn response_channels_lost(&self) -> Arc<AtomicU64> {
        self.adapter.response_channels_lost.clone()
    }

    /// Returns the shared IO event log when `AdapterConfig::enable_io_log`
    /// is set at adapter construction. Shared across all substreams and
    /// transports (QUIC, TCP, Relay) for this adapter.
    pub fn io_log(&self) -> Option<Arc<Mutex<Vec<IoLogEntry>>>> {
        self.adapter.io_counters.io_log.clone()
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

    async fn ban_peer(&self, peer: &MeshAddress) {
        if let Err(e) = self.adapter.ban_peer(peer).await {
            tracing::error!(target: "phalanx::transport", "Failed to ban peer {}: {}", peer.0, e);
        }
    }

    async fn send_response(
        &self,
        channel_id: &str,
        response: RecordingResponse,
    ) -> Result<(), String> {
        self.adapter
            .send_response(channel_id, response)
            .await
            .map_err(|e| e.to_string())
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
        target: &MeshAddress,
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

    use libp2p::gossipsub::{self, IdentTopic, MessageId};
    use libp2p::mdns;
    use libp2p::Multiaddr;

    fn make_gossipsub_message_event(
        propagation_source: PeerId,
        topic: &str,
        data: Vec<u8>,
    ) -> SwarmEvent<PhalanxEvent> {
        let message = gossipsub::Message {
            source: None,
            data,
            sequence_number: None,
            topic: IdentTopic::new(topic).hash(),
        };
        SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message {
            propagation_source,
            message_id: MessageId(vec![0]),
            message,
        }))
    }

    // === Group A: extract_subnet_bucket ===

    #[test]
    fn extract_subnet_bucket_ipv4_uses_first_two_octets() {
        let addr: Multiaddr = "/ip4/192.168.1.1/tcp/4001".parse().unwrap();
        let bucket = extract_subnet_bucket(&addr);
        assert_eq!(bucket.octets(), [192, 168]);
    }

    #[test]
    fn extract_subnet_bucket_ipv6_hashes_first_six_bytes() {
        let addr: Multiaddr = "/ip6/2001:db8::1/tcp/4001".parse().unwrap();
        let bucket = extract_subnet_bucket(&addr);
        let expected = SubnetBucket::from_ipv6_prefix(&[0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00]);
        assert_eq!(bucket, expected);
    }

    #[test]
    fn extract_subnet_bucket_finds_ip_after_other_protocols() {
        let addr: Multiaddr = "/dnsaddr/example.com/p2p-circuit/ip4/10.0.0.5/tcp/0"
            .parse()
            .unwrap();
        let bucket = extract_subnet_bucket(&addr);
        assert_eq!(bucket.octets(), [10, 0]);
    }

    #[test]
    fn extract_subnet_bucket_falls_back_when_no_ip() {
        let addr: Multiaddr = "/dnsaddr/example.com/tcp/4001".parse().unwrap();
        let bucket1 = extract_subnet_bucket(&addr);
        let bucket2 = extract_subnet_bucket(&addr);
        assert_eq!(bucket1, bucket2, "fallback hash must be deterministic");
    }

    // === Group B: translate_swarm_event against real PhalanxEvent ===

    #[test]
    fn translate_real_gossipsub_message_emits_data_received() {
        let propagation_source = PeerId::random();
        let event =
            make_gossipsub_message_event(propagation_source, "phalanx/test", b"hello".to_vec());

        match translate_swarm_event(event)
            .expect("gossipsub message must translate to NetworkEvent")
        {
            NetworkEvent::DataReceived {
                origin,
                topic,
                data,
            } => {
                assert_eq!(origin.0, propagation_source.to_base58());
                assert_eq!(data, b"hello".to_vec());
                assert_eq!(topic.as_str(), "/phalanx/test");
            }
            _ => panic!("expected NetworkEvent::DataReceived"),
        }
    }

    #[test]
    fn translate_mdns_discovered_emits_peer_discovered_with_subnet() {
        let peer_id = PeerId::random();
        let addr: Multiaddr = "/ip4/192.168.1.5/tcp/4001".parse().unwrap();
        let event = SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(vec![(
            peer_id, addr,
        )])));

        match translate_swarm_event(event).expect("mdns Discovered must translate to NetworkEvent")
        {
            NetworkEvent::PeerDiscovered {
                peer,
                source,
                bucket,
                transport,
            } => {
                assert_eq!(peer.0, peer_id.to_base58());
                assert!(matches!(source, DiscoverySource::Mdns));
                assert_eq!(bucket.octets(), [192, 168]);
                assert_eq!(transport, TransportClass::Internet);
            }
            _ => panic!("expected NetworkEvent::PeerDiscovered"),
        }
    }

    #[test]
    fn translate_mdns_discovered_empty_returns_none() {
        let event = SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(vec![])));
        assert!(translate_swarm_event(event).is_none());
    }

    // === Group C: ProtocolWakeCounters ===

    #[test]
    fn protocol_wake_counters_start_at_zero() {
        let counters = ProtocolWakeCounters::default();
        assert_eq!(counters.gossipsub.load(Ordering::Relaxed), 0);
        assert_eq!(counters.kademlia.load(Ordering::Relaxed), 0);
        assert_eq!(counters.mdns.load(Ordering::Relaxed), 0);
        assert_eq!(counters.identify.load(Ordering::Relaxed), 0);
        assert_eq!(counters.autonat.load(Ordering::Relaxed), 0);
        assert_eq!(counters.dcutr.load(Ordering::Relaxed), 0);
        assert_eq!(counters.relay_server.load(Ordering::Relaxed), 0);
        assert_eq!(counters.relay_client.load(Ordering::Relaxed), 0);
        assert_eq!(counters.retrieval.load(Ordering::Relaxed), 0);
        assert_eq!(counters.connection.load(Ordering::Relaxed), 0);
        assert_eq!(counters.listener.load(Ordering::Relaxed), 0);
        assert_eq!(counters.other.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn protocol_wake_counters_clone_shares_state() {
        let a = ProtocolWakeCounters::default();
        let b = a.clone();
        a.gossipsub.fetch_add(7, Ordering::Relaxed);
        assert_eq!(b.gossipsub.load(Ordering::Relaxed), 7);
        a.connection.fetch_add(13, Ordering::Relaxed);
        assert_eq!(b.connection.load(Ordering::Relaxed), 13);
    }

    #[test]
    fn protocol_wake_counters_independent_fields() {
        let counters = ProtocolWakeCounters::default();
        counters.gossipsub.fetch_add(1, Ordering::Relaxed);
        counters.kademlia.fetch_add(2, Ordering::Relaxed);
        assert_eq!(counters.gossipsub.load(Ordering::Relaxed), 1);
        assert_eq!(counters.kademlia.load(Ordering::Relaxed), 2);
        assert_eq!(counters.mdns.load(Ordering::Relaxed), 0);
    }

    // === Group D: AdapterConfig defaults ===

    #[test]
    fn adapter_config_defaults_match_documented_values() {
        let config = AdapterConfig::default();
        assert_eq!(config.event_channel_capacity, 2048);
        assert_eq!(config.max_events_per_peer_per_sec, 100);
        assert!(config.poll_cadence.is_none());
        assert!(!config.enable_wake_log);
        assert!(!config.enable_io_log);
    }

    // === Group T: TimedStore ===

    #[test]
    fn timed_store_take_returns_inserted_value() {
        let mut store: TimedStore<u32> = TimedStore::new(Duration::from_secs(30));
        let t0 = Instant::now();
        store.insert("abc".to_string(), 7, t0);
        assert_eq!(store.take("abc"), Some(7));
    }

    #[test]
    fn timed_store_take_consumes_entry() {
        let mut store: TimedStore<u32> = TimedStore::new(Duration::from_secs(30));
        let t0 = Instant::now();
        store.insert("abc".to_string(), 7, t0);
        assert_eq!(store.take("abc"), Some(7));
        assert_eq!(store.take("abc"), None);
    }

    #[test]
    fn timed_store_evict_expired_drops_old_entries() {
        let mut store: TimedStore<u32> = TimedStore::new(Duration::from_secs(30));
        let t0 = Instant::now();
        store.insert("abc".to_string(), 7, t0);
        let evicted = store.evict_expired(t0 + Duration::from_secs(31));
        assert_eq!(evicted, 1);
        assert_eq!(store.take("abc"), None);
    }

    #[test]
    fn timed_store_evict_expired_keeps_fresh_entries() {
        let mut store: TimedStore<u32> = TimedStore::new(Duration::from_secs(30));
        let t0 = Instant::now();
        store.insert("abc".to_string(), 7, t0);
        let evicted = store.evict_expired(t0 + Duration::from_secs(5));
        assert_eq!(evicted, 0);
        assert_eq!(store.take("abc"), Some(7));
    }

    #[test]
    fn timed_store_insert_replaces_existing_key() {
        let mut store: TimedStore<u32> = TimedStore::new(Duration::from_secs(30));
        let t0 = Instant::now();
        store.insert("abc".to_string(), 7, t0);
        store.insert("abc".to_string(), 99, t0);
        assert_eq!(store.take("abc"), Some(99));
    }

    // === Group R: PerPeerRateLimiter ===

    #[test]
    fn rate_limiter_accepts_within_budget() {
        let peer = PeerId::random();
        let mut limiter = PerPeerRateLimiter::new(3);
        let t0 = Instant::now();
        assert!(limiter.should_accept(peer, t0));
        assert!(limiter.should_accept(peer, t0));
        assert!(limiter.should_accept(peer, t0));
    }

    #[test]
    fn rate_limiter_rejects_over_budget() {
        let peer = PeerId::random();
        let mut limiter = PerPeerRateLimiter::new(3);
        let t0 = Instant::now();
        assert!(limiter.should_accept(peer, t0));
        assert!(limiter.should_accept(peer, t0));
        assert!(limiter.should_accept(peer, t0));
        assert!(!limiter.should_accept(peer, t0));
    }

    #[test]
    fn rate_limiter_resets_after_one_second() {
        let peer = PeerId::random();
        let mut limiter = PerPeerRateLimiter::new(2);
        let t0 = Instant::now();
        assert!(limiter.should_accept(peer, t0));
        assert!(limiter.should_accept(peer, t0));
        assert!(!limiter.should_accept(peer, t0));
        let t1 = t0 + Duration::from_secs(1);
        assert!(limiter.should_accept(peer, t1));
    }

    // Mock behaviour event for testing purposes
    enum MockBehaviourEvent {
        MessageReceived { source: PeerId, payload: Vec<u8> },
    }

    impl Into<NetworkEvent> for MockBehaviourEvent {
        fn into(self) -> NetworkEvent {
            match self {
                MockBehaviourEvent::MessageReceived { source, payload } => {
                    NetworkEvent::DataReceived {
                        origin: MeshAddress::new(source.to_string()),
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
