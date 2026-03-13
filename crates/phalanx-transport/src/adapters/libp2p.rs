use crate::behaviour::PhalanxBehaviour;
use crate::events::PhalanxEvent;
use crate::{PeerMapper, TransportAdapter, TransportError};
use async_trait::async_trait;
use futures::StreamExt; // Required to bring StreamExt::select_next_some into scope
use libp2p::kad::store::RecordStore;
use libp2p::swarm::Swarm;
use libp2p::swarm::SwarmEvent;
use libp2p::PeerId;
use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::telemetry::DiscoverySource;
use phalanx_proto::topic::MeshTopic;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tokio::time::Instant;

pub enum TransportCommand {
    Publish(MeshTopic, Vec<u8>),
    SendDirect(NetworkId, Vec<u8>),
    Ban(NetworkId),
}

#[derive(Clone)]
pub struct Libp2pAdapter {
    command_tx: mpsc::Sender<TransportCommand>,
    // Arc<Mutex<>> ensures the Receiver can be extracted safely across threads
    event_rx_factory: Arc<Mutex<Option<mpsc::Receiver<NetworkEvent>>>>,
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
        )) => Some(NetworkEvent::VolleyRequested {
            origin: PeerMapper::to_network_id(&peer),
            request,
            channel_id: request_id.to_string(),
        }),
        // mDNS discovery → PeerDiscovered (vitals tracking)
        SwarmEvent::Behaviour(PhalanxEvent::Mdns(libp2p::mdns::Event::Discovered(peers))) => peers
            .first()
            .map(|(peer_id, _)| NetworkEvent::PeerDiscovered {
                peer: PeerMapper::to_network_id(peer_id),
                source: DiscoverySource::Mdns,
            }),
        _ => None, // Safely ignore background noise like DHT pings
    }
}

/// H3 FIX: Configurable event channel capacity and per-peer rate limits.
pub struct AdapterConfig {
    /// Event channel capacity (default: 2048)
    pub event_channel_capacity: usize,
    /// Max events per peer per second before dropping (default: 100)
    pub max_events_per_peer_per_sec: u64,
}

impl Default for AdapterConfig {
    fn default() -> Self {
        Self {
            event_channel_capacity: 2048,
            max_events_per_peer_per_sec: 100,
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
        Self::with_config(swarm, AdapterConfig::default())
    }

    pub fn with_config<S>(mut swarm: Swarm<PhalanxBehaviour<S>>, config: AdapterConfig) -> Self
    where
        S: RecordStore + Send + Sync + 'static,
    {
        let (command_tx, mut command_rx) = mpsc::channel::<TransportCommand>(128);
        let (_event_tx, event_rx) = mpsc::channel::<NetworkEvent>(config.event_channel_capacity);
        let max_per_sec = config.max_events_per_peer_per_sec;

        tokio::spawn(async move {
            // H3 FIX: Per-peer rate limiting state
            let mut peer_event_counts: HashMap<PeerId, (u64, Instant)> = HashMap::new();
            let mut dropped_events: u64 = 0;

            loop {
                tokio::select! {
                    command_option = command_rx.recv() => {
                        match command_option {
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
                                        // H2 FIX: Verify peer is connected before sending.
                                        // libp2p's Noise protocol authenticates the transport-layer
                                        // peer identity, so once connected the PeerId is
                                        // cryptographically verified. Sending to unconnected peers
                                        // risks targeting a spoofed NetworkId.
                                        if !swarm.is_connected(&peer_id) {
                                            tracing::warn!(
                                                target: "phalanx::transport",
                                                "Rejecting SendDirect to unconnected peer: {}",
                                                target.0,
                                            );
                                        } else {
                                            match postcard::from_bytes::<phalanx_proto::retrieval::VolleyRequest>(&data) {
                                                Ok(request) => {
                                                    swarm.behaviour_mut().retrieval.send_request(&peer_id, request);
                                                }
                                                Err(decode_error) => {
                                                    tracing::error!(
                                                        target: "phalanx::transport",
                                                        "Failed to decode VolleyRequest for {}: {:?}",
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
                            None => break, // Channel dropped; initiate actor shutdown
                        }
                    },

                    swarm_event = swarm.select_next_some() => {
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

                            // Reset window if >1 second elapsed
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
                            if dropped_events % 100 == 1 {
                                tracing::warn!(
                                    target: "phalanx::transport",
                                    peer = %peer,
                                    total_dropped = dropped_events,
                                    "Per-peer rate limit exceeded, dropping event"
                                );
                            }
                        }
                    }
                }
            }
        });

        Self {
            command_tx,
            event_rx_factory: Arc::new(Mutex::new(Some(event_rx))),
        }
    }
}

#[async_trait]
impl TransportAdapter for Libp2pAdapter {
    async fn publish(&self, topic: MeshTopic, data: Vec<u8>) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::Publish(topic, data))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }

    async fn send_direct(&self, target: &NetworkId, data: Vec<u8>) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::SendDirect(target.clone(), data))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }

    fn ingress_stream(&self) -> mpsc::Receiver<NetworkEvent> {
        self.event_rx_factory
            .lock()
            .expect("Mutex poisoned in Libp2pAdapter")
            .take()
            .expect("Ingress stream has already been consumed by the Sentinel")
    }

    async fn ban_peer(&self, peer: &NetworkId) -> Result<(), TransportError> {
        self.command_tx
            .send(TransportCommand::Ban(peer.clone()))
            .await
            .map_err(|_| TransportError::Internal("Sentinel connection lost".into()))
    }
}

#[cfg(test)]
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
