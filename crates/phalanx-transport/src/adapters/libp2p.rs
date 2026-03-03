use crate::{PeerMapper, TransportAdapter, TransportError};
use async_trait::async_trait;
use futures::StreamExt; // Required to bring StreamExt::select_next_some into scope
use libp2p::swarm::Swarm;
use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::topic::MeshTopic;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

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

impl Libp2pAdapter {
    /// Initializes the Actor Pattern.
    /// The Swarm is moved into a detached Tokio task to preserve thread safety (Sync).
    pub fn new(mut swarm: Swarm<crate::behaviour::PhalanxBehaviour>) -> Self {
        let (command_tx, mut command_rx) = mpsc::channel::<TransportCommand>(128);
        let (_event_tx, event_rx) = mpsc::channel::<NetworkEvent>(1024);

        tokio::spawn(async move {
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

                    _swarm_event = swarm.select_next_some() => {
                        // Translation from libp2p::swarm::SwarmEvent to NetworkEvent goes here.
                        // Example dispatch:
                        // let network_event = translate_event(swarm_event);
                        // let _ = event_tx.send(network_event).await;
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
