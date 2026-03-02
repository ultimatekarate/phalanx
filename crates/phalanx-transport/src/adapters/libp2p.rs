use crate::TransportAdapter;
use async_trait::async_trait;
use libp2p::swarm::Swarm;
use std::sync::{Arc, Mutex}; // Must use std::sync::Mutex for synchronous extraction
use tokio::sync::mpsc;

// Assume these are correctly mapped in your actual prelude/dictionary
use crate::TransportError;
use phalanx_proto::identity::NetworkId;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::topic::MeshTopic;

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
        let (event_tx, event_rx) = mpsc::channel::<NetworkEvent>(1024);

        // Detach the non-Sync Swarm into a localized actor loop.
        // NOTE: In the full Phalanx architecture, this loop logic may be
        // delegated to `MeshSentinel` in the `phalanx-node` crate.
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    // 1. Process outbound commands from the Handle
                    command_option = command_rx.recv() => {
                        match command_option {
                            Some(TransportCommand::Publish(topic, data)) => {
                                // Implement swarm publish logic here
                            }
                            Some(TransportCommand::SendDirect(target, data)) => {
                                // Implement swarm direct send logic here
                            }
                            Some(TransportCommand::Ban(peer)) => {
                                let _ = swarm.disconnect_peer_id(peer.into());
                            }
                            None => break, // Channel dropped, terminate task
                        }
                    },

                    // 2. Process inbound network events from the Swarm
                    swarm_event = libp2p::futures::StreamExt::next(&mut swarm) => {
                        if let Some(event) = swarm_event {
                            // Translate libp2p::swarm::SwarmEvent to phalanx_proto::network::NetworkEvent
                            // let network_event = translate_event(event);
                            // let _ = event_tx.send(network_event).await;
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
