use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};

use crate::base::types::MeshTopic;
use crate::primitives::identity::NetworkId;
use crate::transport::events::NetworkEvent;
use crate::transport::transport::NetworkTransport;
use crate::PhalanxEvent;

pub struct Libp2pAdapter {
    swarm: Swarm<crate::transport::swarm::PhalanxBehaviour>,
}

impl Libp2pAdapter {
    pub fn new(swarm: Swarm<crate::transport::swarm::PhalanxBehaviour>) -> Self {
        Self { swarm }
    }
}

#[async_trait]
impl NetworkTransport for Libp2pAdapter {
    async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        let topic_hash = libp2p::gossipsub::IdentTopic::new(topic.as_str());
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(topic_hash, data)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    async fn next_event(&mut self) -> Option<NetworkEvent> {
        loop {
            match self.swarm.select_next_some().await {
                SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(
                    libp2p::gossipsub::Event::Message {
                        propagation_source,
                        message,
                        ..
                    },
                )) => {
                    return Some(NetworkEvent::DataReceived {
                        origin: NetworkId(propagation_source),
                        topic: MeshTopic::new(message.topic.as_str()),
                        data: message.data,
                    });
                }
                SwarmEvent::ConnectionEstablished { peer_id, .. } => {
                    return Some(NetworkEvent::PeerDiscovered(NetworkId(peer_id)));
                }
                SwarmEvent::Behaviour(PhalanxEvent::Retrieval(
                    libp2p::request_response::Event::Message { message, .. },
                )) => {
                    if let libp2p::request_response::Message::Request {
                        request, channel, ..
                    } = message
                    {
                        // Requires mapping the libp2p channel token to a String or registry ID
                        // depending on how the response routing is architected.
                        return Some(NetworkEvent::RetrievalRequested {
                            request,
                            channel_id: format!("{:?}", channel),
                        });
                    }
                }
                // Silently bypass boilerplate protocol events
                _ => continue,
            }
        }
    }

    async fn ban_peer(&mut self, peer: &NetworkId) {
        let _ = self.swarm.disconnect_peer_id(peer.0);
    }
}
