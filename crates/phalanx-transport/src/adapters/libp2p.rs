use crate::adapters::TransportAdapter;
use crate::events::PhalanxEvent;
use async_trait::async_trait;
use libp2p::futures::StreamExt;
use libp2p::request_response::ResponseChannel;
use libp2p::swarm::{Swarm, SwarmEvent};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::*;
use phalanx_proto::topic::MeshTopic;
use std::collections::HashMap;
pub struct Libp2pAdapter {
    swarm: Swarm<crate::behaviour::PhalanxBehaviour>,
    // Maps domain channel IDs back to physical libp2p response tokens
    pending_responses: HashMap<String, ResponseChannel<VolleyResponse>>,
    request_counter: u64,
}

impl Libp2pAdapter {
    pub fn new(swarm: Swarm<crate::behaviour::PhalanxBehaviour>) -> Self {
        Self {
            swarm,
            pending_responses: HashMap::new(),
            request_counter: 0,
        }
    }
}

#[async_trait]
impl TransportAdapter for Libp2pAdapter {
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
                    libp2p::request_response::Event::Message {
                        message:
                            libp2p::request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    },
                )) => {
                    self.request_counter += 1;
                    let channel_id = format!("req-{}", self.request_counter);

                    // Store the one-shot channel token
                    self.pending_responses.insert(channel_id.clone(), channel);
                    let origin = NetworkId::random(); // TODO: This is temporary.
                    return Some(NetworkEvent::VolleyRequested {
                        origin,
                        request,
                        channel_id,
                    });
                }
                _ => continue,
            }
        }
    }

    async fn ban_peer(&mut self, peer: &NetworkId) {
        let _ = self.swarm.disconnect_peer_id(peer.0);
    }

    async fn send_response(
        &mut self,
        channel_id: &str,
        response: VolleyResponse,
    ) -> Result<(), String> {
        // Retrieve and consume the one-shot libp2p channel
        let channel = self
            .pending_responses
            .remove(channel_id)
            .ok_or_else(|| "Channel ID not found or already consumed".to_string())?;

        // Note: Assumes the request_response behaviour is named `retrieval` in PhalanxBehaviour.
        // Adjust field name if defined differently in swarm.rs.
        self.swarm
            .behaviour_mut()
            .retrieval
            .send_response(channel, response)
            .map_err(|_| "Failed to push response to underlying libp2p stream".to_string())
    }
}
