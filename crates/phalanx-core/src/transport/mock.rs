use async_trait::async_trait;
use std::collections::HashSet;
use tokio::sync::mpsc;

use crate::base::types::MeshTopic;
use crate::primitives::identity::NetworkId;
use crate::transport::events::NetworkEvent;
use crate::transport::network_transport::NetworkTransport;
use crate::transport::protocol::VolleyResponse;

pub struct MockTransport {
    ingress_rx: mpsc::Receiver<NetworkEvent>,
    egress_tx: Option<mpsc::Sender<(MeshTopic, Vec<u8>)>>,
    pub captured_responses: Vec<(String, VolleyResponse)>,
    banned_peers: HashSet<NetworkId>,
}

impl MockTransport {
    pub fn new(
        ingress_rx: mpsc::Receiver<NetworkEvent>,
        egress_tx: Option<mpsc::Sender<(MeshTopic, Vec<u8>)>>,
    ) -> Self {
        Self {
            ingress_rx,
            egress_tx,
            captured_responses: Vec::new(),
            banned_peers: HashSet::new(),
        }
    }

    pub fn is_banned(&self, peer: &NetworkId) -> bool {
        self.banned_peers.contains(peer)
    }
}

#[async_trait]
impl NetworkTransport for MockTransport {
    async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        if let Some(tx) = &self.egress_tx {
            tx.send((topic.clone(), data))
                .await
                .map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.ingress_rx.recv().await
    }

    async fn ban_peer(&mut self, peer: &NetworkId) {
        self.banned_peers.insert(*peer);
    }

    async fn send_response(
        &mut self,
        channel_id: &str,
        response: VolleyResponse,
    ) -> Result<(), String> {
        // In the simulation harness, we simply log the response for deterministic test verification.
        self.captured_responses
            .push((channel_id.to_string(), response));
        Ok(())
    }
}
