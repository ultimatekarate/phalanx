use async_trait::async_trait;
use std::collections::HashSet;
use tokio::sync::mpsc;

use crate::base::types::MeshTopic;
use crate::primitives::identity::NetworkId;
use crate::transport::events::NetworkEvent;
use crate::transport::NetworkTransport;

pub struct MockTransport {
    ingress_rx: mpsc::Receiver<NetworkEvent>,
    egress_tx: Option<mpsc::Sender<(MeshTopic, Vec<u8>)>>,
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
}
