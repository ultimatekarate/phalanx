use crate::NetworkTransport;
use async_trait::async_trait;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::*;
use phalanx_proto::telemetry::SimEvent;
use std::collections::HashSet;
use tokio::sync::mpsc;

pub struct MockTransport {
    ingress_rx: mpsc::Receiver<NetworkEvent>,
    egress_tx: Option<mpsc::Sender<(MeshTopic, Vec<u8>)>>,
    telemetry_tx: Option<mpsc::Sender<SimEvent>>,
    local_id: NetworkId,
    pub captured_responses: Vec<(String, RecordingResponse)>,
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
            telemetry_tx: None,
            local_id: NetworkId::from("mock-default"), // Ephemeral default for pure unit tests
            captured_responses: Vec::new(),
            banned_peers: HashSet::new(),
        }
    }

    /// Injects the simulation telemetry bus into the mock adapter.
    pub fn with_telemetry(
        mut self,
        local_id: NetworkId,
        telemetry_tx: mpsc::Sender<SimEvent>,
    ) -> Self {
        self.local_id = local_id;
        self.telemetry_tx = Some(telemetry_tx);
        self
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
        self.banned_peers.insert(peer.clone());

        // Synthesize the telemetry event for the Simulation Harness
        if let Some(tx) = &self.telemetry_tx {
            let event = SimEvent::AttackAttemptBlocked {
                attacker: peer.clone(),
                target: self.local_id.clone(),
                reason: "Peer blacklisted by MockTransport policy".to_string(),
            };

            // Fire and forget; do not block the transport layer on telemetry back pressure
            let _ = tx.send(event).await;
        }
    }

    async fn send_response(
        &mut self,
        channel_id: &str,
        response: RecordingResponse,
    ) -> Result<(), String> {
        self.captured_responses
            .push((channel_id.to_string(), response));
        Ok(())
    }
}
