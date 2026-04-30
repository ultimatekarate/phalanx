use crate::routing::MeshRoutingTable;
use async_trait::async_trait;

use phalanx_proto::network::EgressPort;
use phalanx_proto::network::{IngressPort, NetworkEvent};
use phalanx_proto::prelude::*;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

#[derive(Clone)]
pub struct MockAdapter {
    id: MeshAddress,
    mesh_bus: Arc<RwLock<MeshRoutingTable>>,
}

impl MockAdapter {
    pub fn new(
        id: MeshAddress,
        _ingress_rx: mpsc::Receiver<NetworkEvent>,
        mesh_bus: Arc<RwLock<MeshRoutingTable>>,
    ) -> Self {
        Self { id, mesh_bus }
    }
}

#[async_trait]
impl EgressPort for MockAdapter {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        let table = self.mesh_bus.read().await;
        for sender in table.routes.values() {
            let event = NetworkEvent::DataReceived {
                origin: self.id.clone(),
                topic: topic.clone(),
                data: data.clone(),
            };
            let _ = sender.send(event).await;
        }
        Ok(())
    }

    async fn ban_peer(&self, _peer: &MeshAddress) {
        // No-op in simulation mock
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
        _recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn find_providers(
        &self,
        _recording_id: &phalanx_proto::identity::RecordingId,
    ) -> Result<(), String> {
        Ok(())
    }

    async fn send_request(
        &self,
        _target: &MeshAddress,
        _request: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        Ok(())
    }
}

pub struct MockIngress {
    rx: mpsc::Receiver<NetworkEvent>,
}

impl MockIngress {
    pub fn new(rx: mpsc::Receiver<NetworkEvent>) -> Self {
        Self { rx }
    }
}

#[async_trait]
impl IngressPort for MockIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.rx.recv().await
    }
}
