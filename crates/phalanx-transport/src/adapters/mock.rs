use crate::routing::MeshRoutingTable;
use async_trait::async_trait;

use crate::TransportAdapter;
use crate::TransportError;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::*;
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex, RwLock};

pub struct MockAdapter {
    id: NetworkId,
    ingress_rx: Mutex<Option<mpsc::Receiver<NetworkEvent>>>,
    mesh_bus: Arc<RwLock<MeshRoutingTable>>,
}

impl MockAdapter {
    pub fn new(
        id: NetworkId,
        ingress_rx: mpsc::Receiver<NetworkEvent>,
        mesh_bus: Arc<RwLock<MeshRoutingTable>>,
    ) -> Self {
        Self {
            id,
            ingress_rx: Mutex::new(Some(ingress_rx)),
            mesh_bus,
        }
    }
}

#[async_trait]
impl TransportAdapter for MockAdapter {
    async fn publish(&self, topic: MeshTopic, data: Vec<u8>) -> Result<(), TransportError> {
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

    async fn send_direct(&self, target: &NetworkId, data: Vec<u8>) -> Result<(), TransportError> {
        let table = self.mesh_bus.read().await;
        if let Some(sender) = table.routes.get(target) {
            let event = NetworkEvent::DataReceived {
                origin: self.id.clone(),
                topic: MeshTopic::default(),
                data,
            };
            sender
                .send(event)
                .await
                .map_err(|_| TransportError::Network("Peer channel closed".into()))?;
        }
        Ok(())
    }

    fn ingress_stream(&self) -> mpsc::Receiver<NetworkEvent> {
        self.ingress_rx
            .blocking_lock()
            .take()
            .expect("Ingress stream has already been consumed")
    }

    async fn ban_peer(&self, _peer: &NetworkId) -> Result<(), TransportError> {
        // No-op in simulation mock
        Ok(())
    }
}
