use crate::routing::table::MeshRoutingTable;
use crate::signaling::NetworkEvent;
use async_trait::async_trait;
use libp2p::TransportError;
use phalanx_proto::prelude::*;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};

// crates/phalanx-transport/src/adapters/virtual.rs
pub struct MockAdapter {
    id: NetworkId,
    ingress_tx: mpsc::Sender<NetworkEvent>,
    ingress_rx: mpsc::Receiver<NetworkEvent>,
    mesh_bus: Arc<RwLock<MeshRoutingTable>>, // The Simulation's shared "Ether"
}

#[async_trait]
impl TransportAdapter for MockAdapter {
    async fn send(
        &self,
        target: &NetworkId,
        topic: MeshTopic,
        data: Vec<u8>,
    ) -> Result<(), TransportError> {
        // "Across the virtual wire..."
        self.mesh_bus.route_to(target, topic, data).await
    }

    async fn ingress_stream(&self) -> mpsc::Receiver<NetworkEvent> {
        // "Through the simulation conduit..."
        self.ingress_rx.clone()
    }
}
