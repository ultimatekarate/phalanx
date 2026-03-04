use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{MeshTopic, NetworkId, VolleyResponse};
use phalanx_transport::NetworkTransport;

struct FailingTransport;

#[async_trait::async_trait]
impl NetworkTransport for FailingTransport {
    async fn send_response(&mut self, _: &str, _: VolleyResponse) -> Result<(), String> {
        // Pillar 3: Force failure to verify re-queueing
        Err("Simulated Network Failure".to_string())
    }
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        None
    }
    async fn publish(&mut self, _: &MeshTopic, _: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    async fn ban_peer(&mut self, _: &NetworkId) {}
}
