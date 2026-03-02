use crate::PendingEgress;
use phalanx_proto::VolleyResponse;
use std::time::Duration;

impl MeshRoutingTable {
    async fn dispatch_resilient_response(&mut self, channel_id: String, response: VolleyResponse) {
        if self.pending_egress.len() >= 1000 {
            self.pending_egress.pop_front();
        }
        if self
            .network
            .send_response(&channel_id, response.clone())
            .await
            .is_err()
        {
            self.pending_egress.push_back(PendingEgress::new(
                channel_id,
                response,
                Duration::from_millis(500),
            ));
        }
    }
}
