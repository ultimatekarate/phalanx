use phalanx_proto::RecordingResponse;

use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::*;
use std::collections::HashMap;
use tokio::sync::mpsc;

/// The central switchboard for the Transport layer.
/// In a mock or local environment, it routes events between virtual peers.
/// In production, it matches incoming RecordingResponses to their pending requests.
#[derive(Debug)]
pub struct MeshRoutingTable {
    /// Maps a virtual peer's MeshAddress to their local event inbox (Used for MockAdapter)
    pub routes: HashMap<MeshAddress, mpsc::Sender<NetworkEvent>>,

    /// Maps a unique channel ID to the sender waiting for a response (Used for Resilient Retrieval)
    pub pending_responses: HashMap<String, mpsc::Sender<RecordingResponse>>,
}

impl Default for MeshRoutingTable {
    fn default() -> Self {
        Self::new()
    }
}

impl MeshRoutingTable {
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
            pending_responses: HashMap::new(),
        }
    }

    /// Dispatches a response back to the async task that requested it.
    pub async fn dispatch_resilient_response(
        &mut self,
        channel_id: String,
        response: RecordingResponse,
    ) {
        // If there is a task waiting for this specific channel_id, send the response to it.
        // If it was dropped or timed out, we just ignore the stale response.
        if let Some(sender) = self.pending_responses.remove(&channel_id) {
            if sender.send(response).await.is_err() {
                tracing::debug!(
                    channel = %channel_id,
                    "Routing Table: Dropped response, receiver task already died."
                );
            }
        } else {
            tracing::warn!(
                channel = %channel_id,
                "Routing Table: Received response for unknown or expired channel."
            );
        }
    }
}
