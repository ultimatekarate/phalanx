use crate::clock::TrustedClock; // Node Hands: The actual Clock
use phalanx_forensics::judge::IntegrityGate; // Verbs: The Integrity Gate (Gate 3)
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*; // Nouns: NetworkId, ShardError, WitnessEnvelope
use phalanx_proto::VolleyRequest;
use tokio::sync::oneshot;
use tracing::info;

pub struct RetrievalOrchestrator {
    pub clock: TrustedClock,
}

impl Default for RetrievalOrchestrator {
    fn default() -> Self {
        Self::new()
    }
}

impl RetrievalOrchestrator {
    pub fn new() -> Self {
        Self {
            clock: TrustedClock::new(),
        }
    }

    /// Forensic validation of recovered data.
    /// This prevents a malicious peer from serving "poisoned" historical data.
    pub async fn verify_mesh_egress(
        &self,
        envelopes: Vec<WitnessEnvelope>,
        local_id: &NetworkId,
    ) -> Result<Vec<WitnessEnvelope>, ShardError> {
        let mut verified = Vec::with_capacity(envelopes.len());
        let mut anchor = None;

        let now = PhalanxTimestamp::now();
        for env in envelopes {
            // Apply Gate 3: Integrity verification
            let validated = env.check_integrity(local_id, now, 10_000, anchor)?;
            anchor = Some(validated.calculate_anchor());
            verified.push(validated);
        }
        info!(
            count = verified.len(),
            "Retrieval: Data verified via Integrity Gate"
        );
        Ok(verified)
    }
}

/// Encapsulates an external request for forensic evidence, bridging the
/// network boundary to the internal storage engine.
pub struct RetrievalQuery {
    /// The forensic identity of the node requesting the data.
    pub origin: NetworkId,

    /// The strongly-typed parameters of the requested evidence.
    pub request: VolleyRequest,

    /// The return channel to dispatch the result back to the Sentinel
    /// for network routing.
    pub reply_to: oneshot::Sender<VolleyResponse>,
}
