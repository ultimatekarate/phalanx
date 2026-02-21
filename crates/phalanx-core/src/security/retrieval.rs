use crate::primitives::identity::NetworkId;
use crate::primitives::shards::{ShardError, WitnessEnvelope};
use crate::primitives::time::TrustedClock;
use crate::security::gate::IntegrityGate;
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
        for env in envelopes {
            // Apply Gate 3: Integrity verification
            let validated = env.check_integrity(local_id, &self.clock, 10)?;
            verified.push(validated);
        }
        info!(
            count = verified.len(),
            "Retrieval: Data verified via Integrity Gate"
        );
        Ok(verified)
    }
}
