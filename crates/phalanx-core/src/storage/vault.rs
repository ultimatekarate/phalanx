use std::collections::BTreeMap;
use tracing::{instrument, warn};

use crate::base::config::PhalanxConfig;
use crate::base::types::ByteCapacity;
use crate::primitives::identity::Did;
use crate::primitives::shards::{StorageSequence, WitnessEnvelope};
use crate::primitives::time::TimeError;
use crate::storage::crucible::Crucible;
use crate::storage::strategies::VolleyAmalgam;

#[derive(Debug, thiserror::Error)]
pub enum GuardianError {
    #[error("Quota exceeded: {0:?}")]
    QuotaExceeded(ByteCapacity),

    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    #[error("Replay attack detected: Sequence {0} is too old")]
    ReplayDetected(u64),

    #[error("WAL write failed: {0}")]
    WalWriteFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Time synchronization failure: {0}")]
    TimeSource(#[from] TimeError),

    #[error("Attack attempt blocked: Peer {0} is blacklisted")]
    BlacklistedPeer(String),

    #[error("Cryptographic verification failed: {0}")]
    VerificationFailed(String),

    #[error("Crucible commit failed: {0}")]
    CrucibleError(String),
}

pub struct Guardian {
    pub crucible: Crucible<VolleyAmalgam>,
    pub active_volleys: BTreeMap<Did, BTreeMap<StorageSequence, WitnessEnvelope>>,
    pub local_did: Did,
}

impl Guardian {
    pub fn new(_vault_path: &str, _config: &PhalanxConfig, local_did: Did) -> Self {
        Self {
            crucible: Crucible::new(),
            active_volleys: BTreeMap::new(),
            local_did,
        }
    }

    /// The sole entry point for data promotion into the permanent archive.
    /// This enforces the Sentinel/Guardian split by requiring matured envelopes.
    #[instrument(skip(self, envelope), fields(owner = %envelope.did))]
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) -> Result<(), GuardianError> {
        // 1. Mandatory Forensic Validation
        if !envelope.verify() {
            return Err(GuardianError::VerificationFailed(
                "Signature invalid".into(),
            ));
        }

        let owner = envelope.did.clone();
        let sequence = envelope.evidence.sequence_id();

        // 2. Promotion to Active Volley
        let user_vault = self
            .active_volleys
            .entry(owner)
            .or_default();

        user_vault.insert(sequence, envelope.clone());

        // 3. Optional: Trigger Crucible Commit
        self.check_and_finalize_volley(&envelope.did)?;

        Ok(())
    }

    fn check_and_finalize_volley(&mut self, _did: &Did) -> Result<(), GuardianError> {
        // Implementation for batch-committing envelopes to long-term storage
        Ok(())
    }

    pub fn get_active_volley_shards(
        &self,
        did: &Did,
    ) -> Option<&BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.active_volleys.get(did)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::identity::{NetworkId, PhalanxIdentity};
    use crate::primitives::shards::{DataPayload, Evidence, StorageSequence, VideoShard, VolleyId};
    use crate::primitives::time::PhalanxTimestamp;

    #[test]
    fn test_ingest_envelope_valid() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let config = PhalanxConfig::default();
        let mut guardian = Guardian::new("test_vault", &config, identity.did.clone());

        let shard = VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("v1"),
            payload: DataPayload::Clear(vec![1, 2, 3]),
        };

        let envelope =
            WitnessEnvelope::new(Evidence::Video(shard), &identity, NetworkId::random()).unwrap();

        assert!(guardian.ingest_envelope(envelope).is_ok());
        assert!(guardian.active_volleys.contains_key(&identity.did));
    }
}
