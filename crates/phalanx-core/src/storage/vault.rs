use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;
use tracing::{info, instrument};

use crate::base::config::PhalanxConfig;
use crate::base::types::ByteCapacity;
use crate::primitives::identity::Did;
use crate::primitives::shards::{StorageSequence, Volley, WitnessEnvelope};
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
    pub vault_path: String,
    pub local_did: Did,
}

impl Guardian {
    pub fn new(vault_path: &str, _config: &PhalanxConfig, local_did: Did) -> Self {
        Self {
            crucible: Crucible::new(),
            vault_path: vault_path.to_string(),
            local_did,
        }
    }

    /// The sole entry point for data promotion into the permanent archive.
    #[instrument(skip(self, envelope), fields(owner = %envelope.did))]
    pub fn ingest_envelope(&mut self, envelope: WitnessEnvelope) -> Result<(), GuardianError> {
        // 1. Mandatory Forensic Validation
        if !envelope.verify() {
            return Err(GuardianError::VerificationFailed(
                "Signature invalid".into(),
            ));
        }

        // 2. Promotion to Active Volley via Crucible
        if let Some(volley) = self.crucible.process(envelope) {
            self.commit_volley_to_disk(&volley)?;
        }

        // 3. Trigger standard TTL evaluation
        self.check_and_finalize_volley()?;

        Ok(())
    }

    /// Evaluates active working contexts for TTL expiration.
    pub fn check_and_finalize_volley(&mut self) -> Result<(), GuardianError> {
        // Utilize the predefined threshold from strategies.rs logic
        let stale_volleys = self.crucible.flush_stale(Duration::from_secs(1));
        for volley in stale_volleys {
            self.commit_volley_to_disk(&volley)?;
        }
        Ok(())
    }

    /// Explicit salvage command for node termination sequences.
    pub fn force_salvage_all(&mut self) -> Result<(), GuardianError> {
        let active_volleys = self.crucible.flush_all();
        for volley in active_volleys {
            self.commit_volley_to_disk(&volley)?;
        }
        Ok(())
    }

    fn commit_volley_to_disk(&self, volley: &Volley) -> Result<(), GuardianError> {
        let serialized_volley = postcard::to_stdvec(volley)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        let mut path = PathBuf::from(&self.vault_path);
        path.push(volley.owner_did.to_safe_name());

        std::fs::create_dir_all(&path).map_err(|e| {
            GuardianError::WalWriteFailed(format!("Directory creation failed: {}", e))
        })?;

        path.push(format!("{}.phlx", volley.id.as_str()));

        std::fs::write(&path, serialized_volley).map_err(|e| {
            GuardianError::WalWriteFailed(format!("Archive disk write failed: {}", e))
        })?;

        info!(path = ?path, "Volley archived successfully");
        Ok(())
    }

    pub fn get_active_volley_shards(
        &self,
        did: &Did,
    ) -> Option<&BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.crucible
            .get(&did.to_string())
            .map(|buffer| &buffer.artifacts)
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

        // 1. Verify successful ingestion routing
        assert!(guardian.ingest_envelope(envelope).is_ok());

        // 2. Verify Crucible state mutation via public API
        let active_shards = guardian.get_active_volley_shards(&identity.did);
        assert!(
            active_shards.is_some(),
            "Crucible should contain an active volley buffer for this DID"
        );
        assert!(
            active_shards.unwrap().contains_key(&StorageSequence(1)),
            "Volley buffer should contain the ingested sequence ID"
        );
    }
}
