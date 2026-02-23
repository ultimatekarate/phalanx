use std::collections::BTreeMap;
use std::time::Duration;

use crate::base::config::PhalanxConfig;
use crate::base::types::ByteCapacity;
use crate::primitives::identity::Did;
use crate::primitives::shards::{
    EnvelopeState, FragmentedEnvelope, StorageSequence, Volley, WitnessEnvelope,
};
use crate::primitives::time::TimeError;
use crate::storage::crucible::Crucible;
use crate::storage::strategies::VolleyAmalgam;
use tokio::fs;

use tracing;

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
    pub async fn ingest_envelope(&mut self, state: EnvelopeState) -> Result<(), GuardianError> {
        tracing::debug!("Guardian: Received envelope for ingestion. Verifying...");

        match state {
            EnvelopeState::Intact(envelope) => {
                // 1. Cryptographic Verification
                if !envelope.verify() {
                    return Err(GuardianError::VerificationFailed(
                        "Witness signature mismatch".into(),
                    ));
                }

                // 2. Volley Aggregation
                // The Crucible (bound to VolleyAmalgam) handles sequence-ordering
                if let Some(volley) = self.crucible.process(envelope) {
                    self.commit_volley_to_disk(&volley).await?;
                }
            }
            EnvelopeState::Fragmented(fragmented) => {
                // 3. Forensic Gap Archival
                // We persist the gap report to ensure the timeline remains continuous
                self.archive_fragmented_shard(fragmented).await?;
            }
        }

        // Trigger TTL checks, stale volley flushing, and workbench cleanup
        self.check_and_finalize_volley().await?;

        Ok(())
    }

    /// Evaluates active working contexts for TTL expiration.
    pub async fn check_and_finalize_volley(&mut self) -> Result<(), GuardianError> {
        // Utilize the predefined threshold from strategies.rs logic
        let stale_volleys = self.crucible.flush_stale(Duration::from_secs(1));
        for volley in stale_volleys {
            self.commit_volley_to_disk(&volley).await?;
        }
        Ok(())
    }

    async fn archive_fragmented_shard(
        &mut self,
        fragmented: FragmentedEnvelope,
    ) -> Result<(), GuardianError> {
        tracing::warn!(
            shard_id = %fragmented.shard_id,
            missing_chunks = fragmented.gap_report.missing_chunk_indices.len(),
            "Guardian: Committing forensic gap record to disk"
        );

        // Serialize the FragmentedEnvelope as a proof of absence
        let gap_data = postcard::to_stdvec(&fragmented)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        let file_name = format!("{}.gap", fragmented.shard_id);
        let path = std::path::Path::new(&self.vault_path).join(file_name);

        fs::write(path, gap_data)
            .await
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))
    }

    /// Explicit salvage command for node termination sequences.
    pub async fn force_salvage_all(&mut self) -> Result<(), GuardianError> {
        let active_volleys = self.crucible.flush_all();
        for volley in active_volleys {
            self.commit_volley_to_disk(&volley).await?;
        }
        Ok(())
    }

    /// Non-blocking Disk Persistence
    async fn commit_volley_to_disk(&self, volley: &Volley) -> Result<(), GuardianError> {
        let mut path = std::path::PathBuf::from(&self.vault_path);

        // FORENSIC PROTOCOL: Use sanitized safe names for filesystem compatibility
        let peer_dir_name = volley.owner_did.to_safe_name();

        // Idempotency check: If the vault_path already ends with the peer's directory,
        // do not append it again. This handles harness-injected paths.
        if !path.ends_with(&peer_dir_name) {
            path.push(&peer_dir_name);
        }

        tracing::info!(target: "phalanx::forensics", resolved_path = ?path, "DISK_COMMIT_START");

        if let Err(e) = fs::create_dir_all(&path).await {
            tracing::error!(target: "phalanx::forensics", error = %e, "DIR_CREATION_FAILED");
            return Err(GuardianError::WalWriteFailed(e.to_string()));
        }

        let file_name = format!("{}.vid.phlx", volley.id.as_str());
        path.push(file_name);

        let bytes = postcard::to_stdvec(volley)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        // Perform non-blocking write
        fs::write(&path, &bytes).await.map_err(|e| {
            tracing::error!(target: "phalanx::forensics", error = %e, "WRITE_FAILED");
            GuardianError::WalWriteFailed(e.to_string())
        })?;

        tracing::info!(target: "phalanx::forensics", file = ?path, "DISK_WRITE_SUCCESS");
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
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_ingest_envelope_valid() {
        // 1. Setup ephemeral test environment
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let vault_path = temp_dir.path().to_string_lossy().to_string();

        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let config = PhalanxConfig::default();
        let mut guardian = Guardian::new(&vault_path, &config, identity.did.clone());

        let shard = VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("v1"),
            payload: DataPayload::Clear(vec![1, 2, 3]),
        };

        let envelope = WitnessEnvelope::new(Evidence::Video(shard), &identity, NetworkId::random())
            .expect("WitnessEnvelope construction failed");

        let result = guardian
            .ingest_envelope(EnvelopeState::Intact(envelope))
            .await;
        assert!(result.is_ok(), "Ingestion failed: {:?}", result.err());

        // 3. Verify Crucible state mutation via public API
        let active_shards = guardian.get_active_volley_shards(&identity.did);

        assert!(
            active_shards.is_some(),
            "Crucible should contain an active volley buffer for this DID"
        );

        let shards_map = active_shards.unwrap();
        assert!(
            shards_map.contains_key(&StorageSequence(1)),
            "Volley buffer should contain the ingested sequence ID"
        );
    }
}
