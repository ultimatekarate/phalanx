use phalanx_forensics::crucible::Crucible;
use phalanx_forensics::crucible::VolleyAmalgam;
use phalanx_proto::prelude::*;
use phalanx_proto::storage::GuardianError;
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::fs;
use tracing::{debug, info, instrument, warn};

pub struct Guardian {
    pub crucible: Crucible<VolleyAmalgam>,
    pub vault_path: String,
    pub local_did: Did,
}

impl Guardian {
    pub fn new(vault_path: &str, _config: &PhalanxConfig, local_did: Did) -> Self {
        Self {
            crucible: Crucible::new(VolleyAmalgam, Duration::from_secs(5)),
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

                let seq = envelope.evidence.sequence_id();
                let volley_id = envelope.evidence.volley_id();

                if seq.0 > 1 {
                    let prev_seq = StorageSequence(seq.0 - 1);

                    // Look up the previous anchor in the vault
                    if let Some(prev_envelope) = self.get_shard(volley_id, prev_seq) {
                        let actual_hash = prev_envelope.signature_hash();

                        // Verify the cryptographic link
                        if envelope.prev_hash != Some(actual_hash) {
                            tracing::error!(
                                "TIMELINE HIJACK DETECTED: Volley {} Seq {} points to invalid hash.",
                                volley_id, seq.0
                            );
                            return Err(GuardianError::ChainIntegrityViolation);
                        }
                    } else {
                        // OPTIONAL: Strict Contiguous Check
                        // If you want to reject sequence 2 if sequence 1 isn't here yet:
                        // return Err(GuardianError::MissingCausalityAnchor);
                    }
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

    pub fn get_shard(
        &self,
        volley_id: &VolleyId,
        sequence_id: StorageSequence,
    ) -> Option<WitnessEnvelope> {
        // We leverage the Crucible's active contexts directly
        self.get_active_volley_shards(volley_id)
            .and_then(|shards| shards.get(&sequence_id))
            .cloned()
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
    pub async fn salvage(&mut self) -> Result<(), GuardianError> {
        let active_volleys = self.crucible.flush_all();

        if active_volleys.is_empty() {
            return Ok(());
        }

        for volley in active_volleys {
            self.commit_volley_to_disk(&volley).await?;
        }
        Ok(())
    }

    /// Non-blocking Disk Persistence
    pub async fn commit_volley_to_disk(&self, volley: &Volley) -> Result<(), GuardianError> {
        // FIX: Standardize on .volley extension across the entire crate
        let file_name = format!("{}.volley", volley.id);
        let path = std::path::PathBuf::from(&self.vault_path)
            .join(volley.owner_did.to_safe_name())
            .join(file_name);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;
        }

        let data = postcard::to_stdvec(&volley)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        fs::write(&path, data)
            .await
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;

        info!(path = ?path, "DISK_WRITE_SUCCESS: Volley committed");
        Ok(())
    }

    pub fn get_active_volley_shards(
        &self,
        volley_id: &VolleyId, // 1. FIX: Use the specific stream ID, not the person
    ) -> Option<&BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.crucible
            .contexts // 2. FIX: Crucible doesn't have .get(), its BTreeMap is 'contexts'
            .get(volley_id) // 3. FIX: No more .to_string()!
            .map(|ctx| &ctx.accumulator.artifacts) // 4. FIX: Access through WorkContext wrapper
    }
}

#[async_trait]
impl TransientJournal for FileJournal {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError> {
        // 1. Serialize and explicitly map the postcard::Error to a String
        let payload = postcard::to_allocvec(chunk)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        // 2. Prepare length-prefix (4-byte unsigned little-endian)
        let payload_length = payload.len() as u32;
        let length_bytes = payload_length.to_le_bytes();

        // 3. Write framing length, then payload
        self.handle
            .write_all(&length_bytes)
            .await
            .map_err(ShardError::Io)?;
        self.handle
            .write_all(&payload)
            .await
            .map_err(ShardError::Io)?;

        // 4. Flush data to disk (excluding metadata for performance)
        self.handle.sync_data().await.map_err(ShardError::Io)?;

        Ok(())
    }

    async fn sync(&mut self) -> Result<(), ShardError> {
        self.handle.sync_all().await.map_err(ShardError::Io)
    }

    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        let mut chunks = Vec::new();

        // 1. Rewind the file pointer to the beginning for boot-time recovery
        self.handle
            .seek(SeekFrom::Start(0))
            .await
            .map_err(ShardError::Io)?;

        // 2. Stream chunks sequentially using the 4-byte length prefix
        loop {
            let mut len_buf = [0u8; 4];
            match self.handle.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break, // Deterministic EOF
                Err(e) => return Err(ShardError::Io(e)),
            }

            let payload_len = u32::from_le_bytes(len_buf);
            let mut payload = vec![0u8; payload_len as usize];

            match self.handle.read_exact(&mut payload).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::warn!(
                        "WAL corruption detected: Incomplete payload. Truncating remainder."
                    );
                    break;
                }
                Err(e) => return Err(ShardError::Io(e)),
            }

            if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&payload) {
                chunks.push(chunk);
            } else {
                tracing::warn!("WAL corruption detected: Failed to deserialize payload.");
                break;
            }
        }

        // 3. Reset the file pointer to the end to resume appending
        self.handle
            .seek(SeekFrom::End(0))
            .await
            .map_err(ShardError::Io)?;

        Ok(chunks)
    }

    async fn clear(&mut self) -> Result<(), ShardError> {
        self.handle = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.file_path)
            .await
            .map_err(ShardError::Io)?;
        Ok(())
    }

    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError> {
        let salvage_path = self.file_path.with_file_name("egress_salvage.bin");

        let encoded = postcard::to_allocvec(pending).map_err(|e| {
            ShardError::SerializationError(format!("Salvage serialization failed: {}", e))
        })?;

        tokio::fs::write(&salvage_path, encoded)
            .await
            .map_err(ShardError::Io)?;

        info!(path = ?salvage_path, "Egress Salvage: State persisted to journal");
        Ok(())
    }

    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        let salvage_path = self.file_path.with_file_name("egress_salvage.bin");
        if !salvage_path.exists() {
            return Ok(vec![]);
        }

        let encoded = tokio::fs::read(&salvage_path)
            .await
            .map_err(ShardError::Io)?;

        let pending: Vec<PendingEgress> = postcard::from_bytes(&encoded).map_err(|_| {
            ShardError::Encryption(crate::security::e2ee::CryptoError::DecryptionFailure)
        })?;

        // Cleanup after recovery to prevent replay of the same retry state
        let _ = tokio::fs::remove_file(salvage_path).await;

        Ok(pending)
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

        // Define a specific VolleyId for this stream
        let vid = VolleyId::new("v1");

        let shard = VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: vid.clone(), // Use the VolleyId here
            payload: DataPayload::Clear(vec![1, 2, 3]),
        };

        // 2. Seal the unit (The 4th argument is None for the start of the chain)
        let envelope =
            WitnessEnvelope::new(Evidence::Video(shard), &identity, NetworkId::random(), None)
                .expect("WitnessEnvelope construction failed");

        let result = guardian
            .ingest_envelope(EnvelopeState::Intact(envelope))
            .await;
        assert!(result.is_ok(), "Ingestion failed: {:?}", result.err());

        // 3. FIX: Verify Crucible state mutation using the VolleyId, NOT the Did
        let active_shards = guardian.get_active_volley_shards(&vid);

        assert!(
            active_shards.is_some(),
            "Crucible should contain an active volley buffer for this VolleyId"
        );

        let shards_map = active_shards.unwrap();
        assert!(
            shards_map.contains_key(&StorageSequence(1)),
            "Volley buffer should contain the ingested sequence ID"
        );
    }

    #[tokio::test]
    async fn test_guardian_ingestion_cycle() {
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

        // FIX: Add 'None' as the 4th argument (the causality link)
        let envelope = WitnessEnvelope::new(
            Evidence::Video(shard),
            &identity,
            NetworkId::random(),
            None, // Start of causality chain
        )
        .expect("WitnessEnvelope construction failed");

        let result = guardian
            .ingest_envelope(EnvelopeState::Intact(envelope))
            .await;

        assert!(result.is_ok());
    }
}
