use crate::FileJournal;
use crate::NodeConfig;
use async_trait::async_trait;
use phalanx_forensics::crucible::Crucible;
use phalanx_forensics::crucible::VolleyAmalgam;
use phalanx_forensics::crucible::{EnvelopeHashExt, EvidenceExt};
use phalanx_forensics::cryptography::{decrypt_bytes, encrypt_bytes};
use phalanx_forensics::gate::PromotionGate;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::Volley;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::TrustedClock;
use phalanx_proto::types::ForensicUnit;
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tracing::info;

const MAX_WAL_CHUNK_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB
const MAX_WORKBENCH_STATE_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB
const MAX_EGRESS_SALVAGE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
const AEAD_NONCE_LEN: usize = 24;

pub fn derive_vault_key(identity: &PhalanxIdentity) -> SymmetricKey {
    SymmetricKey(blake3::derive_key(
        "phalanx.vault.v1.disk-encryption",
        &identity.keypair.to_bytes(),
    ))
}

pub struct Guardian {
    pub crucible: Crucible<VolleyAmalgam>,
    pub vault_path: String,
    pub local_did: Did,
    pub clock: Arc<dyn TrustedClock>,
    pub vault_key: SymmetricKey,
}

impl Guardian {
    pub fn new(
        vault_path: &str,
        _config: &NodeConfig,
        local_did: Did,
        clock: Arc<dyn TrustedClock>,
        vault_key: SymmetricKey,
    ) -> Self {
        Self {
            crucible: Crucible::new(VolleyAmalgam, Duration::from_secs(5), 1000),
            vault_path: vault_path.to_string(),
            local_did,
            clock,
            vault_key,
        }
    }

    /// The sole entry point for data promotion into the permanent archive.
    pub async fn ingest_envelope(
        &mut self,
        state: EnvelopeState,
        current_tolerance: Duration,
    ) -> Result<(), GuardianError> {
        tracing::debug!("Guardian: Received envelope for ingestion. Verifying...");

        match state {
            EnvelopeState::Intact(envelope) => {
                let vid = envelope.evidence.volley_id().clone();
                let seq = envelope.evidence.sequence_id();
                let sender_did = envelope.witness_peer_id.clone(); // The DID we SHOULD be banning

                // Log the attempt
                tracing::info!(volley = %vid, seq = %seq.0, from = %sender_did, "Guardian: Processing frame");

                let seq = envelope.evidence.sequence_id();
                let volley_id = envelope.evidence.volley_id().clone();
                let mut anchor = None;

                if seq.0 > 1 {
                    let prev_seq = StorageSequence(seq.0 - 1);

                    // Look up the previous anchor in the vault
                    if let Some(prev_envelope) = self.get_shard(&volley_id, prev_seq) {
                        anchor = Some(prev_envelope.signature_hash());
                    }
                }

                // 1. Promotion Gate (Integrity + Continuity + Time)
                let node_id = envelope.witness_peer_id.clone();

                let unit = ForensicUnit::new(envelope);
                let absolute_max_ms = 30_000; // hard coded for now
                let dynamic_limit = (current_tolerance.as_millis() as u64).min(absolute_max_ms);

                let verified_unit = unit
                    .promote(&node_id, &*self.clock, dynamic_limit, anchor)
                    .map_err(|e| match e {
                        ShardError::InvalidConfiguration(ref msg)
                            if msg.contains("Causality Break") =>
                        {
                            GuardianError::ChainIntegrityViolation(msg.clone())
                        }
                        _ => GuardianError::VerificationFailed(e.to_string()),
                    })?;

                // 2. Volley Aggregation
                // The Crucible now accepts only Verified units
                let maybe_volley = self.crucible.process(verified_unit)?;

                if let Some(volley) = maybe_volley {
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
        self.check_and_finalize_volley(current_tolerance).await?;

        Ok(())
    }

    /// Evaluates active working contexts for TTL expiration.
    pub async fn check_and_finalize_volley(
        &mut self,
        current_tolerance: Duration,
    ) -> Result<(), GuardianError> {
        // Utilize the predefined threshold from strategies.rs logic
        let stale_volleys = self.crucible.flush_stale(current_tolerance);
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
            missing_chunks = fragmented.gap_report.missing_indices.len(),
            "Guardian: Committing forensic gap record to disk"
        );

        let gap_data = postcard::to_allocvec(&fragmented)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        let file_name = format!("{}.gap", fragmented.shard_id);
        let path = std::path::Path::new(&self.vault_path).join(file_name);

        atomic_encrypted_write(&path, &gap_data, &self.vault_key).await
    }

    /// Explicit salvage command for node termination sequences.
    pub async fn salvage(&mut self) -> Result<Vec<Volley>, GuardianError> {
        // Flush the Crucible to extract all pending reassemblies from memory
        let active_volleys = self.crucible.flush_all();

        // Early return if there's nothing to save (returns an empty Vec)
        if active_volleys.is_empty() {
            return Ok(vec![]);
        }

        // Commit each volley to the permanent silo (The 'Hands' layer)
        // We iterate by reference so we can return the collection at the end
        for volley in &active_volleys {
            self.commit_volley_to_disk(volley).await?;
        }

        // 4. Return the collection to satisfy the return type Result<Vec<Volley>, ...>
        Ok(active_volleys)
    }

    /// Non-blocking Disk Persistence
    pub async fn commit_volley_to_disk(&self, volley: &Volley) -> Result<(), GuardianError> {
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

        let data = postcard::to_allocvec(&volley)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        atomic_encrypted_write(&path, &data, &self.vault_key).await?;

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

/// Encrypt and atomically write to disk (write .tmp → rename to final path).
async fn atomic_encrypted_write(
    path: &Path,
    plaintext: &[u8],
    key: &SymmetricKey,
) -> Result<(), GuardianError> {
    let (nonce, ciphertext) = encrypt_bytes(key, plaintext)
        .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

    // On-disk format: [24-byte nonce][ciphertext + poly1305 tag]
    let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);

    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &sealed)
        .await
        .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;

    fs::rename(&tmp_path, path)
        .await
        .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))
}

/// Read and decrypt a file written by `atomic_encrypted_write`.
pub async fn read_encrypted_file(
    path: &Path,
    key: &SymmetricKey,
) -> Result<Vec<u8>, GuardianError> {
    let sealed = fs::read(path)
        .await
        .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

    if sealed.len() < AEAD_NONCE_LEN {
        return Err(GuardianError::StorageFailure(
            "File too small for AEAD frame".to_string(),
        ));
    }

    let (nonce, ciphertext) = sealed.split_at(AEAD_NONCE_LEN);
    decrypt_bytes(key, nonce, ciphertext)
        .map_err(|_| GuardianError::StorageFailure("AEAD authentication failed".to_string()))
}

#[async_trait]
impl TransientJournal for FileJournal {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError> {
        // 1. Serialize → encrypt
        let plaintext = postcard::to_allocvec(chunk)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        let (nonce, ciphertext) = encrypt_bytes(&self.vault_key, &plaintext)
            .map_err(|e| ShardError::Encryption(e.to_string()))?;

        // 2. Frame: [4-byte LE len][24-byte nonce][ciphertext]
        let frame_len = (nonce.len() + ciphertext.len()) as u32;
        self.handle
            .write_all(&frame_len.to_le_bytes())
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;
        self.handle
            .write_all(&nonce)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;
        self.handle
            .write_all(&ciphertext)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        // 3. Flush data to disk
        self.handle
            .sync_data()
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        Ok(())
    }

    async fn sync(&mut self) -> Result<(), ShardError> {
        self.handle
            .sync_all()
            .await
            .map_err(|e| ShardError::Io(e.to_string()))
    }

    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        let mut chunks = Vec::new();

        // 1. Rewind the file pointer to the beginning for boot-time recovery
        self.handle
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        // 2. Stream chunks sequentially using the 4-byte length prefix
        loop {
            let mut len_buf = [0u8; 4];
            match self.handle.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(ShardError::Io(e.to_string())),
            }

            let frame_len = u32::from_le_bytes(len_buf);

            // Bounds check: reject frames larger than 16 MiB
            if frame_len > MAX_WAL_CHUNK_BYTES {
                tracing::warn!(
                    frame_len,
                    "WAL corruption: frame exceeds 16 MiB limit, skipping"
                );
                // Attempt to seek past the corrupt frame
                match self.handle.seek(SeekFrom::Current(frame_len as i64)).await {
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }

            if (frame_len as usize) < AEAD_NONCE_LEN {
                tracing::warn!(
                    frame_len,
                    "WAL corruption: frame too small for AEAD, skipping"
                );
                match self.handle.seek(SeekFrom::Current(frame_len as i64)).await {
                    Ok(_) => continue,
                    Err(_) => break,
                }
            }

            let mut frame = vec![0u8; frame_len as usize];
            match self.handle.read_exact(&mut frame).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::warn!("WAL corruption: incomplete frame, truncating");
                    break;
                }
                Err(e) => return Err(ShardError::Io(e.to_string())),
            }

            // Split frame into [nonce][ciphertext]
            let (nonce, ciphertext) = frame.split_at(AEAD_NONCE_LEN);

            let plaintext = match decrypt_bytes(&self.vault_key, nonce, ciphertext) {
                Ok(pt) => pt,
                Err(_) => {
                    tracing::warn!("WAL corruption: AEAD authentication failed, skipping record");
                    continue;
                }
            };

            match postcard::from_bytes::<ShardChunk>(&plaintext) {
                Ok(chunk) => chunks.push(chunk),
                Err(_) => {
                    tracing::warn!("WAL corruption: deserialization failed, skipping record");
                    continue;
                }
            }
        }

        // 3. Reset the file pointer to the end to resume appending
        self.handle
            .seek(SeekFrom::End(0))
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        Ok(chunks)
    }

    async fn clear(&mut self) -> Result<(), ShardError> {
        self.handle = tokio::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(&self.file_path)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;
        Ok(())
    }

    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError> {
        let salvage_path = self.file_path.with_file_name("egress_salvage.bin");

        let plaintext = postcard::to_allocvec(pending).map_err(|e| {
            ShardError::SerializationError(format!("Salvage serialization failed: {}", e))
        })?;

        let (nonce, ciphertext) = encrypt_bytes(&self.vault_key, &plaintext)
            .map_err(|e| ShardError::Encryption(e.to_string()))?;

        let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);

        // Atomic write: tmp → rename
        let tmp_path = salvage_path.with_extension("tmp");
        tokio::fs::write(&tmp_path, &sealed)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;
        tokio::fs::rename(&tmp_path, &salvage_path)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        info!(path = ?salvage_path, "Egress Salvage: State persisted to journal");
        Ok(())
    }

    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        let salvage_path = self.file_path.with_file_name("egress_salvage.bin");
        if !salvage_path.exists() {
            return Ok(vec![]);
        }

        let sealed = tokio::fs::read(&salvage_path)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        // Bounds check
        if sealed.len() as u64 > MAX_EGRESS_SALVAGE_BYTES {
            return Err(ShardError::SerializationError(
                "Egress salvage file exceeds 64 MiB limit".to_string(),
            ));
        }

        if sealed.len() < AEAD_NONCE_LEN {
            return Err(ShardError::SerializationError(
                "Egress salvage file too small for AEAD frame".to_string(),
            ));
        }

        let (nonce, ciphertext) = sealed.split_at(AEAD_NONCE_LEN);
        let plaintext = decrypt_bytes(&self.vault_key, nonce, ciphertext)
            .map_err(|e| ShardError::Encryption(e.to_string()))?;

        let pending: Vec<PendingEgress> = postcard::from_bytes(&plaintext)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        // Cleanup after successful recovery
        let _ = tokio::fs::remove_file(salvage_path).await;

        Ok(pending)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_forensics::witness::WitnessAuthority;
    use phalanx_proto::evidence::Evidence;
    use phalanx_proto::evidence::VideoShard;
    use phalanx_proto::time::SystemClock;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_ingest_envelope_valid() {
        // 1. Setup ephemeral test environment
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let vault_path = temp_dir.path().to_string_lossy().to_string();

        let identity = PhalanxIdentity::new_ephemeral();
        let vault_key = derive_vault_key(&identity);
        let config = NodeConfig::default();
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key,
        );

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
        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(shard),
            &identity,
            NetworkId::random(),
            None,
        )
        .expect("WitnessEnvelope construction failed");

        let result = guardian
            .ingest_envelope(EnvelopeState::Intact(envelope), Duration::from_secs(1))
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

        let identity = PhalanxIdentity::new_ephemeral();
        let vault_key = derive_vault_key(&identity);
        let config = NodeConfig::default();
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key,
        );

        let shard = VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("v1"),
            payload: DataPayload::Clear(vec![1, 2, 3]),
        };

        // FIX: Add 'None' as the 4th argument (the causality link)
        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(shard),
            &identity,
            NetworkId::random(),
            None,
        )
        .expect("WitnessEnvelope construction failed");

        let result = guardian
            .ingest_envelope(EnvelopeState::Intact(envelope), Duration::from_secs(1))
            .await;

        assert!(result.is_ok());
    }
}
