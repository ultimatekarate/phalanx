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
use phalanx_proto::types::ByteCapacity;
use phalanx_proto::types::ForensicUnit;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tracing::info;
use zeroize::Zeroizing;
const MAX_WAL_CHUNK_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB
const _MAX_WORKBENCH_STATE_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB
const MAX_EGRESS_SALVAGE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
/// P2 FIX: Maximum aggregate WAL size before rejecting new writes.
/// Prevents unbounded WAL growth that could exhaust disk space.
const MAX_WAL_AGGREGATE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB
const AEAD_NONCE_LEN: usize = 24;

/// M7 FIX: Vault key derivation now includes a random 32-byte salt.
/// This ensures that identity key compromise does not directly yield the vault key.
/// The salt is stored unencrypted in a `.vault_salt` file next to the vault directory.
pub fn derive_vault_key(identity: &PhalanxIdentity, salt: &[u8; 32]) -> SymmetricKey {
    let key_bytes = Zeroizing::new(identity.keypair.to_bytes());
    // Concatenate domain separator with salt for the BLAKE3 derivation context
    let mut context_input = Vec::with_capacity(key_bytes.len() + salt.len());
    context_input.extend_from_slice(&*key_bytes);
    context_input.extend_from_slice(salt);
    SymmetricKey(blake3::derive_key(
        "phalanx.vault.v1.disk-encryption",
        &context_input,
    ))
}

/// Load or create the vault salt file. Generated once with OsRng on first vault creation.
pub fn load_or_create_vault_salt(vault_path: &str) -> std::io::Result<[u8; 32]> {
    let salt_path = std::path::Path::new(vault_path).join(".vault_salt");
    if salt_path.exists() {
        let bytes = std::fs::read(&salt_path)?;
        if bytes.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Vault salt file is not 32 bytes",
            ));
        }
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&bytes);
        Ok(salt)
    } else {
        use rand_core::{OsRng, RngCore};
        let mut salt = [0u8; 32];
        OsRng.fill_bytes(&mut salt);
        // Ensure parent directory exists
        if let Some(parent) = salt_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&salt_path, salt)?;
        Ok(salt)
    }
}

/// Per-node storage accounting. Distinguishes own evidence from foreign
/// (relay/replica) data to support fair contribution tracking and eviction policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageLedger {
    /// Bytes of MY evidence stored in the local vault.
    pub own_bytes: ByteCapacity,
    /// Foreign shards I'm a K-replica for (long-term committed storage).
    pub foreign_committed_bytes: ByteCapacity,
    /// Foreign shards in the relay buffer (transient, evictable).
    pub foreign_transient_bytes: ByteCapacity,
    /// Cumulative bytes of my evidence pushed to the mesh.
    pub own_bytes_pushed: ByteCapacity,
}

impl StorageLedger {
    /// Total foreign bytes (committed + transient).
    pub fn total_foreign_bytes(&self) -> u64 {
        self.foreign_committed_bytes.as_u64() + self.foreign_transient_bytes.as_u64()
    }

    /// Total bytes held locally (own + all foreign).
    pub fn total_local_bytes(&self) -> u64 {
        self.own_bytes.as_u64() + self.total_foreign_bytes()
    }

    /// Record ingestion of own evidence.
    pub fn record_own_ingestion(&mut self, bytes: u64) {
        self.own_bytes = ByteCapacity(self.own_bytes.as_u64() + bytes);
    }

    /// Record ingestion of foreign evidence (transient until promoted to committed).
    pub fn record_foreign_ingestion(&mut self, bytes: u64) {
        self.foreign_transient_bytes = ByteCapacity(self.foreign_transient_bytes.as_u64() + bytes);
    }

    /// Promote transient foreign storage to committed (K-replica confirmed).
    pub fn promote_to_committed(&mut self, bytes: u64) {
        let moved = bytes.min(self.foreign_transient_bytes.as_u64());
        self.foreign_transient_bytes =
            ByteCapacity(self.foreign_transient_bytes.as_u64().saturating_sub(moved));
        self.foreign_committed_bytes = ByteCapacity(self.foreign_committed_bytes.as_u64() + moved);
    }

    /// Record bytes of own evidence successfully pushed to the mesh.
    pub fn record_own_push(&mut self, bytes: u64) {
        self.own_bytes_pushed = ByteCapacity(self.own_bytes_pushed.as_u64() + bytes);
    }

    /// Evict foreign transient bytes (e.g., relay buffer cleanup).
    pub fn evict_transient(&mut self, bytes: u64) {
        self.foreign_transient_bytes =
            ByteCapacity(self.foreign_transient_bytes.as_u64().saturating_sub(bytes));
    }
}

pub struct Guardian {
    pub crucible: Crucible<VolleyAmalgam>,
    pub vault_path: String,
    pub local_did: Did,
    pub clock: Arc<dyn TrustedClock>,
    pub vault_key: SymmetricKey,
    /// Per-node storage accounting for fairness and eviction policy.
    pub ledger: StorageLedger,
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
            ledger: StorageLedger::default(),
        }
    }

    /// The sole entry point for data promotion into the permanent archive.
    pub async fn ingest_envelope(
        &mut self,
        state: EnvelopeState,
        current_tolerance: Duration,
    ) -> Result<(), GuardianError> {
        tracing::debug!("Guardian: Received envelope for ingestion. Verifying...");

        let EnvelopeState::Intact(envelope) = state;
        let vid = envelope.evidence.volley_id().clone();
        let seq = envelope.evidence.sequence_id();
        let sender_did = envelope.witness_peer_id.clone();

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

        // Promotion Gate (Integrity + Continuity + Time)
        let node_id = envelope.witness_peer_id.clone();

        let unit = ForensicUnit::new(envelope);
        // T4 FIX: Pass Duration directly instead of raw u64.
        // Clamp dynamic tolerance to an absolute max of 30 seconds.
        let max_tolerance = Duration::from_secs(30);
        let clamped_tolerance = current_tolerance.min(max_tolerance);

        let verified_unit = unit
            .promote(&node_id, &*self.clock, clamped_tolerance, anchor)
            .map_err(|e| match e {
                ShardError::InvalidConfiguration(ref msg) if msg.contains("Causality Break") => {
                    GuardianError::ChainIntegrityViolation(msg.clone())
                }
                _ => GuardianError::VerificationFailed(e.to_string()),
            })?;

        // Volley Aggregation
        // The Crucible now accepts only Verified units
        let maybe_volley = self.crucible.process(verified_unit)?;

        if let Some(volley) = maybe_volley {
            self.commit_volley_to_disk(&volley).await?;
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

        // Return the collection to satisfy the return type Result<Vec<Volley>, ...>
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

    /// Estimates the total bytes held across all active volley contexts in the crucible.
    /// Used by the StorageActor to feed WAL/storage pressure into the integral loop.
    pub fn wal_bytes_estimate(&self) -> u64 {
        // Conservative per-envelope estimate: signature (64) + evidence (~4KB avg) + metadata
        const AVG_ENVELOPE_BYTES: u64 = 4096;
        self.crucible
            .contexts
            .values()
            .map(|ctx| ctx.accumulator.artifacts.len() as u64 * AVG_ENVELOPE_BYTES)
            .sum()
    }

    pub fn get_active_volley_shards(
        &self,
        volley_id: &VolleyId,
    ) -> Option<&BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.crucible
            .contexts // FIX: Crucible doesn't have .get(), its BTreeMap is 'contexts'
            .get(volley_id) // FIX: No more .to_string()!
            .map(|ctx| &ctx.accumulator.artifacts) // FIX: Access through WorkContext wrapper
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
        // P2 FIX: Check aggregate WAL size before writing.
        // Prevents unbounded WAL growth from sustained high-volume ingestion.
        let current_wal_size = self.handle.metadata().await.map(|m| m.len()).unwrap_or(0);
        if current_wal_size >= MAX_WAL_AGGREGATE_BYTES {
            tracing::warn!(
                wal_size = current_wal_size,
                limit = MAX_WAL_AGGREGATE_BYTES,
                "P2: WAL aggregate size limit reached, rejecting write"
            );
            return Err(ShardError::Io(
                "WAL aggregate size limit exceeded".to_string(),
            ));
        }

        // Serialize → encrypt
        let plaintext = postcard::to_allocvec(chunk)
            .map_err(|e| ShardError::SerializationError(e.to_string()))?;

        let (nonce, ciphertext) = encrypt_bytes(&self.vault_key, &plaintext)
            .map_err(|e| ShardError::Encryption(e.to_string()))?;

        // Frame: [4-byte LE len][24-byte nonce][ciphertext]
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

        // Flush data to disk
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

        // Rewind the file pointer to the beginning for boot-time recovery
        self.handle
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;

        // Stream chunks sequentially using the 4-byte length prefix
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

        // Reset the file pointer to the end to resume appending
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
    use phalanx_proto::evidence::ForensicMetrics;
    use phalanx_proto::evidence::VideoShard;
    use phalanx_proto::time::SystemClock;
    use phalanx_proto::types::Fps;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_ingest_envelope_valid() {
        // 1. Setup ephemeral test environment
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let vault_path = temp_dir.path().to_string_lossy().to_string();

        let identity = PhalanxIdentity::new_ephemeral();
        let vault_key = derive_vault_key(&identity, &[0u8; 32]);
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
            fps: Fps::new(30),
            volley_id: vid.clone(), // Use the VolleyId here
            payload: DataPayload::Clear(vec![1, 2, 3]),
            lens_metrics: ForensicMetrics::default(),
        };

        // Seal the unit (The 4th argument is None for the start of the chain)
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

        // FIX: Verify Crucible state mutation using the VolleyId, NOT the Did
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
        let vault_key = derive_vault_key(&identity, &[0u8; 32]);
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
            fps: Fps::new(30),
            volley_id: VolleyId::new("v1"),
            payload: DataPayload::Clear(vec![1, 2, 3]),
            lens_metrics: ForensicMetrics::default(),
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

    // ── StorageLedger Tests ──

    #[test]
    fn test_storage_ledger_defaults_to_zero() {
        let ledger = StorageLedger::default();
        assert_eq!(ledger.own_bytes.as_u64(), 0);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 0);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 0);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 0);
        assert_eq!(ledger.total_foreign_bytes(), 0);
        assert_eq!(ledger.total_local_bytes(), 0);
    }

    #[test]
    fn test_storage_ledger_own_ingestion_tracking() {
        let mut ledger = StorageLedger::default();
        ledger.record_own_ingestion(1000);
        assert_eq!(ledger.own_bytes.as_u64(), 1000);
        assert_eq!(ledger.total_local_bytes(), 1000);

        ledger.record_own_ingestion(500);
        assert_eq!(ledger.own_bytes.as_u64(), 1500);
        assert_eq!(
            ledger.total_foreign_bytes(),
            0,
            "Foreign should be unaffected"
        );
    }

    #[test]
    fn test_storage_ledger_foreign_ingestion_is_transient() {
        let mut ledger = StorageLedger::default();
        ledger.record_foreign_ingestion(2000);

        // Foreign ingestion lands in transient first
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 2000);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 0);
        assert_eq!(ledger.total_foreign_bytes(), 2000);
        assert_eq!(ledger.total_local_bytes(), 2000);
    }

    #[test]
    fn test_storage_ledger_promote_transient_to_committed() {
        let mut ledger = StorageLedger::default();
        ledger.record_foreign_ingestion(3000);

        // Promote 1000 bytes to committed (K-replica confirmed)
        ledger.promote_to_committed(1000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 2000);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 1000);
        assert_eq!(
            ledger.total_foreign_bytes(),
            3000,
            "Total foreign unchanged"
        );

        // Promote more than available transient — clamped to available
        ledger.promote_to_committed(5000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 0);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 3000);
    }

    #[test]
    fn test_storage_ledger_own_push_tracking() {
        let mut ledger = StorageLedger::default();
        ledger.record_own_push(500);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 500);
        ledger.record_own_push(300);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 800);
    }

    #[test]
    fn test_storage_ledger_evict_transient() {
        let mut ledger = StorageLedger::default();
        ledger.record_foreign_ingestion(5000);

        ledger.evict_transient(2000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 3000);

        // Evict more than available — saturating subtraction, no underflow
        ledger.evict_transient(10000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 0);
    }

    #[test]
    fn test_storage_ledger_combined_accounting() {
        let mut ledger = StorageLedger::default();

        // Simulate a node that stores own evidence and hosts foreign replicas
        ledger.record_own_ingestion(10_000);
        ledger.record_foreign_ingestion(8_000);
        ledger.promote_to_committed(3_000); // 3K committed, 5K transient
        ledger.record_own_push(6_000);

        assert_eq!(ledger.own_bytes.as_u64(), 10_000);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 3_000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 5_000);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 6_000);
        assert_eq!(ledger.total_foreign_bytes(), 8_000);
        assert_eq!(ledger.total_local_bytes(), 18_000);

        // Evict transient relay buffer
        ledger.evict_transient(5_000);
        assert_eq!(ledger.total_foreign_bytes(), 3_000);
        assert_eq!(ledger.total_local_bytes(), 13_000);
    }
}
