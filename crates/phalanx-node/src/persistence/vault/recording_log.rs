// crates/phalanx-node/src/persistence/vault/recording_log.rs
//
// Append-only recording log: one file per recording with O(1) random access
// via in-memory index. Handles shard append, single/bulk reads, hydration,
// and index rebuild on startup.

use super::crypto::AEAD_NONCE_LEN;
use phalanx_forensics::crucible::EvidenceExt;
use phalanx_forensics::cryptography::{decrypt_bytes, encrypt_bytes};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::prelude::*;
use phalanx_proto::storage::GuardianError;
use std::collections::BTreeMap;
use std::path::PathBuf;
use tokio::fs;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};

const MAX_WAL_CHUNK_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB
/// Frame header size for recording log entries: 4-byte sequence_id + 4-byte payload_len.
const RECORDING_FRAME_HEADER_LEN: usize = 8;

/// Append-only recording log. One file per recording, mirroring the WAL pattern.
/// Stores post-reassembly WitnessEnvelopes with O(1) random access via in-memory index.
#[allow(dead_code)]
pub(super) struct RecordingLog {
    pub file: tokio::fs::File,
    /// Maps sequence_id → byte offset in the recording log file for O(1) seeks.
    pub index: BTreeMap<StorageSequence, u64>,
    pub recording_id: RecordingId,
    pub owner_did: Did,
    pub path: PathBuf,
}

// ── Guardian extension methods for recording log operations ──

use super::Guardian;

impl Guardian {
    /// Append a single shard to the recording log. Disk-first — called immediately
    /// after fountain reassembly, before any in-memory verification.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Frame arithmetic — payload sizes bounded by MTU.
    pub async fn append_shard(&mut self, envelope: &WitnessEnvelope) -> Result<(), GuardianError> {
        let recording_id = envelope.evidence.recording_id().clone();

        // Cryptographic Forgetting: reject shards for revoked recordings.
        if self.revoked_recordings.contains(&recording_id) {
            return Err(GuardianError::RecordingRevoked(recording_id.to_string()));
        }

        let sequence_id = envelope.evidence.sequence_id();
        let owner_did = envelope.did.clone();

        // Get or create the RecordingLog for this recording
        if !self.recording_logs.contains_key(&recording_id) {
            let dir_path = PathBuf::from(&self.vault_path).join(owner_did.to_safe_name());
            fs::create_dir_all(&dir_path)
                .await
                .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

            // Sanitize id for fs path. Hydration at line reconstructs RecordingId from
            // file_stem, so this is a no-op round-trip for the alphanumeric ids the FFI generates
            // today; non-alphanumeric ids would diverge from the canonical id in the envelope body.
            let file_path = dir_path.join(format!("{}.recording", recording_id.to_safe_name()));

            let file = tokio::fs::OpenOptions::new()
                .create(true)
                .read(true)
                .append(true)
                .open(&file_path)
                .await
                .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

            self.recording_logs.insert(
                recording_id.clone(),
                RecordingLog {
                    file,
                    index: BTreeMap::new(),
                    recording_id: recording_id.clone(),
                    owner_did: owner_did.clone(),
                    path: file_path,
                },
            );
        }

        // Resolve encryption key before taking mutable borrow on recording_logs
        let key = self.resolve_encryption_key(&recording_id);

        let Some(log) = self.recording_logs.get_mut(&recording_id) else {
            return Err(GuardianError::StorageFailure(
                "recording log missing after insert".to_string(),
            ));
        };

        // Record current file position as the index offset
        let offset = log
            .file
            .seek(SeekFrom::End(0))
            .await
            .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

        // Serialize → encrypt
        let plaintext = postcard::to_allocvec(envelope)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        let (nonce, ciphertext) = encrypt_bytes(&key, &plaintext)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        // Frame: [4-byte seq_id LE][4-byte payload_len LE][24-byte nonce][ciphertext]
        let payload_len = (nonce.len() + ciphertext.len()) as u32;
        log.file
            .write_all(&sequence_id.0.to_le_bytes())
            .await
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;
        log.file
            .write_all(&payload_len.to_le_bytes())
            .await
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;
        log.file
            .write_all(&nonce)
            .await
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;
        log.file
            .write_all(&ciphertext)
            .await
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;

        // Flush to disk
        log.file
            .sync_data()
            .await
            .map_err(|e| GuardianError::WalWriteFailed(e.to_string()))?;

        // Update in-memory index
        log.index.insert(sequence_id, offset);

        tracing::debug!(
            recording = %recording_id,
            seq = sequence_id.0,
            offset,
            "Recording log: shard appended"
        );

        Ok(())
    }

    /// Read a single shard from the recording log by sequence_id. O(1) via index lookup.
    ///
    /// When `owner_did` is `Some`, the caller asserts the recording belongs to that
    /// DID. The Guardian rejects the read if the actual owner does not match
    /// (defense-in-depth — the retrieval actor already verifies signatures, but the
    /// storage layer should not blindly trust its callers).
    pub async fn read_shard(
        &mut self,
        recording_id: &RecordingId,
        sequence_id: StorageSequence,
        owner_did: Option<&Did>,
    ) -> Result<WitnessEnvelope, GuardianError> {
        // Resolve decryption key before taking mutable borrow on recording_logs
        let key = self.resolve_encryption_key(recording_id);

        let log = self.recording_logs.get_mut(recording_id).ok_or_else(|| {
            GuardianError::StorageFailure(format!("No recording log for {}", recording_id))
        })?;

        // C1 FIX: Defense-in-depth ownership check at the storage layer.
        if let Some(claimed) = owner_did {
            if *claimed != log.owner_did {
                tracing::warn!(
                    target: "phalanx::guardian",
                    recording = %recording_id,
                    claimed = %claimed,
                    actual = %log.owner_did,
                    "C1: Ownership mismatch — read rejected"
                );
                return Err(GuardianError::StorageFailure(
                    "Ownership mismatch".to_string(),
                ));
            }
        }

        let &offset = log.index.get(&sequence_id).ok_or_else(|| {
            GuardianError::StorageFailure(format!(
                "Shard {} not found in recording {}",
                sequence_id.0, recording_id
            ))
        })?;

        // Seek to the frame
        log.file
            .seek(SeekFrom::Start(offset))
            .await
            .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

        // Read frame header: [4-byte seq_id][4-byte payload_len]
        let mut header = [0u8; RECORDING_FRAME_HEADER_LEN];
        log.file
            .read_exact(&mut header)
            .await
            .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

        let payload_len = u32::from_le_bytes(
            header
                .get(4..8)
                .and_then(|s| <[u8; 4]>::try_from(s).ok())
                .ok_or_else(|| GuardianError::StorageFailure("corrupt frame header".to_string()))?,
        ) as usize;

        // Read encrypted payload
        if payload_len < AEAD_NONCE_LEN {
            return Err(GuardianError::StorageFailure(
                "Recording frame too small for AEAD".to_string(),
            ));
        }
        let mut payload = vec![0u8; payload_len];
        log.file
            .read_exact(&mut payload)
            .await
            .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;
        let (nonce, ciphertext) = payload.split_at(AEAD_NONCE_LEN);
        let plaintext = decrypt_bytes(&key, nonce, ciphertext)
            .map_err(|_| GuardianError::StorageFailure("AEAD authentication failed".to_string()))?;

        // Deserialize
        postcard::from_bytes::<WitnessEnvelope>(&plaintext)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))
    }

    /// Read all shards from a recording log. Linear scan, returns sorted by sequence_id.
    ///
    /// When `owner_did` is `Some`, rejects the read if the actual recording owner
    /// does not match (C1 defense-in-depth).
    pub async fn read_all_shards(
        &mut self,
        recording_id: &RecordingId,
        owner_did: Option<&Did>,
    ) -> Result<Vec<WitnessEnvelope>, GuardianError> {
        // Resolve decryption key before taking mutable borrow on recording_logs
        let key = self.resolve_encryption_key(recording_id);

        let log = match self.recording_logs.get_mut(recording_id) {
            Some(l) => l,
            None => return Ok(vec![]),
        };

        // C1 FIX: Defense-in-depth ownership check at the storage layer.
        if let Some(claimed) = owner_did {
            if *claimed != log.owner_did {
                tracing::warn!(
                    target: "phalanx::guardian",
                    recording = %recording_id,
                    claimed = %claimed,
                    actual = %log.owner_did,
                    "C1: Ownership mismatch — bulk read rejected"
                );
                return Err(GuardianError::StorageFailure(
                    "Ownership mismatch".to_string(),
                ));
            }
        }

        log.file
            .seek(SeekFrom::Start(0))
            .await
            .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

        let mut envelopes = Vec::new();
        loop {
            let mut header = [0u8; RECORDING_FRAME_HEADER_LEN];
            match log.file.read_exact(&mut header).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(GuardianError::StorageFailure(e.to_string())),
            }

            let payload_len = u32::from_le_bytes(
                header
                    .get(4..8)
                    .and_then(|s| <[u8; 4]>::try_from(s).ok())
                    .ok_or_else(|| {
                        GuardianError::StorageFailure("corrupt frame header".to_string())
                    })?,
            ) as usize;

            if payload_len < AEAD_NONCE_LEN || payload_len > MAX_WAL_CHUNK_BYTES as usize {
                tracing::warn!(payload_len, "Recording log: corrupt frame, skipping");
                break;
            }

            let mut payload = vec![0u8; payload_len];
            match log.file.read_exact(&mut payload).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    tracing::warn!("Recording log: truncated frame at tail");
                    break;
                }
                Err(e) => return Err(GuardianError::StorageFailure(e.to_string())),
            }

            let (nonce, ciphertext) = payload.split_at(AEAD_NONCE_LEN);
            let plaintext = match decrypt_bytes(&key, nonce, ciphertext) {
                Ok(pt) => pt,
                Err(_) => {
                    tracing::warn!("Recording log: AEAD failed, skipping frame");
                    continue;
                }
            };

            match postcard::from_bytes::<WitnessEnvelope>(&plaintext) {
                Ok(env) => envelopes.push(env),
                Err(_) => {
                    tracing::warn!("Recording log: deserialization failed, skipping frame");
                    continue;
                }
            }
        }

        // Sort by sequence_id (file order may differ from sequence order)
        envelopes.sort_by_key(|e| e.evidence.sequence_id());
        Ok(envelopes)
    }

    /// List all recording IDs that have recording logs.
    pub fn list_recordings(&self) -> Vec<RecordingId> {
        self.recording_logs.keys().cloned().collect()
    }

    /// C2 FIX: Collect evidence_hash values from persisted recording logs to seed
    /// the replay filter on startup. Decrypts at most `budget_per_recording`
    /// recent frames per recording to extract real evidence_hash values.
    ///
    /// This prevents post-crash replay attacks where an adversary re-submits
    /// previously-seen evidence while the Bloom filter is empty.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)]
    pub async fn collect_recent_evidence_hashes(
        &mut self,
        budget_per_recording: usize,
    ) -> Vec<[u8; 32]> {
        let recording_ids: Vec<RecordingId> = self.recording_logs.keys().cloned().collect();
        let mut hashes = Vec::new();

        for rid in &recording_ids {
            let key = self.resolve_encryption_key(rid);
            let Some(log) = self.recording_logs.get_mut(rid) else {
                continue;
            };

            // Read the last `budget_per_recording` offsets (most recent shards).
            let offsets: Vec<u64> = log
                .index
                .values()
                .rev()
                .take(budget_per_recording)
                .copied()
                .collect();

            for offset in offsets {
                if log.file.seek(SeekFrom::Start(offset)).await.is_err() {
                    continue;
                }
                let mut header = [0u8; RECORDING_FRAME_HEADER_LEN];
                if log.file.read_exact(&mut header).await.is_err() {
                    continue;
                }
                let payload_len = u32::from_le_bytes(
                    header
                        .get(4..8)
                        .and_then(|s| <[u8; 4]>::try_from(s).ok())
                        .unwrap_or([0; 4]),
                ) as usize;
                if payload_len < AEAD_NONCE_LEN || payload_len > MAX_WAL_CHUNK_BYTES as usize {
                    continue;
                }
                let mut payload = vec![0u8; payload_len];
                if log.file.read_exact(&mut payload).await.is_err() {
                    continue;
                }
                let (nonce, ciphertext) = payload.split_at(AEAD_NONCE_LEN);
                let Ok(plaintext) = decrypt_bytes(&key, nonce, ciphertext) else {
                    continue;
                };
                if let Ok(env) = postcard::from_bytes::<WitnessEnvelope>(&plaintext) {
                    hashes.push(env.evidence_hash);
                }
            }
        }

        // Restore file positions to end for future appends.
        for log in self.recording_logs.values_mut() {
            let _ = log.file.seek(SeekFrom::End(0)).await;
        }

        hashes
    }

    /// Rebuild recording log indexes on startup by scanning vault for .recording files.
    pub async fn hydrate_recording_logs(&mut self) -> Result<(), GuardianError> {
        let vault_dir = PathBuf::from(&self.vault_path);
        if !vault_dir.exists() {
            return Ok(());
        }

        // M3 FIX: Clean up orphaned .tmp files from interrupted atomic writes.
        Self::cleanup_orphaned_tmp_files(&vault_dir).await;

        let mut dir_entries = fs::read_dir(&vault_dir)
            .await
            .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;

        while let Some(entry) = dir_entries
            .next_entry()
            .await
            .map_err(|e| GuardianError::StorageFailure(e.to_string()))?
        {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            // Scan DID subdirectory for .recording files
            let mut sub_entries = match fs::read_dir(&path).await {
                Ok(e) => e,
                Err(_) => continue,
            };

            while let Some(sub_entry) = sub_entries
                .next_entry()
                .await
                .map_err(|e| GuardianError::StorageFailure(e.to_string()))?
            {
                let file_path = sub_entry.path();
                if file_path.extension().and_then(|e| e.to_str()) != Some("recording") {
                    continue;
                }

                let recording_id_str = file_path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                let recording_id = RecordingId::new(recording_id_str);

                // Derive owner_did from directory name (best effort)
                let owner_did = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .map(Did::new)
                    .unwrap_or_default();

                let mut file = match tokio::fs::OpenOptions::new()
                    .read(true)
                    .append(true)
                    .open(&file_path)
                    .await
                {
                    Ok(f) => f,
                    Err(e) => {
                        tracing::warn!(path = ?file_path, error = %e, "Failed to open recording log");
                        continue;
                    }
                };

                // Rebuild index by scanning frames
                let index = Self::rebuild_index(&mut file, &self.vault_key).await;

                tracing::info!(
                    recording = %recording_id,
                    shards = index.len(),
                    "Hydrated recording log"
                );

                self.recording_logs.insert(
                    recording_id.clone(),
                    RecordingLog {
                        file,
                        index,
                        recording_id,
                        owner_did,
                        path: file_path,
                    },
                );
            }
        }
        Ok(())
    }

    /// M3 FIX: Remove orphaned `.tmp` files left by interrupted atomic writes.
    /// Scans the vault root and all DID subdirectories.
    async fn cleanup_orphaned_tmp_files(vault_dir: &std::path::Path) {
        let mut cleaned = 0u32;
        let Ok(mut entries) = fs::read_dir(vault_dir).await else {
            return;
        };
        while let Ok(Some(entry)) = entries.next_entry().await {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                if fs::remove_file(&path).await.is_ok() {
                    cleaned = cleaned.saturating_add(1);
                }
            } else if path.is_dir() {
                // Recurse into DID subdirectories (one level only).
                let Ok(mut sub) = fs::read_dir(&path).await else {
                    continue;
                };
                while let Ok(Some(sub_entry)) = sub.next_entry().await {
                    let sub_path = sub_entry.path();
                    if sub_path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                        if fs::remove_file(&sub_path).await.is_ok() {
                            cleaned = cleaned.saturating_add(1);
                        }
                    }
                }
            }
        }
        if cleaned > 0 {
            tracing::info!(count = cleaned, "M3: Cleaned up orphaned .tmp files");
        }
    }

    /// Rebuild the in-memory index from a recording log file. Tolerates corrupt tail frames.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // File offset arithmetic — payload_len read from frame header.
    async fn rebuild_index(
        file: &mut tokio::fs::File,
        _vault_key: &SymmetricKey,
    ) -> BTreeMap<StorageSequence, u64> {
        let mut index = BTreeMap::new();
        let _ = file.seek(SeekFrom::Start(0)).await;

        while let Ok(offset) = file.stream_position().await {
            let mut header = [0u8; RECORDING_FRAME_HEADER_LEN];
            if file.read_exact(&mut header).await.is_err() {
                break;
            }

            let sequence_id = StorageSequence(u32::from_le_bytes(
                header[0..4].try_into().unwrap_or([0; 4]),
            ));
            let payload_len = u32::from_le_bytes(header[4..8].try_into().unwrap_or([0; 4]));

            if payload_len < AEAD_NONCE_LEN as u32 || payload_len > MAX_WAL_CHUNK_BYTES {
                break;
            }

            // Skip payload without full decrypt for speed during index rebuild
            if file
                .seek(SeekFrom::Current(payload_len as i64))
                .await
                .is_err()
            {
                break;
            }

            index.insert(sequence_id, offset);
        }

        // Reset to end for future appends
        let _ = file.seek(SeekFrom::End(0)).await;
        index
    }
}
