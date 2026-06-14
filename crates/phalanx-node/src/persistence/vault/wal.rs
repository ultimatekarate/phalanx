// crates/phalanx-node/src/persistence/vault/wal.rs
//
// FileJournal's TransientJournal implementation: WAL chunk I/O,
// egress salvage, workbench state, and revocation persistence.

use super::crypto::{AEAD_NONCE_LEN, atomic_encrypted_write, read_encrypted_file};
use crate::FileJournal;
use async_trait::async_trait;
use phalanx_forensics::cryptography::{decrypt_bytes, encrypt_bytes};
use phalanx_proto::prelude::*;
use phalanx_proto::revocation::RevocationToken;
use phalanx_proto::storage::PendingEgress;
use phalanx_proto::storage::TransientJournal;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt, SeekFrom};
use tracing::info;

const MAX_WAL_CHUNK_BYTES: u32 = 16 * 1024 * 1024; // 16 MiB
const MAX_EGRESS_SALVAGE_BYTES: u64 = 64 * 1024 * 1024; // 64 MiB
/// P2 FIX: Maximum aggregate WAL size before rejecting new writes.
/// Prevents unbounded WAL growth that could exhaust disk space.
const MAX_WAL_AGGREGATE_BYTES: u64 = 512 * 1024 * 1024; // 512 MiB

#[async_trait]
#[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // WAL frame arithmetic — payload sizes bounded by MTU.
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
        let plaintext = postcard::to_allocvec(chunk)?;

        let (nonce, ciphertext) = encrypt_bytes(&self.vault_key, &plaintext)?;

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

        let (nonce, ciphertext) = encrypt_bytes(&self.vault_key, &plaintext)?;

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
        let plaintext = decrypt_bytes(&self.vault_key, nonce, ciphertext)?;

        let pending: Vec<PendingEgress> = postcard::from_bytes(&plaintext)?;

        // Cleanup after successful recovery
        let _ = tokio::fs::remove_file(salvage_path).await;

        Ok(pending)
    }

    async fn record_workbench_state(&mut self, state_bytes: &[u8]) -> Result<(), ShardError> {
        let (nonce, ciphertext) = encrypt_bytes(&self.vault_key, state_bytes)?;

        // Frame: [8-byte BE len][24-byte nonce][ciphertext]
        let frame_len = (nonce.len() + ciphertext.len()) as u64;
        self.handle
            .write_u64(frame_len)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to write state length: {}", e)))?;
        self.handle
            .write_all(&nonce)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to write state nonce: {}", e)))?;
        self.handle
            .write_all(&ciphertext)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to write state payload: {}", e)))?;

        self.sync().await
    }

    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError> {
        const MAX_WORKBENCH_STATE_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB

        let length = self
            .handle
            .read_u64()
            .await
            .map_err(|e| ShardError::Io(format!("Failed to read state length: {}", e)))?;

        if length > MAX_WORKBENCH_STATE_BYTES {
            return Err(ShardError::SerializationError(
                "Workbench state exceeds 256 MiB limit".to_string(),
            ));
        }

        if (length as usize) < AEAD_NONCE_LEN {
            return Err(ShardError::SerializationError(
                "Workbench state too small for AEAD frame".to_string(),
            ));
        }

        let mut buffer = vec![0u8; length as usize];
        self.handle
            .read_exact(&mut buffer)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to read state payload: {}", e)))?;

        let (nonce, ciphertext) = buffer.split_at(AEAD_NONCE_LEN);
        Ok(decrypt_bytes(&self.vault_key, nonce, ciphertext)?)
    }

    async fn record_revocations(
        &mut self,
        revocations: &[RevocationToken],
    ) -> Result<(), ShardError> {
        let path = self.file_path.with_file_name("revocations.bin");

        // Read existing revocations, append new ones, write back atomically
        let mut all = self.read_all_revocations().await.unwrap_or_default();
        all.extend_from_slice(revocations);

        let plaintext = postcard::to_allocvec(&all)?;
        atomic_encrypted_write(&path, &plaintext, &self.vault_key)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;
        Ok(())
    }

    async fn read_all_revocations(&mut self) -> Result<Vec<RevocationToken>, ShardError> {
        let path = self.file_path.with_file_name("revocations.bin");
        if !path.exists() {
            return Ok(vec![]);
        }
        let plaintext = read_encrypted_file(&path, &self.vault_key)
            .await
            .map_err(|e| ShardError::Io(e.to_string()))?;
        Ok(postcard::from_bytes(&plaintext)?)
    }
}
