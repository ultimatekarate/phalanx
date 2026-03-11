use async_trait::async_trait;
use phalanx_forensics::cryptography::{decrypt_bytes, encrypt_bytes};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::prelude::*;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_WORKBENCH_STATE_BYTES: u64 = 256 * 1024 * 1024; // 256 MiB
const AEAD_NONCE_LEN: usize = 24;

pub struct FileJournal {
    pub file_path: PathBuf,
    pub handle: tokio::fs::File,
    pub vault_key: SymmetricKey,
}

impl FileJournal {
    pub async fn new<P: Into<PathBuf>>(path: P, vault_key: SymmetricKey) -> std::io::Result<Self> {
        let path_buf = path.into();
        let handle = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path_buf)
            .await?;

        Ok(Self {
            file_path: path_buf,
            handle,
            vault_key,
        })
    }
}

// --- THE JOURNAL TRAIT ---
// Allows the Lab (Forensics) to describe the NEED for persistence
// without depending on a specific database, filesystem, or tokio.
#[async_trait]
pub trait TransientJournal: Send + Sync {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;
    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError>;
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError>;

    // NEW: Clean trait signatures for Crucible state recovery. No default tokio implementation.
    async fn record_workbench_state(&mut self, state_bytes: &[u8]) -> Result<(), ShardError>;
    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError>;
}

// --- THE CONCRETE IMPLEMENTATION (HANDS LAYER) ---
#[async_trait]
impl TransientJournal for FileJournal {
    async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
        // Implementation omitted for brevity, assuming existing logic is sound
        Ok(())
    }

    async fn sync(&mut self) -> Result<(), ShardError> {
        self.handle
            .sync_all()
            .await
            .map_err(|e| ShardError::Io(e.to_string()))
    }

    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        // Implementation omitted for brevity
        Ok(vec![])
    }

    async fn clear(&mut self) -> Result<(), ShardError> {
        // Implementation omitted for brevity
        Ok(())
    }

    async fn record_pending_egress(
        &mut self,
        _pending: &[PendingEgress],
    ) -> Result<(), ShardError> {
        Ok(())
    }

    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        Ok(vec![])
    }

    async fn record_workbench_state(&mut self, state_bytes: &[u8]) -> Result<(), ShardError> {
        // 1. Encrypt the state
        let (nonce, ciphertext) = encrypt_bytes(&self.vault_key, state_bytes)
            .map_err(|e| ShardError::Encryption(e.to_string()))?;

        // 2. Frame: [8-byte BE len][24-byte nonce][ciphertext]
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

        // 3. Ensure physical commit to NVMe
        self.sync().await
    }

    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError> {
        // 1. Read the length prefix
        let length = self
            .handle
            .read_u64()
            .await
            .map_err(|e| ShardError::Io(format!("Failed to read state length: {}", e)))?;

        // 2. Bounds check
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

        // 3. Read the encrypted frame
        let mut buffer = vec![0u8; length as usize];
        self.handle
            .read_exact(&mut buffer)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to read state payload: {}", e)))?;

        // 4. Split and decrypt
        let (nonce, ciphertext) = buffer.split_at(AEAD_NONCE_LEN);
        decrypt_bytes(&self.vault_key, nonce, ciphertext)
            .map_err(|e| ShardError::Encryption(e.to_string()))
    }
}
