use async_trait::async_trait;
use phalanx_proto::prelude::*;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt}; // Kept strictly out of the trait definition

pub struct FileJournal {
    pub file_path: PathBuf,
    pub handle: tokio::fs::File,
}

impl FileJournal {
    pub async fn new<P: Into<PathBuf>>(path: P) -> std::io::Result<Self> {
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
        // 1. Write state with a length-prefixed header for safe framing
        self.handle
            .write_u64(state_bytes.len() as u64)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to write state length: {}", e)))?;

        // 2. Write the actual postcard-encoded bytes
        self.handle
            .write_all(state_bytes)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to write state payload: {}", e)))?;

        // 3. Ensure physical commit to NVMe so the Lab can trust the state is saved
        self.sync().await
    }

    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError> {
        // 1. Read the length prefix
        let length = self
            .handle
            .read_u64()
            .await
            .map_err(|e| ShardError::Io(format!("Failed to read state length: {}", e)))?;

        // 2. Read the exact byte frame
        let mut buffer = vec![0u8; length as usize];
        self.handle
            .read_exact(&mut buffer)
            .await
            .map_err(|e| ShardError::Io(format!("Failed to read state payload: {}", e)))?;

        Ok(buffer)
    }
}
