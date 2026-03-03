// crates/phalanx-node/src/storage/journal.rs

use async_trait::async_trait;
use phalanx_proto::prelude::*;

use async_trait::async_trait;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

pub struct FileJournal {
    file_path: PathBuf,
    handle: tokio::fs::File,
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
// Allows the Lab to describe the NEED for persistence without
// depending on a specific database or filesystem.
#[async_trait]
pub trait TransientJournal: Send + Sync {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError>;
    async fn sync(&mut self) -> Result<(), ShardError>;
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError>;
    async fn clear(&mut self) -> Result<(), ShardError>;
    async fn record_pending_egress(&mut self, pending: &[PendingEgress]) -> Result<(), ShardError>;
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError>;
}
