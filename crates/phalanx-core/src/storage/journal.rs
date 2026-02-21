use crate::primitives::shards::{ShardChunk, ShardError};
use crate::storage::reassembler::TransientJournal;
use async_trait::async_trait;
use std::io::SeekFrom;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

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

#[async_trait]
impl TransientJournal for FileJournal {
    async fn record_chunk(&mut self, chunk: &ShardChunk) -> Result<(), ShardError> {
        // 1. Serialize and explicitly map the postcard::Error to a String
        let payload =
            postcard::to_stdvec(chunk).map_err(|e| ShardError::Serialization(e.to_string()))?;

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
}
