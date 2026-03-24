use phalanx_proto::crypto::SymmetricKey;
use std::path::PathBuf;

// TransientJournal trait is defined in phalanx_proto::storage (the canonical location).
// Re-export for convenience within phalanx-node.
pub use phalanx_proto::storage::TransientJournal;

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
