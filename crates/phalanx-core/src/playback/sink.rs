use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;
use zeroize::Zeroize;

use crate::primitives::shards::StorageSequence;

/// The PlaybackSink trait defines the "Exit Gates" for Phalanx data.
/// Whether the data is going to a RAM buffer for the UI or a C2PA-wrapped file,
/// it must pass through this trait.
#[async_trait]
pub trait PlaybackSink: Send + Sync {
    /// Handles a decrypted chunk of forensic data.
    /// The implementation is responsible for the "Dual Exodus" logic.
    async fn handle_chunk(&mut self, sequence_id: StorageSequence, mut data: Vec<u8>)
        -> Result<()>;

    /// Called when the playback sequence is complete or terminated.
    async fn finalize(&mut self) -> Result<()>;
}

/// The Internal Exodus: Feeds the mobile video player's memory buffer.
/// Designed for high speed and ephemerality.
pub struct VideoPlayerSink {
    /// Channel to the native UI layer (e.g., a FrameBuffer or MediaSource)
    ui_tx: mpsc::Sender<Vec<u8>>,
}

impl VideoPlayerSink {
    pub fn new(ui_tx: mpsc::Sender<Vec<u8>>) -> Self {
        Self { ui_tx }
    }
}

#[async_trait]
impl PlaybackSink for VideoPlayerSink {
    async fn handle_chunk(
        &mut self,
        _sequence_id: StorageSequence,
        mut data: Vec<u8>,
    ) -> Result<()> {
        // 1. Hand off to the UI layer.
        // We send a clone to the channel so the UI can process/render it.
        if let Err(e) = self.ui_tx.send(data.clone()).await {
            // If the UI is no longer listening, we drop the data.
            return Err(anyhow::anyhow!("UI playback channel closed: {}", e));
        }

        // 2. THE MASTERPIECE MOVE: Ephemerality.
        // Once the clone is sent, we securely wipe the local 'data' buffer.
        // This ensures the cleartext exists in RAM for the shortest time possible.
        data.zeroize();

        Ok(())
    }

    async fn finalize(&mut self) -> Result<()> {
        // Here we could signal the UI that the "Truth Stream" has ended.
        Ok(())
    }
}

/// The External Exodus: Prepares a C2PA-compliant forensic artifact.
/// (Placeholder for the 'Artifact' half of the Dual Exodus)
pub struct ArtifactSink {
    file_path: std::path::PathBuf,
    // Add C2PA manifest builder components here later
}

#[async_trait]
impl PlaybackSink for ArtifactSink {
    async fn handle_chunk(&mut self, _sequence_id: StorageSequence, _data: Vec<u8>) -> Result<()> {
        // Implementation for writing to disk and building the C2PA manifest
        todo!("Implement C2PA-wrapped file writing")
    }

    async fn finalize(&mut self) -> Result<()> {
        todo!("Finalize C2PA assertions and sign manifest")
    }
}
