use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::playback::PlaybackSink;

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
        if let Err(e) = self.ui_tx.send(data.clone()).await {
            return Err(anyhow::anyhow!("UI playback channel closed: {}", e));
        }

        // 2. Ephemerality: wipe the local buffer once the clone is sent.
        // Cleartext exists in RAM for the shortest time possible.
        data.iter_mut().for_each(|b| *b = 0);
        data.clear();

        Ok(())
    }

    async fn finalize(&mut self) -> Result<()> {
        Ok(())
    }
}

/// The External Exodus: Prepares a C2PA-compliant forensic artifact.
/// (Placeholder for the 'Artifact' half of the Dual Exodus)
pub struct ArtifactSink {
    _file_path: std::path::PathBuf,
    // Add C2PA manifest builder components here later
}

impl ArtifactSink {
    pub fn new(file_path: std::path::PathBuf) -> Self {
        Self {
            _file_path: file_path,
        }
    }
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
