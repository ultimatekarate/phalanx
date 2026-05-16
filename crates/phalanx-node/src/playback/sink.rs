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
    async fn handle_chunk(&mut self, _sequence_id: StorageSequence, data: Vec<u8>) -> Result<()> {
        // Move (not clone) into the channel. A prior version cloned and then
        // zeroized the local copy, but the clone reached C-side memory via
        // leak_bytes_to_c unzeroed — so the producer-side wipe only erased
        // a shorter-lived sibling buffer. Moving eliminates that extra alloc
        // + memset without changing the dominant cleartext lifetime, which
        // is bounded by Flutter's free.
        if let Err(e) = self.ui_tx.send(data).await {
            return Err(anyhow::anyhow!("UI playback channel closed: {}", e));
        }
        Ok(())
    }

    async fn finalize(&mut self) -> Result<()> {
        Ok(())
    }
}
