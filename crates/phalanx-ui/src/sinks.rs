use std::io::Cursor;
use std::path::PathBuf;

use anyhow::Result;
use async_trait::async_trait;
use c2pa::{create_signer, Builder, SigningAlg};
use tokio::sync::mpsc;
use zeroize::Zeroize;

use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::playback::PlaybackSink;
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

pub struct VideoExportSink {
    export_directory: PathBuf,
    identity: String,
}

impl VideoExportSink {
    pub fn new(dir: PathBuf, node_identity: String) -> Self {
        Self {
            export_directory: dir,
            identity: node_identity,
        }
    }

    /// Signs and embeds a C2PA manifest into the media payload.
    /// This is "The Hands" responsibility: secret management and signing.
    async fn sign_and_embed(
        &self,
        builder: &mut Builder,
        payload: &[u8],
        format: &str,
    ) -> anyhow::Result<Vec<u8>> {
        // The Hands provide signing credentials.
        // TODO: load cert/key paths from node configuration instead of hardcoding.
        let signer =
            create_signer::from_files("node_cert.pem", "node_key.pem", SigningAlg::Ed25519, None)?;

        // Builder::sign reads the source asset, embeds the signed C2PA manifest,
        // and writes the result to dest — all in one shot.
        let mut source = Cursor::new(payload);
        let mut dest = Cursor::new(Vec::new());
        builder.sign(signer.as_ref(), format, &mut source, &mut dest)?;

        Ok(dest.into_inner())
    }
}
