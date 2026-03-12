use phalanx_proto::prelude::*;
use zeroize::Zeroize;
use c2pa::create_signer;

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

    impl VideoExportSink {
        async fn sign_and_embed(
            &self, 
            payload: &[u8], 
            unsigned_manifest: Vec<u8>
        ) -> Result<Vec<u8>, SinkError> {
            // This is the "Hands" responsibility: Secret management.
            let signer = create_signer::from_files("node_cert.pem", "node_key.pem", None)
                .map_err(|_| SinkError::CryptoFailure)?;

            // Use the c2pa crate to embed the manifest into the MP4 stream
            let mut signed_output = Vec::new();
            c2pa::embed_bytes(
                "video/mp4", 
                payload, 
                &unsigned_manifest, 
                signer.as_ref(), 
                &mut signed_output
            ).map_err(|_| SinkError::ExportFailed)?;

            Ok(signed_output)
        }
    }
}