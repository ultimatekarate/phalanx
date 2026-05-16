use std::io::Cursor;
use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use c2pa::{create_signer, SigningAlg};
use tokio::sync::mpsc;
use zeroize::Zeroize;

use phalanx_forensics::c2pa_ext::C2paOrchestrator;
use phalanx_proto::evidence::{ForensicMetrics, MediaType, StorageSequence};
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

/// The External Exodus: Writes a C2PA-signed forensic artifact to disk.
///
/// Dual mode:
/// - **Signed**: When `cert_path` and `key_path` are provided, embeds a C2PA manifest
///   with ForensicLens sensor assertions and Ed25519 signature.
/// - **Unsigned**: When certs are absent, writes raw concatenated bytes (still useful
///   as an export, just without provenance claims).
pub struct ArtifactSink {
    file_path: PathBuf,
    buffer: Vec<u8>,
    node_id: String,
    lens_metrics: ForensicMetrics,
    cert_path: Option<String>,
    key_path: Option<String>,
}

impl ArtifactSink {
    pub fn new(
        file_path: PathBuf,
        node_id: String,
        lens_metrics: ForensicMetrics,
        cert_path: Option<String>,
        key_path: Option<String>,
    ) -> Self {
        Self {
            file_path,
            buffer: Vec::new(),
            node_id,
            lens_metrics,
            cert_path,
            key_path,
        }
    }
}

#[async_trait]
impl PlaybackSink for ArtifactSink {
    async fn handle_chunk(&mut self, _sequence_id: StorageSequence, data: Vec<u8>) -> Result<()> {
        self.buffer.extend_from_slice(&data);
        Ok(())
    }

    async fn finalize(&mut self) -> Result<()> {
        let output = match (&self.cert_path, &self.key_path) {
            (Some(cert), Some(key)) => {
                let mut builder = C2paOrchestrator::build_manifest_with_lens(
                    &self.node_id,
                    MediaType::VideoMp4,
                    &self.lens_metrics,
                )
                .context("Failed to build C2PA manifest")?;

                let signer = create_signer::from_files(cert, key, SigningAlg::Ed25519, None)
                    .context("Failed to create C2PA signer from cert/key files")?;

                let mut source = Cursor::new(&self.buffer);
                let mut dest = Cursor::new(Vec::new());
                builder
                    .sign(signer.as_ref(), "video/mp4", &mut source, &mut dest)
                    .context("C2PA signing failed")?;

                dest.into_inner()
            }
            _ => self.buffer.clone(),
        };

        tokio::fs::write(&self.file_path, &output)
            .await
            .context("Failed to write artifact file")?;

        self.buffer.zeroize();
        Ok(())
    }
}
