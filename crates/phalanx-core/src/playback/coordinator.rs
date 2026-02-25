use crate::playback::sink::PlaybackSink;
use crate::primitives::identity::PhalanxIdentity;
use crate::storage::vault::Guardian;
use anyhow::{Context, Result};
use std::time::Duration;
use tokio::sync::mpsc;

pub struct PlaybackCoordinator<S: PlaybackSink> {
    guardian: Guardian,
    identity: PhalanxIdentity,
    sink: S,
    discovery_tx: mpsc::Sender<u64>,
    current_sequence: u64,
}

impl<S: PlaybackSink> PlaybackCoordinator<S> {
    pub fn new(
        guardian: Guardian,
        identity: PhalanxIdentity,
        sink: S,
        discovery_tx: mpsc::Sender<u64>,
    ) -> Self {
        Self {
            guardian,
            identity,
            sink,
            discovery_tx,
            current_sequence: 1, // Forensic truth starts at 1
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        loop {
            // Attempt to pull from the "Safe Room" (Guardian)
            // Implicit Trust: Data only enters the Guardian via the StorageActor's Gate
            match self.guardian.get_shard(self.current_sequence).await {
                Some(encrypted_shard) => {
                    // JIT Decryption: Lightweight symmetric math (AES-GCM or ChaCha20)
                    let decrypted = self
                        .identity
                        .decrypt_payload(&encrypted_shard.data)
                        .context("Failed JIT decryption in Playback")?;

                    // Push to the Sink (UI Stream or File Artifact)
                    self.sink
                        .handle_chunk(self.current_sequence, decrypted)
                        .await?;

                    self.current_sequence += 1;
                }
                None => {
                    // GAP DETECTED: The "Samson Reflex"
                    // Signal the Engine/Libp2p adapter to find this specific sequence.
                    if let Err(e) = self.discovery_tx.try_send(self.current_sequence) {
                        // Using try_send to avoid blocking the loop if the channel is full
                        // But we log it as a forensic bottleneck.
                        eprintln!(
                            "Discovery channel full, retrying gap fill for {}: {}",
                            self.current_sequence, e
                        );
                    }

                    // Mobile-Conscientious Wait: Avoid tight-looping the CPU
                    tokio::time::sleep(Duration::from_millis(150)).await;
                }
            }
        }
    }
}
