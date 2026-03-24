// crates/phalanx-node/src/actors/playback.rs

use crate::actors::egress::EgressCommand;
use crate::actors::storage::StorageCommand;
use phalanx_proto::crypto::{SealedLocator, SymmetricKey};
use phalanx_proto::evidence::{DataPayload, Evidence, StorageSequence};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId};
use phalanx_proto::playback::PlaybackSink;
use phalanx_proto::retrieval::RecordingRequest;

use phalanx_forensics::cryptography::grant::GrantAuthority;

use anyhow::{Context, Result};
use ed25519_dalek::Signer;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct PlaybackCoordinator<V: PlaybackSink, A: PlaybackSink> {
    storage_tx: mpsc::Sender<StorageCommand>,
    egress_tx: mpsc::Sender<EgressCommand>,
    decryption_key: Option<SymmetricKey>,
    video_sink: V,
    audio_sink: A,
    discovery_tx: mpsc::Sender<(RecordingId, StorageSequence)>,
    providers_rx: mpsc::Receiver<(RecordingId, Vec<NetworkId>)>,
    identity: Arc<PhalanxIdentity>,
    current_sequence: StorageSequence,
}

impl<V: PlaybackSink, A: PlaybackSink> PlaybackCoordinator<V, A> {
    #[allow(clippy::too_many_arguments)] // Coordinator is assembled once per playback session
    pub fn new(
        storage_tx: mpsc::Sender<StorageCommand>,
        egress_tx: mpsc::Sender<EgressCommand>,
        decryption_key: Option<SymmetricKey>,
        video_sink: V,
        audio_sink: A,
        discovery_tx: mpsc::Sender<(RecordingId, StorageSequence)>,
        providers_rx: mpsc::Receiver<(RecordingId, Vec<NetworkId>)>,
        identity: Arc<PhalanxIdentity>,
    ) -> Self {
        Self {
            storage_tx,
            egress_tx,
            decryption_key,
            video_sink,
            audio_sink,
            discovery_tx,
            providers_rx,
            identity,
            current_sequence: StorageSequence(1), // Forensic truth starts at 1
        }
    }

    pub async fn run(&mut self, recording_id: RecordingId) -> Result<()> {
        loop {
            // Non-blocking: drain any provider results that arrived since last iteration.
            // Using try_recv() instead of select! to avoid cancelling the oneshot reply_rx
            // future below if a provider event arrives mid-wait.
            while let Ok((rec_id, providers)) = self.providers_rx.try_recv() {
                if rec_id == recording_id {
                    self.request_shards_from_providers(&rec_id, providers).await;
                }
            }

            let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();

            // Ask the StorageActor for the frame
            self.storage_tx
                .send(StorageCommand::GetShard {
                    recording_id: recording_id.clone(),
                    sequence_id: self.current_sequence,
                    reply_to: reply_tx,
                })
                .await
                .context("StorageActor mailbox closed")?;

            // Await the response from the StorageActor
            let shard_opt = reply_rx
                .await
                .context("StorageActor dropped the response channel")?;
            match shard_opt {
                Some(envelope) => {
                    // Demux: extract payload by value — no clone needed.
                    // Envelope is consumed; only the decoded bytes continue downstream.
                    let (payload, is_audio) = match envelope.evidence {
                        Evidence::Video(v) => (v.payload, false),
                        Evidence::Audio(a) => (a.payload, true),
                        Evidence::Gap(_) | Evidence::Handover(_) | Evidence::Proximity(_) => {
                            self.current_sequence.0 += 1;
                            continue;
                        }
                    };

                    let frame_data = match payload {
                        DataPayload::Clear(data) => data,
                        DataPayload::Encrypted { ciphertext, .. } => {
                            let _key = self.decryption_key.as_ref().context(
                                "Encountered encrypted shard, but no SymmetricKey was provided",
                            )?;
                            // TODO: real decryption — currently returns ciphertext directly
                            ciphertext
                        }
                        DataPayload::Missing => {
                            self.current_sequence.0 += 1;
                            continue;
                        }
                        DataPayload::Compressed(compressed_data) => {
                            phalanx_forensics::reassembler::decompress_payload(&compressed_data)
                                .map_err(|e| {
                                    anyhow::anyhow!("Failed to decompress LZ4 payload: {}", e)
                                })?
                        }
                    };

                    // Route to the correct sink — Rust demuxes, Flutter reads two channels.
                    if is_audio {
                        self.audio_sink
                            .handle_chunk(self.current_sequence, frame_data)
                            .await?;
                    } else {
                        self.video_sink
                            .handle_chunk(self.current_sequence, frame_data)
                            .await?;
                    }
                    self.current_sequence.0 += 1;
                }
                None => {
                    // Gap detected, trigger Samson Reflex
                    let _ = self
                        .discovery_tx
                        .try_send((recording_id.clone(), self.current_sequence));
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    /// Construct cryptographically signed retrieval requests and send to each provider.
    ///
    /// Uses real X25519 ECDH + XChaCha20-Poly1305 via `GrantAuthority::seal()` for the
    /// SealedLocator, and Ed25519 for the request signature. This is the inverse of
    /// `verify_retrieval_auth()` in identity.rs.
    async fn request_shards_from_providers(
        &self,
        recording_id: &RecordingId,
        providers: Vec<NetworkId>,
    ) {
        // 1. Construct SealedLocator with real crypto.
        // A null key produces a grant that anyone can unseal — never allow this.
        let key_bytes: &[u8; 32] = match self.decryption_key.as_ref() {
            Some(k) => k.as_bytes(),
            None => {
                tracing::error!("Cannot request shards: no decryption key available");
                return;
            }
        };

        let locator = match SealedLocator::seal(
            recording_id.clone(),
            key_bytes,
            &self.identity,
            self.identity.did.clone(), // self-recovery: recipient is self
            phalanx_proto::crypto::GrantPermissions::default(),
        ) {
            Ok(loc) => loc,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to seal locator for shard request");
                return;
            }
        };

        // 2. Sign (target_did, recording_id, locator) with own key.
        //    This is the inverse of verify_retrieval_auth() in identity.rs:227-250.
        let signed_data = (&self.identity.did, recording_id, &locator);
        let msg = match postcard::to_allocvec(&signed_data) {
            Ok(m) => m,
            Err(e) => {
                tracing::error!(error = ?e, "Failed to serialize shard request for signing");
                return;
            }
        };
        let signature = self.identity.keypair.sign(&msg).to_bytes().to_vec();

        let request = RecordingRequest {
            target_did: self.identity.did.clone(),
            recording_id: recording_id.clone(),
            locator,
            signature,
        };

        // 3. Send to each provider via EgressActor
        for provider in providers {
            let _ = self
                .egress_tx
                .send(EgressCommand::RequestShards {
                    target: provider,
                    request: request.clone(),
                })
                .await;
        }
    }
}
