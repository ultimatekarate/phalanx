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

/// Diagnostic counters returned after playback completes.
/// Used by the FFI layer to log stats visible on Android logcat.
#[derive(Debug, Default)]
pub struct PlaybackStats {
    pub shards_found: u32,
    pub shards_missing: u32,
    pub video_sent: u32,
    pub audio_sent: u32,
    pub decode_failures: u32,
}

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
    /// Number of times the current sequence has been retried without success.
    retry_count: u32,
    /// Number of consecutive sequences that were gaps (no shard found).
    consecutive_gaps: u32,
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
            retry_count: 0,
            consecutive_gaps: 0,
        }
    }

    #[allow(clippy::arithmetic_side_effects)] // Sequence arithmetic for playback timing.
    #[allow(clippy::cognitive_complexity)] // Linear state-machine loop; splitting would obscure flow.
    pub async fn run(&mut self, recording_id: RecordingId) -> Result<PlaybackStats> {
        let mut stats = PlaybackStats::default();
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
                    // Reset gap counters — we found data.
                    self.retry_count = 0;
                    self.consecutive_gaps = 0;
                    stats.shards_found += 1;

                    let evidence_type = match &envelope.evidence {
                        Evidence::Video(_) => "Video",
                        Evidence::Audio(_) => "Audio",
                        Evidence::Gap(_) => "Gap",
                        Evidence::Handover(_) => "Handover",
                        Evidence::Proximity(_) => "Proximity",
                    };
                    eprintln!(
                        "[Phalanx Playback] seq {}: got {} shard",
                        self.current_sequence.0, evidence_type
                    );

                    // Demux: extract payload + timestamp + fps + audio metadata by value.
                    // Video arm sets sample_rate/channels to 0 (unused); audio arm sets
                    // timestamp/interval to 0 (unused). No Option, no unwrap.
                    let (payload, is_audio, timestamp_ms, frame_interval_ms, sample_rate, channels) =
                        match envelope.evidence {
                            Evidence::Video(v) => {
                                let ts = v.timestamp.as_u64();
                                let interval = if v.fps.get() > 0 {
                                    1000u64 / u64::from(v.fps.get())
                                } else {
                                    33 // fallback ~30fps
                                };
                                (v.payload, false, ts, interval, 0u32, 0u8)
                            }
                            Evidence::Audio(a) => {
                                let sr = a.sample_rate.get();
                                let ch = a.channels.get();
                                (a.payload, true, 0u64, 0u64, sr, ch)
                            }
                            Evidence::Gap(_) | Evidence::Handover(_) | Evidence::Proximity(_) => {
                                self.current_sequence.0 += 1;
                                continue;
                            }
                        };

                    // Capture sequence for sink calls, then advance immediately.
                    // If decode/verify/sink fails and run() returns an error,
                    // the counter is already past this frame — no retry stall.
                    let seq = self.current_sequence;
                    self.current_sequence.0 += 1;

                    let payload_desc = match &payload {
                        DataPayload::Missing => "Missing",
                        DataPayload::Clear(_) => "Clear",
                        DataPayload::Compressed(_) => "Compressed",
                        DataPayload::Encrypted { .. } => "Encrypted",
                    };
                    eprintln!(
                        "[Phalanx Playback] seq {seq}: payload is {payload_desc}, has_key={}",
                        self.decryption_key.is_some()
                    );

                    let frame_data = match payload {
                        DataPayload::Missing => continue,
                        other => {
                            match phalanx_forensics::decode_payload(
                                other,
                                self.decryption_key.as_ref(),
                            ) {
                                Ok(data) => data,
                                Err(e) => {
                                    eprintln!("[Phalanx Playback] decode_payload FAILED at seq {seq}: {e:?}");
                                    tracing::warn!(seq = seq.0, error = ?e, "Skipping frame: decode_payload failed");
                                    stats.decode_failures += 1;
                                    continue;
                                }
                            }
                        }
                    };

                    // Route to the correct sink — Rust demuxes, Flutter reads two channels.
                    // Errors here mean the Flutter receiver was dropped (playback stopped).
                    // Use match instead of ? to log before terminating.
                    if is_audio {
                        // Prepend 6-byte metadata header so Dart can configure AudioTrack.
                        // bytes 0..4: sample_rate (u32 LE)
                        // byte 4:    channels (u8)
                        // byte 5:    reserved (0u8, alignment)
                        // bytes 6..: raw PCM
                        #[allow(clippy::arithmetic_side_effects)]
                        // 6 + PCM len cannot overflow usize
                        let mut prefixed = Vec::with_capacity(6 + frame_data.len());
                        prefixed.extend_from_slice(&sample_rate.to_le_bytes());
                        prefixed.push(channels);
                        prefixed.push(0u8);
                        prefixed.extend_from_slice(&frame_data);
                        if let Err(e) = self.audio_sink.handle_chunk(seq, prefixed).await {
                            eprintln!("[Phalanx Playback] audio sink error at seq {seq}: {e:?}");
                            break Ok(stats);
                        }
                        stats.audio_sent += 1;
                    } else {
                        // Video payload is postcard-serialized Vec<Vec<u8>> (list of JPEG frames).
                        // Deserialize and send each JPEG individually to the sink.
                        // Falls back to raw bytes if deserialization fails (legacy format).
                        match postcard::from_bytes::<Vec<Vec<u8>>>(&frame_data) {
                            Ok(jpeg_frames) => {
                                eprintln!(
                                    "[Phalanx Playback] seq {seq}: decoded {} JPEG frames",
                                    jpeg_frames.len()
                                );
                                for (i, frame) in jpeg_frames.iter().enumerate() {
                                    // Prepend 8-byte LE timestamp for playback pacing.
                                    // Offset each frame within the shard by its index × per-frame interval.
                                    // This distributes the shard's frames evenly across the capture period.
                                    let frame_ts = timestamp_ms + (i as u64) * frame_interval_ms;
                                    let mut timed = Vec::with_capacity(8 + frame.len());
                                    timed.extend_from_slice(&frame_ts.to_le_bytes());
                                    timed.extend_from_slice(frame);
                                    if let Err(e) = self.video_sink.handle_chunk(seq, timed).await {
                                        eprintln!("[Phalanx Playback] video sink error: {e:?}");
                                        break;
                                    }
                                    stats.video_sent += 1;
                                }
                            }
                            Err(e) => {
                                eprintln!("[Phalanx Playback] seq {seq}: postcard deser failed ({e:?}), sending {} raw bytes", frame_data.len());
                                let mut timed = Vec::with_capacity(8 + frame_data.len());
                                timed.extend_from_slice(&timestamp_ms.to_le_bytes());
                                timed.extend_from_slice(&frame_data);
                                if let Err(e) = self.video_sink.handle_chunk(seq, timed).await {
                                    eprintln!("[Phalanx Playback] video sink error: {e:?}");
                                    break Ok(stats);
                                }
                                stats.video_sent += 1;
                            }
                        }
                    }
                }
                None => {
                    self.retry_count += 1;

                    // After 5 retries at the same sequence (~500ms), skip this gap.
                    // With DHT discovery, providers may still arrive in time;
                    // for local-only playback, this prevents infinite stalling.
                    if self.retry_count >= 5 {
                        tracing::debug!(
                            seq = self.current_sequence.0,
                            "Playback: skipping missing sequence after retries"
                        );
                        stats.shards_missing += 1;
                        self.current_sequence.0 += 1;
                        self.retry_count = 0;
                        self.consecutive_gaps += 1;

                        // After 20 consecutive gap-skips, conclude the recording is finished.
                        // 20 gaps × 5 retries × 100ms = ~10 seconds of patience.
                        if self.consecutive_gaps >= 20 {
                            tracing::info!(
                                "Playback: recording appears complete (20 consecutive gaps)"
                            );
                            break Ok(stats);
                        }
                        continue;
                    }

                    // Try DHT discovery for the missing shard
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
