use crate::clock::TrustedClock;
use crate::persistence::outbound::OutboundQueue;
use crate::vitals::{Homeostasis, SystemGovernor};
use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::gate::{LensGate, LensThresholds, WitnessGate};
use phalanx_forensics::judge::PayloadCipher;
use phalanx_forensics::reassembler::FountainChunkifier;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, ChunkType, Evidence, SignatureHash, VideoShard};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, ShardId};
use phalanx_proto::network::EgressPort;
use phalanx_proto::prelude::*;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

/// Configuration bundle for MediaEgressActor construction.
/// Groups topic routing, encoding, channel, and resilience parameters to keep `new()` ergonomic.
pub struct MediaEgressConfig {
    pub video_rx: mpsc::Receiver<VideoShard>,
    pub audio_rx: mpsc::Receiver<AudioShard>,
    pub video_topic: MeshTopic,
    pub audio_topic: MeshTopic,
    pub symbol_size: SymbolSize,
    pub repair_ratio: RepairRatio,
    /// WAL directory for outbound queue persistence. Failed publishes are persisted
    /// here and retried with exponential backoff until network conditions improve.
    pub wal_dir: PathBuf,
    /// Integral feedback: outbound queue pressure feeds into `w_integral` via
    /// `record_storage_pressure()`, driving FPS self-regulation.
    pub system_governor: Arc<SystemGovernor>,
    /// Denominator for storage pressure ratio (typically `config.storage.max_storage_bytes`).
    pub max_storage_bytes: u64,
    /// Encryption key for payload AEAD (legacy fallback / KEK).
    /// Encryption runs here (async worker thread) rather than on the FFI capture
    /// thread — keeps the camera callback fast. Low-end Mediatek devices with weak
    /// entropy sources and slow cores drop frames when XChaCha20 + getrandom()
    /// block the camera HAL return path.
    pub vault_key: SymmetricKey, // Phalanx is for the people.
    /// Per-recording content key receiver. When `Some`, encrypts with the recording's
    /// DEK instead of vault_key. Updated via watch channel when recordings start/stop.
    pub content_key_rx: tokio::sync::watch::Receiver<Option<SymmetricKey>>,
    /// Trusted clock for forensic timestamps.
    pub clock: Arc<TrustedClock>,
    /// LensGate thresholds — calibrated if sensor setup was performed, defaults otherwise.
    pub lens_thresholds: LensThresholds,
}

pub struct MediaEgressActor<E: EgressPort> {
    egress: E,
    video_rx: mpsc::Receiver<VideoShard>,
    audio_rx: mpsc::Receiver<AudioShard>,
    video_topic: MeshTopic,
    audio_topic: MeshTopic,
    identity: Arc<PhalanxIdentity>,
    local_id: NetworkId,
    video_prev_hash: Option<SignatureHash>,
    audio_prev_hash: Option<SignatureHash>,
    symbol_size: SymbolSize,
    repair_ratio: RepairRatio,
    /// Encryption key (legacy fallback / KEK) — encrypt payloads on async thread, not FFI.
    vault_key: SymmetricKey,
    /// Per-recording content key. Prefers this over vault_key when `Some`.
    content_key_rx: tokio::sync::watch::Receiver<Option<SymmetricKey>>,
    /// Monotonic shard ID counter. Each sealed envelope gets a unique ShardId
    /// so the receiver's Crucible can track reassembly contexts independently.
    next_shard_id: u64,
    /// WAL-backed persistent queue for failed publishes. Crash-safe, FIFO, exponential
    /// backoff (5s base, 5min cap), abandonment after 10 attempts with forensic audit log.
    outbound_queue: OutboundQueue,
    /// Integral feedback: outbound queue bytes drive `w_integral` → composite stress → FPS.
    system_governor: Arc<SystemGovernor>,
    /// Denominator for the storage pressure ratio reported to the governor.
    max_storage_bytes: u64,
    /// Trusted clock for forensic timestamps.
    clock: Arc<TrustedClock>,
    /// LensGate thresholds for capture-time provenance verification.
    lens_thresholds: LensThresholds,
}

impl<E: EgressPort> MediaEgressActor<E> {
    pub async fn new(
        egress: E,
        identity: Arc<PhalanxIdentity>,
        local_id: NetworkId,
        config: MediaEgressConfig,
    ) -> std::io::Result<Self> {
        let outbound_queue = OutboundQueue::new(config.wal_dir).await?;
        Ok(Self {
            egress,
            video_rx: config.video_rx,
            audio_rx: config.audio_rx,
            video_topic: config.video_topic,
            audio_topic: config.audio_topic,
            identity,
            local_id,
            video_prev_hash: None,
            audio_prev_hash: None,
            symbol_size: config.symbol_size,
            repair_ratio: config.repair_ratio,
            vault_key: config.vault_key,
            content_key_rx: config.content_key_rx,
            next_shard_id: 0,
            outbound_queue,
            system_governor: config.system_governor,
            max_storage_bytes: config.max_storage_bytes,
            clock: config.clock,
            lens_thresholds: config.lens_thresholds,
        })
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and timestamp arithmetic.
    pub async fn run(mut self) {
        let mut retry_tick = tokio::time::interval(Duration::from_secs(5));
        let mut video_open = true;
        let mut audio_open = true;

        loop {
            tokio::select! {
                result = self.video_rx.recv(), if video_open => {
                    match result {
                        Some(shard) => self.process_media_egress(Evidence::Video(shard), true).await,
                        None => video_open = false,
                    }
                }
                result = self.audio_rx.recv(), if audio_open => {
                    match result {
                        Some(shard) => self.process_media_egress(Evidence::Audio(shard), false).await,
                        None => audio_open = false,
                    }
                }
                _ = retry_tick.tick() => {
                    self.process_retry_queue().await;
                }
            }

            // Exit only when both capture channels closed AND retry queue drained
            if !video_open && !audio_open && self.outbound_queue.is_empty() {
                break;
            }
        }
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Sequence counter and timestamp arithmetic.
    async fn process_media_egress(&mut self, mut evidence: Evidence, is_video: bool) {
        let topic = match &evidence {
            Evidence::Video(_) => self.video_topic.clone(),
            Evidence::Audio(_) => self.audio_topic.clone(),
            _ => {
                tracing::warn!("Unexpected evidence type for media egress");
                return;
            }
        };

        if !self.gate_and_encrypt(&mut evidence) {
            return;
        }

        let prev_hash = if is_video {
            self.video_prev_hash.take()
        } else {
            self.audio_prev_hash.take()
        };

        let envelope = match evidence.seal(&self.identity, self.local_id.clone(), prev_hash) {
            Ok(env) => env,
            Err(e) => {
                tracing::error!("Failed to seal media evidence: {}", e);
                return;
            }
        };

        let new_hash = envelope.signature_hash();
        if is_video {
            self.video_prev_hash = Some(new_hash);
        } else {
            self.audio_prev_hash = Some(new_hash);
        }

        let envelope_bytes = match postcard::to_allocvec(&envelope) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to serialize media envelope: {}", e);
                return;
            }
        };

        let shard_id = ShardId(self.next_shard_id);
        self.next_shard_id += 1;

        let now = self.clock.now().unwrap_or_default();
        let chunks = match envelope_bytes.fountain_chunkify(
            shard_id,
            self.identity.did.clone(),
            self.symbol_size,
            ChunkType::Witnessed,
            self.repair_ratio,
            now,
        ) {
            Ok(chunks) => chunks,
            Err(e) => {
                tracing::error!(event = "fountain_encode_failed", error = %e,
                    "Failed to fountain-encode evidence");
                return;
            }
        };

        self.publish_fountain_symbols(&topic, shard_id, chunks, is_video)
            .await;
    }

    // ── Media Egress Handlers ───────────────────────────────────────────

    /// LensGate provenance check + AEAD encryption.
    /// Returns `false` if the evidence must be dropped (provenance rejection or
    /// encryption failure — plaintext MUST NOT reach the mesh).
    fn gate_and_encrypt(&self, evidence: &mut Evidence) -> bool {
        // LensGate: verify sensor provenance BEFORE encryption.
        // Rejects synthetic/deepfake frames at the source.
        if let Evidence::Video(ref v) = evidence {
            if let Err(e) = v.lens_metrics.check_provenance(&self.lens_thresholds) {
                tracing::error!(event = "lens_gate_local_rejection", error = %e);
                return false;
            }
        }

        // Encrypt payload on the async worker thread (not the FFI capture thread).
        // Encryption failure is fatal — plaintext evidence MUST NOT reach the mesh.
        // Prefer per-recording content key (DEK) over vault_key (KEK fallback).
        let key = self
            .content_key_rx
            .borrow()
            .as_ref()
            .cloned()
            .unwrap_or_else(|| self.vault_key.clone());
        match evidence {
            Evidence::Video(v) => {
                if let Err(e) = v.payload.apply_encryption(&key) {
                    tracing::error!("Video encryption failed — dropping shard to prevent plaintext broadcast: {e}");
                    return false;
                }
            }
            Evidence::Audio(a) => {
                if let Err(e) = a.payload.apply_encryption(&key) {
                    tracing::error!("Audio encryption failed — dropping shard to prevent plaintext broadcast: {e}");
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    /// Publish each fountain symbol as a separate gossipsub message.
    /// Failed symbols are persisted to the WAL for retry.
    #[allow(clippy::arithmetic_side_effects)] // Published counter increment.
    async fn publish_fountain_symbols(
        &mut self,
        topic: &MeshTopic,
        shard_id: ShardId,
        chunks: Vec<phalanx_proto::evidence::ShardChunk>,
        is_video: bool,
    ) {
        let symbol_count = chunks.len();
        let mut published = 0;
        for chunk in chunks {
            match postcard::to_allocvec(&chunk) {
                Ok(data) => {
                    // Clone before publish: publish() takes Vec<u8> by value.
                    // On failure we need the original bytes for WAL enqueue.
                    if let Err(e) = self.egress.publish(topic, data.clone()).await {
                        tracing::error!(
                            event = "symbol_publish_failed",
                            shard_id = shard_id.0,
                            symbol = published,
                            error = %e,
                            "Failed to publish fountain symbol — enqueueing for retry"
                        );
                        if let Err(wal_err) = self
                            .outbound_queue
                            .enqueue(topic.clone(), data, self.clock.now().unwrap_or_default())
                            .await
                        {
                            tracing::error!(
                                error = %wal_err,
                                "Failed to persist to OutboundQueue WAL"
                            );
                        }
                    } else {
                        published += 1;
                    }
                }
                Err(e) => tracing::error!("Failed to serialize fountain symbol: {}", e),
            }
        }

        tracing::debug!(
            event = "media_egress_complete",
            shard_id = shard_id.0,
            symbols_published = published,
            symbols_total = symbol_count,
            is_video = is_video,
        );
    }

    /// Drain pending entries from the outbound queue, respecting exponential backoff,
    /// and report queue pressure to the Volterra integral for FPS self-regulation.
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Retry counter and timestamp arithmetic.
    async fn process_retry_queue(&mut self) {
        if self.outbound_queue.is_empty() {
            return;
        }

        let now = self.clock.now().unwrap_or_default();
        let batch = self.outbound_queue.drain_batch(10);

        for entry in batch {
            // Check if backoff period has elapsed
            let ready = match entry.last_attempt {
                None => true,
                Some(last) => {
                    let delay = OutboundQueue::backoff_delay(entry.attempts);
                    now.0 >= last.0 + delay.as_millis() as u64
                }
            };

            if !ready {
                self.outbound_queue.requeue_unchanged(entry);
                continue;
            }

            if self
                .egress
                .publish(&entry.topic, entry.envelope_bytes.clone())
                .await
                .is_ok()
            {
                if let Err(e) = self.outbound_queue.acknowledge(entry.id).await {
                    tracing::error!(error = %e, "Failed to acknowledge outbound entry");
                }
                tracing::debug!(event = "outbound_retry_success", entry_id = entry.id.0);
            } else if let Err(e) = self.outbound_queue.requeue_failed(entry, now).await {
                tracing::error!(error = %e, "Failed to requeue outbound entry");
            }
        }

        // Feed outbound queue pressure into the Volterra integral.
        // As the queue grows → w_integral rises → composite stress rises → FPS drops
        // → fewer shards captured → queue growth self-regulates.
        self.system_governor
            .record_storage_pressure(self.outbound_queue.total_bytes().0, self.max_storage_bytes);
    }
}
