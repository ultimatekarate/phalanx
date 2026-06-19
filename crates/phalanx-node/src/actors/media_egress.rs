use crate::actors::shutdown::ShutdownSignal;
use crate::clock::TrustedClock;
use crate::persistence::outbound::OutboundQueue;
use crate::vitals::{Homeostasis, SystemGovernor};
use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::gate::{self, WitnessGate};
use phalanx_forensics::judge::PayloadCipher;
use phalanx_forensics::reassembler::FountainChunkifier;
use phalanx_proto::corroboration::ProximityWitness;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{
    AudioShard, ChunkType, Evidence, PrnuPosterior, SignatureHash, VideoShard,
};
use phalanx_proto::identity::{PhalanxIdentity, ShardId, WitnessId};
use phalanx_proto::network::EgressPort;
use phalanx_proto::prelude::*;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

/// Configuration bundle for MediaEgressActor construction.
/// Groups topic routing, encoding, channel, and resilience parameters to keep `new()` ergonomic.
pub struct MediaEgressConfig {
    pub video_rx: mpsc::Receiver<VideoShard>,
    pub audio_rx: mpsc::Receiver<AudioShard>,
    /// Proximity witnesses drained by `RecordingSessionState::stop`. Each is
    /// sealed here into a signed `Evidence::Proximity` envelope and egressed
    /// with the recording — see `process_proximity_egress`.
    pub proximity_rx: mpsc::Receiver<ProximityWitness>,
    pub video_topic: MeshTopic,
    pub audio_topic: MeshTopic,
    pub symbol_size: SymbolSize,
    pub repair_ratio: RepairRatio,
    /// Number of RaptorQ symbols carried per `egress.publish()` call. Default
    /// 1 publishes one symbol per call (pre-bundling behavior); larger values
    /// amortize per-message processing cost on the libp2p path.
    pub symbol_bundle_size: SymbolBundleSize,
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
    /// Bayesian PRNU posterior — shared with the capture path (FFI).
    /// Updated on every video frame; MediaEgressActor reads for gate checks.
    pub prnu_posterior: Arc<Mutex<PrnuPosterior>>,
    /// Storage command sender — for persisting local capture shards to the Guardian.
    /// Without this, locally-recorded evidence exists only in transit (mesh egress)
    /// and is lost if the app closes before any peer receives it.
    pub storage_tx: mpsc::Sender<crate::actors::storage::StorageCommand>,
}

pub struct MediaEgressActor<E: EgressPort> {
    egress: E,
    video_rx: mpsc::Receiver<VideoShard>,
    audio_rx: mpsc::Receiver<AudioShard>,
    proximity_rx: mpsc::Receiver<ProximityWitness>,
    video_topic: MeshTopic,
    audio_topic: MeshTopic,
    identity: Arc<PhalanxIdentity>,
    local_id: WitnessId,
    video_prev_hash: Option<SignatureHash>,
    audio_prev_hash: Option<SignatureHash>,
    symbol_size: SymbolSize,
    repair_ratio: RepairRatio,
    /// Symbols batched into a single egress publish (see MediaEgressConfig).
    symbol_bundle_size: SymbolBundleSize,
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
    /// Bayesian PRNU posterior for luminance-conditioned provenance verification.
    prnu_posterior: Arc<Mutex<PrnuPosterior>>,
    /// Storage command sender — persist local captures to Guardian.
    storage_tx: mpsc::Sender<crate::actors::storage::StorageCommand>,
    /// Shared cancellation signal. The run loop's select! polls this arm with
    /// `biased;` priority so cancel wins deterministically at shutdown. When
    /// cancel fires with items still in the retry queue, the actor exits
    /// without flushing them — an accepted loss per the C2 plan (if the
    /// network is broken enough that the retry queue isn't draining, nothing
    /// at shutdown time can flush it either).
    shutdown: Arc<ShutdownSignal>,
}

impl<E: EgressPort> MediaEgressActor<E> {
    pub async fn new(
        egress: E,
        identity: Arc<PhalanxIdentity>,
        local_id: WitnessId,
        config: MediaEgressConfig,
        shutdown: Arc<ShutdownSignal>,
    ) -> std::io::Result<Self> {
        let outbound_queue = OutboundQueue::new(config.wal_dir).await?;
        Ok(Self {
            egress,
            video_rx: config.video_rx,
            audio_rx: config.audio_rx,
            proximity_rx: config.proximity_rx,
            video_topic: config.video_topic,
            audio_topic: config.audio_topic,
            identity,
            local_id,
            video_prev_hash: None,
            audio_prev_hash: None,
            symbol_size: config.symbol_size,
            repair_ratio: config.repair_ratio,
            symbol_bundle_size: config.symbol_bundle_size,
            vault_key: config.vault_key,
            content_key_rx: config.content_key_rx,
            storage_tx: config.storage_tx,
            next_shard_id: 0,
            outbound_queue,
            system_governor: config.system_governor,
            max_storage_bytes: config.max_storage_bytes,
            clock: config.clock,
            prnu_posterior: config.prnu_posterior,
            shutdown,
        })
    }

    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Counter increments and timestamp arithmetic.
    pub async fn run(mut self) {
        let mut retry_tick = tokio::time::interval(Duration::from_secs(5));
        let mut video_open = true;
        let mut audio_open = true;
        let mut proximity_open = true;
        let mut cancelled = false;

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.cancelled() => {
                    cancelled = true;
                }
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
                result = self.proximity_rx.recv(), if proximity_open => {
                    match result {
                        Some(witness) => self.process_proximity_egress(witness).await,
                        None => proximity_open = false,
                    }
                }
                _ = retry_tick.tick() => {
                    self.process_retry_queue().await;
                }
            }

            // Cancellation is an additional exit — the existing "all channels
            // closed AND retry queue empty" condition still holds for graceful
            // egress-channel-close shutdown. On cancel, pending retry-queue
            // items are abandoned; see the `shutdown` field doc comment.
            if cancelled {
                break;
            }
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

        // Persist locally so playback works without network round-trip.
        // Fire-and-forget — local storage failure doesn't block mesh distribution.
        {
            let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
            let _ = self
                .storage_tx
                .try_send(crate::actors::storage::StorageCommand::WriteShard {
                    envelope: envelope.clone(),
                    reply_to: reply_tx,
                });
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

        let class = if is_video { "video" } else { "audio" };
        self.publish_fountain_symbols(&topic, shard_id, chunks, class)
            .await;
    }

    /// Seal a proximity witness as a standalone `Evidence::Proximity` envelope
    /// and egress it on the recording's media path. Unlike media shards,
    /// proximity is signed corroboration metadata, not secret payload: no
    /// LensGate, no AEAD, no media hash-chain. Persisted locally (so it is
    /// archived with the recording) and fountain-published on the video topic so
    /// a custody Stronghold reassembles it and `collect_proximity` folds it into
    /// the `CorroborationProof`.
    #[allow(clippy::arithmetic_side_effects)] // Monotonic shard-id increment.
    async fn process_proximity_egress(&mut self, witness: ProximityWitness) {
        let envelope =
            match Evidence::Proximity(witness).seal(&self.identity, self.local_id.clone(), None) {
                Ok(env) => env,
                Err(e) => {
                    tracing::error!(event = "proximity_seal_failed", error = %e,
                        "Failed to seal proximity witness");
                    return;
                }
            };

        // Persist locally so the witness is archived alongside the recording's
        // shards (a directed archive push to a Stronghold includes it).
        {
            let (reply_tx, _reply_rx) = tokio::sync::oneshot::channel();
            let _ = self
                .storage_tx
                .try_send(crate::actors::storage::StorageCommand::WriteShard {
                    envelope: envelope.clone(),
                    reply_to: reply_tx,
                });
        }

        let envelope_bytes = match postcard::to_allocvec(&envelope) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!(event = "proximity_serialize_failed", error = %e,
                    "Failed to serialize proximity envelope");
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
                    "Failed to fountain-encode proximity witness");
                return;
            }
        };

        let topic = self.video_topic.clone();
        self.publish_fountain_symbols(&topic, shard_id, chunks, "proximity")
            .await;
    }

    // ── Media Egress Handlers ───────────────────────────────────────────

    /// LensGate provenance check + AEAD encryption.
    /// Returns `false` if the evidence must be dropped (provenance rejection or
    /// encryption failure — plaintext MUST NOT reach the mesh).
    fn gate_and_encrypt(&self, evidence: &mut Evidence) -> bool {
        // LensGate: verify sensor provenance BEFORE encryption.
        // Uses Bayesian posterior for luminance-conditioned PRNU floor.
        if let &mut Evidence::Video(ref v) = evidence {
            let posterior = self
                .prnu_posterior
                .lock()
                .map(|p| *p)
                .unwrap_or_else(|_| PrnuPosterior::new_uninformed());
            if let Err(e) = gate::check_provenance_bayesian(
                &v.lens_metrics,
                &posterior,
                gate::MOIRE_NATURAL_UPPER_BOUND * gate::MOIRE_SAFETY_FACTOR,
                phalanx_forensics::calibrate::PRNU_CONFIDENCE_SIGMA,
            ) {
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
                    tracing::error!(
                        "Video encryption failed — dropping shard to prevent plaintext broadcast: {e}"
                    );
                    return false;
                }
            }
            Evidence::Audio(a) => {
                if let Err(e) = a.payload.apply_encryption(&key) {
                    tracing::error!(
                        "Audio encryption failed — dropping shard to prevent plaintext broadcast: {e}"
                    );
                    return false;
                }
            }
            _ => {}
        }
        true
    }

    /// Publish fountain symbols as bundled gossipsub messages. Each publish
    /// carries `symbol_bundle_size` symbols (a `Vec<ShardChunk>`-encoded
    /// payload). Bundling amortizes the per-message processing cost on the
    /// libp2p path so the publisher's demand stays inside the per-peer queue's
    /// drain rate. On bundle-publish failure each chunk is enqueued
    /// individually to the WAL, preserving per-chunk retry semantics; the WAL
    /// on-disk format stays per-chunk for backward compatibility with
    /// pre-upgrade contents.
    async fn publish_fountain_symbols(
        &mut self,
        topic: &MeshTopic,
        shard_id: ShardId,
        chunks: Vec<phalanx_proto::evidence::ShardChunk>,
        class: &'static str,
    ) {
        let symbol_count = chunks.len();
        let mut published: usize = 0;
        let bundle_n = self.symbol_bundle_size.get() as usize;

        for batch in chunks.chunks(bundle_n) {
            // postcard serializes &[T] and Vec<T> identically (length-
            // prefixed sequence), so passing the slice avoids cloning the
            // symbols into a fresh Vec on the hot path.
            match postcard::to_allocvec(batch) {
                Ok(data) => {
                    if let Err(e) = self.egress.publish(topic, data).await {
                        tracing::error!(
                            event = "bundle_publish_failed",
                            shard_id = shard_id.0,
                            bundle_symbols = batch.len(),
                            error = %e,
                            "Failed to publish symbol bundle — enqueueing chunks for retry"
                        );
                        // Enqueue each chunk individually as single-chunk
                        // bytes. WAL format is unchanged (per-chunk records);
                        // process_retry_queue wraps each WAL chunk back into
                        // a length-1 bundle on republish.
                        for chunk in batch {
                            match postcard::to_allocvec(chunk) {
                                Ok(chunk_bytes) => {
                                    if let Err(wal_err) = self
                                        .outbound_queue
                                        .enqueue(
                                            topic.clone(),
                                            chunk_bytes,
                                            self.clock.now().unwrap_or_default(),
                                        )
                                        .await
                                    {
                                        tracing::error!(
                                            error = %wal_err,
                                            "Failed to persist chunk to OutboundQueue WAL"
                                        );
                                    }
                                }
                                Err(e) => {
                                    tracing::error!("Failed to re-serialize chunk for WAL: {e}")
                                }
                            }
                        }
                    } else {
                        published = published.saturating_add(batch.len());
                    }
                }
                Err(e) => tracing::error!("Failed to serialize symbol bundle: {e}"),
            }
        }

        tracing::debug!(
            event = "media_egress_complete",
            shard_id = shard_id.0,
            symbols_published = published,
            symbols_total = symbol_count,
            bundle_size = bundle_n,
            class = class,
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

            // WAL stores per-chunk bytes (postcard-encoded ShardChunk). The
            // wire format expects Vec<ShardChunk>, so wrap the WAL bytes in
            // a length-1 bundle before republishing. Retried chunks degrade
            // from bundled to one-publish-per-chunk on the rare retry path.
            let republish_bytes = match postcard::from_bytes::<phalanx_proto::evidence::ShardChunk>(
                &entry.envelope_bytes,
            ) {
                // Wrap in a length-1 slice (NOT a fixed-size array) so
                // postcard emits a length-prefixed sequence — matches the
                // Vec<ShardChunk> wire format that receivers deserialize.
                Ok(chunk) => match postcard::to_allocvec(std::slice::from_ref(&chunk)) {
                    Ok(bytes) => bytes,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            entry_id = entry.id.0,
                            "Failed to wrap WAL chunk into length-1 bundle; \
                             dropping retry"
                        );
                        let _ = self.outbound_queue.acknowledge(entry.id).await;
                        continue;
                    }
                },
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        entry_id = entry.id.0,
                        "Failed to deserialize WAL chunk; dropping retry"
                    );
                    let _ = self.outbound_queue.acknowledge(entry.id).await;
                    continue;
                }
            };

            if self
                .egress
                .publish(&entry.topic, republish_bytes)
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
