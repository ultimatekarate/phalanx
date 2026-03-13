use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::gate::WitnessGate;
use phalanx_forensics::reassembler::FountainChunkifier;
use phalanx_proto::evidence::{AudioShard, ChunkType, Evidence, SignatureHash, VideoShard};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, ShardId};
use phalanx_proto::prelude::*;
use phalanx_transport::EgressPort;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Configuration bundle for MediaEgressActor construction.
/// Groups topic routing, encoding, and channel parameters to keep `new()` ergonomic.
pub struct MediaEgressConfig {
    pub video_rx: mpsc::Receiver<VideoShard>,
    pub audio_rx: mpsc::Receiver<AudioShard>,
    pub video_topic: MeshTopic,
    pub audio_topic: MeshTopic,
    pub symbol_size: SymbolSize,
    pub repair_ratio: RepairRatio,
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
    /// Monotonic shard ID counter. Each sealed envelope gets a unique ShardId
    /// so the receiver's Crucible can track reassembly contexts independently.
    next_shard_id: u64,
}

impl<E: EgressPort> MediaEgressActor<E> {
    pub fn new(
        egress: E,
        identity: Arc<PhalanxIdentity>,
        local_id: NetworkId,
        config: MediaEgressConfig,
    ) -> Self {
        Self {
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
            next_shard_id: 0,
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(shard) = self.video_rx.recv() => {
                    self.process_media_egress(Evidence::Video(shard), true).await;
                }
                Some(shard) = self.audio_rx.recv() => {
                    self.process_media_egress(Evidence::Audio(shard), false).await;
                }
                else => break,
            }
        }
    }

    async fn process_media_egress(&mut self, evidence: Evidence, is_video: bool) {
        let topic = match &evidence {
            Evidence::Video(_) => &self.video_topic,
            Evidence::Audio(_) => &self.audio_topic,
            _ => {
                tracing::warn!("Unexpected evidence type for media egress");
                return;
            }
        };

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

        // Serialize the sealed envelope
        let envelope_bytes = match postcard::to_allocvec(&envelope) {
            Ok(data) => data,
            Err(e) => {
                tracing::error!("Failed to serialize media envelope: {}", e);
                return;
            }
        };

        // Fountain-encode into ShardChunks.
        // Each symbol is self-describing (12-byte OTI prefix) so the receiver
        // can initialize the decoder from ANY received symbol.
        let shard_id = ShardId(self.next_shard_id);
        self.next_shard_id += 1;

        let chunks = match envelope_bytes.fountain_chunkify(
            shard_id,
            self.identity.did.clone(),
            self.symbol_size,
            ChunkType::Witnessed,
            self.repair_ratio,
        ) {
            Ok(chunks) => chunks,
            Err(e) => {
                tracing::error!(event = "fountain_encode_failed", error = %e,
                    "Failed to fountain-encode evidence");
                return;
            }
        };

        // Publish each fountain symbol as a separate gossipsub message.
        // The receiver's ingestion pipeline deserializes each as a ShardChunk
        // and feeds it to the Reassembler's fountain decoder.
        let symbol_count = chunks.len();
        let mut published = 0;
        for chunk in chunks {
            match postcard::to_allocvec(&chunk) {
                Ok(data) => {
                    if let Err(e) = self.egress.publish(topic, data).await {
                        tracing::error!(
                            event = "symbol_publish_failed",
                            shard_id = shard_id.0,
                            symbol = published,
                            error = %e,
                            "Failed to publish fountain symbol"
                        );
                        // TODO: enqueue to OutboundQueue for retry
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
}
