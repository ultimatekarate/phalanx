use libp2p::identity;
use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::gate::WitnessGate;
use phalanx_proto::evidence::{AudioShard, Evidence, SignatureHash, VideoShard};
use phalanx_proto::identity::NetworkId;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::prelude::*;
use phalanx_transport::EgressPort;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::hardware::audio;

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
}

impl<E: EgressPort> MediaEgressActor<E> {
    pub fn new(
        egress: E,
        identity: Arc<PhalanxIdentity>,
        video_rx: mpsc::Receiver<VideoShard>,
        audio_rx: mpsc::Receiver<AudioShard>,
        video_topic: MeshTopic,
        audio_topic: MeshTopic,
        local_id: NetworkId,
    ) -> Self {
        Self {
            egress,
            video_rx,
            audio_rx,
            video_topic,
            audio_topic,
            identity,
            local_id,
            video_prev_hash: None,
            audio_prev_hash: None,
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

        match postcard::to_allocvec(&envelope) {
            Ok(data) => {
                if let Err(e) = self.egress.publish(topic, data).await {
                    tracing::error!("Failed to publish media egress: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to serialize media envelope: {}", e),
        }
    }
}
