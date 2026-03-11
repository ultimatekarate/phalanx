use phalanx_proto::evidence::{AudioShard, Evidence, VideoShard};
use phalanx_proto::identity::NetworkId;
use phalanx_proto::prelude::*;
use phalanx_transport::EgressPort;
use tokio::sync::mpsc;

pub struct MediaEgressActor<E: EgressPort> {
    egress: E,
    video_rx: mpsc::Receiver<VideoShard>,
    audio_rx: mpsc::Receiver<AudioShard>,
    video_topic: MeshTopic,
    audio_topic: MeshTopic,
    local_id: NetworkId,
}

impl<E: EgressPort> MediaEgressActor<E> {
    pub fn new(
        egress: E,
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
            local_id,
        }
    }

    pub async fn run(mut self) {
        loop {
            tokio::select! {
                Some(shard) = self.video_rx.recv() => {
                    self.process_media_egress(Evidence::Video(shard)).await;
                }
                Some(shard) = self.audio_rx.recv() => {
                    self.process_media_egress(Evidence::Audio(shard)).await;
                }
                else => break,
            }
        }
    }

    async fn process_media_egress(&self, evidence: Evidence) {
        let topic = match &evidence {
            Evidence::Video(_) => &self.video_topic,
            Evidence::Audio(_) => &self.audio_topic,
            _ => {
                tracing::warn!("Unexpected evidence type for media egress");
                return;
            }
        };

        match postcard::to_allocvec(&evidence) {
            Ok(data) => {
                if let Err(e) = self.egress.publish(topic, data).await {
                    tracing::error!("Failed to publish media egress: {}", e);
                }
            }
            Err(e) => tracing::error!("Failed to serialize media evidence: {}", e),
        }
    }
}
