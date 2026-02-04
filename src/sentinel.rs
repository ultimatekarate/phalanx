use std::collections::HashMap;
use tokio::time::Instant;
use tracing::{info, warn, debug, instrument};

use crate::shards::{
    Evidence, VideoShard, ReassemblyBuffer, ShardChunk, 
    ShardId, WitnessEnvelope
};
use crate::audio::AudioShard;
use crate::config::PhalanxConfig;
use crate::identity::{NetworkId, PhalanxIdentity};

// =====================
// HEALTH & CAPACITY
// =====================

/// Tracks peer vitality and their reported resource availability.
pub struct HealthTracker {
    pub heartbeats: HashMap<NetworkId, Instant>,
    pub capacities: HashMap<NetworkId, ControlMessage>,
    pub pulse_timeout: std::time::Duration,
}

impl HealthTracker {
    pub fn new(config: &PhalanxConfig) -> Self {
        Self {
            heartbeats: HashMap::new(),
            capacities: HashMap::new(),
            pulse_timeout: std::time::Duration::from_secs(config.network.pulse_timeout_secs),
        }
    }

    pub fn register_activity(&mut self, peer_id: NetworkId) {
        self.heartbeats.insert(peer_id, Instant::now());
    }

    pub fn is_peer_stale(&self, peer_id: &NetworkId) -> bool {
        self.heartbeats.get(peer_id)
            .map(|t| t.elapsed() > self.pulse_timeout)
            .unwrap_or(true)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlMessage {
    pub sender: NetworkId,
    pub load_factor: f32,
    pub storage_remaining_mb: u64,
}

// =====================
// SENTINEL CORE
// =====================

pub struct Sentinel {
    pub video_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub audio_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub health_tracker: HealthTracker,
}

impl Sentinel {
    pub fn new(config: &PhalanxConfig) -> Self {
        Self {
            video_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            health_tracker: HealthTracker::new(config),
        }
    }

    /// Primary entry point for reassembling network chunks into signed Evidence.
    #[instrument(skip(self, identity, chunk), level = "debug")]
    pub fn process_chunk(
        &mut self,
        chunk: ShardChunk,
        topic: &str,
        config: &PhalanxConfig,
        identity: &PhalanxIdentity,
        local_peer_id: NetworkId,
    ) -> Option<WitnessEnvelope> {
        // 1. Route to correct buffer based on network topic
        let is_video = topic == config.network.video_topic;
        let buffers = if is_video {
            &mut self.video_buffers
        } else {
            &mut self.audio_buffers
        };

        let shard_id = chunk.shard_id;
        let buffer = buffers
            .entry(shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        // 2. Update buffer state
        buffer.last_activity = Instant::now();
        if chunk.chunk_index < chunk.total_chunks {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        // 3. Finalize if reassembly is complete
        if buffer.is_complete() {
            debug!(%shard_id, "Reassembly complete. Finalizing evidence.");
            let data = buffer.assemble();
            
            let evidence = if is_video {
                postcard::from_bytes::<VideoShard>(&data).ok().map(Evidence::Video)
            } else {
                postcard::from_bytes::<AudioShard>(&data).ok().map(Evidence::Audio)
            };

            // Immediate cleanup of the completed buffer
            buffers.remove(&shard_id);

            if let Some(ev) = evidence {
                info!(%shard_id, "Successfully witnessed forensic unit.");
                return Some(WitnessEnvelope::new(ev, identity, local_peer_id));
            } else {
                warn!(%shard_id, "Deserialization failed for reassembled shard.");
            }
        }

        None
    }

    /// Garbage collection for incomplete reassemblies that have timed out.
    pub fn prune_stale_buffers(&mut self, config: &PhalanxConfig) {
        let timeout = std::time::Duration::from_secs(config.network.grace_period);

        self.video_buffers.retain(|id, buffer| {
            let active = buffer.last_activity.elapsed() < timeout;
            if !active { debug!(shard_id = %id, "Pruning stale video buffer"); }
            active
        });

        self.audio_buffers.retain(|id, buffer| {
            let active = buffer.last_activity.elapsed() < timeout;
            if !active { debug!(shard_id = %id, "Pruning stale audio buffer"); }
            active
        });
    }
}