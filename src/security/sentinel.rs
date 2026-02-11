use std::collections::HashMap;

use tokio::time::{Instant, Duration};
use tracing::{info, warn, debug, instrument};

use crate::protocol::shards::{
    Evidence, VideoShard, AudioShard, ReassemblyBuffer, ShardChunk, 
    ShardId, WitnessEnvelope
};

use crate::core::config::{PhalanxPhysics, PhalanxConfig};
use crate::security::identity::{NetworkId, PhalanxIdentity};

// =====================
// HEALTH & CAPACITY
// =====================
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PowerState {
    Normal,
    Leaf, // Focus strictly on self-preservation
}

/// Tracks peer vitality and their reported resource availability.
pub struct HealthTracker {
    pub heartbeats: HashMap<NetworkId, Instant>,
    pub capacities: HashMap<NetworkId, ControlMessage>,
    pub peer_contracts: HashMap<NetworkId, Duration>,
}

impl HealthTracker {
    pub fn new() -> Self {
        Self {
            heartbeats: HashMap::new(),
            capacities: HashMap::new(),
            peer_contracts: HashMap::new(),
        }
    }

    pub fn register_activity(&mut self, msg: ControlMessage) {
        let peer_id = msg.sender;
        self.heartbeats.insert(peer_id, Instant::now());
        self.peer_contracts.insert(peer_id, Duration::from_millis(msg.heartbeat_ms));
        self.capacities.insert(peer_id, msg);
    }

    pub fn is_peer_stale(&self, peer_id: &NetworkId, physics: &PhalanxPhysics) -> bool {
        let last_time = match self.heartbeats.get(peer_id) {
            Some(t) => t,
            None => return true,
        };

        // Use the peer's reported interval, or fall back to physics default if unknown
        let default_load_factor = 0.0;
        let contract = self.peer_contracts.get(peer_id)
            .cloned()
            .unwrap_or_else(|| physics.heartbeat_interval(default_load_factor));

        // Apply physics jitter_factor to allow for network variance
        let grace_period = contract * physics.jitter_factor as u32;
        
        last_time.elapsed() > grace_period
    }   
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlMessage {
    pub sender: NetworkId,
    pub load_factor: f32,
    pub storage_remaining_mb: u64,
    pub heartbeat_ms: u64
}

/// Tracks the behavior and resource usage of remote peers
#[derive(Debug, Default)]
pub struct PeerReputation {
    pub active_buffers: usize,
    pub invalid_sigs: u32,
    pub total_shards_sent: u64,
    pub last_seen_load: f32,
    pub is_blacklisted: bool,
}

// =====================
// SENTINEL CORE
// =====================

pub struct Sentinel {
    pub video_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub audio_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub health_tracker: HealthTracker,
    pub peer_registry: Vec<NetworkId>,
    pub power_state: PowerState,
}

impl Sentinel {
    pub fn new(_config: &PhalanxConfig) -> Self {
        Self {
            video_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            health_tracker: HealthTracker::new(),
            peer_registry: Vec::new(),
            power_state: PowerState::Normal,
        }
    }

    pub fn set_power_state(&mut self, state: PowerState) {
        if self.power_state != state {
            warn!(new_state = ?state, "Sentinel power state transition");
            self.power_state = state;
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
        if self.power_state == PowerState::Leaf && chunk.owner_did != identity.did {
            debug!(did = %chunk.owner_did, "Leaf Mode: Dropping foreign chunk to save battery");
            return None;
        }

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
    pub fn prune_stale_buffers(&mut self, _config: &PhalanxConfig, physics: &PhalanxPhysics) {
        let timeout = physics.shard_timeout();

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