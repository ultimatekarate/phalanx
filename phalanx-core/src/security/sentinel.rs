use std::collections::HashMap;

use tokio::time::Instant;
use tracing::{info, warn, debug, instrument};

use crate::protocol::shards::{
    Evidence, VideoShard, AudioShard, ReassemblyBuffer, ShardChunk, 
    ShardId, WitnessEnvelope, ChunkType
};

use crate::core::types::{MeshTopic, PowerState, TrafficGovernor, UnitInterval, VitalityRate};

use crate::core::config::{PhalanxPhysics, PhalanxConfig};
use crate::security::identity::{NetworkId, PhalanxIdentity};

// =====================
// HEALTH & CAPACITY
// =====================
/// Tracks peer vitality and their reported resource availability.
pub struct HealthTracker {
    pub heartbeats: HashMap<NetworkId, Instant>,
    pub capacities: HashMap<NetworkId, ControlMessage>,
    pub peer_contracts: HashMap<NetworkId, VitalityRate>,
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
        self.peer_contracts.insert(peer_id, VitalityRate::new(msg.heartbeat_ms));
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
            .unwrap_or_else(|| {
                VitalityRate::calculate(physics, PowerState::Normal, UnitInterval::new(default_load_factor))
            });

        // Apply physics jitter_factor to allow for network variance
        let grace_period = contract.as_duration() * physics.jitter_factor as u32;
        
        last_time.elapsed() > grace_period
    }   
}
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlMessage {
    pub sender: NetworkId,
    pub load_factor: f32,
    pub storage_remaining_mb: u64,
    pub heartbeat_ms: u64,
    pub is_leaf: bool
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
    pub governor: TrafficGovernor,
    pub video_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub audio_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub health_tracker: HealthTracker,
    pub peer_registry: Vec<NetworkId>,
    pub power_state: PowerState,
    pub battery_level: UnitInterval,
}

impl Sentinel {
    pub fn new(_config: &PhalanxConfig) -> Self {
        Self {
            video_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            health_tracker: HealthTracker::new(),
            peer_registry: Vec::new(),
            power_state: PowerState::Normal,
            battery_level: UnitInterval::new(1.0),
            governor: TrafficGovernor::new(),
        }
    }

    // Automatically adjusts the internal PowerState based on environmental data.
    pub fn update_power_strategy(&mut self) {
        let battery = self.get_system_battery();

        let target_state = if battery.is_critical() {
            PowerState::Leaf
        } else {
            PowerState::Normal
        };

        if self.power_state != target_state {
            warn!(battery = %battery, old = ?self.power_state, new = ?target_state, "Power strategy shift");
            self.power_state = target_state;

            self.governor.set_state(target_state);
        }
    }

    // Returns true if the node should ignore all foreign traffic.
    pub fn is_leaf_mode(&self) -> bool {
        self.power_state == PowerState::Leaf
    }

    fn get_system_battery(&self) -> UnitInterval {
        // Current Simulation: 80% (Normal Mode)
        // Change to < 0.15 to test Leaf Mode logic.
        UnitInterval::new(0.80) 
    }

    pub fn set_power_state(&mut self, state: PowerState) {
        if self.power_state != state {
            warn!(new_state = ?state, "Sentinel power state transition");
            self.power_state = state;

            self.governor.set_state(state);
        }
    }

    /// Primary entry point for reassembling network chunks into signed Evidence.
    #[instrument(skip(self, identity, chunk), level = "debug")]
    pub fn process_chunk(
        &mut self,
        chunk: ShardChunk,
        topic: &MeshTopic,
        config: &PhalanxConfig,
        identity: &PhalanxIdentity,
        local_peer_id: NetworkId,
    ) -> Option<WitnessEnvelope> {
        if !self.governor.should_accept(&chunk.owner_did, &identity.did) {
            debug!(did = %chunk.owner_did, "TrafficGovernor: Rejecting foreign chunk in Leaf Mode");
            return None;
        }
        // 1. Route to correct buffer based on network topic
        let is_video = topic == &config.network.video_topic;
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
            let raw_data = buffer.assemble();

            // Immediate cleanup of the completed buffer
            buffers.remove(&shard_id);

            match chunk.chunk_type {
                ChunkType::Witnessed => {
                    // This was a relayed envelope from the mesh; deserialize as such
                    postcard::from_bytes::<WitnessEnvelope>(&raw_data).ok()
                }
                ChunkType::ForensicUnit => {
                    // This was local raw data; we must wrap it in an envelope now
                    let evidence = if is_video {
                        postcard::from_bytes::<VideoShard>(&raw_data).ok().map(Evidence::Video)
                    } else {
                        postcard::from_bytes::<AudioShard>(&raw_data).ok().map(Evidence::Audio)
                    };

                    if let Some(ev) = evidence {
                        info!(%shard_id, "Successfully witnessed local forensic unit.");
                        Some(WitnessEnvelope::new(ev, identity, local_peer_id))
                    } else {
                        warn!(%shard_id, "Deserialization failed for reassembled raw shard.");
                        None
                    }
                }
            }
        } else { 
            None
        }
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

#[cfg(test)]
mod leaf_mode_tests {
    use super::*;

    #[test]
    fn test_sentinel_leaf_mode_filtering() {
        let (identity, _) = PhalanxIdentity::generate();
        let (stranger, _) = PhalanxIdentity::generate();
        let config = PhalanxConfig::default();
        let local_peer = NetworkId::random();
        
        let mut sentinel = Sentinel::new(&config);
        sentinel.set_power_state(PowerState::Leaf);

        // 1. Foreign chunk (labeled as Witnessed/Relayed)
        let foreign_chunk = ShardChunk {
            shard_id: ShardId(1),
            chunk_index: 0,
            total_chunks: 2,
            data: vec![1, 2, 3],
            owner_did: stranger.did.clone(),
            chunk_type: ChunkType::Witnessed, // Corrected
        };

        // 2. Local chunk (labeled as ForensicUnit/Raw)
        let local_chunk = ShardChunk {
            shard_id: ShardId(2),
            chunk_index: 0,
            total_chunks: 2,
            data: vec![4, 5, 6],
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::ForensicUnit, // Added
        };

        // 3. Process Foreign
        sentinel.process_chunk(foreign_chunk, &config.network.video_topic, &config, &identity, local_peer);
        assert_eq!(sentinel.video_buffers.len(), 0, "Sentinel leaked foreign data in Leaf Mode");

        // 4. Process Local
        sentinel.process_chunk(local_chunk, &config.network.video_topic, &config, &identity, local_peer);
        assert_eq!(sentinel.video_buffers.len(), 1, "Sentinel failed to process local data in Leaf Mode");
    }
}