use std::collections::HashMap;
use tokio::time::Instant;
use tracing::{debug, instrument, warn};

use crate::primitives::identity::{NetworkId, PhalanxIdentity};
use crate::primitives::shards::{
    AudioShard, ChunkType, Evidence, ReassemblyBuffer, ShardChunk, ShardError, ShardId, VideoShard,
    WitnessEnvelope,
};

use crate::security::gate::BufferCapacityGate;

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::base::types::{MeshTopic, PowerState, TrafficGovernor, UnitInterval, VitalityRate};

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
    #[must_use]
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
        self.peer_contracts
            .insert(peer_id, VitalityRate::new(msg.heartbeat_ms));
        self.capacities.insert(peer_id, msg);
    }

    #[must_use]
    pub fn is_peer_stale(&self, peer_id: &NetworkId, physics: &PhalanxPhysics) -> bool {
        let last_time = match self.heartbeats.get(peer_id) {
            Some(t) => t,
            None => return true,
        };

        // Use the peer's reported interval, or fall back to physics default if unknown
        let default_load_factor = 0.0;
        let contract = self
            .peer_contracts
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| {
                VitalityRate::calculate(
                    physics,
                    PowerState::Normal,
                    UnitInterval::new(default_load_factor),
                )
            });

        // Apply physics jitter_factor to allow for network variance
        let grace_period = contract.as_duration() * physics.jitter_factor as u32;

        last_time.elapsed() > grace_period
    }
}

/// Standard default method.
impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ControlMessage {
    pub sender: NetworkId,
    pub load_factor: f32,
    pub storage_remaining_mb: u64,
    pub heartbeat_ms: u64,
    pub is_leaf: bool,
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
    #[must_use]
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
    #[must_use]
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
    ) -> Result<Option<WitnessEnvelope>, ShardError> {
        // 1. Governance Gate (Stateless hardware limit enforcement)
        if !self.governor.should_accept(&chunk.owner_did, &identity.did) {
            tracing::debug!(did = %chunk.owner_did, "TrafficGovernor: Rejecting foreign chunk in Leaf Mode");
            return Ok(None); // Benign load-shedding, not an error.
        }

        // 2. Route to correct buffer based on network topic
        let is_video = topic == &config.network.video_topic;

        let (buffers, capacity_limit) = if is_video {
            (&mut self.video_buffers, config.storage.max_video_buffer)
        } else {
            (&mut self.audio_buffers, config.storage.max_audio_buffer)
        };

        let shard_id = chunk.shard_id;

        // 3. Capacity Gate (OOM Defense via LRU Eviction)
        buffers.enforce_capacity_limit(&shard_id, capacity_limit)?;

        tracing::debug!(%shard_id, chunk_index = chunk.chunk_index, "Buffering chunk");
        let buffer = buffers
            .entry(shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        // 4. Update buffer state
        buffer.last_activity = Instant::now(); // todo: forensic now
        if chunk.chunk_index < chunk.total_chunks {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        // 5. Finalize if reassembly is complete
        if buffer.is_complete() {
            tracing::info!(%shard_id, "Reassembly complete. Finalizing evidence.");
            let raw_data = buffer.assemble();

            // Immediate cleanup of the completed buffer
            buffers.remove(&shard_id);

            match chunk.chunk_type {
                ChunkType::Witnessed => {
                    // Relayed envelope from the mesh
                    postcard::from_bytes::<WitnessEnvelope>(&raw_data)
                        .map(Some)
                        .map_err(|e| ShardError::Serialization(e.to_string()))
                }
                ChunkType::ForensicUnit => {
                    // Local raw data; wrap in an envelope
                    let evidence = if is_video {
                        postcard::from_bytes::<VideoShard>(&raw_data)
                            .map(Evidence::Video)
                            .map_err(|e| ShardError::Serialization(e.to_string()))?
                    } else {
                        postcard::from_bytes::<AudioShard>(&raw_data)
                            .map(Evidence::Audio)
                            .map_err(|e| ShardError::Serialization(e.to_string()))?
                    };

                    // Witness Gate: Fallible cryptographic seal
                    let envelope = WitnessEnvelope::new(evidence, identity, local_peer_id)?;
                    tracing::info!(%shard_id, "Successfully witnessed local forensic unit.");

                    Ok(Some(envelope))
                }
            }
        } else {
            Ok(None) // Assembly in progress
        }
    }
    /// Garbage collection for incomplete reassemblies that have timed out.
    pub fn prune_stale_buffers(&mut self, _config: &PhalanxConfig, physics: &PhalanxPhysics) {
        let timeout = physics.shard_timeout();

        self.video_buffers.retain(|id, buffer| {
            let active = buffer.last_activity.elapsed() < timeout;
            if !active {
                debug!(shard_id = %id, "Pruning stale video buffer");
            }
            active
        });

        self.audio_buffers.retain(|id, buffer| {
            let active = buffer.last_activity.elapsed() < timeout;
            if !active {
                debug!(shard_id = %id, "Pruning stale audio buffer");
            }
            active
        });
    }
}

#[cfg(test)]
mod leaf_mode_tests {
    use super::*;
    use std::error::Error;

    #[test]
    fn test_sentinel_leaf_mode_filtering() -> Result<(), Box<dyn Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let (stranger, _) = PhalanxIdentity::generate()?;
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
            chunk_type: ChunkType::Witnessed,
        };

        // 2. Local chunk (labeled as ForensicUnit/Raw)
        let local_chunk = ShardChunk {
            shard_id: ShardId(2),
            chunk_index: 0,
            total_chunks: 2,
            data: vec![4, 5, 6],
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::ForensicUnit,
        };

        // 3. Process Foreign
        let _ = sentinel.process_chunk(
            foreign_chunk,
            &config.network.video_topic,
            &config,
            &identity,
            local_peer.clone(),
        )?;

        assert_eq!(
            sentinel.video_buffers.len(),
            0,
            "Sentinel leaked foreign data in Leaf Mode"
        );

        // 4. Process Local
        let _ = sentinel.process_chunk(
            local_chunk,
            &config.network.video_topic,
            &config,
            &identity,
            local_peer,
        )?;

        assert_eq!(
            sentinel.video_buffers.len(),
            1,
            "Sentinel failed to process local data in Leaf Mode"
        );

        Ok(())
    }
}
