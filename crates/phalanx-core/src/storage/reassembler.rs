use std::collections::HashMap;
use tokio::io::AsyncWriteExt;
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
// REASSEMBLER CORE
// =====================

pub struct Reassembler {
    pub governor: TrafficGovernor,
    pub video_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub audio_buffers: HashMap<ShardId, ReassemblyBuffer>,
    pub health_tracker: HealthTracker,
    pub peer_registry: Vec<NetworkId>,
    pub power_state: PowerState,
    pub battery_level: UnitInterval,
}

impl Reassembler {
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
            warn!(new_state = ?state, "Reassembler power state transition");
            self.power_state = state;

            self.governor.set_state(state);
        }
    }

    /// Primary entry point for reassembling network chunks into signed Evidence.
    /// Primary entry point for reassembling network chunks into signed Evidence.
    #[instrument(skip(self, identity, chunk), level = "debug")]
    pub async fn process_chunk(
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

        // 2. WAL Integration: State Serialization and Disk Flush
        let serialized_chunk_bytes = postcard::to_allocvec(&chunk)
            .map_err(|err| ShardError::Serialization(err.to_string()))?;

        let payload_byte_length = serialized_chunk_bytes.len() as u32;

        let mut wal_file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open("crucible_wal.bin")
            .await
            .map_err(ShardError::Io)?;

        // Append 4-byte Little-Endian prefix followed by the exact payload
        wal_file
            .write_all(&payload_byte_length.to_le_bytes())
            .await
            .map_err(ShardError::Io)?;
        wal_file
            .write_all(&serialized_chunk_bytes)
            .await
            .map_err(ShardError::Io)?;

        // Enforce physical disk synchronization before memory promotion
        wal_file.sync_data().await.map_err(ShardError::Io)?;

        // 3. Route to correct buffer based on network topic
        let is_video = topic == &config.network.video_topic;

        let (buffers, capacity_limit) = if is_video {
            (&mut self.video_buffers, config.storage.max_video_buffer)
        } else {
            (&mut self.audio_buffers, config.storage.max_audio_buffer)
        };

        let shard_id = chunk.shard_id;

        // 4. Capacity Gate (OOM Defense via LRU Eviction)
        buffers.enforce_capacity_limit(&shard_id, capacity_limit)?;

        tracing::debug!(%shard_id, chunk_index = chunk.chunk_index, "Buffering chunk");
        let buffer = buffers
            .entry(shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        // 5. Update buffer state
        buffer.last_activity = Instant::now(); // Note: Pending TrustedClock forensic_now() integration
        if chunk.chunk_index < chunk.total_chunks {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        // 6. Finalize if reassembly is complete
        if buffer.is_complete() {
            tracing::info!(%shard_id, "Reassembly complete. Finalizing evidence.");
            let reassembled_raw_data = buffer.assemble();

            // Immediate cleanup of the completed buffer to free transient memory
            buffers.remove(&shard_id);

            match chunk.chunk_type {
                ChunkType::Witnessed => {
                    // Relayed envelope from the mesh
                    postcard::from_bytes::<WitnessEnvelope>(&reassembled_raw_data)
                        .map(Some)
                        .map_err(|err| ShardError::Serialization(err.to_string()))
                }
                ChunkType::ForensicUnit => {
                    // Local raw data; reconstruct the internal struct
                    let evidence = if is_video {
                        postcard::from_bytes::<VideoShard>(&reassembled_raw_data)
                            .map(Evidence::Video)
                            .map_err(|err| ShardError::Serialization(err.to_string()))?
                    } else {
                        postcard::from_bytes::<AudioShard>(&reassembled_raw_data)
                            .map(Evidence::Audio)
                            .map_err(|err| ShardError::Serialization(err.to_string()))?
                    };

                    // 7. Witness Gate: Fallible cryptographic seal
                    let witness_envelope = WitnessEnvelope::new(evidence, identity, local_peer_id)?;
                    tracing::info!(%shard_id, "Successfully witnessed local forensic unit.");

                    Ok(Some(witness_envelope))
                }
            }
        } else {
            Ok(None) // Assembly remains in progress
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

    /// Internal method strictly for WAL replay. Bypasses the Governor and WAL append.
    pub fn replay_chunk(
        &mut self,
        chunk: ShardChunk,
        config: &PhalanxConfig,
        identity: &PhalanxIdentity,
        local_peer_id: NetworkId,
    ) -> Result<Option<WitnessEnvelope>, ShardError> {
        let is_video = chunk.chunk_type == ChunkType::Witnessed; // Adjust based on your topic/type mapping

        let (buffers, capacity_limit) = if is_video {
            (&mut self.video_buffers, config.storage.max_video_buffer)
        } else {
            (&mut self.audio_buffers, config.storage.max_audio_buffer)
        };

        let shard_id = chunk.shard_id;

        // Capacity Gate (OOM Defense)
        buffers.enforce_capacity_limit(&shard_id, capacity_limit)?;

        let buffer = buffers
            .entry(shard_id)
            .or_insert_with(|| ReassemblyBuffer::new(chunk.total_chunks as usize));

        buffer.last_activity = Instant::now();
        if chunk.chunk_index < chunk.total_chunks {
            buffer.chunks[chunk.chunk_index as usize] = Some(chunk.data);
        }

        if buffer.is_complete() {
            let reassembled_raw_data = buffer.assemble();
            buffers.remove(&shard_id);

            match chunk.chunk_type {
                ChunkType::Witnessed => {
                    postcard::from_bytes::<WitnessEnvelope>(&reassembled_raw_data)
                        .map(Some)
                        .map_err(|err| ShardError::Serialization(err.to_string()))
                }
                ChunkType::ForensicUnit => {
                    let evidence = if is_video {
                        postcard::from_bytes::<VideoShard>(&reassembled_raw_data)
                            .map(Evidence::Video)
                            .map_err(|err| ShardError::Serialization(err.to_string()))?
                    } else {
                        postcard::from_bytes::<AudioShard>(&reassembled_raw_data)
                            .map(Evidence::Audio)
                            .map_err(|err| ShardError::Serialization(err.to_string()))?
                    };

                    WitnessEnvelope::new(evidence, identity, local_peer_id).map(Some)
                }
            }
        } else {
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;

    use crate::primitives::time::PhalanxTimestamp;
    use crate::primitives::shards::{VolleyId, DataPayload, StorageSequence};

#[tokio::test]
    async fn test_reassembler_replay_chunk_reassembly() {
        let (identity, _) = PhalanxIdentity::generate().unwrap();
        let config = PhalanxConfig::default();
        let mut reassembler = Reassembler::new(&config);
        let local_peer = identity.to_network_id();

        // 1. Create a valid, fully-populated VideoShard
        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(), 
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("id"), // Or VolleyId(0)
            payload:DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        });

        // 2. Wrap in an envelope and sign it (This provides valid bytes for postcard)
        let original_envelope = WitnessEnvelope::new(
            evidence, 
            &identity, 
            local_peer.clone()
        ).expect("Failed to sign envelope");
        
        let serialized_envelope = postcard::to_stdvec(&original_envelope)
            .expect("Failed to serialize envelope");
        
        // 3. Shard the serialized bytes into two halves
        let mid = serialized_envelope.len() / 2;
        let (part1, part2) = serialized_envelope.split_at(mid);

        let chunk_1 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 0,
            total_chunks: 2,
            data: part1.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        let chunk_2 = ShardChunk {
            shard_id: ShardId(99),
            chunk_index: 1,
            total_chunks: 2,
            data: part2.to_vec(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };

        // 4. Execute Replay Flow
        let result_1 = reassembler.replay_chunk(chunk_1, &config, &identity, local_peer.clone()).unwrap();
        assert!(result_1.is_none(), "Buffer should be pending after first chunk");

        let result_2 = reassembler.replay_chunk(chunk_2, &config, &identity, local_peer).unwrap();
        
        // 5. Final Verification
        assert!(result_2.is_some(), "Reassembly should be complete");
        let recovered_envelope = result_2.unwrap();
        
        // Assert cryptographic integrity survived the sharding/replay process
        assert_eq!(recovered_envelope.witness_signature, original_envelope.witness_signature);
        assert_eq!(reassembler.video_buffers.len(), 0, "Memory leak: Buffer not cleared");
    }

    #[tokio::test]
    async fn test_reassembler_leaf_mode_filtering() -> Result<(), Box<dyn Error>> {
        let (identity, _) = PhalanxIdentity::generate()?;
        let (stranger, _) = PhalanxIdentity::generate()?;
        let config = PhalanxConfig::default();
        let local_peer = NetworkId::random();

        let mut reassembler = Reassembler::new(&config);
        reassembler.set_power_state(PowerState::Leaf);

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
        let _ = reassembler
            .process_chunk(
                foreign_chunk,
                &config.network.video_topic,
                &config,
                &identity,
                local_peer.clone(),
            )
            .await?;

        assert_eq!(
            reassembler.video_buffers.len(),
            0,
            "Reassembler leaked foreign data in Leaf Mode"
        );

        // 4. Process Local
        let _ = reassembler
            .process_chunk(
                local_chunk,
                &config.network.video_topic,
                &config,
                &identity,
                local_peer,
            )
            .await?;

        assert_eq!(
            reassembler.video_buffers.len(),
            1,
            "Reassembler failed to process local data in Leaf Mode"
        );

        Ok(())
    }
}
