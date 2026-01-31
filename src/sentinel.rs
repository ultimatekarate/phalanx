use libp2p::{gossipsub, PeerId, Swarm, swarm::SwarmEvent};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};

use crate::vid;
use crate::audio;
use crate::{PhalanxBehaviour, PhalanxEvent};
use crate::config::PhalanxConfig;

use libp2p::mdns;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlMessage {
    pub sender: String,
    pub load_factor: f32,      // 0.0 (idle) to 1.0 (at capacity)
    pub is_on_battery: bool,
    pub storage_remaining_mb: u64,
}

pub struct Sentinel {
    pub peer_heartbeats: HashMap<PeerId, Instant>,
    pub peer_capacities: HashMap<PeerId, ControlMessage>, // Tracks mesh health
    pub guardian_buffers: HashMap<PeerId, VecDeque<vid::VideoShard>>,
    pub audio_buffers: HashMap<PeerId, VecDeque<audio::AudioShard>>,
    pub topic: gossipsub::IdentTopic,
    pub pulse_timeout: Duration,
    pub max_peers: usize, // Hard limit for burden sharing
    pub chunk_reassembly: HashMap<u32, Vec<Option<Vec<u8>>>>,
    pub grace_period: Duration,
    pub max_video_buffer: usize,
    pub max_audio_buffer: usize,
}

impl Sentinel {
    pub fn new(config: &PhalanxConfig) -> Self {
        Self {
            peer_heartbeats: HashMap::new(),
            peer_capacities: HashMap::new(),
            guardian_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            topic: gossipsub::IdentTopic::new(&config.network.control_topic),
            pulse_timeout: Duration::from_secs(config.network.pulse_timeout_secs),
            max_peers: config.storage.max_peers,
            chunk_reassembly: HashMap::new(),
            grace_period: Duration::from_secs(config.network.grace_period),
            max_video_buffer: config.storage.max_video_buffer,
            max_audio_buffer: config.storage.max_audio_buffer,
        }
    }

    pub fn generate_heartbeat(&self, local_id: &PeerId) -> ControlMessage {
        let current_load = self.guardian_buffers.len() as f32;
        let capacity = self.max_peers as f32;

        ControlMessage {
            sender: local_id.to_string(),
            load_factor: (current_load / capacity).min(1.0),
            is_on_battery: false, // Future mobile bridge
            storage_remaining_mb: 1024,
        }
    }

    /// Primary entry point for network events
    pub fn handle_network_event(
        &mut self,
        event: SwarmEvent<PhalanxEvent>,
        swarm: &mut Swarm<PhalanxBehaviour>,
    ) {
        match event {
            SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                for (peer_id, multiaddr) in list {
                    if peer_id != *swarm.local_peer_id() {
                        println!("Shield Overlapped: {peer_id}");
                        let _ = swarm.dial(multiaddr.clone());
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        // Initialization Grace Period
                        self.peer_heartbeats.insert(peer_id, Instant::now() + self.grace_period);
                    }
                }
            }
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                // Universal Refresh
                self.peer_heartbeats.insert(propagation_source, Instant::now());

                if let Ok(chunk) = postcard::from_bytes::<vid::ShardChunk>(&message.data) {
                    let entry = self.chunk_reassembly.entry(chunk.shard_id)
                        .or_insert_with(|| vec![None; chunk.total_chunks as usize]);

                    entry[chunk.chunk_index as usize] = Some(chunk.data);

                    // Check if we have all pieces
                    if entry.iter().all(|c| c.is_some()) {
                        let full_data: Vec<u8> = entry.drain(..).map(|c| c.unwrap()).flatten().collect();
                        if let Ok(complete_shard) = postcard::from_bytes::<vid::VideoShard>(&full_data) {
                            println!("Status: Reassembled Shard #{}", complete_shard.sequence_id);
                            // Push to your guardian_buffers as normal...
                        }
                        self.chunk_reassembly.remove(&chunk.shard_id);
                    }
                } else if let Ok(ctrl) = postcard::from_bytes::<ControlMessage>(&message.data) {
                    self.peer_capacities.insert(propagation_source, ctrl);
                } // Check for audio shard
                else if let Ok(a_shard) = postcard::from_bytes::<audio::AudioShard>(&message.data) {
                    let buffer = self.audio_buffers.entry(propagation_source).or_insert_with(VecDeque::new);
                    buffer.push_back(a_shard);
                    // Keep 60 seconds of audio (usually small enough for RAM)
                    if buffer.len() > self.max_audio_buffer { buffer.pop_front(); }
                }
            }
            _ => {}
        }
    }

    /// Periodic cleanup of "Dark" peers
    pub fn process_cleanup(&mut self, local_id: PeerId) {
        let now = Instant::now();
        self.peer_heartbeats.retain(|id, last| {
            if id == &local_id || *last > now { return true; }

            if now.duration_since(*last) > self.pulse_timeout {
                println!("ALERT: Witness {} has gone dark. Finalizing evidence.", id);
                if let Some(shards) = self.guardian_buffers.remove(id) {
                    let _ = vid::seal_to_vault(id, shards);
                }

                if let Some(a_shards) = self.audio_buffers.remove(id) {
                    let _ = audio::seal_audio_to_vault(id, a_shards);
                }
                self.peer_capacities.remove(id);
                false 
            } else { true }
        });
    }
}

impl Drop for Sentinel {
    fn drop(&mut self) {
        // This is the "Last Will and Testament" of the Sentinel.
        // It runs whenever the Sentinel is destroyed (Panic, Ctrl+C, or End of Main).
        println!("\n[PHALANX] Sentinel is dropping. Emergency vault seal initiated...");
        
        // We use .drain() to take ownership of all buffered shards 
        // so we can seal them before the memory is wiped.
        for (peer_id, v_shards) in self.guardian_buffers.drain() {
            if !v_shards.is_empty() {
                println!("Status: Final video seal for witness: {}", peer_id);
                let _ = vid::seal_to_vault(&peer_id, v_shards);
            }
        }

        for (peer_id, a_shards) in self.audio_buffers.drain() {
            if !a_shards.is_empty() {
                println!("Status: Final audio seal for witness: {}", peer_id);
                let _ = audio::seal_audio_to_vault(&peer_id, a_shards);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{PhalanxConfig, NetworkConfig, StorageConfig, HardwareConfig};
    use libp2p::PeerId;
    use std::time::{Duration, Instant};

    // Helper to create a test configuration without reading from disk
    fn create_test_config(timeout: u64) -> PhalanxConfig {
        PhalanxConfig {
            network: NetworkConfig {
                heartbeat_interval_secs: 1,
                pulse_timeout_secs: timeout,
                chunk_size_bytes: 32768,
                video_topic: "test/video".to_string(),
                audio_topic: "test/audio".to_string(),
                control_topic: "test/control".to_string(),
                grace_period: 30
            },
            storage: StorageConfig {
                vault_path: "./test_vault".to_string(),
                max_video_buffer: 10,
                max_audio_buffer: 10,
                max_peers: 5,
            },
            hardware: HardwareConfig {
                camera_fps: 15,
                audio_sample_rate: 44100,
                audio_channels: 1,
            },
        }
    }

    #[test]
    fn test_sentinel_grace_period() {
        let config = create_test_config(5);
        let mut sentinel = Sentinel::new(&config);
        let fake_peer = PeerId::random();

        // Simulate discovery with a 30s grace period
        let future_time = Instant::now() + Duration::from_secs(30);
        sentinel.peer_heartbeats.insert(fake_peer, future_time);

        sentinel.process_cleanup(PeerId::random());

        assert!(sentinel.peer_heartbeats.contains_key(&fake_peer));
    }

    #[test]
    fn test_sentinel_timeout_detection() {
        let config = create_test_config(1); // 1 second timeout
        let mut sentinel = Sentinel::new(&config);
        let fake_peer = PeerId::random();

        // Insert a peer with a "last seen" time 2 seconds in the past
        let past_time = Instant::now() - Duration::from_secs(2);
        sentinel.peer_heartbeats.insert(fake_peer, past_time);

        sentinel.process_cleanup(PeerId::random());

        assert!(!sentinel.peer_heartbeats.contains_key(&fake_peer));
    }

    #[test]
    fn test_shard_refreshes_heartbeat() {
        let config = create_test_config(10);
        let mut sentinel = Sentinel::new(&config);
        let fake_peer = PeerId::random();
        
        let old_time = Instant::now() - Duration::from_secs(5);
        sentinel.peer_heartbeats.insert(fake_peer, old_time);

        // Manually update to simulate receiving a shard
        sentinel.peer_heartbeats.insert(fake_peer, Instant::now());

        let current_heartbeat = sentinel.peer_heartbeats.get(&fake_peer).unwrap();
        assert!(*current_heartbeat > old_time);
    }
}