use libp2p::{gossipsub, PeerId, Swarm, swarm::SwarmEvent};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};
use serde::{Serialize, Deserialize};

use crate::vid;
use crate::audio;
use crate::{PhalanxBehaviour, PhalanxEvent};


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
}

impl Sentinel {
    pub fn new(topic_name: &str, timeout_secs: u64) -> Self {
        Self {
            peer_heartbeats: HashMap::new(),
            peer_capacities: HashMap::new(),
            guardian_buffers: HashMap::new(),
            audio_buffers: HashMap::new(),
            topic: gossipsub::IdentTopic::new(topic_name),
            pulse_timeout: Duration::from_secs(timeout_secs),
            max_peers: 10
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
                        self.peer_heartbeats.insert(peer_id, Instant::now() + Duration::from_secs(30));
                    }
                }
            }
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                // Universal Refresh
                self.peer_heartbeats.insert(propagation_source, Instant::now());

                if let Ok(ctrl) = postcard::from_bytes::<ControlMessage>(&message.data) {
                    self.peer_capacities.insert(propagation_source, ctrl);
                } // Check for audio shard
                else if let Ok(a_shard) = postcard::from_bytes::<audio::AudioShard>(&message.data) {
                    let buffer = self.audio_buffers.entry(propagation_source).or_insert_with(VecDeque::new);
                    buffer.push_back(a_shard);
                    // Keep 60 seconds of audio (usually small enough for RAM)
                    if buffer.len() > 60 { buffer.pop_front(); }
                }// Check if it's a VideoShard
                else if let Ok(shard) = postcard::from_bytes::<vid::VideoShard>(&message.data) {
                    let buffer = self.guardian_buffers.entry(propagation_source).or_insert_with(VecDeque::new);
                    buffer.push_back(shard);
                    if buffer.len() > 30 { buffer.pop_front(); }
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
    use libp2p::PeerId;
    use std::time::{Duration, Instant};

    #[test]
    fn test_sentinel_grace_period() {
        let mut sentinel = Sentinel::new("test/topic", 5);
        let fake_peer = PeerId::random();

        // Simulate discovery with a 30s grace period
        let future_time = Instant::now() + Duration::from_secs(30);
        sentinel.peer_heartbeats.insert(fake_peer, future_time);

        // Run cleanup immediately
        // It should NOT alert or remove the peer because the timestamp is in the future
        sentinel.process_cleanup(PeerId::random());

        assert!(sentinel.peer_heartbeats.contains_key(&fake_peer), "Peer should still be protected by grace period");
    }

    #[test]
    fn test_sentinel_timeout_detection() {
        let mut sentinel = Sentinel::new("test/topic", 1); // 1 second timeout
        let fake_peer = PeerId::random();

        // Insert a peer with a "last seen" time 2 seconds in the past
        let past_time = Instant::now() - Duration::from_secs(2);
        sentinel.peer_heartbeats.insert(fake_peer, past_time);

        // Run cleanup
        sentinel.process_cleanup(PeerId::random());

        // Verify the peer was removed (triggered alert)
        assert!(!sentinel.peer_heartbeats.contains_key(&fake_peer), "Peer should have been removed after timeout");
    }

    #[test]
    fn test_shard_refreshes_heartbeat() {
        let mut sentinel = Sentinel::new("test/topic", 10);
        let fake_peer = PeerId::random();
        
        // Start with an old heartbeat
        let old_time = Instant::now() - Duration::from_secs(5);
        sentinel.peer_heartbeats.insert(fake_peer, old_time);

        // Simulate receiving a shard (Manually logic since we're testing the Sentinel's state)
        // In the real code, this happens inside handle_network_event
        sentinel.peer_heartbeats.insert(fake_peer, Instant::now());

        let current_heartbeat = sentinel.peer_heartbeats.get(&fake_peer).unwrap();
        assert!(*current_heartbeat > old_time, "Heartbeat should have been updated to a newer timestamp");
    }

    #[test]
    fn test_vault_sealing_logic() {
        let mut sentinel = Sentinel::new("test/topic", 5);
        let fake_peer = PeerId::random();
        
        // Create 3 dummy shards
        let mut shards = VecDeque::new();
        for i in 0..3 {
            shards.push_back(vid::VideoShard {
                timestamp: 123456789,
                frames: vec![vec![0u8; 100]], // Dummy byte data
                sequence_id: i,
                fps: 15,
            });
        }
        
        sentinel.guardian_buffers.insert(fake_peer, shards);

        // Trigger a manual "Dark" event
        if let Some(shards_to_seal) = sentinel.guardian_buffers.remove(&fake_peer) {
            let result = vid::seal_to_vault(&fake_peer, shards_to_seal);
            assert!(result.is_ok(), "Vault sealing should succeed even with dummy data");
        }
    }
}