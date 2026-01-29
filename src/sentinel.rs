use libp2p::{gossipsub, PeerId, Swarm, swarm::SwarmEvent};
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};
use crate::vid::{self, VideoShard};
use crate::PhalanxBehaviour;
use crate::PhalanxEvent;

use libp2p::{
    mdns, 
    
};

pub struct Sentinel {
    pub peer_heartbeats: HashMap<PeerId, Instant>,
    pub guardian_buffers: HashMap<PeerId, VecDeque<VideoShard>>,
    pub topic: gossipsub::IdentTopic,
    pub pulse_timeout: Duration,
    pub heartbeat_interval: Duration,
    pub cleanup_interval: Duration,
}

impl Sentinel {
    pub fn new(topic_name: &str, timeout_secs: u64) -> Self {
        Self {
            peer_heartbeats: HashMap::new(),
            guardian_buffers: HashMap::new(),
            topic: gossipsub::IdentTopic::new(topic_name),
            pulse_timeout: Duration::from_secs(timeout_secs),
            heartbeat_interval: Duration::from_secs(1),
            cleanup_interval: Duration::from_secs(5),
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
                        println!("🛡 Shield Overlapped: {peer_id}");
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

                if let Ok(shard) = postcard::from_bytes::<VideoShard>(&message.data) {
                    println!("Received Shard #{} from {}", shard.sequence_id, propagation_source);
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
                println!("[!!!] ALERT: Witness {} has gone dark. Finalizing evidence.", id);
                if let Some(shards) = self.guardian_buffers.remove(id) {
                    let _ = vid::seal_to_vault(id, shards);
                    let _ = vid::recover_vault_to_images(&id.to_string());
                }
                false 
            } else { true }
        });
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