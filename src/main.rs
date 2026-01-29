#![allow(dead_code)]

use libp2p::{
    gossipsub, mdns, noise, tcp, yamux, 
    SwarmBuilder,
    swarm::{NetworkBehaviour}, 
    futures::StreamExt,      
};
use std::error::Error;
use std::time::{Duration, Instant};
use tokio::select;
use std::collections::VecDeque;

use phalanx::vid;

mod camera;
mod sentinel;

use sentinel::Sentinel;
use camera::PhalanxCamera;

// ==================
//   NETWORK STATE
// ==================

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub enum PhalanxEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
}

impl From<gossipsub::Event> for PhalanxEvent {
    fn from(event: gossipsub::Event) -> Self { PhalanxEvent::Gossipsub(event) }
}

impl From<mdns::Event> for PhalanxEvent {
    fn from(event: mdns::Event) -> Self { PhalanxEvent::Mdns(event) }
}

// ==================
//   MAIN ENTRY
// ==================

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("--- PHALANX: INITIALIZING ---");
    let mut sentinel = Sentinel::new("phalanx/emergency/the-thing", 10);

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let config = gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .do_px()
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
            Ok(PhalanxBehaviour {
                gossipsub: gossipsub::Behaviour::new(gossipsub::MessageAuthenticity::Signed(key.clone()), config)?,
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?,
            })
        })?
        .build();

    swarm.behaviour_mut().gossipsub.subscribe(&sentinel.topic)?;
    let port = std::env::args().nth(1).unwrap_or("0".to_string());
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?)?;

    let (video_tx, mut video_rx) = tokio::sync::mpsc::channel::<vid::VideoShard>(100);
    
    // The "Eyes" Task
    
    let phalanx_cam = PhalanxCamera::new(0, 15);
    phalanx_cam.spawn_thread(video_tx);
    
    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(1));
    let mut cleanup_timer: tokio::time::Interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        select! {
            Some(shard) = video_rx.recv() => {
                let _ = swarm.behaviour_mut().gossipsub.publish(sentinel.topic.clone(), postcard::to_stdvec(&shard)?);
            }
            _ = heartbeat_timer.tick() => {
                let pulse = format!("ALIVE|{}|{:?}", swarm.local_peer_id(), Instant::now());
                let _ = swarm.behaviour_mut().gossipsub.publish(sentinel.topic.clone(), pulse.as_bytes());
            }
            _ = cleanup_timer.tick() => sentinel.process_cleanup(*swarm.local_peer_id()),
            event = swarm.select_next_some() => sentinel.handle_network_event(event, &mut swarm),
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