#![allow(dead_code)]

use libp2p::{
    gossipsub, mdns, noise, tcp, yamux, 
    SwarmBuilder, PeerId, Swarm,
    swarm::{NetworkBehaviour, SwarmEvent}, 
    futures::StreamExt,      
};
use std::error::Error;
use std::time::{Duration, Instant};
use std::collections::{HashMap, VecDeque};
use tokio::select;

// Hardware and Media crates
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::pixel_format::RgbFormat;
use nokhwa::Camera;

use phalanx::vid;

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
//   SENTINEL STATE
// ==================

pub struct Sentinel {
    pub peer_heartbeats: HashMap<PeerId, Instant>,
    pub guardian_buffers: HashMap<PeerId, VecDeque<vid::VideoShard>>,
    pub topic: gossipsub::IdentTopic,
    pub pulse_timeout: Duration,
}

impl Sentinel {
    pub fn new(topic_name: &str, timeout_secs: u64) -> Self {
        Self {
            peer_heartbeats: HashMap::new(),
            guardian_buffers: HashMap::new(),
            topic: gossipsub::IdentTopic::new(topic_name),
            pulse_timeout: Duration::from_secs(timeout_secs),
        }
    }

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
                        self.peer_heartbeats.insert(peer_id, Instant::now() + Duration::from_secs(30));
                    }
                }
            }
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                self.peer_heartbeats.insert(propagation_source, Instant::now());
                if let Ok(shard) = postcard::from_bytes::<vid::VideoShard>(&message.data) {
                    println!("📸 Shard #{} from {}", shard.sequence_id, propagation_source);
                    let buffer = self.guardian_buffers.entry(propagation_source).or_insert_with(VecDeque::new);
                    buffer.push_back(shard);
                    if buffer.len() > 30 { buffer.pop_front(); }
                }
            }
            _ => {}
        }
    }

    pub fn process_cleanup(&mut self, local_id: PeerId) {
        let now = Instant::now();
        self.peer_heartbeats.retain(|id, last| {
            if id == &local_id || *last > now { return true; }
            if now.duration_since(*last) > self.pulse_timeout {
                println!("[!!!] ALERT: Witness {} has gone dark.", id);
                if let Some(shards) = self.guardian_buffers.remove(id) {
                    let _ = vid::seal_to_vault(id, shards);
                    let _ = vid::recover_vault_to_images(&id.to_string());
                }
                false 
            } else { true }
        });
    }
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
    std::thread::spawn(move || {
        let mut shredder = vid::Shredder::new();
        let mut camera = Camera::new(CameraIndex::Index(0), RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate)).expect("No Webcam");
        camera.open_stream().expect("Lock failed");
        let mut frames = Vec::new();

        loop {
            if let Ok(frame) = camera.frame() {
                if let Ok(img_buf) = frame.decode_image::<RgbFormat>() {

                    let width = img_buf.width();
                    let height = img_buf.height();
                    let raw_data = img_buf.into_raw();

                    if let Ok(jpeg) = vid::compress_frame(raw_data, width, height) {
                        frames.push(jpeg);
                    }
                }
            }
            if frames.len() >= 15 {
                let shard = shredder.create_shard(frames.split_off(0));
                if video_tx.blocking_send(shard).is_err() { break; }
            }
            std::thread::sleep(Duration::from_millis(66));
        }
    });

    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(1));
    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(5));

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
}