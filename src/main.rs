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

