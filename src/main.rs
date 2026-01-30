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
use tokio::sync::mpsc;

use phalanx::vid;

mod camera;
mod audio;
mod sentinel;

use sentinel::Sentinel;

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
    env_logger::init();

    ctrlc::set_handler(move || {
        println!("\n[PHALANX] Manual Shutdown Signal Received.");
        println!("[PHALANX] Releasing hardware and flushing buffers...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");


    println!("--- PHALANX: INITIALIZING ---");




    // Networking setup
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


    // recording setup
    let (video_tx, mut video_rx) = tokio::sync::mpsc::channel::<vid::VideoShard>(100);
    let (audio_tx, mut audio_rx) = mpsc::channel::<audio::AudioShard>(100);

    // The "Eyes" - Initialized the camera
    let eyes = camera::PhalanxCameraThread { fps: 15 };
    // Make sure the eyes are working
    if let Ok(_) = camera::HardwareCamera::new(0) {
        eyes.spawn(Some(0), video_tx);
    } else {
        println!("Hardware busy/missing. Falling back to Mock Camera.");
        eyes.spawn(None, video_tx); // None signals "Use Mock"
    }

    let ears = audio::PhalanxAudioThread { sample_rate: 44100 };

    // Subscribe to audio and video topic
    let video_topic = gossipsub::IdentTopic::new("phalanx/video");
    let audio_topic = gossipsub::IdentTopic::new("phalanx/audio");
    swarm.behaviour_mut().gossipsub.subscribe(&video_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&audio_topic)?;

    ears.spawn(0, audio_tx);

    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(1));
    let mut cleanup_timer: tokio::time::Interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        select! {
            // Replace the bincode lines in your select! block with this:

            Some(v_shard) = video_rx.recv() => {
                // Standardize on postcard for mobile efficiency
                match postcard::to_stdvec(&v_shard) {
                    Ok(encoded) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(video_topic.clone(), encoded) {
                            println!("Status: Video broadcast failed: {}", e);
                        }
                    }
                    Err(e) => println!("Status: Video serialization error: {}", e),
                }
            }

            Some(a_shard) = audio_rx.recv() => {
                match postcard::to_stdvec(&a_shard) {
                    Ok(encoded) => {
                        if let Err(e) = swarm.behaviour_mut().gossipsub.publish(audio_topic.clone(), encoded) {
                            println!("Status: Audio broadcast failed: {}", e);
                        }
                    }
                    Err(e) => println!("Status: Audio serialization error: {}", e),
                }
            }
            
            _ = heartbeat_timer.tick() => {
                    // Generate a structured heartbeat instead of a raw string
                    let heartbeat = sentinel.generate_heartbeat(swarm.local_peer_id());
                    
                    match postcard::to_stdvec(&heartbeat) {
                        Ok(encoded) => {
                            // Use the control/emergency topic for health updates
                            if let Err(e) = swarm.behaviour_mut().gossipsub.publish(sentinel.topic.clone(), encoded) {
                                println!("Status: Heartbeat broadcast failed: {}", e);
                            }
                        }
                        Err(e) => println!("Status: Heartbeat serialization error: {}", e),
                    }
                }

            _ = cleanup_timer.tick() => sentinel.process_cleanup(*swarm.local_peer_id()),
            event = swarm.select_next_some() => sentinel.handle_network_event(event, &mut swarm),
        }
    }
}

