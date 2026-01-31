#![allow(dead_code)]

use libp2p::{
    gossipsub, mdns, noise, tcp, yamux, 
    SwarmBuilder,
    futures::StreamExt,      
};
use std::error::Error;
use std::time::{Duration};
use tokio::select;
use tokio::sync::mpsc;

use phalanx::vid;
use phalanx::camera;
use phalanx::audio;
use phalanx::sentinel::Sentinel;

use phalanx::{PhalanxBehaviour};


// ==================
//   MAIN ENTRY
// ==================

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    let config = phalanx::config::PhalanxConfig::load("phalanx.toml")
        .expect("Failed to load phalanx.toml. Ensure the file exists in the project root.");

    ctrlc::set_handler(move || {
        println!("\n[PHALANX] Manual Shutdown Signal Received.");
        println!("[PHALANX] Releasing hardware and flushing buffers...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");


    println!("--- PHALANX: INITIALIZING ---");

    // Networking setup
    let mut sentinel = Sentinel::new(&config);

    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let config = gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .max_transmit_size(config.network.chunk_size_bytes + 4096)
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
    let eyes = camera::PhalanxCameraThread { fps: config.hardware.camera_fps };
    // Make sure the eyes are working
    if let Ok(_) = camera::HardwareCamera::new(0) {
        eyes.spawn(Some(0), video_tx);
    } else {
        println!("Hardware busy/missing. Falling back to Mock Camera.");
        eyes.spawn(None, video_tx); // None signals "Use Mock"
    }

    let ears = audio::PhalanxAudioThread { sample_rate: config.hardware.audio_sample_rate };

    // Subscribe to audio and video topic
    let video_topic = gossipsub::IdentTopic::new(&config.network.video_topic);
    let audio_topic = gossipsub::IdentTopic::new(&config.network.audio_topic);

    swarm.behaviour_mut().gossipsub.subscribe(&video_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&audio_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&sentinel.topic)?;

    ears.spawn(0, audio_tx);

    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(config.network.heartbeat_interval_secs));
    let mut cleanup_timer: tokio::time::Interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        select! {
            Some(v_shard) = video_rx.recv() => {
                if let Ok(full_bytes) = postcard::to_stdvec(&v_shard) {
                    // Shred into 32KB chunks to stay well under the 64KB limit
                    let chunks = vid::chunkify(v_shard.sequence_id, full_bytes, config.network.chunk_size_bytes);
                    
                    for chunk in chunks {
                        if let Ok(encoded_chunk) = postcard::to_stdvec(&chunk) {
                            let _ = swarm.behaviour_mut().gossipsub.publish(video_topic.clone(), encoded_chunk);
                        }
                    }
                }
            }

            Some(a_shard) = audio_rx.recv() => {
                if let Ok(encoded) = postcard::to_stdvec(&a_shard) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(audio_topic.clone(), encoded);
                }
            }
            
            
            _ = heartbeat_timer.tick() => {
                let heartbeat = sentinel.generate_heartbeat(swarm.local_peer_id());
                if let Ok(encoded) = postcard::to_stdvec(&heartbeat) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(sentinel.topic.clone(), encoded);
                }
            }

            _ = cleanup_timer.tick() => sentinel.process_cleanup(*swarm.local_peer_id()),
            event = swarm.select_next_some() => sentinel.handle_network_event(event, &mut swarm),
        }
    }
}

