#![allow(dead_code)]

use libp2p::{
    gossipsub,
    futures::StreamExt,      
};
use std::error::Error;
use std::time::{Duration};
use tokio::select;
use tokio::sync::mpsc;

use phalanx::vid;
use phalanx::identity;
use phalanx::camera;
use phalanx::audio;
use phalanx::sentinel::Sentinel;

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
    let my_identity = phalanx::init_identity();
    // Networking setup
    let mut sentinel = Sentinel::new(&config);

    let mut swarm = phalanx::setup_phalanx_swarm(&config).await?;

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
    let sentinel_topic = gossipsub::IdentTopic::new(&config.network.control_topic);

    swarm.behaviour_mut().gossipsub.subscribe(&video_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&audio_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&sentinel.topic)?;

    ears.spawn(0, audio_tx);

    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(config.network.heartbeat_interval_secs));
    let mut cleanup_timer: tokio::time::Interval = tokio::time::interval(Duration::from_secs(5));

    loop {
        select! {
            Some(v_shard) = video_rx.recv() => {
                // 1. Wrap the Shard into a Signed Envelope
                // This is the "Identity Step" that validates your evidence
                let shard_bytes = postcard::to_stdvec(&v_shard).unwrap();
                let signature = my_identity.sign(&shard_bytes);
                
                let envelope = vid::WitnessEnvelope {
                    original_shard: v_shard.clone(),
                    witness_peer_id: swarm.local_peer_id().to_string(),
                    receipt_timestamp: v_shard.timestamp,
                    signature,
                    did: my_identity.did.clone(),
                };

                // 2. Serialize the ENVELOPE (not the raw shard)
                if let Ok(envelope_bytes) = postcard::to_stdvec(&envelope) {
                    // 3. Shred into chunks for P2P transport
                    let chunks = vid::chunkify(
                        v_shard.sequence_id, 
                        envelope_bytes, 
                        config.network.chunk_size_bytes
                    );
                    
                    for chunk in chunks {
                        if let Ok(encoded_chunk) = postcard::to_stdvec(&chunk) {
                            let _ = swarm.behaviour_mut().gossipsub.publish(video_topic.clone(), encoded_chunk);
                        }
                    }
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

