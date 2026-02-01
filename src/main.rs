use libp2p::{
    gossipsub,
    futures::StreamExt,    
    Swarm, swarm::SwarmEvent
};
use std::error::Error;
use std::time::{Duration};
use tokio::select;
use tokio::sync::mpsc;

use phalanx::shards;
use phalanx::camera;
use phalanx::audio;
use phalanx::identity;
use phalanx::sentinel::Sentinel;
use phalanx::config::PhalanxConfig;
use phalanx::PhalanxBehaviour;
use phalanx::PhalanxEvent;

use phalanx::stronghold::Stronghold;

// ==================
//   MAIN ENTRY
// ==================

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();

    // 1. Initialization Phase
    let config = PhalanxConfig::load("phalanx.toml")
        .expect("Critical: phalanx.toml not found.");
    
    setup_shutdown_handler();
    
    let my_identity = phalanx::init_identity();
    let mut sentinel = Sentinel::new(&config);
    let mut storage = Stronghold::new(&config.storage.vault_path);
    let mut swarm = phalanx::setup_phalanx_swarm(&config).await?;

    sentinel.subscribe_all(&mut swarm)?;

    // 2. Network & Hardware Orchestration
    let (video_topic, audio_topic) = subscribe_to_topics(&mut swarm, &config, &sentinel);
    let (mut video_rx, mut audio_rx) = spawn_hardware_threads(&config);

    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(config.network.heartbeat_interval_secs));
    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(5));

    println!("--- PHALANX: ACTIVE ---");

    // 3. The Clean Event Loop
    loop {
        select! {
            Some(v_shard) = video_rx.recv() => {
                handle_video_shard(&mut swarm, &video_topic, v_shard, &my_identity, &config);
            }
            
            Some(a_shard) = audio_rx.recv() => {
                handle_audio_shard(&mut swarm, &audio_topic, a_shard, &my_identity, &config);
            }
            
            _ = heartbeat_timer.tick() => {
                handle_heartbeat(&mut swarm, &mut sentinel);
            }

            _ = cleanup_timer.tick() => {
                let abandoned_evidence = sentinel.process_cleanup(*swarm.local_peer_id());
                for (_, shards) in abandoned_evidence {
                    for envelope in shards {
                        storage.ingest_envelope(envelope);
                    }
                }

                storage.archive_stale_sessions(Duration::from_secs(config.storage.stale_session_threshold));
            }

            event = swarm.select_next_some() => {
                if is_video_message(&event, &sentinel){
                    if let Some(chunk)= message_to_chunk(event){
                        if let Some(envelope) = sentinel.ingest_chunk(chunk) {
                            storage.ingest_envelope(envelope);
                        }
                    }
                } else {
                    sentinel.handle_network_event(event, &mut swarm);
                }
            }
        }
    }
}


// --- EXTRACTED HANDLER FUNCTIONS ---

fn message_to_chunk(event: SwarmEvent<PhalanxEvent>) -> Option<shards::ShardChunk> {
    if let SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(libp2p::gossipsub::Event::Message { message, .. })) = event {
        return postcard::from_bytes::<shards::ShardChunk>(&message.data).ok();
    }
    None
}

fn handle_video_shard(
    swarm: &mut Swarm<PhalanxBehaviour>,
    topic: &gossipsub::IdentTopic,
    shard: shards::VideoShard,
    identity: &identity::PhalanxIdentity,
    config: &PhalanxConfig,
) {
    if let Ok(shard_bytes) = postcard::to_stdvec(&shard) {
        let envelope = shards::WitnessEnvelope {
            original_shard: shard.clone(),
            witness_peer_id: swarm.local_peer_id().to_string(),
            receipt_timestamp: shard.timestamp,
            signature: identity.sign(&shard_bytes),
            did: identity.did.clone(),
        };

        if let Ok(envelope_bytes) = postcard::to_stdvec(&envelope) {
            let chunks = shards::chunkify(shard.sequence_id, envelope_bytes, config.network.chunk_size_bytes);
            for chunk in chunks {
                if let Ok(encoded) = postcard::to_stdvec(&chunk) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded);
                }
            }
        }
    }
}

fn is_video_message(event: &SwarmEvent<PhalanxEvent>, sentinel: &Sentinel) -> bool {
    if let SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(libp2p::gossipsub::Event::Message { message, .. })) = event {
        return message.topic == sentinel.video_topic.hash();
    }
    false
}

fn handle_audio_shard(
    swarm: &mut Swarm<PhalanxBehaviour>,
    topic: &gossipsub::IdentTopic,
    shard: audio::AudioShard,
    identity: &identity::PhalanxIdentity,
    config: &PhalanxConfig,
) {
    // 1. Wrap the audio shard in a signed WitnessEnvelope
    // We use the swarm local peer ID to identify the broadcaster
    let peer_id = swarm.local_peer_id().to_string();
    let envelope = audio::wrap_audio_shard(shard, identity, peer_id);

    // 2. Serialize the entire envelope for transmission
    if let Ok(encoded_envelope) = postcard::to_stdvec(&envelope) {
        // 3. Shred the envelope into chunks to fit Gossipsub MTU
        let chunks = shards::chunkify(
            envelope.original_shard.sequence_id,
            encoded_envelope,
            config.network.chunk_size_bytes,
        );

        // 4. Publish each chunk to the mesh
        for chunk in chunks {
            if let Ok(encoded_chunk) = postcard::to_stdvec(&chunk) {
                if let Err(e) = swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded_chunk) {
                    eprintln!("Network Error: Failed to publish audio chunk: {}", e);
                }
            }
        }
    }
}

fn handle_heartbeat(swarm: &mut Swarm<PhalanxBehaviour>, sentinel: &mut Sentinel) {
    let heartbeat = sentinel.generate_heartbeat(swarm.local_peer_id());
    if let Ok(encoded) = postcard::to_stdvec(&heartbeat) {
        let _ = swarm.behaviour_mut().gossipsub.publish(sentinel.control_topic.clone(), encoded);
    }
}

// --- HELPER SETUP FUNCTIONS ---

fn setup_shutdown_handler() {
    ctrlc::set_handler(move || {
        println!("\n[PHALANX] Shutdown initiated...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");
}

fn subscribe_to_topics(
    swarm: &mut Swarm<PhalanxBehaviour>, 
    config: &PhalanxConfig, 
    sentinel: &Sentinel
) -> (gossipsub::IdentTopic, gossipsub::IdentTopic) {
    let video = gossipsub::IdentTopic::new(&config.network.video_topic);
    let audio = gossipsub::IdentTopic::new(&config.network.audio_topic);

    let _ = swarm.behaviour_mut().gossipsub.subscribe(&video);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&audio);
    let _ = swarm.behaviour_mut().gossipsub.subscribe(&sentinel.control_topic);

    (video, audio)
}

fn spawn_hardware_threads(config: &PhalanxConfig) -> (mpsc::Receiver<shards::VideoShard>, mpsc::Receiver<audio::AudioShard>) {
    let (v_tx, v_rx) = mpsc::channel(64);
    let (a_tx, a_rx) = mpsc::channel(64);

    // 1. Video Thread
    let camera_thread = camera::PhalanxCameraThread { 
        fps: config.hardware.camera_fps 
    };
    camera_thread.spawn(Some(0), v_tx);

    let audio_thread = audio::PhalanxAudioThread { 
        sample_rate: config.hardware.audio_sample_rate,
        channels: config.hardware.audio_channels 
    };
    
    audio_thread.spawn(a_tx); 

    (v_rx, a_rx)
}