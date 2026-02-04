use libp2p::{gossipsub, futures::StreamExt, Swarm, swarm::SwarmEvent};
use std::error::Error;
use std::time::Duration;
use tokio::select;
use tokio::sync::mpsc;

use phalanx::shards::{self, Evidence, WitnessEnvelope};
use phalanx::camera;
use phalanx::audio;
use phalanx::identity::{NetworkId, PhalanxIdentity};
use phalanx::sentinel::{Sentinel, ControlMessage};
use phalanx::config::PhalanxConfig;
use phalanx::PhalanxBehaviour;
use phalanx::stronghold::Stronghold;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    phalanx::obs::init_observability();

    // 1. Initialization Phase
    let config = PhalanxConfig::load_from_env();
    setup_shutdown_handler();
    
    let my_identity = phalanx::init_identity();
    let mut sentinel = Sentinel::new(&config);
    let mut storage = Stronghold::new(&config.storage.vault_path, &config);
    let mut swarm = phalanx::setup_phalanx_swarm(&config).await?;

    let local_peer_id = NetworkId(*swarm.local_peer_id());

    let current_volley_id = format!("volley_{}_{}", 
        my_identity.did.to_safe_name(), 
        chrono::Utc::now().timestamp()
    );
    tracing::info!(volley = %current_volley_id, "New Forensic Volley Initialized");

    // 2. Network & Hardware Orchestration
    subscribe_to_topics(&mut swarm, &config);
    let (mut video_rx, mut audio_rx) = spawn_hardware_threads(&config, current_volley_id);

    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(config.network.heartbeat_interval_secs));
    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(config.network.cleanup_interval_secs));

    println!("--- PHALANX: ACTIVE ---");

    loop {
        select! {
            // --- Hardware Input: Local Capture ---
            Some(v_shard) = video_rx.recv() => {
                handle_local_evidence(&mut swarm, Evidence::Video(v_shard), &my_identity, &config, &mut storage, local_peer_id);
            }
            
            Some(a_shard) = audio_rx.recv() => {
                handle_local_evidence(&mut swarm, Evidence::Audio(a_shard), &my_identity, &config, &mut storage, local_peer_id);
            }
            
            // --- Network Input: Peer Data ---
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(phalanx::PhalanxEvent::Gossipsub(g_event)) => {
                        let topic_str = g_event.message.topic.as_str();
                        
                        // Pass to Sentinel for reassembly
                        if let Ok(chunk) = postcard::from_bytes::<shards::ShardChunk>(&g_event.message.data) {
                            if let Some(envelope) = sentinel.process_chunk(chunk, topic_str, &config, &my_identity, local_peer_id) {
                                storage.ingest_envelope(envelope);
                            }
                        }
                    }
                    SwarmEvent::Behaviour(phalanx::PhalanxEvent::Metadata(_m_event)) => {
                        // Handle subscriptions or peer status if needed
                    }
                    _ => {}
                }
            }

            // --- Maintenance: Heartbeats & Pruning ---
            _ = heartbeat_timer.tick() => {
                broadcast_heartbeat(&mut swarm, &config, local_peer_id);
            }

            _ = cleanup_timer.tick() => {
                sentinel.prune_stale_buffers(&config);
                storage.archive_stale_sessions(Duration::from_secs(config.storage.stale_session_threshold));
            }
        }
    }
}

// --- REFACTORED HANDLERS ---

fn handle_local_evidence(
    swarm: &mut Swarm<PhalanxBehaviour>,
    evidence: Evidence,
    identity: &PhalanxIdentity,
    config: &PhalanxConfig,
    storage: &mut Stronghold,
    local_id: NetworkId,
) {
    // 1. Create Atomic WitnessEnvelope
    let envelope = WitnessEnvelope::new(evidence.clone(), identity, local_id);

    // 2. Persist locally to the Stronghold immediately
    storage.ingest_envelope(envelope.clone());

    // 3. Chunkify and Broadcast
    let topic_str = match evidence {
        Evidence::Video(_) => &config.network.video_topic,
        Evidence::Audio(_) => &config.network.audio_topic,
    };

    if let Ok(encoded_envelope) = postcard::to_stdvec(&envelope) {
        let chunks = shards::chunkify(
            shards::ShardId(evidence.sequence_id().0),
            encoded_envelope,
            config.network.chunk_size_bytes,
            identity.did.clone(),
        );

        let topic = gossipsub::IdentTopic::new(topic_str);
        for chunk in chunks {
            if let Ok(encoded_chunk) = postcard::to_stdvec(&chunk) {
                let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), encoded_chunk);
            }
        }
    }
}

fn broadcast_heartbeat(swarm: &mut Swarm<PhalanxBehaviour>, config: &PhalanxConfig, local_id: NetworkId) {
    let hb = ControlMessage {
        sender: local_id,
        load_factor: 0.0, // Placeholder for system load
        storage_remaining_mb: 1024,
    };

    if let Ok(encoded) = postcard::to_stdvec(&hb) {
        let topic = gossipsub::IdentTopic::new(&config.network.control_topic);
        let _ = swarm.behaviour_mut().gossipsub.publish(topic, encoded);
    }
}

fn subscribe_to_topics(swarm: &mut Swarm<PhalanxBehaviour>, config: &PhalanxConfig) {
    let topics = [
        &config.network.video_topic,
        &config.network.audio_topic,
        &config.network.control_topic,
    ];

    for t in topics {
        let _ = swarm.behaviour_mut().gossipsub.subscribe(&gossipsub::IdentTopic::new(t));
    }
}

fn setup_shutdown_handler() {
    ctrlc::set_handler(move || {
        println!("\n[PHALANX] Shutdown initiated. Sealing vault...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");
}

fn spawn_hardware_threads(config: &PhalanxConfig, volley_id: String) -> (mpsc::Receiver<shards::VideoShard>, mpsc::Receiver<audio::AudioShard>) {
    let (v_tx, v_rx) = mpsc::channel(64);
    let (a_tx, a_rx) = mpsc::channel(64);

    let camera_thread = camera::PhalanxCameraThread { fps: config.hardware.camera_fps };
    camera_thread.spawn(Some(0), v_tx, config.hardware.clone(), volley_id.clone());

    let audio_thread = audio::PhalanxAudioThread { 
        sample_rate: config.hardware.audio_sample_rate,
        channels: config.hardware.audio_channels 
    };
    audio_thread.spawn(a_tx, config.hardware.clone(), volley_id);

    (v_rx, a_rx)
}