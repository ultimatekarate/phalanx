use libp2p::{
    gossipsub,
    mdns,
    identify,
    futures::StreamExt,
    swarm::SwarmEvent, 
    kad
};

use phalanx::{
    core::{
        config::{PhalanxConfig, PhalanxPhysics},
        telemetry, types::MeshTopic
    }, security::{
        identity::{
            NetworkId, PhalanxIdentity
        }, sentinel::{ControlMessage, Sentinel}
    }, storage::guardian::Guardian
};

use std::error::Error;
use std::time::Duration;
use tracing::{info, warn};

use phalanx::{PhalanxEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = telemetry::init_observability();
    info!("PHALANX STRONGHOLD: Initializing Headless PDS...");

    let config = PhalanxConfig::load("phalanx.toml")
        .expect("Failed to load phalanx.toml.");
    
    let (identity, _) = PhalanxIdentity::generate(); 
    let mut storage = Guardian::new("./vault", &config, identity.did.clone());
    let mut sentinel = Sentinel::new(&config);

    let stronghold_flag = true;
    let physics = PhalanxPhysics::default_wan();
    let mut swarm = phalanx::setup_phalanx_swarm(identity.to_libp2p_keypair(), stronghold_flag, physics)?;

    let storage_key = phalanx::network::network::get_storage_key();
    swarm.behaviour_mut().kademlia.start_providing(storage_key.clone())
        .expect("Failed to start providing storage service");

    let local_peer_id = NetworkId(*swarm.local_peer_id());

    // Subscribe to topics
    swarm.behaviour_mut().gossipsub.subscribe(&gossipsub::IdentTopic::new(&config.network.video_topic))?;
    swarm.behaviour_mut().gossipsub.subscribe(&gossipsub::IdentTopic::new(&config.network.audio_topic))?;
    swarm.behaviour_mut().gossipsub.subscribe(&gossipsub::IdentTopic::new(&config.network.control_topic))?;

    let port = std::env::args().nth(1).unwrap_or_else(|| "4001".to_string());
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?)?;

    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(10));
    
    // 1. DYNAMIC HEARTBEAT INITIALIZATION
    // We use a base interval and will reset it based on load.
    let mut heartbeat_timer = tokio::time::interval(physics.heartbeat_interval(0.0));

    info!(peer_id = %local_peer_id, "Stronghold Status: Online.");

    loop {
        // 2. CALCULATE DYNAMIC LOAD FACTOR
        // Heuristic: Sum of reassembly buffers divided by configured capacity.
        let micro_load = storage.micro_layer.len() as f32 / (config.storage.max_peers * 5) as f32;
        let macro_load = storage.macro_layer.len() as f32 / config.storage.max_peers as f32;
        let load_factor = (micro_load + macro_load).clamp(0.0, 1.0);

        let current_interval = physics.heartbeat_interval(load_factor);
        heartbeat_timer.reset_after(current_interval);

        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        let topic: MeshTopic = message.topic.as_str().into();

                        // Handle Evidence Chunks
                        if topic != config.network.control_topic {
                            if let Ok(chunk) = postcard::from_bytes::<phalanx::protocol::shards::ShardChunk>(&message.data) {
                                if let Some(envelope) = sentinel.process_chunk(chunk, &topic, &config, &identity, local_peer_id) {
                                    _ = storage.ingest_envelope(envelope);
                                }
                            }
                        } 
                        // 3. HANDLE INCOMING DYNAMIC HEARTBEATS
                        else if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&message.data) {
                            // Register the peer's contract for staleness tracking
                            sentinel.health_tracker.register_activity(msg);
                        }
                    }
                    
                    SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }

                    SwarmEvent::Behaviour(PhalanxEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    
                    SwarmEvent::Behaviour(PhalanxEvent::Kademlia(kad::Event::OutboundQueryProgressed { 
                        result: kad::QueryResult::StartProviding(Ok(_)), .. 
                    })) => {
                        info!("Successfully announced Storage capability to the network.");
                    }

                    _ => {}
                }
            }

            _ = cleanup_timer.tick() => {
                sentinel.prune_stale_buffers(&config, &physics);
                storage.archive_stale_sessions(Duration::from_secs(config.storage.stale_session_threshold));
            }

            // 4. BROADCAST DYNAMIC HEARTBEAT
            _ = heartbeat_timer.tick() => {
                let hb = ControlMessage {
                    sender: local_peer_id,
                    load_factor,
                    storage_remaining_mb: 10240, // TODO: Implement disk space check
                    heartbeat_ms: current_interval.as_millis() as u64,
                    is_leaf: sentinel.is_leaf_mode()
                };
                
                if let Ok(data) = postcard::to_stdvec(&hb) {
                    let topic = gossipsub::IdentTopic::new(&config.network.control_topic);
                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
                }

                if load_factor > 0.8 {
                    warn!(load = %load_factor, next_interval = ?current_interval, "Stronghold under high load. Throttling heartbeats.");
                }
            }
        }
    }
}