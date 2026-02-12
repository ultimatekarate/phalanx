use libp2p::{
    gossipsub,
    mdns,
    identify,
    futures::StreamExt,
    swarm::SwarmEvent, 
    kad
};

use phalanx_core::{
    core::{
        config::{PhalanxConfig, PhalanxPhysics},
        types::{MeshTopic, PowerState, UnitInterval, VitalityRate}
    }, 
    security::{
        identity::{
            NetworkId, PhalanxIdentity
        }, 
        sentinel::{
            ControlMessage, Sentinel
        },
        telemetry,
    }, storage::guardian::Guardian
};

// - Import the new setup function and key loader
use phalanx_core::network::network::{setup_phalanx_swarm, load_swarm_key, get_storage_key}; 
use std::path::Path;

use std::error::Error;
use std::time::Duration;
use tracing::{info, warn};

use phalanx_core::{PhalanxEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let _guard = telemetry::init_observability();
    info!("PHALANX STRONGHOLD: Initializing Headless PDS...");

    let config = PhalanxConfig::load("phalanx.toml")
        .expect("Failed to load phalanx.toml.");
    
    let (identity, _) = PhalanxIdentity::generate(); 
    let mut storage = Guardian::new("./vault", &config, identity.did.clone());
    let mut sentinel = Sentinel::new(&config);

    // Physics defaults (WAN profile for Stronghold)
    let physics = PhalanxPhysics::default_wan();
    
    // 1. LOAD SWARM KEY (PSK)
    // - We now load this explicitly in main to decouple I/O from the network stack.
    let psk_path = Path::new("swarm.key");
    let psk = load_swarm_key(psk_path);
    
    if psk.is_some() {
        info!("Stronghold joining Private Swarm (Key Loaded).");
    } else {
        warn!("Stronghold joining Public Swarm (No Key Found).");
    }

    // 2. SETUP SWARM
    // - Updated signature: (key, config, physics, psk)
    let mut swarm = setup_phalanx_swarm(
        identity.to_libp2p_keypair(), 
        &config, 
        &physics, 
        psk
    )?;

    let storage_key = get_storage_key();
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
    
    info!(peer_id = %local_peer_id, "Stronghold Status: Online.");

    loop {
        // 3. CALCULATE DYNAMIC LOAD FACTOR
        let active_storage_tasks = storage.micro_layer.len() as f32;
        let max_capacity = config.storage.max_peers as f32;
        let current_load = UnitInterval::new(active_storage_tasks / max_capacity);
        
        let vitality = VitalityRate::calculate(&physics, PowerState::Normal, current_load);
        let next_heartbeat = vitality.as_duration();

        tokio::select! {
            event = swarm.select_next_some() => {
                match event {
                    SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        let topic: MeshTopic = message.topic.as_str().into();

                        if topic != config.network.control_topic {
                            if let Ok(chunk) = postcard::from_bytes::<phalanx_core::protocol::shards::ShardChunk>(&message.data) {
                                if let Some(envelope) = sentinel.process_chunk(chunk, &topic, &config, &identity, local_peer_id) {
                                    _ = storage.ingest_envelope(envelope);
                                }
                            }
                        } 
                        else if let Ok(msg) = postcard::from_bytes::<ControlMessage>(&message.data) {
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

            _ = tokio::time::sleep(next_heartbeat) => {
                let hb = ControlMessage {
                    sender: local_peer_id,
                    load_factor: current_load.as_f32(),
                    storage_remaining_mb: 10240, 
                    heartbeat_ms: vitality.as_u64(),
                    is_leaf: sentinel.is_leaf_mode()
                };
                
                if let Ok(data) = postcard::to_stdvec(&hb) {
                    let topic = gossipsub::IdentTopic::new(&config.network.control_topic);
                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
                }

                if current_load > UnitInterval::new(0.8) {
                    warn!(load = %current_load, next_interval = ?next_heartbeat, "Stronghold under high load. Throttling heartbeats.");
                }
            }
        }
    }
}