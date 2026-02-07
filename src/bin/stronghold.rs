use libp2p::{
    gossipsub,
    mdns,
    identify,
    futures::StreamExt,
    swarm::SwarmEvent, 
    kad
};
use phalanx::identity::NetworkId;
use phalanx::{
    stronghold::Stronghold, 
    sentinel::Sentinel,
    config::{PhalanxConfig, PhalanxPhysics},
    identity::PhalanxIdentity,
};
use std::error::Error;
use std::time::Duration;
use tracing::{info};

use phalanx::{PhalanxEvent};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing (replacing env_logger for forensic-grade logging)
    tracing_subscriber::fmt::init();
    info!("PHALANX STRONGHOLD: Initializing Headless PDS...");

    let config = PhalanxConfig::load("phalanx.toml")
        .expect("Failed to load phalanx.toml.");
    
    // Identity is required for signing any salvaged evidence
    let identity = PhalanxIdentity::generate(); 
    let mut storage = Stronghold::new("./vault", &config, identity.did.clone());
    let mut sentinel = Sentinel::new(&config);

    let stronghold_flag = true;
    let physics = PhalanxPhysics::default_wan();
    let mut swarm = phalanx::setup_phalanx_swarm(identity.to_libp2p_keypair(), stronghold_flag, physics)?;

    let storage_key = phalanx::network::get_storage_key();
    
    // This tells the DHT: "I am a provider for this key"
    swarm.behaviour_mut().kademlia.start_providing(storage_key.clone())
        .expect("Failed to start providing storage service");

    let local_peer_id = NetworkId(*swarm.local_peer_id());

    // 1. Subscribe to configured topics
    swarm.behaviour_mut().gossipsub.subscribe(&gossipsub::IdentTopic::new(&config.network.video_topic))?;
    swarm.behaviour_mut().gossipsub.subscribe(&gossipsub::IdentTopic::new(&config.network.audio_topic))?;
    swarm.behaviour_mut().gossipsub.subscribe(&gossipsub::IdentTopic::new(&config.network.control_topic))?;

    let port = std::env::args().nth(1).unwrap_or_else(|| "4001".to_string());
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?)?;

    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(10));
    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(30));

    info!(peer_id = %local_peer_id, "Stronghold Status: Online.");

    loop {
        tokio::select! {
            // 1. Handle Incoming Network Traffic

            event = swarm.select_next_some() => {

                match event {
                    // 1. Correctly destructure the nested Enums
                    SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        // NOW you have access to the `message` variable
                        let topic_str = message.topic.as_str();

                        if let Ok(chunk) = postcard::from_bytes::<phalanx::shards::ShardChunk>(&message.data) {
                            println!("Stronghold received chunk from: {}", chunk.owner_did);
                            
                            // Reassembly logic
                            if let Some(envelope) = sentinel.process_chunk(chunk, topic_str, &config, &identity, local_peer_id) {
                                _ = storage.ingest_envelope(envelope);
                                println!("Stronghold archived full envelope.");
                            }
                        }
                    }
                    
                    // 2. Handle mDNS to bridge local peers to Kademlia
                    SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }

                    // 3. Handle Identify to update routing table
                    SwarmEvent::Behaviour(PhalanxEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    
                    // 4. Kademlia Events handling
                    SwarmEvent::Behaviour(PhalanxEvent::Kademlia(kad::Event::OutboundQueryProgressed { 
                        result: kad::QueryResult::StartProviding(Ok(_)), .. 
                    })) => {
                        tracing::info!("Successfully announced Storage capability to the network.");
                    }

                    _ => {}
                }
            }

            // 2. Periodic Buffer Pruning
            _ = cleanup_timer.tick() => {
                sentinel.prune_stale_buffers(&config, &physics);
                storage.archive_stale_sessions(Duration::from_secs(config.storage.stale_session_threshold));
            }

            // 3. Outgoing Heartbeats (Capacity Announcements)
            _ = heartbeat_timer.tick() => {
                let hb = phalanx::sentinel::ControlMessage {
                    sender: local_peer_id,
                    load_factor: 0.0, // Stronghold-specific metric
                    storage_remaining_mb: 10240, // Mock value
                };
                
                if let Ok(data) = postcard::to_stdvec(&hb) {
                    let topic = gossipsub::IdentTopic::new(&config.network.control_topic);
                    let _ = swarm.behaviour_mut().gossipsub.publish(topic, data);
                }
            }
        }
    }
}