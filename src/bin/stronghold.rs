use libp2p::futures::StreamExt;
use libp2p::gossipsub;
use phalanx::identity::NetworkId;
use phalanx::{
    stronghold::Stronghold, 
    sentinel::Sentinel,
    config::PhalanxConfig,
    identity::PhalanxIdentity,
};
use std::error::Error;
use std::time::Duration;
use tracing::{info};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // Initialize tracing (replacing env_logger for forensic-grade logging)
    tracing_subscriber::fmt::init();
    info!("PHALANX STRONGHOLD: Initializing Headless PDS...");

    let config = PhalanxConfig::load("phalanx.toml")
        .expect("Failed to load phalanx.toml.");
    
    // Identity is required for signing any salvaged evidence
    let identity = PhalanxIdentity::generate(); 
    let mut storage = Stronghold::new("./vault", &config);
    let mut sentinel = Sentinel::new(&config);
    let mut swarm = phalanx::setup_phalanx_swarm(&config).await?;

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
                    libp2p::swarm::SwarmEvent::Behaviour(phalanx::PhalanxEvent::Gossipsub(gossip_event)) => {
                        let message = &gossip_event.message;
                        let topic_str = message.topic.as_str();
                        
                        if topic_str == config.network.video_topic || topic_str == config.network.audio_topic {
                            if let Ok(chunk) = postcard::from_bytes(&message.data) {
                                // process_chunk now manages reassembly and returns Option<WitnessEnvelope>
                                if let Some(envelope) = sentinel.process_chunk(chunk, topic_str, &config, &identity, local_peer_id) {
                                    storage.ingest_envelope(envelope);
                                }
                            }
                        } else if topic_str == config.network.control_topic {
                            if let Ok(hb) = postcard::from_bytes::<phalanx::sentinel::ControlMessage>(&message.data) {
                                sentinel.health_tracker.register_activity(hb.sender);
                            }
                        }
                    },
                    libp2p::swarm::SwarmEvent::Behaviour(phalanx::PhalanxEvent::Mdns(_mdns_event)) => {
                        // TODO: peer discovery goes here eventually
                    },
                    _ => {}
                }
            }

            // 2. Periodic Buffer Pruning
            _ = cleanup_timer.tick() => {
                sentinel.prune_stale_buffers(&config);
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