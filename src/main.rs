use libp2p::{gossipsub, kad, mdns, identify, swarm::SwarmEvent, futures::StreamExt, Swarm};
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
use phalanx::stronghold::Stronghold;
// Import the new re-exports from lib.rs
use phalanx::{PhalanxBehaviour, PhalanxEvent}; 

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    phalanx::obs::init_observability();

    // 1. Initialization Phase
    let config = PhalanxConfig::load_from_env();
    setup_shutdown_handler();
    
    let my_identity = phalanx::init_identity();
    let mut sentinel = Sentinel::new(&config);
    let mut storage = Stronghold::new(&config.storage.vault_path, &config);
    
    // Initialize swarm
    let mut swarm = phalanx::setup_phalanx_swarm(my_identity.to_libp2p_keypair())?;
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    // Start looking for Strongholds immediately
    let storage_key = phalanx::network::get_storage_key();
    let query_id = swarm.behaviour_mut().kademlia.get_providers(storage_key);
    tracing::info!(?query_id, "Initiated search for Stronghold nodes...");

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
    // TODO: put this in the config
    let mut discovery_timer = tokio::time::interval(Duration::from_secs(30));

    println!("--- PHALANX: ACTIVE (WAN + LAN) ---");

    let bootnodes: Vec<&str> = vec![
        // "/ip4/123.45.67.89/tcp/4001/p2p/12D3KooW..."
    ];

    for peer_str in bootnodes {
        if let Ok(multiaddr) = peer_str.parse::<libp2p::Multiaddr>() {
            tracing::info!("Bootstrapping: Dialing {}", peer_str);
            
            // 1. Dial the node to open the TCP connection
            if let Err(e) = swarm.dial(multiaddr.clone()) {
                 tracing::warn!("Failed to dial bootnode: {}", e);
            }

            // 2. Add it to the Kademlia Routing Table
            // We need to extract the PeerId from the Multiaddr
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = multiaddr.iter().last() {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                tracing::info!("Added Bootnode {} to DHT", peer_id);
            }
        }
    }

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
                    // 1. DATA LAYER (Gossipsub)
                    // We now match strictly against the enum defined in network.rs
                    SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { message, .. })) => {
                        let topic_str = message.topic.as_str();
                        
                        if let Ok(chunk) = postcard::from_bytes::<shards::ShardChunk>(&message.data) {
                            if let Some(envelope) = sentinel.process_chunk(chunk, topic_str, &config, &my_identity, local_peer_id) {
                                storage.ingest_envelope(envelope);
                            }
                        }
                    }

                    // 2. DISCOVERY LAYER (mDNS - Local)
                    // Critical: When mDNS finds a peer, we add them to Kademlia so the DHT knows they exist.
                    SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                        for (peer_id, multiaddr) in list {
                            tracing::info!(%peer_id, "mDNS discovered peer, bridging to Kademlia");
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                        }
                    }

                    // 3. ROUTING LAYER (Kademlia - WAN)
                    SwarmEvent::Behaviour(PhalanxEvent::Kademlia(kad::Event::RoutingUpdated { peer, .. })) => {
                        tracing::debug!(%peer, "DHT Routing Table Updated");
                    }

                    // 4. IDENTITY LAYER (Public IP Resolution)
                    // When we identify a peer, add their listen addresses to the DHT
                    SwarmEvent::Behaviour(PhalanxEvent::Identify(identify::Event::Received { peer_id, info, .. })) => {
                        tracing::debug!(%peer_id, "Identify Received");
                        for addr in info.listen_addrs {
                            swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                        }
                    }
                    

                    SwarmEvent::Behaviour(PhalanxEvent::Kademlia(kad_event)) => {
                        match kad_event {
                            // 1. We found Providers!
                            kad::Event::OutboundQueryProgressed {
                                result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, key, .. })),
                                ..
                            } => {
                                if key == phalanx::network::get_storage_key() {
                                    for peer in providers {
                                        tracing::info!(%peer, "DISCOVERY: Found a Stronghold Node!");
                                        
                                        // ACTION: Automatically connect to them
                                        // This creates a dedicated TCP connection for heavy data transfer
                                        swarm.dial(peer).unwrap_or_else(|e| tracing::warn!("Failed to dial discovered Stronghold: {}", e));
                                        
                                        // OPTIONAL: Add them to a "Preferred Peers" list in your sentinel
                                        // sentinel.register_stronghold(peer); 
                                    }
                                }
                            }
                            
                            // 2. Search finished (no more results coming for this query)
                            kad::Event::OutboundQueryProgressed {
                                result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FinishedWithNoAdditionalRecord { .. })),
                                ..
                            } => {
                                tracing::debug!("Stronghold discovery query finished.");
                            }

                            // 3. Routing Table Updates (keep your existing logging here)
                            kad::Event::RoutingUpdated { peer, .. } => {
                                tracing::debug!(%peer, "DHT Routing Table Updated");
                            }
                            
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }

            // --- Maintenance: Heartbeats & Pruning ---
            _ = heartbeat_timer.tick() => {
                broadcast_heartbeat(&mut swarm, &config, local_peer_id);
            }

            _ = discovery_timer.tick() => {
                // Every 30 seconds, ask the network: "Who provides Storage?"
                let key = phalanx::network::get_storage_key();
                swarm.behaviour_mut().kademlia.get_providers(key);
                tracing::debug!("Refreshing Stronghold discovery...");
            }

            _ = cleanup_timer.tick() => {
                sentinel.prune_stale_buffers(&config);
                storage.archive_stale_sessions(Duration::from_secs(config.storage.stale_session_threshold));

                // re-announce the service
                let storage_key = phalanx::network::get_storage_key();
                let _ = swarm.behaviour_mut().kademlia.start_providing(storage_key);
            }
        }
    }
}

// --- HANDLERS (Slightly updated signatures) ---

fn handle_local_evidence(
    swarm: &mut Swarm<PhalanxBehaviour>,
    evidence: Evidence,
    identity: &PhalanxIdentity,
    config: &PhalanxConfig,
    storage: &mut Stronghold,
    local_id: NetworkId,
) {
    let envelope = WitnessEnvelope::new(evidence.clone(), identity, local_id);
    storage.ingest_envelope(envelope.clone());

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
        load_factor: 0.0,
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