use libp2p::{gossipsub, identify, kad, mdns, swarm::SwarmEvent, Swarm, futures::StreamExt};
use std::error::Error;
use std::time::Duration;
use tokio::select;
use tokio::sync::mpsc;

// Internal Modules
use phalanx::shards::{self, Evidence, WitnessEnvelope};
use phalanx::camera;
use phalanx::audio;
use phalanx::identity::{NetworkId, PhalanxIdentity};
use phalanx::sentinel::{Sentinel, ControlMessage};
use phalanx::config::PhalanxConfig;
use phalanx::stronghold::Stronghold;
use phalanx::{PhalanxBehaviour, PhalanxEvent}; 

// --- THE STATE STRUCT ---
// Encapsulates the "Self" so the main loop doesn't have to manage variables.
struct PhalanxNode {
    sentinel: Sentinel,
    storage: Stronghold,
    identity: PhalanxIdentity,
    config: PhalanxConfig,
    local_peer_id: NetworkId,
}

impl PhalanxNode {
    /// The Central Brain: Decides what to do with a Network Event
    fn handle_network_event(
        &mut self, 
        event: PhalanxEvent, 
        swarm: &mut Swarm<PhalanxBehaviour>
    ) {
        match event {
            // 1. DATA LAYER: Receive Evidence Shards
            PhalanxEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                let topic_str = message.topic.as_str();
                
                // Deserialize the shard
                if let Ok(chunk) = postcard::from_bytes::<shards::ShardChunk>(&message.data) {
                    // Pass to Sentinel for Reassembly
                    if let Some(envelope) = self.sentinel.process_chunk(
                        chunk, 
                        topic_str, 
                        &self.config, 
                        &self.identity, 
                        self.local_peer_id
                    ) {
                        // If reassembly is complete, save to vault
                        self.storage.ingest_envelope(envelope);
                    }
                }
            }

            // 2. DISCOVERY: mDNS (Local Network)
            PhalanxEvent::Mdns(mdns::Event::Discovered(list)) => {
                for (peer_id, multiaddr) in list {
                    tracing::debug!(%peer_id, "mDNS: Discovered local peer");
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                }
            }

            // 3. ROUTING: Kademlia (WAN/DHT)
            PhalanxEvent::Kademlia(kad_event) => {
                self.handle_kademlia_event(kad_event, swarm);
            }

            // 4. IDENTITY: Public IP Resolution
            PhalanxEvent::Identify(identify::Event::Received { peer_id, info, .. }) => {
                for addr in info.listen_addrs {
                    swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                }
            }

            _ => {}
        }
    }

    /// Sub-handler for DHT logic (Service Discovery)
    fn handle_kademlia_event(
        &self, 
        event: libp2p::kad::Event, 
        swarm: &mut Swarm<PhalanxBehaviour>
    ) {
        match event {
            // Found a Service Provider (Stronghold)
            kad::Event::OutboundQueryProgressed {
                result: kad::QueryResult::GetProviders(Ok(kad::GetProvidersOk::FoundProviders { providers, key, .. })),
                ..
            } => {
                // Ensure it is the correct service key
                if key == phalanx::network::get_storage_key() {
                    for peer in providers {
                        tracing::info!(%peer, "DISCOVERY: Found Stronghold Node!");
                        // Auto-dial to establish direct data link
                        swarm.dial(peer).unwrap_or_else(|_| {});
                    }
                }
            }
            // Ignore other DHT events (routing updates, etc)
            _ => {}
        }
    }
    
    /// Handler for Local Hardware Inputs (Camera/Mic)
    fn handle_local_evidence(
        &mut self,
        swarm: &mut Swarm<PhalanxBehaviour>,
        evidence: Evidence
    ) {
        // 1. Create Witness Envelope
        let envelope = WitnessEnvelope::new(evidence.clone(), &self.identity, self.local_peer_id);
        
        // 2. Persist Locally (Always save your own data first)
        self.storage.ingest_envelope(envelope.clone());
    
        // 3. Select Topic
        let topic_str = match evidence {
            Evidence::Video(_) => &self.config.network.video_topic,
            Evidence::Audio(_) => &self.config.network.audio_topic,
        };
    
        // 4. Chunkify and Broadcast
        if let Ok(encoded) = postcard::to_stdvec(&envelope) {
            let chunks = shards::chunkify(
                shards::ShardId(evidence.sequence_id().0),
                encoded,
                self.config.network.chunk_size_bytes,
                self.identity.did.clone(),
            );
    
            let topic = gossipsub::IdentTopic::new(topic_str);
            for chunk in chunks {
                if let Ok(chunk_bytes) = postcard::to_stdvec(&chunk) {
                    let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), chunk_bytes);
                }
            }
        }
    }

    /// Broadcast System Status
    fn broadcast_heartbeat(&self, swarm: &mut Swarm<PhalanxBehaviour>) {
        let hb = ControlMessage {
            sender: self.local_peer_id,
            load_factor: 0.0, // Placeholder
            storage_remaining_mb: 1024, // Placeholder
        };
    
        if let Ok(encoded) = postcard::to_stdvec(&hb) {
            let topic = gossipsub::IdentTopic::new(&self.config.network.control_topic);
            let _ = swarm.behaviour_mut().gossipsub.publish(topic, encoded);
        }
    }
}

// --- MAIN ENTRY POINT ---
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    phalanx::obs::init_observability();

    // 1. Initialization Phase
    let config = PhalanxConfig::load_from_env();
    setup_shutdown_handler();
    
    let my_identity = phalanx::init_identity();
    let sentinel = Sentinel::new(&config);
    let storage = Stronghold::new(&config.storage.vault_path, &config);
    
    // Setup Network with proper key conversion
    let mut swarm = phalanx::setup_phalanx_swarm(my_identity.to_libp2p_keypair())?;
    
    // Bind to Random Port (Client Mode)
    // Use Port 0 to let OS assign an available port
    swarm.listen_on("/ip4/0.0.0.0/tcp/0".parse()?)?;

    let local_peer_id = NetworkId(*swarm.local_peer_id());

    // Initialize State Bundle
    let mut node = PhalanxNode {
        sentinel,
        storage,
        identity: my_identity,
        config: config.clone(),
        local_peer_id,
    };

    // 2. Hardware Orchestration
    let current_volley_id = format!("volley_{}_{}", node.identity.did.to_safe_name(), chrono::Utc::now().timestamp());
    tracing::info!(volley = %current_volley_id, "New Forensic Volley Initialized");
    
    subscribe_to_topics(&mut swarm, &config);
    let (mut video_rx, mut audio_rx) = spawn_hardware_threads(&config, current_volley_id);

    // 3. Timers
    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(config.network.heartbeat_interval_secs));
    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(config.network.cleanup_interval_secs));
    let mut discovery_timer = tokio::time::interval(Duration::from_secs(30)); // Service Discovery

    // 4. Bootstrap (Optional - Add your VPS here)
    let bootnodes: Vec<&str> = vec![]; 
    for peer_str in bootnodes {
        if let Ok(multiaddr) = peer_str.parse::<libp2p::Multiaddr>() {
            tracing::info!("Bootstrapping: Dialing {}", peer_str);
            let _ = swarm.dial(multiaddr.clone());
            // Add to DHT
            if let Some(libp2p::multiaddr::Protocol::P2p(peer_id)) = multiaddr.iter().last() {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
            }
        }
    }

    println!("--- PHALANX SENSOR: ONLINE (WAN + LAN) ---");

    // 5. The Clean Loop
    loop {
        select! {
            // --- Hardware Inputs ---
            Some(v_shard) = video_rx.recv() => {
                node.handle_local_evidence(&mut swarm, Evidence::Video(v_shard));
            }
            
            Some(a_shard) = audio_rx.recv() => {
                node.handle_local_evidence(&mut swarm, Evidence::Audio(a_shard));
            }

            // --- Network Events ---
            // The swarm yields events; we delegate processing to the Node struct.
            event = swarm.select_next_some() => {
                if let SwarmEvent::Behaviour(phalanx_event) = event {
                    node.handle_network_event(phalanx_event, &mut swarm);
                }
            }

            // --- Maintenance Timers ---
            _ = heartbeat_timer.tick() => {
                node.broadcast_heartbeat(&mut swarm);
            }

            _ = discovery_timer.tick() => {
                // Periodically ask the network: "Who provides storage?"
                let key = phalanx::network::get_storage_key();
                swarm.behaviour_mut().kademlia.get_providers(key);
            }

            _ = cleanup_timer.tick() => {
                node.sentinel.prune_stale_buffers(&node.config);
                node.storage.archive_stale_sessions(Duration::from_secs(node.config.storage.stale_session_threshold));
            }
        }
    }
}

// --- HELPERS ---

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