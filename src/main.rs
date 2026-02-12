use libp2p::{gossipsub, identify, kad, mdns, swarm::SwarmEvent, Swarm, futures::StreamExt};
use phalanx::core::types::UnitInterval;
use std::error::Error;
use std::time::Duration;
use tokio::select;
use tokio::sync::mpsc;

// Internal Modules
use phalanx::protocol::shards::{self, Evidence, WitnessEnvelope};
use phalanx::hardware::{camera, audio};
use phalanx::security::identity::{NetworkId, PhalanxIdentity};
use phalanx::security::sentinel::{Sentinel, ControlMessage};
use phalanx::security::e2ee;
use phalanx::core::config::{PhalanxConfig, PhalanxPhysics};
use phalanx::storage::guardian::Guardian;
use phalanx::{PhalanxBehaviour, PhalanxEvent}; 

// --- THE STATE STRUCT ---
// Encapsulates the "Self" so the main loop doesn't have to manage variables.
struct PhalanxNode {
    sentinel: Sentinel,
    storage: Guardian,
    identity: PhalanxIdentity,
    config: PhalanxConfig,
    local_peer_id: NetworkId,
}

impl PhalanxNode {
    /// The Central Brain: Decides what to do with a Network Event
    fn handle_network_event(
        &mut self, 
        event: PhalanxEvent, 
        swarm: &mut Swarm<PhalanxBehaviour>,
        is_leaf: bool
    ) {
        match event {
            // 1. DATA LAYER: Receive Evidence Shards
            PhalanxEvent::Gossipsub(gossipsub::Event::Message { message, .. }) => {
                let topic_str = message.topic.as_str();
                
                // Deserialize the shard
                if let Ok(chunk) = postcard::from_bytes::<shards::ShardChunk>(&message.data) {
                    // Pass to Sentinel for Reassembly
                    if let Some(envelope) = self.sentinel.process_chunk(
                        chunk.clone(), 
                        topic_str, 
                        &self.config, 
                        &self.identity, 
                        self.local_peer_id
                    ) {
                        // If reassembly is complete, save to vault
                        _ = self.storage.ingest_envelope(envelope);
                    }

                    self.storage.ingest_chunk(chunk.clone(), is_leaf);
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
                if key == phalanx::network::network::get_storage_key() {
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
        _ = self.storage.ingest_envelope(envelope.clone());
    
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
    fn broadcast_heartbeat(&self, swarm: &mut Swarm<PhalanxBehaviour>, physics: &PhalanxPhysics) {
        let load_factor = (self.sentinel.video_buffers.len() + self.sentinel.audio_buffers.len()) as f32 
                    / self.config.storage.max_peers as f32;
    
        // 2. Derive dynamic interval
        let current_interval = physics.heartbeat_interval(load_factor);
        
        let hb = ControlMessage {
            sender: self.local_peer_id,
            load_factor: load_factor, 
            storage_remaining_mb: 1024, // Placeholder
            heartbeat_ms: current_interval.as_millis() as u64,
            is_leaf: self.sentinel.is_leaf_mode(),
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
    phalanx::core::telemetry::init_observability();

    // 1. Initialization Phase
    let config = PhalanxConfig::load_from_env();
    setup_shutdown_handler();
    
    let my_identity = phalanx::init_identity();
    let sentinel = Sentinel::new(&config);
    let storage = Guardian::new(&config.storage.vault_path, &config, my_identity.did.clone());
    
    // 3. SYNC TIME (Blocking or Async)
    // We do this BEFORE starting the network to ensure we don't accept bad data.
    println!("[PHALANX] Synchronizing Clock with NTP...");
    let clock_ref = storage.clock.clone();
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async {
            let _ = clock_ref.synchronize().await;
        });
    }).await?;

    let stronghold_flag = true;
    // Setup Network with proper key conversion
    let physics = PhalanxPhysics::default_wan();
    let mut swarm = phalanx::setup_phalanx_swarm(my_identity.to_libp2p_keypair(), stronghold_flag, physics)?;
    
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
        node.sentinel.update_power_strategy();
        let is_leaf = node.sentinel.is_leaf_mode();
        
        let raw_load = (node.sentinel.video_buffers.len() + node.sentinel.audio_buffers.len()) as f32
                    / node.config.storage.max_peers as f32;
        let load_factor = UnitInterval::new(raw_load);

        let next_heartbeat = physics.heartbeat_interval(load_factor.as_f32());

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
                    node.handle_network_event(phalanx_event, &mut swarm, is_leaf);
                }
            }

            // --- Maintenance Timers ---
            // 
            _ = tokio::time::sleep(next_heartbeat) => {
                node.broadcast_heartbeat(&mut swarm, &physics);

                if load_factor > UnitInterval::new(0.7) {
                    tracing::warn!(load = %load_factor, interval = ?next_heartbeat, "Node under stress: Throttling heartbeats");
                }
            }

            _ = discovery_timer.tick() => {
                // Periodically ask the network: "Who provides storage?"
                let key = phalanx::network::network::get_storage_key();
                swarm.behaviour_mut().kademlia.get_providers(key);
            }

            _ = cleanup_timer.tick() => {
                node.sentinel.prune_stale_buffers(&node.config, &physics);
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

fn spawn_hardware_threads(config: &PhalanxConfig, volley_id: String) -> (mpsc::Receiver<shards::VideoShard>, mpsc::Receiver<shards::AudioShard>) {
    let (v_tx, v_rx) = mpsc::channel(64);
    let (a_tx, a_rx) = mpsc::channel(64);

    let session_key: [u8; 32] = e2ee::generate_session_key();
    tracing::info!("E2EE Enabled. Session Key Generated.");

    // FIX: Use new constructor for PhalanxCameraThread
    let camera_thread = camera::PhalanxCameraThread::new(&config.hardware);
    camera_thread.spawn(Some(0), v_tx, config.hardware.clone(), volley_id.clone(), Some(session_key));

    let audio_thread = audio::PhalanxAudioThread::new(&config.hardware);
    audio_thread.spawn(a_tx, config.hardware.clone(), volley_id, Some(session_key));

    (v_rx, a_rx)
}

#[cfg(test)]
mod tests {
    use phalanx::hardware::{camera, audio};
    use phalanx::core::config::HardwareConfig;
    use phalanx::protocol::shards::DataPayload;
    use phalanx::security::e2ee;
    use tokio::sync::mpsc;
    use std::time::Duration;

    #[tokio::test]
    async fn test_camera_thread_produces_encrypted_shards() {
        // 1. Setup
        let (tx, mut rx) = mpsc::channel(10);
        let config = HardwareConfig {
            camera_fps: 10, // Fast FPS for quick test
            audio_sample_rate: 44100,
            audio_channels: 2,
        };
        let volley_id = "test_volley".to_string();
        let key = e2ee::generate_session_key();

        // 2. Spawn Thread
        // FIX: Use new constructor
        let cam_thread = camera::PhalanxCameraThread::new(&config);
        // Passing None for index forces MockCamera (via default behavior in CameraDriver)
        cam_thread.spawn(None, tx, config, volley_id.clone(), Some(key));

        // 3. Receive Shard (Wait max 2s)
        let shard = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Timed out waiting for camera shard")
            .expect("Channel closed unexpectedly");

        // 4. Verification
        assert_eq!(shard.volley_id, volley_id);
        
        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce.len(), 24);
                assert!(!ciphertext.is_empty());
                
                // 5. Verify Decryptability
                let decrypted = shard.payload.decrypt(&key).expect("Failed to decrypt shard");
                // VideoShard frames are serialized Vec<Vec<u8>>
                let frames: Vec<Vec<u8>> = postcard::from_bytes(&decrypted).unwrap();
                assert!(!frames.is_empty(), "Decrypted frames should not be empty");
            },
            DataPayload::Clear(_) => panic!("Camera thread produced CLEAR text despite having a key!"),
        }
    }

    #[tokio::test]
    async fn test_audio_thread_produces_encrypted_shards() {
        // 1. Setup
        let (tx, mut rx) = mpsc::channel(10);
        let config = HardwareConfig {
            camera_fps: 1, 
            audio_sample_rate: 44100,
            audio_channels: 2,
        };
        let volley_id = "test_volley_audio".to_string();
        let key = e2ee::generate_session_key();

        // 2. Spawn
        let audio_thread = audio::PhalanxAudioThread::new(&config);
        audio_thread.spawn(tx, config.clone(), volley_id, Some(key));

        // 3. Receive
        let shard = tokio::time::timeout(Duration::from_secs(3), rx.recv())
            .await
            .expect("Timed out waiting for audio shard")
            .expect("Channel closed");

        // 4. Verification
        match &shard.payload {
            DataPayload::Encrypted { nonce, ciphertext } => {
                assert_eq!(nonce.len(), 24);
                assert!(!ciphertext.is_empty());
                
                // 5. Verify Decryptability
                let decrypted = shard.payload.decrypt(&key).expect("Failed to decrypt audio");
                
                let expected_bytes = (config.audio_sample_rate * config.audio_channels as u32 * 2) as usize;
                assert_eq!(decrypted.len(), expected_bytes, "Shard did not contain 1 second of audio data");
            },
            DataPayload::Clear(_) => panic!("Audio thread produced CLEAR text despite having a key!"),
        }
    }
}

