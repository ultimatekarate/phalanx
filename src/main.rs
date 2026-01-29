#![allow(dead_code)]

use libp2p::{
    gossipsub, mdns, noise, tcp, yamux, 
    SwarmBuilder,
    swarm::NetworkBehaviour, 
    futures::StreamExt,      
};
use std::error::Error;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::{io, select};

// Hardware and Media crates
use nokhwa::utils::{CameraIndex, RequestedFormat, RequestedFormatType};
use nokhwa::pixel_format::RgbFormat;
use nokhwa::Camera;

use phalanx::vid;

// Define how Phalanx behaves on the network
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour, // Automatically finds other "Phalanx" nodes on the local WiFi
}
// 2. The Custom Event Enum (Must be in the same scope)
pub enum PhalanxEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
}

// 3. The "Glue" (Telling Rust how to wrap sub-events into PhalanxEvent)
impl From<gossipsub::Event> for PhalanxEvent {
    fn from(event: gossipsub::Event) -> Self { PhalanxEvent::Gossipsub(event) }
}

impl From<mdns::Event> for PhalanxEvent {
    fn from(event: mdns::Event) -> Self { PhalanxEvent::Mdns(event) }
}

// ==================
//   MAIN LOOP
// ==================
#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    // System setup
    env_logger::init();
    println!("--- PHALANX: OVERLAPPING SHIELD INITIALIZING ---");

    ctrlc::set_handler(move || {
        println!("\nSentinel shutting down. Releasing hardware...");
        std::process::exit(0);
    }).expect("Error setting Ctrl-C handler");

    // Make sure the camera is working.
    match phalanx::vid::test_single_capture() {
        Ok(size) => println!("Success! Captured a frame of {} bytes.", size),
        Err(e) => println!("Hardware Error: {}", e),
    }

    // Setup Identity & Security (The "Device Passport")
    let mut swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(tcp::Config::default(), noise::Config::new, yamux::Config::default)?
        .with_behaviour(|key| {
            let message_id_fn = |message: &gossipsub::Message| {
                let mut s = std::collections::hash_map::DefaultHasher::new();
                std::hash::Hash::hash(&message.data, &mut s);
                gossipsub::MessageId::from(std::hash::Hasher::finish(&s).to_string())
            };

            let gossipsub_config = gossipsub::ConfigBuilder::default()
                .heartbeat_interval(Duration::from_secs(1))
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .message_id_fn(message_id_fn)
                .max_transmit_size(8 * 1024 * 1024)// 8MB per shard
                .do_px()
                .build()
                .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

            Ok(PhalanxBehaviour {
                gossipsub: gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config,
                )?,
                mdns: mdns::tokio::Behaviour::new(mdns::Config::default(), key.public().to_peer_id())?,
            })
        })?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    // topic subscription and listening
    let topic = gossipsub::IdentTopic::new("phalanx/emergency/the-thing");
    swarm.behaviour_mut().gossipsub.subscribe(&topic)?;

    let port = std::env::args().nth(1).unwrap_or("0".to_string());
    let listen_addr = format!("/ip4/0.0.0.0/tcp/{}", port);
    swarm.listen_on(listen_addr.parse()?)?;

    // Define the local state
    // let mut stdin = io::BufReader::new(io::stdin()).lines();
    let mut peer_heartbeats: HashMap<libp2p::PeerId, Instant> = HashMap::new();
    let mut guardian_buffers: HashMap<libp2p::PeerId, std::collections::VecDeque<vid::VideoShard>> = HashMap::new();

    // Timers
    let mut heartbeat_timer = tokio::time::interval(Duration::from_secs(1));
    let mut cleanup_timer = tokio::time::interval(Duration::from_secs(5));
    const PULSE_TIMEOUT: Duration = Duration::from_secs(10); // 5 seconds of silence = Seizure/Crash
    

    // Define the communication channel
    let (video_tx, mut video_rx) = tokio::sync::mpsc::channel::<vid::VideoShard>(100);

    // 2. Spawn the "Eyes" Task
    std::thread::spawn(move || {
        let mut shredder = vid::Shredder::new();
        
        // Move camera initialization INSIDE the task
        let mut camera = Camera::new(
            CameraIndex::Index(0), 
            RequestedFormat::new::<RgbFormat>(RequestedFormatType::AbsoluteHighestFrameRate)
        ).expect("Webcam not found");
        camera.open_stream().expect("Camera lock failed");

        let mut frame_bundle = Vec::new();
        let frame_duration = std::time::Duration::from_millis(66); // ~15 FPS

        loop {
            if let Ok(frame) = camera.frame() {
                if let Ok(decoded) = frame.decode_image::<RgbFormat>() {
                    let (w, h) = (decoded.width(), decoded.height());
                    
                    // Compress individual frame
                    if let Ok(jpeg) = vid::compress_frame(decoded.into_raw(), w, h) {
                        frame_bundle.push(jpeg);
                    }
                }
            }

            // Once we have 15 frames (1 second of footage), send the bundle
            if frame_bundle.len() >= 15 {

                let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
                let shard = vid::VideoShard {
                    timestamp: now,
                    frames: frame_bundle.split_off(0), // Clears the bundle for the next second
                    sequence_id: shredder.next_id(), // You'll need a small helper method for this
                    fps: 15,
                };
                
                if video_tx.blocking_send(shard).is_err() {
                    break; // Exit if the main loop closed
                }
            }
            std::thread::sleep(frame_duration);
        }
    });

    loop {
        select! {
            Some(shard) = video_rx.recv() => {
                let payload = postcard::to_stdvec(&shard).unwrap();
                match swarm.behaviour_mut().gossipsub.publish(topic.clone(), payload) {
                    Ok(id) => println!("Shard #{} broadcasted (ID: {:?})", shard.sequence_id, id),
                    Err(e) => eprintln!("BROADCAST ERROR: {:?}", e),
                }
            }

            // BRANCH B: The Dead Man's Pulse (The Heartbeat)
            _ = heartbeat_timer.tick() => {
    
                let mesh_peers = swarm.behaviour_mut().gossipsub.all_peers().count();
    
                if mesh_peers > 0 {
                    // If this prints, Node B is sending pulses to NO ONE.
                    println!("{} peers are listening",mesh_peers);
                }
                let pulse = format!("ALIVE|{}|{:?}", swarm.local_peer_id(), Instant::now());
                let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), pulse.as_bytes());
            }

            /*
            // BRANCH C: Manual Input
            Ok(Some(line)) = stdin.next_line() => {
                let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), line.as_bytes());
            }
            */

            // BRANCH D: Monitoring for "Dark" Peers
            // If we notice that someone in the area loses connection abruptly,
            // make sure that what they are recording is still uploaded.
            _ = cleanup_timer.tick() => {
                let now = Instant::now();
                let local_id = *swarm.local_peer_id(); // Get our own ID

                peer_heartbeats.retain(|id, &mut last| {

                    // Don't check on yourself!
                    if id == &local_id { return true; }

                    // Timestamps can be in the future due to initialization
                    if last > now {
                        return true; 
                    }

                    if now.duration_since(last) > PULSE_TIMEOUT {
                        println!("[!!!] ALERT: Witness {} has gone dark. Finalizing evidence.", id);

                        if let Some(shards) = guardian_buffers.remove(id) {
                            let _ = vid::seal_to_vault(id, shards);
                            let _ = vid::recover_vault_to_images(&id.to_string());
                        }
                        false 
                    } else { true }
                });
            }

            // BRANCH E: Network Events
            event = swarm.select_next_some() => match event {
                libp2p::swarm::SwarmEvent::Behaviour(PhalanxEvent::Mdns(mdns::Event::Discovered(list))) => {
                    
                    for (peer_id, multiaddr) in list {
                        if peer_id != *swarm.local_peer_id() {
                            println!("Shield Overlapped: {peer_id}");
                            let _ = swarm.dial(multiaddr.clone());
                            swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                            peer_heartbeats.insert(peer_id,Instant::now() + Duration::from_secs(30));
                        
                        }
                    }
                },
                libp2p::swarm::SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(gossipsub::Event::Message { propagation_source, message, .. })) => {
                    
                    peer_heartbeats.insert(propagation_source, Instant::now());
                    let msg_data=&message.data;
                    
                    // Try to parse the heartbeat, if that fails try to parse shards
                    if let Ok(shard) = postcard::from_bytes::<vid::VideoShard>(msg_data) {
                        println!("Received Shard #{} from {}", shard.sequence_id, propagation_source);
            
                        // 3. Store in the Guardian Buffer
                        let buffer = guardian_buffers.entry(propagation_source).or_insert_with(std::collections::VecDeque::new);
                        buffer.push_back(shard);

                        // 4. Protection: Only keep the last 30 shards (~1 minute of evidence)
                        if buffer.len() > 30 { buffer.pop_front(); }
                    } else {
                        let msg_content = String::from_utf8_lossy(msg_data);

                        if msg_content.starts_with("ALIVE|") {
                            // Clock was already reset at step 1, so we just acknowledge the pulse
                            println!("Heartbeat from {}", propagation_source);
                        }
                    }
                },
                _ => {}
            }
        }
    }
}