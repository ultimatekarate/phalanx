use libp2p::{futures::StreamExt, swarm::SwarmEvent};
use phalanx::{
    stronghold::Stronghold, 
    vid::{WitnessEnvelope, ShardChunk}, 
    sentinel::Sentinel,
    config::PhalanxConfig,
};
use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    println!("PHALANX STRONGHOLD: Initializing Headless PDS...");

    // 1. Load Configuration
    let config = PhalanxConfig::load("config.toml").unwrap_or_default();
    
    // 2. Initialize the Storage Engine (The Stronghold)
    let mut storage = Stronghold::new("./vault");
    
    // 3. Initialize the Sentinel (For reassembling network chunks)
    let mut sentinel = Sentinel::new();

    // 4. Initialize Networking Swarm
    // We use the same behavior defined in your lib.rs
    let mut swarm = phalanx::setup_swarm(&config).await?;
    let video_topic = libp2p::gossipsub::IdentTopic::new("phalanx-video");
    swarm.behaviour_mut().gossipsub.subscribe(&video_topic)?;

    println!("Stronghold Status: Online. PeerID: {}", swarm.local_peer_id());

    // 5. The Event Loop
    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(phalanx::PhalanxEvent::Gossipsub(libp2p::gossipsub::Event::Message {
                    message, ..
                })) => {
                    if message.topic == video_topic.hash() {
                        // A. Decode the incoming network chunk
                        if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&message.data) {
                            // B. Pass to Sentinel to reassemble chunks into a full Envelope
                            if let Some(envelope_bytes) = sentinel.ingest_chunk(chunk) {
                                // C. Deserialze the reassembled Envelope
                                if let Ok(envelope) = postcard::from_bytes::<WitnessEnvelope>(&envelope_bytes) {
                                    println!("Stronghold: Received verified shard {} from DID: {}", 
                                        envelope.original_shard.sequence_id, 
                                        envelope.did
                                    );
                                    // D. Ingest into the Stronghold persistence logic
                                    storage.ingest_envelope(envelope);
                                }
                            }
                        }
                    }
                }
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Stronghold listening on: {:?}", address);
                }
                _ => {}
            }
        }
    }
}