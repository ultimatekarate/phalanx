use libp2p::{futures::StreamExt, swarm::SwarmEvent};
use phalanx::{
    stronghold::Stronghold, 
    shards::{WitnessEnvelope, ShardChunk}, 
    sentinel::Sentinel,
    config::PhalanxConfig,
    identity::PhalanxIdentity,
};

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    println!("PHALANX STRONGHOLD: Initializing Headless PDS...");

    // 1. Load Configuration
    let config = PhalanxConfig::load("phalanx.toml")
        .expect("Failed to load phalanx.toml. PDS requires a valid configuration.");
    
    // Initialize the Storage Engine (The Stronghold)
    let mut storage = Stronghold::new("./vault");
    let mut sentinel = Sentinel::new(&config);
    let mut swarm = phalanx::setup_phalanx_swarm(&config).await?;

    let video_topic = libp2p::gossipsub::IdentTopic::new(&config.network.video_topic);
    swarm.behaviour_mut().gossipsub.subscribe(&video_topic)?;
    swarm.behaviour_mut().gossipsub.subscribe(&sentinel.control_topic)?;

    let port = std::env::args().nth(1).unwrap_or("4001".to_string());
    swarm.listen_on(format!("/ip4/0.0.0.0/tcp/{}", port).parse()?)?;

    println!("Stronghold Status: Online. PeerID: {}", swarm.local_peer_id());

    loop {
        tokio::select! {
            event = swarm.select_next_some() => match event {
                SwarmEvent::Behaviour(phalanx::PhalanxEvent::Gossipsub(libp2p::gossipsub::Event::Message { message, .. })) => {
                    if message.topic == video_topic.hash() {
                        if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(&message.data) {
                            if let Some(envelope_bytes) = handle_reassembly(&mut sentinel, chunk) {
                                process_verified_envelope(&envelope_bytes, &mut storage);
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

fn process_verified_envelope(bytes: &[u8], storage: &mut Stronghold) {
    if let Ok(envelope) = postcard::from_bytes::<WitnessEnvelope>(bytes) {
        if let Ok(shard_bytes) = postcard::to_stdvec(&envelope.original_shard) {
            let clean_did = envelope.did.replace("did:key:z", "");
            
            if let Ok(pubkey_bytes) = bs58::decode(clean_did).into_vec() {
                if PhalanxIdentity::verify(&pubkey_bytes, &shard_bytes, &envelope.signature) {
                    println!("Verified: Shard #{} [DID: {}]", envelope.original_shard.sequence_id, envelope.did);
                    storage.ingest_envelope(envelope);
                } else {
                    println!("Rejected: Signature Mismatch for DID {}", envelope.did);
                }
            }
        }
    }
}

fn handle_reassembly(sentinel: &mut Sentinel, chunk: ShardChunk) -> Option<Vec<u8>> {
    let entry = sentinel.chunk_reassembly.entry(chunk.shard_id)
        .or_insert_with(|| vec![None; chunk.total_chunks as usize]);

    if (chunk.chunk_index as usize) < entry.len() {
        entry[chunk.chunk_index as usize] = Some(chunk.data);
    }

    if entry.iter().all(|c| c.is_some()) {
        let full_data: Vec<u8> = entry.drain(..).map(|c| c.unwrap()).flatten().collect();
        sentinel.chunk_reassembly.remove(&chunk.shard_id);
        return Some(full_data);
    }
    None
}