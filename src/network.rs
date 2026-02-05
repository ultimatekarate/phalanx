// src/network.rs

use libp2p::{
    gossipsub, identify, kad, mdns, noise, 
    swarm::NetworkBehaviour, tcp, yamux, Swarm
};
use std::time::Duration;
use tokio::io;

// Define a custom Kademlia Record Store (MemoryStore is fine for now)
pub type PhalanxKadStore = kad::store::MemoryStore;

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<PhalanxKadStore>,
    pub identify: identify::Behaviour,
}

#[derive(Debug)]
pub enum PhalanxEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
    Kademlia(kad::Event),
    Identify(identify::Event),
}

// Boilerplate trait implementations to wrap the events
impl From<gossipsub::Event> for PhalanxEvent {
    fn from(v: gossipsub::Event) -> Self { Self::Gossipsub(v) }
}
impl From<mdns::Event> for PhalanxEvent {
    fn from(v: mdns::Event) -> Self { Self::Mdns(v) }
}
impl From<kad::Event> for PhalanxEvent {
    fn from(v: kad::Event) -> Self { Self::Kademlia(v) }
}
impl From<identify::Event> for PhalanxEvent {
    fn from(v: identify::Event) -> Self { Self::Identify(v) }
}

pub fn setup_phalanx_swarm(
    local_key: libp2p::identity::Keypair,
) -> Result<Swarm<PhalanxBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = libp2p::PeerId::from(local_key.public());
    
    // 1. Configure Kademlia & Identify (as we did before)
    let kad_store = kad::store::MemoryStore::new(local_peer_id);
    let kad_config = kad::Config::default();
    let kademlia = kad::Behaviour::with_config(local_peer_id, kad_store, kad_config);

    let identify = identify::Behaviour::new(identify::Config::new(
        "/phalanx/1.0.0".to_string(),
        local_key.public(),
    ));

    // 2. Configure Gossipsub & mDNS
    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(Duration::from_secs(1))
        .validation_mode(gossipsub::ValidationMode::Strict)
        .build()
        .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub_config,
    )?;

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

    // 3. Build the Behaviour
    let behaviour = PhalanxBehaviour {
        gossipsub,
        mdns,
        kademlia,
        identify,
    };

    // 4. THE NEW BUILDER FLOW (v0.56.0)
    let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()                             // Use Tokio for the runtime
        .with_tcp(                                // Use TCP transport
            tcp::Config::default().nodelay(true),
            noise::Config::new,                   // Upgrade with Noise
            yamux::Config::default,               // Upgrade with Yamux
        )?
        .with_behaviour(|_| behaviour)?           // Attach the Phalanx behaviour
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}