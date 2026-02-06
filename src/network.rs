use libp2p::{
    gossipsub, identify, kad, mdns, noise, 
    relay, dcutr, autonat, 
    swarm::{NetworkBehaviour}
        , SwarmBuilder, 
    tcp, yamux, Swarm, Transport,
    core::upgrade::Version
};
use std::time::Duration;
use tokio::io;
use libp2p::kad::RecordKey;
use crate::config::PhalanxPhysics;
use void::Void;

// Define a custom Kademlia Record Store
pub type PhalanxKadStore = kad::store::MemoryStore;

// Service Keys
pub const SERVICE_STORAGE: &[u8] = b"phalanx/service/storage/v1";

pub fn get_storage_key() -> RecordKey {
    RecordKey::new(&SERVICE_STORAGE)
}

#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    // Phase 1 Core
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<PhalanxKadStore>,
    pub identify: identify::Behaviour,

    // Phase 1 NAT Traversal
    pub relay_server: relay::Behaviour,      
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,              
    pub autonat: autonat::Behaviour, // <--- The field causing the error

    pub physics: PhalanxPhysics,
}

#[derive(Debug)]
pub enum PhalanxEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
    Kademlia(kad::Event),
    Identify(identify::Event),
    RelayServer(relay::Event),
    RelayClient(relay::client::Event),
    Dcutr(dcutr::Event),
    Autonat(autonat::Event), // <--- Ensure this variant exists
}

// --- TRAIT IMPLEMENTATIONS ---
// These allow the generic NetworkBehaviour to "bubble up" events to your enum.
impl From<Void> for PhalanxEvent {
    fn from(event: Void) -> Self {
        // This tells the compiler: "If a Void event happens, the program is invalid."
        // Since Void is uninhabited, this code is technically unreachable, 
        // but it satisfies the type checker.
        void::unreachable(event)
    }
}

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
impl From<relay::Event> for PhalanxEvent {
    fn from(v: relay::Event) -> Self { Self::RelayServer(v) }
}
impl From<relay::client::Event> for PhalanxEvent {
    fn from(v: relay::client::Event) -> Self { Self::RelayClient(v) }
}
impl From<dcutr::Event> for PhalanxEvent {
    fn from(v: dcutr::Event) -> Self { Self::Dcutr(v) }
}
// !!! THIS IS THE MISSING BLOCK CAUSING YOUR ERROR !!!
impl From<autonat::Event> for PhalanxEvent {
    fn from(v: autonat::Event) -> Self { Self::Autonat(v) }
}

pub fn setup_phalanx_swarm(
    local_key: libp2p::identity::Keypair,
    is_stronghold: bool,
    physics: PhalanxPhysics,
) -> Result<Swarm<PhalanxBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = libp2p::PeerId::from(local_key.public());
    
    // 1. Core Protocols
    let kad_store = kad::store::MemoryStore::new(local_peer_id);
    let kademlia = kad::Behaviour::with_config(local_peer_id, kad_store, kad::Config::default());

    let identify = identify::Behaviour::new(identify::Config::new(
        "/phalanx/1.0.0".to_string(),
        local_key.public(),
    ));

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub::ConfigBuilder::default()
            .heartbeat_interval(physics.heartbeat_interval())
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|msg| io::Error::new(io::ErrorKind::Other, msg))?,
    )?;

    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;

    // 2. NAT Traversal Protocols
    
    // A. Relay Server (Stronghold Only)
    let relay_config = if is_stronghold {
        relay::Config::default()
    } else {
        relay::Config {
            max_reservations: 0, 
            ..Default::default()
        }
    };
    let relay_server = relay::Behaviour::new(local_peer_id, relay_config);

    // B. Relay Client & DCUtR
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let dcutr = dcutr::Behaviour::new(local_peer_id);

    // C. AutoNAT
    let autonat_config = autonat::Config {
        use_connected: true,
        ..Default::default()
    };
    let autonat = autonat::Behaviour::new(local_peer_id, autonat_config);

    // 3. Build Behaviour
    let behaviour = PhalanxBehaviour {
        gossipsub,
        mdns,
        kademlia,
        identify,
        relay_server,
        relay_client,
        dcutr,
        autonat,
        physics
    };

    // 4. Build Swarm
    let swarm = SwarmBuilder::with_existing_identity(local_key)
        .with_tokio()
        .with_tcp(
            tcp::Config::default().nodelay(true),
            noise::Config::new,
            yamux::Config::default,
        )?
        .with_other_transport(|key| {
            let noise_config = noise::Config::new(&key).unwrap();
            let yamux_config = yamux::Config::default();
            
            
            relay_transport
                .upgrade(Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux_config)
        })? // Chained Relay Transport
        .with_dns()?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}