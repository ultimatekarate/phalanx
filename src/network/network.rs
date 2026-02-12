use libp2p::{
    gossipsub, dns, identify, kad, mdns, noise, 
    relay, dcutr, autonat, pnet, 
    swarm::{NetworkBehaviour}, 
    tcp, yamux, Swarm, Transport, SwarmBuilder, 
    core::upgrade::Version,
    PeerId,
    identity::Keypair,
};
use libp2p::kad::RecordKey;
use libp2p::pnet::PreSharedKey;

use std::error::Error;
use std::time::Duration;
use std::path::Path;
use std::fs;

use futures::future::Either;

// Domain Imports
use crate::core::config::{PhalanxConfig, PhalanxPhysics};
use crate::core::types::{UnitInterval, VitalityRate, PowerState};

// --- CONSTANTS ---
pub type PhalanxKadStore = kad::store::MemoryStore;
// Protocol ID is now derived from Config, but we keep the service key constant
pub const SERVICE_STORAGE: &[u8] = b"phalanx/service/storage/v1";

pub fn get_storage_key() -> RecordKey {
    RecordKey::new(&SERVICE_STORAGE)
}

// --- BEHAVIOUR DEFINITION ---
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<PhalanxKadStore>,
    pub identify: identify::Behaviour,
    pub relay_server: relay::Behaviour,      
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
    pub autonat: autonat::Behaviour,
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
    Autonat(autonat::Event),
}

// Macro to delegate enum variants (Boilerplate reduction)
impl From<gossipsub::Event> for PhalanxEvent { fn from(v: gossipsub::Event) -> Self { Self::Gossipsub(v) } }
impl From<mdns::Event> for PhalanxEvent { fn from(v: mdns::Event) -> Self { Self::Mdns(v) } }
impl From<kad::Event> for PhalanxEvent { fn from(v: kad::Event) -> Self { Self::Kademlia(v) } }
impl From<identify::Event> for PhalanxEvent { fn from(v: identify::Event) -> Self { Self::Identify(v) } }
impl From<relay::Event> for PhalanxEvent { fn from(v: relay::Event) -> Self { Self::RelayServer(v) } }
impl From<relay::client::Event> for PhalanxEvent { fn from(v: relay::client::Event) -> Self { Self::RelayClient(v) } }
impl From<dcutr::Event> for PhalanxEvent { fn from(v: dcutr::Event) -> Self { Self::Dcutr(v) } }
impl From<autonat::Event> for PhalanxEvent { fn from(v: autonat::Event) -> Self { Self::Autonat(v) } }

// --- 1. TRANSPORT BUILDER (Pure, No Side Effects) ---
fn build_transport(
    local_key: &Keypair, 
    psk: Option<PreSharedKey>
) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, Box<dyn Error>> {
    
    let noise_config = noise::Config::new(local_key)?;
    let yamux_config = yamux::Config::default();

    // Base TCP Transport
    let base_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    
    // Upgrade to DNS (Non-Panicking)
    let dns_transport =  dns::tokio::Transport::system(base_transport)?;

    // Handle Optional Private Network (PNet) Encryption
    // We utilize libp2p's EitherTransport to avoid complex type erasure early on
    let transport = if let Some(key) = psk {
        let pnet_config = pnet::PnetConfig::new(key);
        dns_transport.and_then(move |socket, _| pnet_config.handshake(socket))
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .boxed()
    } else {
        dns_transport
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .boxed()
    };

    Ok(transport)
}

// --- 2. BEHAVIOUR BUILDER (Config Driven) ---
fn build_behaviour(
    local_key: &Keypair, 
    config: &PhalanxConfig,
    physics: &PhalanxPhysics
) -> Result<PhalanxBehaviour, Box<dyn Error>> {
    let local_peer_id = local_key.public().to_peer_id();

    // A. Gossipsub with VitalityRate
    // We use the unified physics logic to set the mesh heartbeat
    let gossip_heartbeat = VitalityRate::calculate(
        physics, 
        PowerState::Normal, 
        UnitInterval::new(0.0) // Assume baseline load for initialization
    ).as_duration();

    let gossipsub_config = gossipsub::ConfigBuilder::default()
        .heartbeat_interval(gossip_heartbeat) 
        .validation_mode(gossipsub::ValidationMode::Strict)
        .max_transmit_size(config.network.max_chunk_size_bytes as usize * 2) // Allow overhead
        .build()
        .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?;

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()), 
        gossipsub_config
    )?;

    // B. Kademlia
    let mut kademlia = kad::Behaviour::new(
        local_peer_id, 
        kad::store::MemoryStore::new(local_peer_id)
    );
    kademlia.set_mode(Some(kad::Mode::Server));

    // C. Identify (Dynamic Protocol Version)
    let identify = identify::Behaviour::new(identify::Config::new(
        config.network.protocol_version.clone(), // "/phalanx/1.0.0"
        local_key.public(),
    ));

    // D. Other Behaviours
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
    let (relay_client, _) = relay::client::Behaviour::new(local_peer_id, relay::client::Config::default());
    let relay_server = relay::Behaviour::new(local_peer_id, relay::Config::default());
    let dcutr = dcutr::Behaviour::new(local_peer_id);
    let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());

    Ok(PhalanxBehaviour {
        gossipsub,
        mdns,
        kademlia,
        identify,
        relay_server,
        relay_client,
        dcutr,
        autonat,
    })
}

// --- 3. HELPER: SWARM KEY LOADER (Separated I/O) ---
/// Reads the swarm key from disk. Caller handles this in a blocking context if needed.
pub fn load_swarm_key(path: &Path) -> Option<PreSharedKey> {
    match fs::read(path) {
        Ok(bytes) => {
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                Some(PreSharedKey::new(arr))
            } else {
                tracing::error!("Swarm key at {:?} is corrupt (wrong length). Ignoring.", path);
                None
            }
        },
        Err(_) => None // No key found, strictly Public Mode
    }
}

pub fn generate_swarm_key(path: &str) -> std::io::Result<()> {
    use dalek_rand::RngCore;
    let mut key = [0u8; 32];
    dalek_rand::OsRng.fill_bytes(&mut key);
    fs::write(path, key)
}

// --- 4. MAIN ORCHESTRATOR ---
/// Initializes the Phalanx Swarm.
/// 
/// - `local_key`: Identity of the node.
/// - `config`: Dynamic configuration source.
/// - `physics`: Physics engine for timing parameters.
/// - `psk`: Optional Private Network key (Inject this!).
pub fn setup_phalanx_swarm(
    local_key: libp2p::identity::Keypair,
    is_stronghold: bool,
    physics: PhalanxPhysics,
) -> Result<Swarm<PhalanxBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = libp2p::PeerId::from(local_key.public());

    // ... [PSK loading logic remains the same] ...
    let psk = if let Ok(key_bytes) = fs::read("swarm.key") {
        match key_bytes.try_into() {
            Ok(bytes) => Some(pnet::PreSharedKey::new(bytes)),
            Err(_) => None
        }
    } else {
        None
    };

    // ... [Behaviour initialization remains the same] ...
    let kad_store = kad::store::MemoryStore::new(local_peer_id);
    let kademlia = kad::Behaviour::with_config(local_peer_id, kad_store, kad::Config::default());
    
    let identify = identify::Behaviour::new(identify::Config::new(
        "/phalanx/1.0.0".to_string(),
        local_key.public(),
    ));

    let gossip_heartbeat = VitalityRate::calculate(
        &physics, 
        PowerState::Normal, 
        UnitInterval::new(0.0)
    ).as_duration();

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()),
        gossipsub::ConfigBuilder::default()
            .heartbeat_interval(gossip_heartbeat)
            .validation_mode(gossipsub::ValidationMode::Strict)
            .build()
            .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?,
    )?;

    // ... [Other behaviours: mdns, relay, dcutr, autonat] ...
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
    let relay_config = if is_stronghold { relay::Config::default() } else { relay::Config { max_reservations: 0, ..Default::default() } };
    let relay_server = relay::Behaviour::new(local_peer_id, relay_config);
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let dcutr = dcutr::Behaviour::new(local_peer_id);
    let autonat_config = autonat::Config { use_connected: true, ..Default::default() };
    let autonat = autonat::Behaviour::new(local_peer_id, autonat_config);

    let behaviour = PhalanxBehaviour {
        gossipsub, mdns, kademlia, identify,
        relay_server, relay_client, dcutr, autonat
    };

    // --- SWARM BUILDER (Fixed DNS) ---
    let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_other_transport(|key| {
            let base_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
            
            // FIX: Use `libp2p::dns::tokio::Transport`
            // In libp2p 0.56, TokioDnsConfig is gone. You must use the `tokio` module.
            let dns_transport = libp2p::dns::tokio::Transport::system(base_transport)
                .unwrap_or_else(|e| {
                    panic!("Failed to initialize DNS transport: {:?}", e);
                });

            // Handle PSK Encryption (Type Unification)
            let transport = if let Some(psk_key) = psk.clone() {
                dns_transport.and_then(move |socket, _| {
                    pnet::PnetConfig::new(psk_key).handshake(socket)
                })
                .map(|stream, _| Either::Left(stream)) 
                .boxed()
            } else {
                dns_transport
                .map(|stream, _| Either::Right(stream)) 
                .boxed()
            };

            let noise_config = noise::Config::new(key).unwrap();
            let yamux_config = yamux::Config::default();

            transport
                .upgrade(Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux_config)
        })?
        .with_other_transport(|key| {
            let noise_config = noise::Config::new(&key).unwrap();
            let yamux_config = yamux::Config::default();
            relay_transport
                .upgrade(Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux_config)
        })?
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c: libp2p::swarm::Config| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}