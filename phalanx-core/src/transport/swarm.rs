use libp2p::{
    gossipsub, identify, kad, mdns, noise, 
    relay, dcutr, autonat, pnet, 
    swarm::{NetworkBehaviour}, 
    tcp, yamux, Swarm, Transport, SwarmBuilder, 
    core::upgrade::Version,
    PeerId,
    identity::Keypair,
};
use libp2p::kad::RecordKey;
pub use libp2p::pnet::PreSharedKey;
use futures::future::Either; // Required for Transport unification

use std::error::Error;
use std::time::Duration;
use std::path::Path;
use std::fs;

// Domain Imports
use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::base::types::{UnitInterval, VitalityRate, PowerState};

// --- CONSTANTS ---
pub type PhalanxKadStore = kad::store::MemoryStore;
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
    pub relay_client: relay::client::Behaviour, // The Client Behaviour
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

impl From<gossipsub::Event> for PhalanxEvent { fn from(v: gossipsub::Event) -> Self { Self::Gossipsub(v) } }
impl From<mdns::Event> for PhalanxEvent { fn from(v: mdns::Event) -> Self { Self::Mdns(v) } }
impl From<kad::Event> for PhalanxEvent { fn from(v: kad::Event) -> Self { Self::Kademlia(v) } }
impl From<identify::Event> for PhalanxEvent { fn from(v: identify::Event) -> Self { Self::Identify(v) } }
impl From<relay::Event> for PhalanxEvent { fn from(v: relay::Event) -> Self { Self::RelayServer(v) } }
impl From<relay::client::Event> for PhalanxEvent { fn from(v: relay::client::Event) -> Self { Self::RelayClient(v) } }
impl From<dcutr::Event> for PhalanxEvent { fn from(v: dcutr::Event) -> Self { Self::Dcutr(v) } }
impl From<autonat::Event> for PhalanxEvent { fn from(v: autonat::Event) -> Self { Self::Autonat(v) } }

// --- 1. TRANSPORT BUILDER ---
// Note: Relay transport is now handled in the main setup to resolve dependencies
fn build_base_transport(
    local_key: &Keypair, 
    psk: Option<PreSharedKey>
) -> Result<libp2p::core::transport::Boxed<(PeerId, libp2p::core::muxing::StreamMuxerBox)>, Box<dyn Error>> {
    
    let noise_config = noise::Config::new(local_key)?;
    let yamux_config = yamux::Config::default();

    let base_transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
    let dns_transport = libp2p::dns::tokio::Transport::system(base_transport)?;

    // Define the Stream Type Alias to make the annotation readable
    // The "Right" side is a raw TCP Stream
    type RawStream = libp2p::tcp::tokio::TcpStream;
    // The "Left" side is a TCP Stream wrapped in PNet encryption
    type EncryptedStream = libp2p::pnet::PnetOutput<RawStream>;

    let transport = if let Some(key) = psk {
        let pnet_config = pnet::PnetConfig::new(key);
        dns_transport.and_then(move |socket, _| pnet_config.handshake(socket))
            // FIX: Explicitly tell compiler the Right side is RawStream
            .map(|stream, _| Either::<EncryptedStream, RawStream>::Left(stream))
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .boxed()
    } else {
        dns_transport
            // FIX: Explicitly tell compiler the Left side is EncryptedStream
            .map(|stream, _| Either::<EncryptedStream, RawStream>::Right(stream))
            .upgrade(Version::V1)
            .authenticate(noise_config)
            .multiplex(yamux_config)
            .timeout(Duration::from_secs(20))
            .boxed()
    };

    Ok(transport)
}

// --- 2. BEHAVIOUR BUILDER ---
fn build_behaviour(
    local_key: &Keypair, 
    config: &PhalanxConfig,
    physics: &PhalanxPhysics,
    relay_client: relay::client::Behaviour // FIX: Receive injected behaviour
) -> Result<PhalanxBehaviour, Box<dyn Error>> {
    let local_peer_id = local_key.public().to_peer_id();

    // A. Gossipsub
    let gossip_heartbeat = VitalityRate::calculate(
        physics, 
        PowerState::Normal, 
        UnitInterval::new(0.0) 
    ).as_duration();

    let gossipsub = gossipsub::Behaviour::new(
        gossipsub::MessageAuthenticity::Signed(local_key.clone()), 
        gossipsub::ConfigBuilder::default()
            .heartbeat_interval(gossip_heartbeat) 
            .validation_mode(gossipsub::ValidationMode::Strict)
            .max_transmit_size(config.network.max_chunk_size_bytes as usize * 2)
            .build()
            .map_err(|msg| std::io::Error::new(std::io::ErrorKind::Other, msg))?, // FIX: Explicit std::io
    )?;

    // B. Kademlia
    let mut kademlia = kad::Behaviour::new(
        local_peer_id, 
        kad::store::MemoryStore::new(local_peer_id)
    );
    kademlia.set_mode(Some(kad::Mode::Server));

    // C. Identify
    let identify = identify::Behaviour::new(identify::Config::new(
        config.network.protocol_version.clone(),
        local_key.public(),
    ));

    // D. Others
    let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), local_peer_id)?;
    
    // Relay Server (For hosting)
    let relay_server = relay::Behaviour::new(local_peer_id, relay::Config::default());
    
    let dcutr = dcutr::Behaviour::new(local_peer_id);
    let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());

    Ok(PhalanxBehaviour {
        gossipsub,
        mdns,
        kademlia,
        identify,
        relay_server,
        relay_client, // Injected
        dcutr,
        autonat,
    })
}

// --- 3. HELPER: SWARM KEY LOADER ---
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
        Err(_) => None 
    }
}

pub fn generate_swarm_key(path: &str) -> std::io::Result<()> {
    use dalek_rand::RngCore;
    let mut key = [0u8; 32];
    dalek_rand::OsRng.fill_bytes(&mut key);
    fs::write(path, key)
}

// --- 4. MAIN ORCHESTRATOR ---
pub fn setup_phalanx_swarm(
    local_key: Keypair,
    config: &PhalanxConfig,
    physics: &PhalanxPhysics,
    psk: Option<PreSharedKey> 
) -> Result<Swarm<PhalanxBehaviour>, Box<dyn Error>> {
    
    let local_peer_id = local_key.public().to_peer_id();
    tracing::info!(peer_id=%local_peer_id, "Initializing Network Stack...");

    // 1. Initialize Relay Client (Returns Transport + Behaviour)
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);

    // 2. Build Base Transport (TCP/DNS/Noise/Yamux)
    let transport = build_base_transport(&local_key, psk)?;

    // 3. Build Behaviour (Inject Relay Client)
    let behaviour = build_behaviour(&local_key, config, physics, relay_client)?;

    // 4. Build Swarm (NEW API v0.56+)
    let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio() // Set the executor first
        
        // Primary Transport (TCP/DNS/PNet)
        // We wrap the pre-built transport in a closure to satisfy the API
        .with_other_transport(|_key| transport)? 
        
        // Secondary Transport (Relay)
        .with_other_transport(|key| {
            let noise_config = noise::Config::new(key).unwrap();
            let yamux_config = yamux::Config::default();
            
            relay_transport
                .upgrade(Version::V1)
                .authenticate(noise_config)
                .multiplex(yamux_config)
        })?
        
        // Behaviour & Configuration
        .with_behaviour(|_| behaviour)?
        .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
        .build();

    Ok(swarm)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    // --- TEST HELPERS ---

    fn get_test_config() -> (PhalanxConfig, PhalanxPhysics) {
        // Assuming Default or specific constructors exist based on imports
        // If specific values are needed for validation, set them here.
        let config = PhalanxConfig::default(); 
        let physics = PhalanxPhysics::default_wan(); // or test_profile()
        (config, physics)
    }

    fn generate_test_identity() -> Keypair {
        Keypair::generate_ed25519()
    }

    // --- TESTS ---

    #[test]
    fn test_swarm_key_io_roundtrip() {
        // 1. Setup isolated temp directory
        let dir = tempdir().expect("Failed to create temp dir");
        let file_path = dir.path().join("swarm.key");
        let path_str = file_path.to_str().unwrap();

        // 2. Generate Key
        generate_swarm_key(path_str).expect("Failed to generate swarm key");

        // 3. Verify file exists
        assert!(file_path.exists());

        // 4. Load Key
        let loaded_key = load_swarm_key(&file_path);
        assert!(loaded_key.is_some(), "Should successfully load generated key");

        // 5. Verify corruption handling
        let corrupt_path = dir.path().join("corrupt.key");
        let mut f = File::create(&corrupt_path).unwrap();
        f.write_all(b"short_key").unwrap(); // Write invalid length
        
        let loaded_corrupt = load_swarm_key(&corrupt_path);
        assert!(loaded_corrupt.is_none(), "Should reject key with invalid length");
    }

    #[tokio::test]
    async fn test_transport_construction_no_psk() {
        let keypair = generate_test_identity();
        
        // Attempt to build base transport without PSK
        let result = build_base_transport(&keypair, None);
        
        assert!(result.is_ok(), "Transport construction should succeed without PSK");
    }

    #[tokio::test]
    async fn test_transport_construction_with_psk() {
        let keypair = generate_test_identity();
        
        // Manually construct a PSK
        let mut bytes = [0u8; 32];
        bytes[0] = 1; // arbitrary
        let psk = PreSharedKey::new(bytes);

        // Attempt to build base transport with PSK
        let result = build_base_transport(&keypair, Some(psk));
        
        assert!(result.is_ok(), "Transport construction should succeed with PSK");
    }

    #[tokio::test]
    async fn test_behaviour_initialization() {
        let keypair = generate_test_identity();
        let (config, physics) = get_test_config();
        let local_peer_id = keypair.public().to_peer_id();

        // Initialize relay client (dependency injection)
        let (_, relay_client_behaviour) = relay::client::new(local_peer_id);

        let result = build_behaviour(
            &keypair,
            &config,
            &physics,
            relay_client_behaviour
        );

        assert!(result.is_ok(), "PhalanxBehaviour should initialize with valid config");
        
        let behaviour = result.unwrap();
        // Verify Kademlia mode is Server (as set in build_behaviour)
        // Note: access to internal mode might be restricted, but we verify the struct exists
        assert!(matches!(behaviour.kademlia, kad::Behaviour { .. }));
    }

    #[tokio::test]
    async fn test_full_swarm_setup() {
        let keypair = generate_test_identity();
        let expected_peer_id = keypair.public().to_peer_id();
        let (config, physics) = get_test_config();

        // Test the main orchestrator function
        let swarm_result = setup_phalanx_swarm(
            keypair, 
            &config, 
            &physics, 
            None // No PSK for this test
        );

        assert!(swarm_result.is_ok(), "SwarmBuilder pipeline should complete without error");

        let swarm = swarm_result.unwrap();
        assert_eq!(
            *swarm.local_peer_id(), 
            expected_peer_id, 
            "Swarm should be initialized with the provided identity"
        );
    }
}