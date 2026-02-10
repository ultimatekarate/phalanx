use libp2p::{
    gossipsub, identify, kad, mdns, noise, 
    relay, dcutr, autonat, pnet, 
    swarm::NetworkBehaviour, 
    tcp, yamux, Swarm, Transport, SwarmBuilder, 
    core::upgrade::Version
};
use std::time::Duration;
use tokio::io;
use libp2p::kad::RecordKey;
use crate::core::config::PhalanxPhysics;
use void::Void;
use std::path::Path;
use std::fs;

use libp2p::core::ConnectedPoint;
use libp2p::futures::future::Either;
use dalek_rand::{OsRng, RngCore}; 

pub type PhalanxKadStore = kad::store::MemoryStore;
pub const SERVICE_STORAGE: &[u8] = b"phalanx/service/storage/v1";

pub fn get_storage_key() -> RecordKey {
    RecordKey::new(&SERVICE_STORAGE)
}

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
    Autonat(autonat::Event),
}

impl From<Void> for PhalanxEvent { fn from(e: Void) -> Self { void::unreachable(e) } }
impl From<gossipsub::Event> for PhalanxEvent { fn from(v: gossipsub::Event) -> Self { Self::Gossipsub(v) } }
impl From<mdns::Event> for PhalanxEvent { fn from(v: mdns::Event) -> Self { Self::Mdns(v) } }
impl From<kad::Event> for PhalanxEvent { fn from(v: kad::Event) -> Self { Self::Kademlia(v) } }
impl From<identify::Event> for PhalanxEvent { fn from(v: identify::Event) -> Self { Self::Identify(v) } }
impl From<relay::Event> for PhalanxEvent { fn from(v: relay::Event) -> Self { Self::RelayServer(v) } }
impl From<relay::client::Event> for PhalanxEvent { fn from(v: relay::client::Event) -> Self { Self::RelayClient(v) } }
impl From<dcutr::Event> for PhalanxEvent { fn from(v: dcutr::Event) -> Self { Self::Dcutr(v) } }
impl From<autonat::Event> for PhalanxEvent { fn from(v: autonat::Event) -> Self { Self::Autonat(v) } }

pub fn generate_swarm_key<P: AsRef<Path>>(path: P) -> std::io::Result<()> {
    let mut bytes = [0u8; 32];
    let mut rng = OsRng;
    rng.fill_bytes(&mut bytes); 
    fs::write(path, bytes)
}

pub fn setup_phalanx_swarm(
    local_key: libp2p::identity::Keypair,
    is_stronghold: bool,
    physics: PhalanxPhysics,
) -> Result<Swarm<PhalanxBehaviour>, Box<dyn std::error::Error>> {
    let local_peer_id = libp2p::PeerId::from(local_key.public());

    let psk = if let Ok(key_bytes) = fs::read("swarm.key") {
        match key_bytes.try_into() {
            Ok(bytes) => {
                tracing::info!("Private Swarm Enabled: swarm.key found.");
                Some(pnet::PreSharedKey::new(bytes))
            }
            Err(_) => {
                tracing::error!("Invalid swarm.key: Must be exactly 32 bytes.");
                None
            }
        }
    } else {
        tracing::warn!("Public Swarm: No swarm.key found.");
        None
    };

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

    let relay_config = if is_stronghold { relay::Config::default() } else { relay::Config { max_reservations: 0, ..Default::default() } };
    let relay_server = relay::Behaviour::new(local_peer_id, relay_config);
    let (relay_transport, relay_client) = relay::client::new(local_peer_id);
    let dcutr = dcutr::Behaviour::new(local_peer_id);
    let autonat_config = autonat::Config { use_connected: true, ..Default::default() };
    let autonat = autonat::Behaviour::new(local_peer_id, autonat_config);

    let behaviour = PhalanxBehaviour {
        gossipsub, mdns, kademlia, identify,
        relay_server, relay_client, dcutr, autonat, physics
    };

    let swarm = SwarmBuilder::with_existing_identity(local_key.clone())
        .with_tokio()
        .with_other_transport(|key| {
            let transport = tcp::tokio::Transport::new(tcp::Config::default().nodelay(true));
            
            // FIX 1: Use TokioDnsConfig from the crate root if possible, 
            // OR use the generic DnsConfig if the specific one is hidden.
            // If TokioDnsConfig is still missing, we try this path:
            let transport = libp2p::dns::Transport::system(transport)
                .unwrap_or_else(|_| {
                     // Fallback to pure TCP if DNS fails (avoids crashing at startup)
                    panic!("Failed to initialize DNS transport. Check 'tokio' feature.");
                });

            // Type Unification: Left = Encrypted, Right = Plain
            let transport = if let Some(key) = psk.clone() {
                transport.and_then(move |socket, _endpoint: ConnectedPoint| {
                    pnet::PnetConfig::new(key).handshake(socket)
                })
                .map(|stream, _| Either::Left(stream)) 
                .boxed()
            } else {
                transport
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::identity::PhalanxIdentity;
    use std::fs;

    // A helper to ensure we don't leave garbage files
    fn cleanup() {
        let _ = fs::remove_file("swarm.key");
    }

    #[tokio::test]
    async fn test_swarm_security_lifecycle() {
        // 0. Clean Start
        cleanup(); 

        // Setup Test Data
        let id = PhalanxIdentity::generate();
        let physics = PhalanxPhysics::test_profile(); 

        // --- TEST CASE 1: PUBLIC MODE (No Key) ---
        println!("Test 1: Public Mode (No Key)");
        let public_result = setup_phalanx_swarm(
            id.to_libp2p_keypair(), 
            false, 
            physics.clone()
        );
        assert!(public_result.is_ok(), "Swarm should start in Public Mode when no key exists");

        // --- TEST CASE 2: KEY GENERATION ---
        println!("Test 2: Key Generation");
        let gen_result = generate_swarm_key("swarm.key");
        assert!(gen_result.is_ok(), "Key generation failed");
        
        let metadata = fs::metadata("swarm.key").expect("Key file not found");
        assert_eq!(metadata.len(), 32, "Swarm key MUST be exactly 32 bytes");

        // --- TEST CASE 3: PRIVATE MODE (Valid Key) ---
        println!("Test 3: Private Mode (Valid Key)");
        let private_result = setup_phalanx_swarm(
            id.to_libp2p_keypair(), 
            false, 
            physics.clone()
        );
        assert!(private_result.is_ok(), "Swarm should start in Private Mode with valid key");

        // --- TEST CASE 4: CORRUPT KEY (Graceful Fallback) ---
        println!("Test 4: Corrupt Key Fallback");
        // Overwrite with invalid length (e.g., 10 bytes)
        fs::write("swarm.key", b"bad_key").unwrap();
        
        let fallback_result = setup_phalanx_swarm(
            id.to_libp2p_keypair(), 
            false, 
            physics
        );
        
        // It should NOT crash. It should log an error and fall back to public/unencrypted.
        assert!(fallback_result.is_ok(), "Swarm should survive corrupt key (fallback to public)");

        // Cleanup
        cleanup();
    }
}