use libp2p::{gossipsub, mdns, noise, tcp, yamux, Swarm, SwarmBuilder, swarm::NetworkBehaviour};

pub mod shards;
pub mod camera;
pub mod audio;
pub mod sentinel;
pub mod config;
pub mod identity;
pub mod stronghold;

use crate::config::PhalanxConfig;
use crate::identity::PhalanxIdentity;

use std::error::Error;
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub enum PhalanxEvent {
    Gossipsub(gossipsub::Event),
    Mdns(mdns::Event),
}

impl From<gossipsub::Event> for PhalanxEvent {
    fn from(event: gossipsub::Event) -> Self { PhalanxEvent::Gossipsub(event) }
}

impl From<mdns::Event> for PhalanxEvent {
    fn from(event: mdns::Event) -> Self { PhalanxEvent::Mdns(event) }
}

pub async fn setup_phalanx_swarm(config: &PhalanxConfig) -> Result<Swarm<PhalanxBehaviour>, Box<dyn Error>> {
    let swarm = SwarmBuilder::with_new_identity()
        .with_tokio()
        .with_tcp(
            tcp::Config::default(), 
            noise::Config::new, 
            yamux::Config::default
        )?
        .with_behaviour(|key| {
            // Gossipsub setup with validation matching our chunk size
            let gossip_config = gossipsub::ConfigBuilder::default()
                .validation_mode(gossipsub::ValidationMode::Permissive)
                .max_transmit_size(config.network.chunk_size_bytes + 4096)
                .do_px()
                .build()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

            Ok(PhalanxBehaviour {
                gossipsub: gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()), 
                    gossip_config
                )?,
                mdns: mdns::tokio::Behaviour::new(
                    mdns::Config::default(), 
                    key.public().to_peer_id()
                )?,
            })
        })?
        .build();

    Ok(swarm)
}

pub fn init_identity() -> PhalanxIdentity {
    let id_path = "identity.bin";

    PhalanxIdentity::load_from_disk(id_path).unwrap_or_else(|_| {
        println!("Status: Generating new Phalanx Identity...");

        let new_id = PhalanxIdentity::generate();
        new_id.save_to_disk(id_path).expect("Failed to save identity to disk.");

        new_id
    })
}