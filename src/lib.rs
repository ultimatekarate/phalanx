use libp2p::{gossipsub, mdns, noise, tcp, yamux, Swarm, SwarmBuilder, swarm::NetworkBehaviour};

pub mod shards;
pub mod camera;
pub mod audio;
pub mod sentinel;
pub mod config;
pub mod identity;
pub mod stronghold; 
pub mod obs;
pub mod sim;

use crate::config::PhalanxConfig;
use crate::identity::{PhalanxIdentity, NetworkId};

use std::error::Error;
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "PhalanxEvent")]
pub struct PhalanxBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
}

pub struct PhalanxGossipEvent {
    pub source: NetworkId,
    pub message: gossipsub::Message,
    pub message_id: gossipsub::MessageId,
}

pub enum PhalanxEvent {
    Gossipsub(Box<PhalanxGossipEvent>),
    Mdns(mdns::Event),
}

impl From<gossipsub::Event> for PhalanxEvent {
    fn from(event: gossipsub::Event) -> Self {
        match event {
            gossipsub::Event::Message { propagation_source, message, message_id } => {
                PhalanxEvent::Gossipsub(Box::new(PhalanxGossipEvent {
                    source: NetworkId(propagation_source), // Intercept and wrap here
                    message,
                    message_id,
                }))
            },
            // TODO: Add other gossip events here
            _ => {
                panic!("Unhandled Gossipsub event type in PhalanxEvent conversion");
            }
        }
    }
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
                .map_err(std::io::Error::other)?;

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