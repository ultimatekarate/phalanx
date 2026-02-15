use std::error::Error;
use tokio::sync::mpsc;
use futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};

// Alignment: Use the correct location for the physics engine and strategy
use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::storage::strategies::ShardAmalgam; 
use crate::storage::vault::Guardian;
use crate::primitives::identity::{PhalanxIdentity, Did, NetworkId};
use crate::primitives::shards::{VideoShard, AudioShard, Evidence, WitnessEnvelope};
use crate::{PhalanxBehaviour, PhalanxEvent};
pub use libp2p::pnet::PreSharedKey;

pub struct PhalanxEngine {
    #[allow(dead_code)]
    config: PhalanxConfig, // Will be used in runtime config later.

    identity: PhalanxIdentity,
    swarm: Swarm<PhalanxBehaviour>,

    #[allow(dead_code)]
    crucible: crate::storage::crucible::Crucible<ShardAmalgam>, // Will be used for incoming GossipSub assembly

    guardian: Guardian,
    video_rx: mpsc::Receiver<VideoShard>,
    audio_rx: mpsc::Receiver<AudioShard>,
}

impl PhalanxEngine {
    pub fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        physics: PhalanxPhysics,
        psk: Option<PreSharedKey>,
    ) -> Result<Self, Box<dyn Error>> {
        // 1. Type Alignment: Convert raw [u8; 32] back to PreSharedKey for the utility
        let network_keypair = identity.to_libp2p_keypair();

        let local_peer_id = network_keypair.public().to_peer_id();
        let local_did = Did::from(local_peer_id.to_string());
        let guardian = Guardian::new(
            &config.storage.vault_path, 
            &config, 
            local_did
        );

        // 2. Argument Alignment: setup_phalanx_swarm requires (Keypair, &Config, &Physics, Option<PSK>)
        // We do not .await because the utility is synchronous (per E0277)
        let swarm = crate::transport::swarm::setup_phalanx_swarm(
            network_keypair, // local_key: Keypair
            &config,                  // config: &PhalanxConfig
            &physics,                 // physics: &PhalanxPhysics
            psk                       // psk: Option<PreSharedKey>
        )?; // Removed .await per compiler help

        let (_video_tx, video_rx) = mpsc::channel(config.storage.max_video_buffer);
        let (_audio_tx, audio_rx) = mpsc::channel(config.storage.max_audio_buffer);

        Ok(Self {
            config,
            identity,
            swarm,
            crucible: crate::storage::crucible::Crucible::new(),
            guardian: guardian,
            video_rx,
            audio_rx,
        })
    }

    /// FFI Helper: Boots the engine with default settings rooted at a specific path.
    ///
    /// Behavior: This is the primary entry point for Mobile/FFI bindings where
    /// passing complex structs is difficult. It configures the Vault to live
    /// at `storage_path` and generates/loads a default Identity.
    pub fn new_at_path(storage_path: &str) -> Result<Self, Box<dyn Error>> {
        // 1. Configure Storage Root
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = storage_path.to_string();

        // 2. Load Identity (In a real scenario, this should load from storage_path)
        // For now, we use the standard loader
        let identity = crate::init_identity();

        // 3. Default Physics
        let physics = PhalanxPhysics::default_wan();

        // 4. Initialize (No PSK for default mobile boot)
        Self::new(config, identity, physics, None)
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {

        let local_peer_id = self.swarm.local_peer_id().clone();
        let local_network_id = NetworkId::from(local_peer_id);

        loop {
            tokio::select! {
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await?;
                }

                Some(shard) = self.video_rx.recv() => {
                    // 1. Wrap raw shard in Evidence Enum
                    let evidence = Evidence::Video(shard);
                    // 2. Sign and Seal into WitnessEnvelope
                    let envelope = WitnessEnvelope::new(evidence, &self.identity, local_network_id.clone());
                    // 3. Persist and Aggregate
                    self.finalize_reassembly(envelope).await?;
                }

                Some(shard) = self.audio_rx.recv() => {
                    // 1. Wrap raw shard in Evidence Enum
                    let evidence = Evidence::Audio(shard);
                    // 2. Sign and Seal into WitnessEnvelope
                    let envelope = WitnessEnvelope::new(evidence, &self.identity, local_network_id.clone());
                    // 3. Persist and Aggregate
                    self.finalize_reassembly(envelope).await?;
                }
            }
        }
    }

    async fn finalize_reassembly(&mut self, envelope: WitnessEnvelope) -> Result<(), Box<dyn Error>> {
        // 1. Commit to Write-Ahead Log (WAL) and disk
        // Note: ingest_envelope is synchronous/blocking in the current Guardian impl
        self.guardian.ingest_envelope(envelope)?; 
        
        // 2. (Optional) Forward to Crucible for aggregation into Volleys
        // self.crucible.process(...) 

        Ok(())
    }

    async fn handle_swarm_event(&mut self, event: SwarmEvent<PhalanxEvent>) -> Result<(), Box<dyn Error>> {
        match event {
            SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(_gossip_event)) => {
                // Future reassembly logic
            }
            _ => {}
        }
        Ok(())
    }
}