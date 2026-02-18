use futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};
use std::error::Error;
use tokio::sync::mpsc;
use tracing::{error, info}; // Added tracing imports

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::primitives::identity::{init_identity, Did, IdentityError, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{AudioShard, Evidence, ShardId, VideoShard, WitnessEnvelope};
use crate::primitives::time::{TimeError, TrustedClock}; // Added TrustedClock
use crate::security::gate::{ForensicGate, IntegrityGate, WitnessGate}; // Import the Gates
use crate::storage::strategies::ShardAmalgam;
use crate::storage::vault::Guardian;
use crate::{PhalanxBehaviour, PhalanxEvent};
use std::io;

pub use libp2p::pnet::PreSharedKey;

#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    #[error("Critical startup failure: {0}")]
    StartupFailure(String),
    #[error("Identity subsystem failure: {0}")]
    Identity(#[from] IdentityError),
    #[error("Forensic persistence error: {0}")]
    Io(#[from] io::Error),
    #[error("Time synchronization error: {0}")]
    Time(#[from] TimeError),
    #[error("Fatal simulator state: {0}")]
    Simulation(String),
}

pub struct PhalanxEngine {
    #[allow(dead_code)]
    config: PhalanxConfig,
    identity: PhalanxIdentity,
    clock: TrustedClock, // Added TrustedClock
    swarm: Swarm<PhalanxBehaviour>,
    #[allow(dead_code)]
    crucible: crate::storage::crucible::Crucible<ShardAmalgam>,
    guardian: Guardian,
    video_rx: mpsc::Receiver<VideoShard>,
    audio_rx: mpsc::Receiver<AudioShard>,

    // Internal state
    seq_counter: u64,
}

impl PhalanxEngine {
    pub fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        physics: PhalanxPhysics,
        psk: Option<PreSharedKey>,
    ) -> Result<Self, Box<dyn Error>> {
        let network_keypair = identity
            .to_libp2p_keypair()
            .map_err(|e| EngineError::StartupFailure(format!("Identity invalid: {}", e)))?;

        // Guardian init (Storage)
        let local_peer_id = network_keypair.public().to_peer_id();
        let local_did = Did::from(local_peer_id.to_string());
        let guardian = Guardian::new(&config.storage.vault_path, &config, local_did);

        // Swarm init (Network)
        let swarm =
            crate::transport::swarm::setup_phalanx_swarm(network_keypair, &config, &physics, psk)?;

        // Channels (Sensors)
        let (_video_tx, video_rx) = mpsc::channel(config.storage.max_video_buffer);
        let (_audio_tx, audio_rx) = mpsc::channel(config.storage.max_audio_buffer);

        // Clock init
        let clock = TrustedClock::new();

        Ok(Self {
            config,
            identity,
            clock,
            swarm,
            crucible: crate::storage::crucible::Crucible::new(),
            guardian,
            video_rx,
            audio_rx,
            seq_counter: 0,
        })
    }

    /// FFI Helper: Boots the engine with minimal arguments for Mobile integration.
    ///
    /// Behavior: This is the primary entry point for Android/iOS bindings where
    /// passing complex Rust structs is difficult. It:
    /// 1. Sets the Storage Root to `storage_path`.
    /// 2. Loads (or generates) the default Identity from disk.
    /// 3. Applies the `default_wan()` physics profile (high latency tolerance).
    pub fn new_at_path(storage_path: &str) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = storage_path.to_string();

        let identity = init_identity("identity.bin").unwrap();
        let physics = PhalanxPhysics::default_wan();

        Self::new(config, identity, physics, None)
    }

    /// The Main Gated Event Loop
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_peer_id = *self.swarm.local_peer_id();
        let local_network_id = NetworkId::from(local_peer_id);

        info!(
            "Phalanx Engine: Active and Gated. PeerID: {}",
            local_peer_id
        );

        loop {
            tokio::select! {
                // ------------------------------------------------------------------
                // PIPELINE 1: RECEPTION (Network -> Storage)
                // ------------------------------------------------------------------
                event = self.swarm.select_next_some() => {
                    match event {
                        SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(
                            libp2p::gossipsub::Event::Message {
                                propagation_source: _,
                                message_id: _,
                                message, // <--- Extract the message struct here
                            }
                        ))=> {
                            // 1. Serialization Gate
                            let envelope = postcard::from_bytes::<WitnessEnvelope>(&message.data)
                                .ok_or_log("deserialization_err", &local_network_id, "Malformed wire packet");

                            // 2. Integrity & Temporal Gate
                            let verified_env = envelope.and_then(|env| {
                                env.check_integrity(&local_network_id, &self.clock, 10) // 10s tolerance
                            });

                            // 3. Promotion Gate (Storage)
                            if let Some(env) = verified_env {
                                if let Err(e) = self.guardian.ingest_envelope(env) {
                                    error!(event = "vault_write_err", error = %e, "Failed to persist foreign evidence");
                                }
                            }
                        }
                        _ => {} // Handle other swarm events if necessary
                    }
                }

                // ------------------------------------------------------------------
                // PIPELINE 2: VIDEO INGESTION (Sensor -> Network)
                // ------------------------------------------------------------------
                Some(shard) = self.video_rx.recv() => {
                    let shard_id = ShardId(self.seq_counter as u32);

                    // Seal -> Chunkify -> Broadcast
                    let chunks = Evidence::Video(shard)
                        .seal(&self.identity, local_network_id)
                        .and_then(|env| {
                            env.chunkify(shard_id)
                                .ok_or_log("chunkify_err", &local_network_id, "Video processing failed")
                        });

                    if let Some(valid_chunks) = chunks {
                        for _chunk in valid_chunks {
                            // self.broadcast_chunk(chunk).await; // TODO: Implement broadcast
                        }
                        self.seq_counter += 1;

                        // We also persist our own data to the WAL
                        // Note: In a real implementation, you might persist the Envelope *before* chunking
                    }
                }

                // ------------------------------------------------------------------
                // PIPELINE 3: AUDIO INGESTION (Sensor -> Network)
                // ------------------------------------------------------------------
                Some(shard) = self.audio_rx.recv() => {
                    let shard_id = ShardId(self.seq_counter as u32);

                    let chunks = Evidence::Audio(shard)
                        .seal(&self.identity, local_network_id)
                        .and_then(|env| {
                            env.chunkify(shard_id)
                                .ok_or_log("chunkify_err", &local_network_id, "Audio processing failed")
                        });

                    if let Some(valid_chunks) = chunks {
                        for _chunk in valid_chunks {
                            // self.broadcast_chunk(chunk).await;
                        }
                        self.seq_counter += 1;
                    }
                }
            }
        }
    }

    /// Helper for committing to storage (used internally or by pipelines)
    async fn _finalize_reassembly(
        &mut self,
        envelope: WitnessEnvelope,
    ) -> Result<(), Box<dyn Error>> {
        self.guardian.ingest_envelope(envelope)?;
        Ok(())
    }
}
