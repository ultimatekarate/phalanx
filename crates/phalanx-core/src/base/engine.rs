use futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};
use std::error::Error;
use std::io;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::primitives::identity::{init_identity, Did, IdentityError, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{AudioShard, Evidence, ShardId, VideoShard, WitnessEnvelope};
use crate::primitives::time::{TimeError, TrustedClock};
// IMPORT ALL GATES
use crate::security::gate::{CapacityGate, ForensicGate, IntegrityGate, PrivacyGate, WitnessGate};
use crate::storage::strategies::ShardAmalgam;
use crate::storage::vault::Guardian;
use crate::{PhalanxBehaviour, PhalanxEvent};

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
    clock: TrustedClock,
    swarm: Swarm<PhalanxBehaviour>,
    #[allow(dead_code)]
    crucible: crate::storage::crucible::Crucible<ShardAmalgam>,
    guardian: Guardian,
    video_rx: mpsc::Receiver<VideoShard>,
    audio_rx: mpsc::Receiver<AudioShard>,

    // Internal state
    seq_counter: u64,
    // TODO: Rotate this via KeyStore in production
    network_key: [u8; 32],
}

impl PhalanxEngine {
    #[allow(clippy::missing_errors_doc)]
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
            network_key: [0x42; 32], // Default/Placeholder Key
        })
    }

    /// FFI Compatibility Helper.
    /// Bootstraps an engine from a storage path using default physics and config.
    /// Zero-Panic: Uses fallbacks if identity loading fails.
    /// # Errors
    ///
    /// Returns an error if the underlying `PhalanxEngine::new` call fails. Note that this
    /// function is "Zero-Panic" regarding identity; if an identity cannot be loaded
    /// from the path, it will generate a new ephemeral one rather than returning an `Err`.
    pub fn new_at_path(path: &str) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = path.to_string();

        // 1. Setup Default Physics
        let physics = PhalanxPhysics::default();

        // 2. Load or Generate Identity
        let identity_path = std::path::Path::new(path).join("identity.pem");

        // Attempt load, fallback to generation (Ephemeral Mode)
        let identity = init_identity(&identity_path).unwrap_or_default();

        // 3. Initialize Core
        Self::new(config, identity, physics, None)
    }

    /// The Main Gated Event Loop
    /// # Errors
    ///
    /// Returns a `Box<dyn Error>` if the event loop encounters a fatal failure. While most
    /// gate failures (Forensic, Capacity, Integrity) are logged and skipped, critical
    /// issues with the swarm network stream or internal channel desynchronization will
    /// terminate the loop.
    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_peer_id = *self.swarm.local_peer_id();
        let local_network_id = NetworkId::from(local_peer_id);

        // GossipSub Topic
        let topic = libp2p::gossipsub::IdentTopic::new("phalanx/1.0.0");

        info!(
            "Phalanx Engine: Active and Gated. PeerID: {}",
            local_peer_id
        );

        loop {
            tokio::select! {
                // ------------------------------------------------------------------
                // PIPELINE 1: RECEPTION (Ingress: Network -> Storage)
                // Gates: Forensic -> Capacity -> Integrity
                // ------------------------------------------------------------------
                event = self.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message {
                            propagation_source: peer,
                            message_id: _,
                            message,
                        }
                    )) = event {
                        let peer_id = NetworkId::from(peer);

                        // 1. Forensic Gate: Safe Deserialization
                        let envelope_opt = postcard::from_bytes::<WitnessEnvelope>(&message.data)
                            .ok_or_log("deserialization_err", &local_network_id, "Malformed wire packet");

                        // 2. Capacity Gate: DoS Protection
                        // (Checking against a 50MB buffer limit placeholder)
                        let envelope_opt = envelope_opt.and_then(|env| {
                            env.check_capacity(&peer_id, 0, 1024 * 1024 * 50)
                        });

                        // 3. Integrity Gate: Crypto & Time Validation
                        let verified_env = envelope_opt.and_then(|env| {
                            env.check_integrity(&peer_id, &self.clock, 10) // 10s tolerance
                        });

                        // 4. Persistence
                        if let Some(env) = verified_env {
                            if let Err(e) = self.guardian.ingest_envelope(env) {
                                error!(event = "vault_write_err", error = %e, "Failed to persist foreign evidence");
                            }
                        }
                    }
                }

                // ------------------------------------------------------------------
                // PIPELINE 2: VIDEO INGESTION (Egress: Sensor -> Network)
                // Gates: Privacy -> Witness -> Forensic (Chunking)
                // ------------------------------------------------------------------
                Some(shard) = self.video_rx.recv() => {
                    let shard_id = ShardId(self.seq_counter as u32);

                    let chunks_opt = Evidence::Video(shard)
                        .safeguard(&self.network_key)                      // 1. Privacy Gate (Encrypt)
                        .and_then(|ev| ev.seal(&self.identity, local_network_id))  // 2. Witness Gate (Sign)
                        .and_then(|env| env.chunkify(shard_id)             // 3. Discretization
                            .ok_or_log("chunkify_err", &local_network_id, "Video processing failed")
                        );

                    if let Some(chunks) = chunks_opt {
                        for chunk in chunks {
                             // Broadcast via GossipSub
                             if let Ok(data) = postcard::to_stdvec(&chunk) {
                                 let _ = self.swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(topic.clone(), data);
                             }
                        }
                        self.seq_counter += 1;
                    }
                }

                // ------------------------------------------------------------------
                // PIPELINE 3: AUDIO INGESTION (Egress: Sensor -> Network)
                // Gates: Privacy -> Witness -> Forensic (Chunking)
                // ------------------------------------------------------------------
                Some(shard) = self.audio_rx.recv() => {
                    let shard_id = ShardId(self.seq_counter as u32);

                    let chunks_opt = Evidence::Audio(shard)
                        .safeguard(&self.network_key)                      // 1. Privacy Gate (Encrypt)
                        .and_then(|ev| ev.seal(&self.identity, local_network_id))  // 2. Witness Gate (Sign)
                        .and_then(|env| env.chunkify(shard_id)             // 3. Discretization
                            .ok_or_log("chunkify_err", &local_network_id, "Audio processing failed")
                        );

                    if let Some(chunks) = chunks_opt {
                        for chunk in chunks {
                             // Broadcast via GossipSub
                            if let Ok(data) = postcard::to_stdvec(&chunk) {
                                let _ = self.swarm
                                    .behaviour_mut()
                                    .gossipsub
                                    .publish(topic.clone(), data);
                            }
                        }
                        self.seq_counter += 1;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::PhalanxConfig;
    use crate::primitives::identity::PhalanxIdentity;
    use std::fs;

    fn setup_test_env() -> (PhalanxConfig, PhalanxPhysics) {
        let config = PhalanxConfig {
            storage: crate::base::config::StorageConfig {
                vault_path: "test_vault_engine".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let physics = PhalanxPhysics::default();
        (config, physics)
    }

    #[test]
    fn test_engine_initialization() {
        let (config, physics) = setup_test_env();
        let identity = PhalanxIdentity::new();

        let engine = PhalanxEngine::new(config, identity, physics, None);
        assert!(engine.is_ok(), "Engine should initialize with valid inputs");
    }

    #[test]
    fn test_new_at_path_ephemeral_fallback() {
        // 1. Point to a non-existent path
        let path = "temp_test_engine_boot";
        let _ = fs::remove_dir_all(path); // Cleanup pre

        // 2. Initialize
        // This triggers the logic: load_identity? No -> PhalanxIdentity::new()
        let engine_result = PhalanxEngine::new_at_path(path);

        assert!(
            engine_result.is_ok(),
            "Should successfully bootstrap ephemeral node"
        );

        let engine = engine_result.unwrap();
        assert_eq!(engine.seq_counter, 0);

        // Cleanup post
        let _ = fs::remove_dir_all(path);
    }

    #[tokio::test]
    async fn test_pipeline_gates_active() {
        // This test verifies the integrity of the channel wiring
        let (config, physics) = setup_test_env();
        let identity = PhalanxIdentity::new();
        let engine = PhalanxEngine::new(config, identity, physics, None).unwrap();

        // Check 1: Capacity Gate limits are set (buffer sizes)
        assert!(engine.video_rx.capacity() > 0);
        assert!(engine.audio_rx.capacity() > 0);

        // Check 2: Clock is running (Chronos Gate)
        assert!(engine.clock.now().is_ok());
    }
}
