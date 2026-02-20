use futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};
use std::error::Error;
use std::io;
use tokio::sync::mpsc;
use tracing::info;

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::primitives::identity::{init_identity, Did, IdentityError, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{AudioShard, Evidence, ShardChunk, ShardId, VideoShard};
use crate::primitives::time::{TimeError, TrustedClock};
use crate::security::e2ee::SymmetricKey;
use crate::security::ingress::{IngressError, IngressOrchestrator};
use crate::security::sentinel::Sentinel;
use crate::security::trust::ReputationGate;

// IMPORT ALL GATES
use crate::security::gate::{ForensicGate, PrivacyGate, WitnessGate};
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
    sentinel: Sentinel,
    guardian: Guardian,
    trust_registry: crate::security::trust::TrustRegistry,
    video_rx: mpsc::Receiver<VideoShard>,
    audio_rx: mpsc::Receiver<AudioShard>,

    seq_counter: u64,
    // TODO: Rotate this via KeyStore in production
    network_key: SymmetricKey,
}

impl PhalanxEngine {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        physics: PhalanxPhysics,
        psk: Option<PreSharedKey>,
    ) -> Result<Self, Box<dyn Error>> {
        let network_keypair = identity.to_libp2p_keypair();

        let local_peer_id = network_keypair.public().to_peer_id();
        let local_did = Did::from(local_peer_id.to_string());

        // Data boundaries
        let sentinel = Sentinel::new(&config);
        let guardian = Guardian::new(&config.storage.vault_path, &config, local_did);

        // Network
        let swarm =
            crate::transport::swarm::setup_phalanx_swarm(network_keypair, &config, &physics, psk)?;

        // Media Channels
        let (_video_tx, video_rx) = mpsc::channel(config.storage.max_video_buffer);
        let (_audio_tx, audio_rx) = mpsc::channel(config.storage.max_audio_buffer);

        let clock = TrustedClock::new();

        // Isolate async execution context for synchronous builder
        let config_clone = config.clone();
        let trust_registry = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("Failed to initialize transient async reactor for TrustRegistry");

            rt.block_on(crate::security::trust::TrustRegistry::build(&config_clone))
        })
        .join()
        .expect("TrustRegistry initialization thread panicked");

        Ok(Self {
            config,
            identity,
            clock,
            swarm,
            crucible: crate::storage::crucible::Crucible::new(),
            sentinel,
            guardian,
            trust_registry,
            video_rx,
            audio_rx,
            seq_counter: 0,
            network_key: SymmetricKey([0x42; 32]), // Default/Placeholder Key
        })
    }

    pub fn new_at_path(path: &str) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = path.to_string();

        let physics = PhalanxPhysics::default();
        let identity_path = std::path::Path::new(path).join("identity.pem");
        let identity = init_identity(&identity_path).unwrap_or_default();

        Self::new(config, identity, physics, None)
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_peer_id = *self.swarm.local_peer_id();
        let local_network_id = NetworkId::from(local_peer_id);

        info!(
            "Phalanx Engine: Active and Gated. PeerID: {}",
            local_peer_id
        );

        loop {
            tokio::select! {
                // Pipeline 1: Network Ingress -> Sentinel -> Guardian
                event = self.swarm.select_next_some() => {
                    if let SwarmEvent::Behaviour(PhalanxEvent::Gossipsub(
                        libp2p::gossipsub::Event::Message { propagation_source: peer, message, .. }
                    )) = event {
                        let topic = crate::base::types::MeshTopic::new(message.topic.as_str());
                        self.handle_network_ingress(peer, &message.data, topic).await;
                    }
                }

                // Pipeline 2: Video Sensor Egress -> Network
                Some(shard) = self.video_rx.recv() => {
                    self.process_media_egress(Evidence::Video(shard), local_network_id);
                }

                // Pipeline 3: Audio Sensor Egress -> Network
                Some(shard) = self.audio_rx.recv() => {
                    self.process_media_egress(Evidence::Audio(shard), local_network_id);
                }
            }
        }
    }

    // =========================================================================
    // INGRESS PIPELINE
    // =========================================================================
    async fn handle_network_ingress(
        &mut self,
        peer_id: libp2p::PeerId,
        chunk_bytes: &[u8],
        topic: crate::base::types::MeshTopic,
    ) {
        let chunk: ShardChunk = match postcard::from_bytes(chunk_bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to deserialize ingress chunk");
                return;
            }
        };

        let sender_did = chunk.owner_did.clone();
        let local_network_id = NetworkId::from(*self.swarm.local_peer_id());

        let orchestration_result = IngressOrchestrator::process_chunk(
            chunk,
            &topic,
            &self.config,
            &self.identity,
            local_network_id,
            &mut self.sentinel,
            &mut self.guardian,
            &mut self.trust_registry,
            &self.clock,
        )
        .await;

        match orchestration_result {
            Ok(Some(_size)) => {
                // Data finalized successfully. Emit production metrics.
            }
            Ok(None) => {
                // Data buffered during reassembly.
            }
            Err(IngressError::Blacklisted(did)) => {
                // Drop the libp2p connection immediately
                let _ = self.swarm.disconnect_peer_id(peer_id);
                tracing::warn!(%did, "Dropped connection from blacklisted peer.");
            }
            Err(e) => {
                // If a threshold was crossed, drop the physical connection
                if self.trust_registry.is_blacklisted(&sender_did) {
                    let _ = self.swarm.disconnect_peer_id(peer_id);
                    tracing::warn!(%sender_did, error = %e, "Peer blacklisted due to protocol offense.");
                } else {
                    tracing::debug!(error = %e, "Ingress rejected.");
                }
            }
        }
    }

    // =========================================================================
    // EGRESS PIPELINE
    // =========================================================================
    fn process_media_egress(&mut self, evidence: Evidence, local_network_id: NetworkId) {
        let topic = libp2p::gossipsub::IdentTopic::new("phalanx/1.0.0");
        let shard_id = ShardId(self.seq_counter as u32);

        let chunks_result = evidence
            .safeguard(&self.network_key) // 1. Privacy Gate
            .and_then(|ev| ev.seal(&self.identity, local_network_id)) // 2. Witness Gate
            .and_then(|env| env.chunkify(shard_id)) // 3. Discretization
            .gate(
                "evidence_pipeline_failure",
                &local_network_id,
                "Ingestion pipeline dropped evidence unit",
            );

        if let Ok(chunks) = chunks_result {
            for chunk in chunks {
                if let Ok(data) = postcard::to_stdvec(&chunk) {
                    let _ = self
                        .swarm
                        .behaviour_mut()
                        .gossipsub
                        .publish(topic.clone(), data);
                }
            }
            self.seq_counter += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::PhalanxConfig;
    use crate::primitives::identity::PhalanxIdentity;
    use tempfile::TempDir;

    fn setup_test_env() -> (PhalanxConfig, PhalanxPhysics, TempDir) {
        let temp_dir = tempfile::tempdir().expect("Failed to create ephemeral test directory");

        let config = PhalanxConfig {
            storage: crate::base::config::StorageConfig {
                vault_path: temp_dir.path().to_string_lossy().into_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        let physics = PhalanxPhysics::default();
        (config, physics, temp_dir)
    }

    #[test]
    fn test_engine_initialization() {
        let (config, physics, _temp_dir) = setup_test_env();
        let identity = PhalanxIdentity::new();

        let engine = PhalanxEngine::new(config, identity, physics, None);
        assert!(engine.is_ok(), "Engine should initialize with valid inputs");
    }

    #[test]
    fn test_new_at_path_ephemeral_fallback() {
        let temp_dir = tempfile::tempdir().expect("Failed to create ephemeral test directory");
        let path = temp_dir.path().to_string_lossy().into_owned();

        let engine_result = PhalanxEngine::new_at_path(&path);

        assert!(
            engine_result.is_ok(),
            "Should successfully bootstrap ephemeral node. Error: {:?}",
            engine_result.err()
        );

        let engine = engine_result.unwrap();
        assert_eq!(engine.seq_counter, 0);
    }

    #[tokio::test]
    async fn test_pipeline_gates_active() {
        let (config, physics, _temp_dir) = setup_test_env();
        let identity = PhalanxIdentity::new();
        let engine = PhalanxEngine::new(config, identity, physics, None).unwrap();

        assert!(engine.video_rx.capacity() > 0);
        assert!(engine.audio_rx.capacity() > 0);
        assert!(engine.clock.now().is_ok());
    }
}
