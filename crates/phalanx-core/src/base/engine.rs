use futures::StreamExt;
use libp2p::swarm::{Swarm, SwarmEvent};
use std::error::Error;
use std::io;
use tokio::sync::mpsc;
use tracing::info;

use crate::base::config::{PhalanxConfig, PhalanxPhysics};
use crate::base::types::{NodeMode, TrafficGovernor};
use crate::primitives::identity::{init_identity, Did, IdentityError, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{Evidence, ShardChunk, ShardError, ShardId};
use crate::primitives::time::{TimeError, TrustedClock};
use crate::security::e2ee::SymmetricKey;
use crate::security::ingress::{
    IngressContext, IngressError, IngressOrchestrator, SecurityPipeline,
};
use crate::security::trust::TrustRegistry;
use crate::storage::reassembler::{Reassembler, TransientJournal};
use crate::transport::health::HealthTracker;

// IMPORT ALL GATES
use crate::security::gate::{ForensicGate, PrivacyGate, WitnessGate};

use crate::storage::vault::Guardian;
use crate::PhalanxEvent;

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

// POLYFILL: Required until Phase 5 (Mobile Binary Integration) is complete
pub struct NoOpJournal;
#[async_trait::async_trait]
impl TransientJournal for NoOpJournal {
    async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
        Ok(())
    }
    async fn sync(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        Ok(vec![])
    }

    async fn clear(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
}

pub struct PhalanxEngine<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub guardian: Guardian,
    pub trust_registry: TrustRegistry,
    pub health_tracker: HealthTracker,
    pub governor: TrafficGovernor,
    pub mode: NodeMode,
    pub config: PhalanxConfig,
    pub identity: PhalanxIdentity,
    pub clock: TrustedClock,
    pub swarm: Swarm<crate::transport::swarm::PhalanxBehaviour>,
    pub video_rx: mpsc::Receiver<crate::primitives::shards::VideoShard>,
    pub audio_rx: mpsc::Receiver<crate::primitives::shards::AudioShard>,
    pub seq_counter: u64,
    pub network_key: SymmetricKey,
    pub journal: J, // Injected Transient WAL
}

impl<J: TransientJournal + Send + 'static> PhalanxEngine<J> {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        physics: PhalanxPhysics,
        psk: Option<PreSharedKey>,
        journal: J,
    ) -> Result<Self, Box<dyn Error>> {
        let network_keypair = identity.to_libp2p_keypair();

        let local_peer_id = network_keypair.public().to_peer_id();
        let local_did = Did::from(local_peer_id.to_string());

        // Data boundaries
        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&config.storage.vault_path, &config, local_did);

        // Orchestration state
        let health_tracker = HealthTracker::new();
        let governor = TrafficGovernor::new();
        let mode = NodeMode::Standard;

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
            reassembler,
            guardian,
            trust_registry,
            health_tracker,
            governor,
            mode,
            video_rx,
            audio_rx,
            seq_counter: 0,
            network_key: SymmetricKey([0x42; 32]), // Default/Placeholder Key
            journal,
        })
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
                // Pipeline 1: Network Ingress -> Reassembler -> Guardian
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

        // 1. Allocate Parameter Objects
        let ctx = IngressContext {
            config: &self.config,
            identity: &self.identity,
            network_id: local_network_id,
            clock: &self.clock,
            governor: &self.governor,
            mode: self.mode,
        };

        let mut pipeline = SecurityPipeline {
            reassembler: &mut self.reassembler,
            guardian: &mut self.guardian,
            trust_registry: &mut self.trust_registry,
            health_tracker: &mut self.health_tracker,
            journal: &mut self.journal,
        };

        // 2. Execute Shared Orchestration
        let orchestration_result =
            IngressOrchestrator::process_chunk(chunk, &topic, &ctx, &mut pipeline).await;

        // 3. Handle Production-Specific Physical Actions
        match orchestration_result {
            Ok(Some(_size)) => {
                // Future integration point for physical node metrics mapping
            }
            Ok(None) => {}
            Err(IngressError::Blacklisted(did)) => {
                let _ = self.swarm.disconnect_peer_id(peer_id);
                tracing::warn!(%did, "Dropped connection from blacklisted peer.");
            }
            Err(e) => {
                let trust_level = self.trust_registry.check_trust(&sender_did);
                if matches!(trust_level, crate::security::trust::TrustLevel::Blocked) {
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

impl PhalanxEngine<NoOpJournal> {
    pub fn new_at_path(path: &str) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = path.to_string();

        let physics = PhalanxPhysics::default();
        let identity_path = std::path::Path::new(path).join("identity.pem");
        let identity = init_identity(&identity_path).unwrap_or_default();

        Self::new(config, identity, physics, None, NoOpJournal)
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

        let engine = PhalanxEngine::new(config, identity, physics, None, NoOpJournal);
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
        let engine = PhalanxEngine::new(config, identity, physics, None, NoOpJournal).unwrap();

        assert!(engine.video_rx.capacity() > 0);
        assert!(engine.audio_rx.capacity() > 0);
        assert!(engine.clock.now().is_ok());
    }
}
