use std::error::Error;
use std::io;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{info, warn};

use crate::base::config::PhalanxConfig;
use crate::base::types::{MeshTopic, NodeMode, TrafficGovernor};
use crate::primitives::identity::{init_identity, Did, IdentityError, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{Evidence, ShardChunk, ShardError, ShardId};
use crate::primitives::time::{TimeError, TrustedClock};
use crate::security::e2ee::SymmetricKey;
use crate::security::trust::{Offense, ReputationGate, TrustLevel, TrustRegistry};
use crate::storage::reassembler::{Reassembler, TransientJournal};
use crate::storage::vault::{Guardian, GuardianError};
use crate::transport::events::NetworkEvent;
use crate::transport::health::HealthTracker;
use crate::transport::network_transport::NetworkTransport;

// IMPORT ALL GATES
use crate::security::gate::{ForensicGate, PrivacyGate, WitnessGate};

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

// =========================================================================
// UNIFIED STORAGE ACTOR
// =========================================================================
pub struct StorageActor<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub guardian: Guardian,
    pub journal: J,
    pub config: PhalanxConfig,
    pub identity: PhalanxIdentity,
    pub chunk_rx: mpsc::Receiver<(ShardChunk, MeshTopic, NetworkId)>,
    pub forensic_tx: mpsc::Sender<(NetworkId, Did, GuardianError)>,
    pub local_peer_id: NetworkId,
}

impl<J: TransientJournal> StorageActor<J> {
    pub async fn run(mut self) {
        let mut maintenance_timer = tokio::time::interval(Duration::from_millis(1000));

        loop {
            tokio::select! {
                res = self.chunk_rx.recv() => {
                    match res {
                        Some((chunk, topic, peer_id)) => {
                            self.process_incoming_chunk(chunk, topic, peer_id).await;
                        }
                        None => {
                            warn!("Ingress channel closed. Initiating emergency salvage.");
                            let _ = self.guardian.force_salvage_all();
                            return;
                        }
                    }
                }
                _ = maintenance_timer.tick() => {
                    tracing::info!(target: "phalanx::forensics", "MAINTENANCE_TICK_START");
                    if let Err(err) = self.guardian.check_and_finalize_volley() {
                        tracing::error!(target: "phalanx::forensics", error = %err, "Maintenance flush failed");
                    }
                }
            }
        }
    }

    async fn process_incoming_chunk(
        &mut self,
        chunk: ShardChunk,
        topic: MeshTopic,
        peer_id: NetworkId,
    ) {
        let chunk_owner_did = chunk.owner_did.clone();

        let envelope_opt = self
            .reassembler
            .ingest_chunk(
                chunk,
                &mut self.journal,
                &topic,
                &self.config,
                &self.identity,
                peer_id,
            )
            .await;

        match envelope_opt {
            Ok(Some(envelope)) => {
                if let Err(err) = self.guardian.ingest_envelope(envelope) {
                    tracing::error!(error = %err, "Vault rejected envelope");
                    let _ = self.forensic_tx.try_send((peer_id, chunk_owner_did, err));
                }
            }
            Ok(None) => {}
            Err(err) => tracing::warn!(error = %err, "Reassembler rejected data chunk"),
        }
    }
}

// =========================================================================
// PHALANX ENGINE
// =========================================================================
pub struct PhalanxEngine<T: NetworkTransport, J: TransientJournal> {
    pub trust_registry: TrustRegistry,
    pub health_tracker: HealthTracker,
    pub governor: TrafficGovernor,
    pub mode: NodeMode,
    pub config: PhalanxConfig,
    pub identity: PhalanxIdentity,
    pub clock: TrustedClock,
    pub network: T,
    pub video_rx: mpsc::Receiver<crate::primitives::shards::VideoShard>,
    pub audio_rx: mpsc::Receiver<crate::primitives::shards::AudioShard>,
    pub seq_counter: u64,
    pub network_key: SymmetricKey,
    pub chunk_tx: mpsc::Sender<(ShardChunk, MeshTopic, NetworkId)>,
    pub forensic_rx: mpsc::Receiver<(NetworkId, Did, GuardianError)>,
    pub storage_task: JoinHandle<()>,
    pub _journal_phantom: std::marker::PhantomData<J>,
}

impl<T: NetworkTransport, J: TransientJournal + Send + 'static> PhalanxEngine<T, J> {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        network: T,
        journal: J,
    ) -> Result<Self, Box<dyn Error>> {
        let local_did = identity.did.clone();
        let local_network_id = identity.to_network_id();

        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&config.storage.vault_path, &config, local_did);

        let health_tracker = HealthTracker::new();
        let governor = TrafficGovernor::new();
        let mode = NodeMode::Standard;

        let (_video_tx, video_rx) = mpsc::channel(config.storage.max_video_buffer);
        let (_audio_tx, audio_rx) = mpsc::channel(config.storage.max_audio_buffer);
        let (chunk_tx, chunk_rx) = mpsc::channel(1024);
        let (forensic_tx, forensic_rx) = mpsc::channel(100);

        let clock = TrustedClock::new();

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

        let storage_actor = StorageActor {
            reassembler,
            guardian,
            journal,
            config: config.clone(),
            identity: identity.clone(),
            chunk_rx,
            forensic_tx,
            local_peer_id: local_network_id,
        };

        let storage_task = tokio::spawn(async move {
            storage_actor.run().await;
        });

        Ok(Self {
            config,
            identity,
            clock,
            network,
            trust_registry,
            health_tracker,
            governor,
            mode,
            video_rx,
            audio_rx,
            seq_counter: 0,
            network_key: SymmetricKey([0x42; 32]),
            chunk_tx,
            forensic_rx,
            storage_task,
            _journal_phantom: std::marker::PhantomData,
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_network_id = self.identity.to_network_id();

        info!(
            "Phalanx Engine: Active and Gated. PeerID: {}",
            local_network_id
        );

        loop {
            tokio::select! {
                Some(event) = self.network.next_event() => {
                    match event {
                        NetworkEvent::DataReceived { origin, topic, data } => {
                            self.handle_network_ingress(origin, &data, topic).await;
                        }
                        NetworkEvent::Shutdown => break,
                        _ => {}
                    }
                }
                Some(shard) = self.video_rx.recv() => {
                    self.process_media_egress(Evidence::Video(shard), local_network_id).await;
                }
                Some(shard) = self.audio_rx.recv() => {
                    self.process_media_egress(Evidence::Audio(shard), local_network_id).await;
                }
                Some((peer_id, owner_did, err)) = self.forensic_rx.recv() => {
                    let offense = match err {
                        GuardianError::VerificationFailed(_) => Some(Offense::InvalidSignature),
                        GuardianError::QuotaExceeded(_) => Some(Offense::QuotaExceeded),
                        GuardianError::ReplayDetected(_) => Some(Offense::ReplayAttack),
                        _ => None,
                    };

                    if let Some(offense_type) = offense {
                        self.trust_registry.record_offense(&owner_did, offense_type, &self.clock).await;

                        if self.trust_registry.is_blacklisted(&owner_did) {
                            // Immediately enforce the ban at the network transport layer.
                            self.network.ban_peer(&peer_id).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    // [handle_network_ingress and process_media_egress remain unchanged]
    async fn handle_network_ingress(
        &mut self,
        peer_id: NetworkId,
        chunk_bytes: &[u8],
        topic: MeshTopic,
    ) {
        let local_network_id = self.identity.to_network_id();

        // 1. PRE-ALLOCATION FIREWALL: Filter strictly by transport-layer NetworkId
        if !self.governor.should_accept(&peer_id, &local_network_id) {
            return;
        }

        // 2. DESERIALIZATION BOUNDARY: Allocate memory for the payload
        let chunk: ShardChunk = match postcard::from_bytes(chunk_bytes) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to deserialize ingress chunk");
                return;
            }
        };

        let sender_did = chunk.owner_did.clone();

        // 3. APPLICATION-LAYER FORENSICS: Verify reputation of the embedded Did
        let explicit_trust = self.trust_registry.check_trust(&sender_did);
        if matches!(explicit_trust, TrustLevel::Blocked)
            || self.trust_registry.is_blacklisted(&sender_did)
        {
            self.network.ban_peer(&peer_id).await;
            tracing::warn!(%sender_did, "Dropped connection from blacklisted peer.");
            return;
        }

        // 4. STORAGE ESCALATION
        if self.chunk_tx.try_send((chunk, topic, peer_id)).is_err() {
            tracing::warn!("Storage layer channel saturated. Dropping ingress chunk.");
        }
    }

    async fn process_media_egress(&mut self, evidence: Evidence, local_network_id: NetworkId) {
        let topic = MeshTopic::new("phalanx/1.0.0");
        let shard_id = ShardId(self.seq_counter as u32);

        let chunks_result = evidence
            .safeguard(&self.network_key)
            .and_then(|ev| ev.seal(&self.identity, local_network_id))
            .and_then(|env| env.chunkify(shard_id))
            .gate(
                "evidence_pipeline_failure",
                &local_network_id,
                "Ingestion pipeline dropped evidence unit",
            );

        if let Ok(chunks) = chunks_result {
            for chunk in chunks {
                if let Ok(data) = postcard::to_stdvec(&chunk) {
                    let _ = self.network.publish(&topic, data).await;
                }
            }
            self.seq_counter += 1;
        }
    }
}

impl<T: NetworkTransport> PhalanxEngine<T, NoOpJournal> {
    pub fn new_at_path(path: &str, network: T) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = path.to_string();

        let identity_path = std::path::Path::new(path).join("identity.pem");
        let identity = init_identity(&identity_path).unwrap_or_default();

        Self::new(config, identity, network, NoOpJournal)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::PhalanxConfig;
    use crate::base::types::MeshTopic;
    use crate::primitives::identity::PhalanxIdentity;
    use crate::transport::events::NetworkEvent;
    use crate::transport::mock::MockTransport;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    /// Helper to generate a dummy adapter for pure unit tests
    fn create_mock_transport() -> MockTransport {
        let (_, ingress_rx) = mpsc::channel::<NetworkEvent>(10);
        let (egress_tx, _) = mpsc::channel::<(MeshTopic, Vec<u8>)>(10);
        MockTransport::new(ingress_rx, Some(egress_tx))
    }

    fn setup_test_env() -> (PhalanxConfig, TempDir) {
        let temp_dir = tempfile::tempdir().expect("Failed to create ephemeral test directory");

        let config = PhalanxConfig {
            storage: crate::base::config::StorageConfig {
                vault_path: temp_dir.path().to_string_lossy().into_owned(),
                ..Default::default()
            },
            ..Default::default()
        };
        // Physics removed, as it is now strictly a production adapter concern
        (config, temp_dir)
    }

    #[tokio::test]
    async fn test_engine_initialization() {
        let (config, _temp_dir) = setup_test_env();
        let identity = PhalanxIdentity::new();
        let network = create_mock_transport();

        let engine = PhalanxEngine::new(config, identity, network, NoOpJournal);
        assert!(engine.is_ok(), "Engine should initialize with valid inputs");
    }

    #[tokio::test]
    async fn test_new_at_path_ephemeral_fallback() {
        let temp_dir = tempfile::tempdir().expect("Failed to create ephemeral test directory");
        let path = temp_dir.path().to_string_lossy().into_owned();
        let network = create_mock_transport();

        let engine_result = PhalanxEngine::new_at_path(&path, network);

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
        let (config, _temp_dir) = setup_test_env();
        let identity = PhalanxIdentity::new();
        let network = create_mock_transport();

        let engine = PhalanxEngine::new(config, identity, network, NoOpJournal).unwrap();

        assert!(engine.video_rx.capacity() > 0);
        assert!(engine.audio_rx.capacity() > 0);
        assert!(engine.clock.now().is_ok());
    }
}
