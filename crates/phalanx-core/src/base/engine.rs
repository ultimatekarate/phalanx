use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{Duration, Instant};
use tracing::{error, info, warn};

use crate::base::config::PhalanxConfig;
use crate::base::types::{MeshTopic, NodeMode, TrafficGovernor};
use crate::primitives::identity::{init_identity, Did, IdentityError, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{
    CausalitySession, Evidence, ShardChunk, ShardError, ShardId, VolleyId, WitnessEnvelope,
};
use crate::primitives::time::{TimeError, TrustedClock};
use crate::security::e2ee::SymmetricKey;
use crate::security::retrieval::RetrievalOrchestrator;
use crate::security::trust::{Offense, ReputationGate, TrustLevel, TrustRegistry};
use crate::storage::reassembler::{Reassembler, TransientJournal};
use crate::storage::vault::{Guardian, GuardianError};
use crate::transport::events::NetworkEvent;
use crate::transport::health::HealthTracker;
use crate::transport::network_transport::NetworkTransport;
use crate::transport::protocol::VolleyResponse;

// IMPORT ALL GATES
use crate::security::gate::{ForensicGate, PrivacyGate};
use crate::storage::kademlia::PeerEvaluator;

pub use libp2p::pnet::PreSharedKey;

pub struct PendingEgress {
    pub channel_id: String,
    pub response: VolleyResponse,
    pub attempt_count: u32,
    pub next_attempt: Instant,
}

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
    #[error("Security breach: {0}")]
    SecurityBreach(String),
    #[error("Critical storage failure: {0}")]
    StorageFailure(String),
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

/// Encapsulates a one-time request for forensic data extraction sent to the StorageActor.
pub struct RetrievalQuery {
    pub volley_id: VolleyId,
    pub reply_to: oneshot::Sender<Result<Vec<WitnessEnvelope>, GuardianError>>,
}

// =========================================================================
// PEER EVALUATOR CACHE BOUNDARY
// =========================================================================

#[derive(Clone, Default)]
pub struct SyncReputationCache {
    pub scores: Arc<RwLock<HashMap<NetworkId, f32>>>,
}

impl PeerEvaluator for SyncReputationCache {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32 {
        *self.scores.read().unwrap().get(peer_id).unwrap_or(&1.0)
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
    pub query_rx: mpsc::Receiver<RetrievalQuery>,
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
                            let _ = self.guardian.salvage().await;
                            return;
                        }
                    }
                }
                Some(query) = self.query_rx.recv() => {
                    self.handle_retrieval_query(query).await;
                }
                _ = maintenance_timer.tick() => {
                    if let Err(err) = self.guardian.check_and_finalize_volley().await {
                        error!(target: "phalanx::forensics", error = %err, "Maintenance flush failed");
                    }
                }
            }
        }
    }

    async fn handle_retrieval_query(&self, query: RetrievalQuery) {
        let result = match self.guardian.get_active_volley_shards(&query.volley_id) {
            Some(shard_map) => {
                let envelopes: Vec<WitnessEnvelope> = shard_map.values().cloned().collect();
                Ok(envelopes)
            }
            None => Ok(Vec::new()),
        };

        let _ = query.reply_to.send(result);
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
                if let Err(err) = self.guardian.ingest_envelope(envelope).await {
                    error!(error = %err, "Vault rejected envelope");
                    let _ = self.forensic_tx.try_send((peer_id, chunk_owner_did, err));
                }
            }
            Ok(None) => {}
            Err(err) => warn!(error = %err, "Reassembler rejected data chunk"),
        }
    }
}

// =========================================================================
// PHALANX ENGINE
// =========================================================================
pub struct PhalanxEngine<T: NetworkTransport, J: TransientJournal> {
    pub trust_registry: TrustRegistry,
    pub reputation_cache: Arc<SyncReputationCache>,
    pub health_tracker: HealthTracker,
    pub governor: TrafficGovernor,
    pub mode: NodeMode,
    pub config: PhalanxConfig,
    pub identity: Arc<PhalanxIdentity>,
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
    pub query_tx: mpsc::Sender<RetrievalQuery>,
    pub session: CausalitySession,
}

impl<T: NetworkTransport, J: TransientJournal + Send + 'static> PhalanxEngine<T, J> {
    pub fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        network: T,
        journal: J,
        trust_registry: TrustRegistry,
        reputation_cache: Arc<SyncReputationCache>,
    ) -> Result<Self, Box<dyn Error>> {
        let local_did = identity.did.clone();
        let local_network_id = identity.to_network_id();

        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&config.storage.vault_path, &config, local_did);

        let (_video_tx, video_rx) = mpsc::channel(config.storage.max_video_buffer);
        let (_audio_tx, audio_rx) = mpsc::channel(config.storage.max_audio_buffer);
        let (query_tx, query_rx) = mpsc::channel(100);
        let (chunk_tx, chunk_rx) = mpsc::channel(1024);
        let (forensic_tx, forensic_rx) = mpsc::channel(100);

        let storage_actor = StorageActor {
            reassembler,
            guardian,
            journal,
            config: config.clone(),
            identity: identity.clone(),
            chunk_rx,
            forensic_tx,
            local_peer_id: local_network_id,
            query_rx,
        };

        let storage_task = tokio::spawn(async move {
            storage_actor.run().await;
        });

        let arc_identity = Arc::new(identity).clone();
        let session = CausalitySession::new(arc_identity.clone(), local_network_id);

        Ok(Self {
            config,
            identity: arc_identity.clone(),
            clock: TrustedClock::new(),
            network,
            trust_registry,
            reputation_cache,
            health_tracker: HealthTracker::new(),
            governor: TrafficGovernor::new(),
            mode: NodeMode::Standard,
            video_rx,
            audio_rx,
            seq_counter: 0,
            network_key: SymmetricKey([0x42; 32]),
            chunk_tx,
            forensic_rx,
            storage_task,
            _journal_phantom: std::marker::PhantomData,
            query_tx,
            session,
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
                        NetworkEvent::RetrievalRequested { origin, request, channel_id } => {
                            // Phase 1: Privacy Enforcement
                            // If the user hasn't authorized THIS specific person, we stop here.
                            if let Err(_err) = self.identity.verify_retrieval_auth(&request) {
                                warn!(
                                    peer = %origin,
                                    volley = %request.volley_id,
                                    "Privacy Gate: Unauthorized retrieval attempt blocked"
                                );
                                let _ = self.network.send_response(&channel_id, VolleyResponse::Unauthorized).await;
                                continue;
                            }

                            // Phase 2: Data Extraction (only happens if authorized)
                            let (reply_tx, reply_rx) = oneshot::channel();
                            let query = RetrievalQuery {
                                volley_id: request.volley_id.clone(), // Use the VolleyId from the protocol
                                reply_to: reply_tx,
                            };

                            if self.query_tx.send(query).await.is_err() {
                                let _ = self.network.send_response(&channel_id, VolleyResponse::Throttled).await;
                                continue;
                            }

                            // 3. Collect and Egress
                            match reply_rx.await {
                                Ok(Ok(envelopes)) => {
                                    let orchestrator = RetrievalOrchestrator::new();
                                    match orchestrator.verify_mesh_egress(envelopes, &local_network_id).await {
                                        Ok(verified_data) => {
                                            let response = crate::transport::protocol::VolleyResponse::Success(verified_data);
                                            let _ = self.network.send_response(&channel_id, response).await;
                                        }
                                        Err(_) => {
                                            let _ = self.network.send_response(
                                                &channel_id,
                                                crate::transport::protocol::VolleyResponse::NotFound
                                            ).await;
                                        }
                                    }
                                }
                                _ => {
                                    let _ = self.network.send_response(
                                        &channel_id,
                                        crate::transport::protocol::VolleyResponse::NotFound
                                    ).await;
                                }
                            }
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
                    self.handle_forensic_violation(peer_id, owner_did, err).await;
                }
            }
        }
        Ok(())
    }

    async fn _promote_evidence(&mut self, evidence: Evidence) -> Result<(), EngineError> {
        let local_network_id = self.identity.to_network_id();
        let topic = MeshTopic::new("phalanx/1.0.0"); // Standard forensic topic

        // 1. Seal via Session (Updates causality)
        let envelope = self
            .session
            .seal_evidence(evidence)
            .map_err(|e| EngineError::SecurityBreach(e.to_string()))?;

        // 2. Fragment
        let shard_id = ShardId(self.seq_counter as u32);
        let chunks = envelope
            .chunkify(shard_id)
            .map_err(|e| EngineError::SecurityBreach(e.to_string()))?;

        // 3. FIX: Send as a tuple to satisfy the Ingress pipeline
        for chunk in chunks {
            if let Err(e) = self
                .chunk_tx
                .send((chunk, topic.clone(), local_network_id))
                .await
            {
                error!("Engine: Loopback channel failed: {}", e);
                return Err(EngineError::StorageFailure(e.to_string()));
            }
        }

        self.seq_counter += 1;
        Ok(())
    }

    async fn handle_forensic_violation(
        &mut self,
        peer_id: NetworkId,
        owner_did: Did,
        err: GuardianError,
    ) {
        let offense = match err {
            GuardianError::VerificationFailed(_) => Some(Offense::InvalidSignature),
            GuardianError::QuotaExceeded(_) => Some(Offense::QuotaExceeded),
            GuardianError::ReplayDetected(_) => Some(Offense::ReplayAttack),
            _ => None,
        };

        if let Some(offense_type) = offense {
            self.trust_registry
                .record_offense(&owner_did, offense_type, &self.clock)
                .await;
            let updated_score = self.trust_registry.evaluate_reputation(&peer_id);
            self.reputation_cache
                .scores
                .write()
                .unwrap()
                .insert(peer_id, updated_score);

            if self.trust_registry.is_blacklisted(&owner_did) {
                self.network.ban_peer(&peer_id).await;
            }
        }
    }

    async fn handle_network_ingress(
        &mut self,
        peer_id: NetworkId,
        chunk_bytes: &[u8],
        topic: MeshTopic,
    ) {
        let local_network_id = self.identity.to_network_id();
        if !self.governor.should_accept(&peer_id, &local_network_id) {
            return;
        }

        if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(chunk_bytes) {
            let sender_did = chunk.owner_did.clone();
            if matches!(
                self.trust_registry.check_trust(&sender_did),
                TrustLevel::Blocked
            ) || self.trust_registry.is_blacklisted(&sender_did)
            {
                self.network.ban_peer(&peer_id).await;
                return;
            }
            let _ = self.chunk_tx.try_send((chunk, topic, peer_id));
        }
    }

    async fn process_media_egress(&mut self, evidence: Evidence, local_network_id: NetworkId) {
        let topic = MeshTopic::new("phalanx/1.0.0");
        let shard_id = ShardId(self.seq_counter as u32);

        let chunks_result = evidence
            .safeguard(&self.network_key)
            .and_then(|ev| self.session.seal_evidence(ev))
            .and_then(|env| env.chunkify(shard_id))
            .gate(
                "egress_gate_failure",
                &local_network_id,
                "Evidence pipeline failure",
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

// =========================================================================
// SPECIALIZED EPHEMERAL IMPLEMENTATION
// =========================================================================
impl<T: NetworkTransport> PhalanxEngine<T, NoOpJournal> {
    /// Bootstraps an ephemeral node for testing or transient forensic sessions.
    pub fn new_at_path(path: &str, network: T) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = path.to_string();

        let identity =
            init_identity(std::path::Path::new(path).join("identity.pem")).unwrap_or_default();
        let registry_config = config.clone();

        // Build registry synchronously for test isolation
        let trust_registry = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(TrustRegistry::build(&registry_config))
        })
        .join()
        .expect("TrustRegistry setup failure");

        Self::new(
            config,
            identity,
            network,
            NoOpJournal,
            trust_registry,
            Arc::new(SyncReputationCache::default()),
        )
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
        (config, temp_dir)
    }

    #[tokio::test]
    async fn test_engine_initialization() {
        let (config, _temp_dir) = setup_test_env();
        let identity = PhalanxIdentity::new();
        let network = create_mock_transport();

        let trust_registry = TrustRegistry::build(&config).await;
        let reputation_cache = Arc::new(SyncReputationCache::default());

        let engine = PhalanxEngine::new(
            config,
            identity,
            network,
            NoOpJournal,
            trust_registry,
            reputation_cache,
        );
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

        let trust_registry = TrustRegistry::build(&config).await;
        let reputation_cache = Arc::new(SyncReputationCache::default());

        let engine = PhalanxEngine::new(
            config,
            identity,
            network,
            NoOpJournal,
            trust_registry,
            reputation_cache,
        )
        .unwrap();

        assert!(engine.video_rx.capacity() > 0);
        assert!(engine.audio_rx.capacity() > 0);
        assert!(engine.clock.now().is_ok());
    }
}
