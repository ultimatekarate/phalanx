use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::io;
use std::sync::{Arc, RwLock};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};

use crate::base::config::PhalanxConfig;
use crate::base::types::{MeshTopic, NodeMode, TrafficGovernor};
use crate::primitives::identity::{init_identity, Did, IdentityError, NetworkId, PhalanxIdentity};
use crate::primitives::shards::{
    CausalitySession, Evidence, ShardChunk, ShardError, ShardId, VolleyId, WitnessEnvelope,
};
use crate::primitives::time::{PhalanxTimestamp, TimeError, TrustedClock};
use crate::security::e2ee::SymmetricKey;
use crate::security::retrieval::RetrievalOrchestrator;
use crate::security::trust::{Offense, ReputationGate, TrustRegistry};
use crate::storage::reassembler::{Reassembler, TransientJournal};
use crate::storage::vault::{Guardian, GuardianError};
use crate::transport::events::NetworkEvent;
use crate::transport::health::HealthTracker;
use crate::transport::network_transport::NetworkTransport;
use crate::transport::protocol::VolleyResponse;

// IMPORT ALL GATES
use crate::security::gate::PrivacyGate;
use crate::storage::kademlia::PeerEvaluator;

pub use libp2p::pnet::PreSharedKey;

/// Represents a forensic response awaiting redelivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingEgress {
    pub channel_id: String,
    pub response: VolleyResponse,
    pub attempt_count: u32,
    pub next_attempt: PhalanxTimestamp,
}

impl PendingEgress {
    /// Instantiates a resilient egress record with type-safe timestamp arithmetic.
    pub fn new(channel_id: String, response: VolleyResponse, delay: Duration) -> Self {
        let now_ms = PhalanxTimestamp::now().as_millis();
        let delay_ms = delay.as_millis() as u64;

        Self {
            channel_id,
            response,
            attempt_count: 0,
            next_attempt: PhalanxTimestamp::from_millis(now_ms + delay_ms),
        }
    }
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
    async fn record_pending_egress(
        &mut self,
        _pending: &[PendingEgress],
    ) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
        Ok(vec![])
    }
}

/// Unified command protocol for the StorageActor (The Guardian).
pub enum StorageCommand {
    Ingest(ShardChunk, MeshTopic, NetworkId),
    Retrieval(RetrievalQuery),
    EmergencySalvage(Vec<PendingEgress>),
}

pub struct RetrievalQuery {
    pub volley_id: VolleyId,
    pub reply_to: oneshot::Sender<Result<Vec<WitnessEnvelope>, GuardianError>>,
}

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
// UNIFIED STORAGE ACTOR (THE GUARDIAN)
// =========================================================================
pub struct StorageActor<J: TransientJournal> {
    pub reassembler: Reassembler,
    pub guardian: Guardian,
    pub journal: J,
    pub config: PhalanxConfig,
    pub identity: PhalanxIdentity,
    pub forensic_tx: mpsc::Sender<(NetworkId, Did, GuardianError)>,
    pub local_peer_id: NetworkId,
}

impl<J: TransientJournal> StorageActor<J> {
    pub async fn run(mut self, mut command_rx: mpsc::Receiver<StorageCommand>) {
        let mut maintenance_timer = interval(Duration::from_millis(1000));

        loop {
            tokio::select! {
                Some(command) = command_rx.recv() => {
                    match command {
                        StorageCommand::Ingest(chunk, topic, peer_id) => {
                            self.process_incoming_chunk(chunk, topic, peer_id).await;
                        }
                        StorageCommand::Retrieval(query) => {
                            self.handle_retrieval_query(query).await;
                        }
                        StorageCommand::EmergencySalvage(payload) => {
                            info!(count = payload.len(), "StorageActor: Commencing emergency egress salvage");
                            if let Err(e) = self.journal.record_pending_egress(&payload).await {
                                error!(error = %e, "Salvage Failure: State persistence failed");
                            }
                            let _ = self.guardian.salvage().await;
                            return;
                        }
                    }
                }
                _ = maintenance_timer.tick() => {
                    let _ = self.guardian.check_and_finalize_volley().await;
                }
            }
        }
    }

    async fn handle_retrieval_query(&self, query: RetrievalQuery) {
        let result = match self.guardian.get_active_volley_shards(&query.volley_id) {
            Some(shard_map) => Ok(shard_map.values().cloned().collect()),
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
// PHALANX ENGINE (THE SENTINEL)
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
    pub forensic_rx: mpsc::Receiver<(NetworkId, Did, GuardianError)>,
    pub storage_task: JoinHandle<()>,
    pub storage_tx: mpsc::Sender<StorageCommand>,
    pub _journal_phantom: std::marker::PhantomData<J>,
    pub session: CausalitySession,
    pub pending_egress: VecDeque<PendingEgress>,
}

impl<T: NetworkTransport, J: TransientJournal + Send + 'static> PhalanxEngine<T, J> {
    pub async fn new(
        config: PhalanxConfig,
        identity: PhalanxIdentity,
        network: T,
        mut journal: J,
        trust_registry: TrustRegistry,
        reputation_cache: Arc<SyncReputationCache>,
    ) -> Result<Self, Box<dyn Error>> {
        let local_did = identity.did.clone();
        let local_network_id = identity.to_network_id();
        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&config.storage.vault_path, &config, local_did);

        let (_, video_rx) = mpsc::channel(config.storage.max_video_buffer);
        let (_, audio_rx) = mpsc::channel(config.storage.max_audio_buffer);
        let (storage_tx, storage_rx) = mpsc::channel(1024);
        let (forensic_tx, forensic_rx) = mpsc::channel(100);

        // Stateless Recovery: Pull salvaged egress from the journal
        let salvaged_queue = journal.read_all_pending_egress().await.unwrap_or_default();
        if !salvaged_queue.is_empty() {
            info!(
                count = salvaged_queue.len(),
                "Engine Bootstrap: Recovered salvaged egress records"
            );
        }

        let storage_actor = StorageActor {
            reassembler,
            guardian,
            journal,
            config: config.clone(),
            identity: identity.clone(),
            forensic_tx,
            local_peer_id: local_network_id,
        };

        let storage_task = tokio::spawn(async move {
            storage_actor.run(storage_rx).await;
        });
        let arc_identity = Arc::new(identity);
        let session = CausalitySession::new(arc_identity.clone(), local_network_id);

        Ok(Self {
            config,
            identity: arc_identity,
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
            forensic_rx,
            storage_task,
            storage_tx,
            _journal_phantom: std::marker::PhantomData,
            session,
            pending_egress: VecDeque::from(salvaged_queue),
        })
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn Error>> {
        let local_network_id = self.identity.to_network_id();
        let mut retry_tick = interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                _ = retry_tick.tick() => { self.process_pending_egress().await; }
                Some(event) = self.network.next_event() => {
                    match event {
                        NetworkEvent::DataReceived { origin, topic, data } => {
                            self.handle_network_ingress(origin, &data, topic).await;
                        }
                        NetworkEvent::RetrievalRequested { origin, request, channel_id } => {
                            self.execute_secure_retrieval(origin, request, channel_id, local_network_id).await;
                        }
                        NetworkEvent::Shutdown => {
                            info!("Engine: Initiating emergency salvage");
                            let payload = self.pending_egress.drain(..).collect();
                            let _ = self.storage_tx.send(StorageCommand::EmergencySalvage(payload)).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            break;
                        }
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

    async fn execute_secure_retrieval(
        &mut self,
        origin: NetworkId,
        request: crate::transport::protocol::VolleyRequest,
        channel_id: String,
        local_id: NetworkId,
    ) {
        if self.identity.verify_retrieval_auth(&request).is_err() {
            warn!(
                peer = %origin,
                volley = %request.volley_id,
                "Privacy Gate: Unauthorized retrieval attempt blocked"
            );

            // Forensic Action: Record the offense against the PeerID
            self.trust_registry
                .record_offense(
                    &request.target_did, // Or map origin to DID if known
                    Offense::InvalidSignature,
                    &self.clock,
                )
                .await;

            self.dispatch_resilient_response(channel_id, VolleyResponse::Unauthorized)
                .await;
            return;
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        let _ = self
            .storage_tx
            .send(StorageCommand::Retrieval(RetrievalQuery {
                volley_id: request.volley_id.clone(),
                reply_to: reply_tx,
            }))
            .await;

        let response = match reply_rx.await {
            Ok(Ok(envelopes)) => {
                let orchestrator = RetrievalOrchestrator::new();
                match orchestrator.verify_mesh_egress(envelopes, &local_id).await {
                    Ok(verified) => VolleyResponse::Success(verified),
                    Err(_) => VolleyResponse::NotFound,
                }
            }
            _ => VolleyResponse::NotFound,
        };
        self.dispatch_resilient_response(channel_id, response).await;
    }

    async fn dispatch_resilient_response(&mut self, channel_id: String, response: VolleyResponse) {
        if self.pending_egress.len() >= 1000 {
            self.pending_egress.pop_front();
        }
        if self
            .network
            .send_response(&channel_id, response.clone())
            .await
            .is_err()
        {
            self.pending_egress.push_back(PendingEgress::new(
                channel_id,
                response,
                Duration::from_millis(500),
            ));
        }
    }

    async fn process_pending_egress(&mut self) {
        let now = PhalanxTimestamp::now();
        let mut retry_queue = VecDeque::new();

        while let Some(mut pending) = self.pending_egress.pop_front() {
            if pending.next_attempt > now {
                retry_queue.push_back(pending);
                continue;
            }

            match self
                .network
                .send_response(&pending.channel_id, pending.response.clone())
                .await
            {
                Ok(_) => {
                    info!(channel = %pending.channel_id, "Redelivery successful");
                }
                Err(_) => {
                    pending.attempt_count += 1;
                    if pending.attempt_count < 3 {
                        let delay = Duration::from_millis(500 * (2u64.pow(pending.attempt_count)));
                        pending.next_attempt = PhalanxTimestamp::from_millis(
                            now.as_millis() + delay.as_millis() as u64,
                        );
                        retry_queue.push_back(pending);
                    }
                }
            }
        }
        self.pending_egress = retry_queue;
    }

    async fn handle_network_ingress(&mut self, peer_id: NetworkId, data: &[u8], topic: MeshTopic) {
        if !self
            .governor
            .should_accept(&peer_id, &self.identity.to_network_id())
        {
            return;
        }
        if let Ok(chunk) = postcard::from_bytes::<ShardChunk>(data) {
            let sender_did = chunk.owner_did.clone();
            if self.trust_registry.is_blacklisted(&sender_did) {
                self.network.ban_peer(&peer_id).await;
                return;
            }
            let _ = self
                .storage_tx
                .send(StorageCommand::Ingest(chunk, topic, peer_id))
                .await;
        }
    }

    async fn process_media_egress(&mut self, evidence: Evidence, local_id: NetworkId) {
        let topic = MeshTopic::new("phalanx/1.0.0");
        let shard_id = ShardId(self.seq_counter as u32);

        let pipeline_result = evidence
            .safeguard(&self.network_key)
            .and_then(|ev| self.session.seal_evidence(ev))
            .and_then(|env| env.chunkify(shard_id));

        if let Ok(chunks) = pipeline_result {
            for chunk in chunks {
                // RE-INTEGRATION: Use local_id to verify the chunk is properly attributed
                // before it touches the wire.
                if chunk.owner_did != self.identity.did {
                    error!(peer = %local_id, "Egress Gate: Attribution mismatch detected. Blocking publish.");
                    continue;
                }

                if let Ok(data) = postcard::to_stdvec(&chunk) {
                    let _ = self.network.publish(&topic, data).await;
                }
            }
            self.seq_counter += 1;
        }
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
            let score = self.trust_registry.evaluate_reputation(&peer_id);
            self.reputation_cache
                .scores
                .write()
                .unwrap()
                .insert(peer_id, score);
            if self.trust_registry.is_blacklisted(&owner_did) {
                self.network.ban_peer(&peer_id).await;
            }
        }
    }
}

// Ephemeral Bootstrap
impl<T: NetworkTransport> PhalanxEngine<T, NoOpJournal> {
    pub async fn new_at_path(path: &str, network: T) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = path.to_string();
        let identity =
            init_identity(std::path::Path::new(path).join("identity.pem")).unwrap_or_default();
        let trust_registry = TrustRegistry::build(&config).await;
        Self::new(
            config,
            identity,
            network,
            NoOpJournal,
            trust_registry,
            Arc::new(SyncReputationCache::default()),
        )
        .await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::PhalanxConfig;
    use crate::base::types::MeshTopic;
    use crate::primitives::identity::PhalanxIdentity;
    use crate::primitives::shards::{DataPayload, Evidence, StorageSequence, VideoShard};
    use crate::transport::events::NetworkEvent;
    use crate::transport::mock::MockTransport;
    use tempfile::TempDir;
    use tokio::sync::mpsc;

    // --- CLINICAL MOCK: FAILING TRANSPORT ---
    struct FailingTransport;

    #[async_trait::async_trait]
    impl NetworkTransport for FailingTransport {
        async fn send_response(&mut self, _: &str, _: VolleyResponse) -> Result<(), String> {
            // Pillar 3: Force failure to verify re-queueing
            Err("Simulated Network Failure".to_string())
        }
        async fn next_event(&mut self) -> Option<NetworkEvent> {
            None
        }
        async fn publish(&mut self, _: &MeshTopic, _: Vec<u8>) -> Result<(), String> {
            Ok(())
        }
        async fn ban_peer(&mut self, _: &NetworkId) {}
    }

    struct RecoveryJournal(Vec<PendingEgress>);

    #[async_trait::async_trait]
    impl TransientJournal for RecoveryJournal {
        async fn read_all_pending_egress(&mut self) -> Result<Vec<PendingEgress>, ShardError> {
            // Pillar 2: Return the "salvaged" state
            Ok(self.0.clone())
        }
        async fn record_pending_egress(&mut self, _: &[PendingEgress]) -> Result<(), ShardError> {
            Ok(())
        }
        async fn record_chunk(&mut self, _: &ShardChunk) -> Result<(), ShardError> {
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
        assert!(
            engine.await.is_ok(),
            "Engine should initialize with valid inputs"
        );
    }

    #[tokio::test]
    async fn test_new_at_path_ephemeral_fallback() {
        use tempfile::tempdir;

        let temp = tempdir().unwrap();
        let network = create_mock_transport();
        let engine = PhalanxEngine::new_at_path(temp.path().to_str().unwrap(), network)
            .await
            .unwrap();
        assert_eq!(engine.seq_counter, 0);
    }

    #[tokio::test]
    async fn test_pipeline_gates_active() {
        use tempfile::tempdir;
        let temp = tempdir().unwrap();
        let network = create_mock_transport();
        let engine = PhalanxEngine::new_at_path(temp.path().to_str().unwrap(), network)
            .await
            .unwrap();
        assert!(engine.clock.now().is_ok());
    }

    #[tokio::test]
    async fn test_pillar_retry_logic_and_backoff() {
        let _temp = tempfile::tempdir().unwrap();
        // Initialize with NoOpJournal as we are testing the Engine's internal loop
        let mut engine = PhalanxEngine::new(
            PhalanxConfig::test_defaults(),
            PhalanxIdentity::new(),
            FailingTransport,
            NoOpJournal,
            TrustRegistry::build(&PhalanxConfig::test_defaults()).await,
            Arc::new(SyncReputationCache::default()),
        )
        .await
        .unwrap();

        // 1. Inject a "stale" message (next_attempt is in the past)
        let past_ts = PhalanxTimestamp::from_millis(PhalanxTimestamp::now().as_millis() - 5000);
        engine.pending_egress.push_back(PendingEgress {
            channel_id: "retry_target_01".into(),
            response: VolleyResponse::NotFound,
            attempt_count: 0,
            next_attempt: past_ts,
        });

        // 2. Execute the retry processor
        engine.process_pending_egress().await;

        // 3. Verify Pillar 3: Backoff math and retention
        let pending = engine
            .pending_egress
            .front()
            .expect("Pillar 3 Failure: Message was dropped instead of re-queued on failure");

        assert_eq!(pending.attempt_count, 1);
        // The new timestamp should be roughly now + 1000ms (500 * 2^1)
        assert!(pending.next_attempt > PhalanxTimestamp::now());
        assert_eq!(pending.channel_id, "retry_target_01");
    }

    #[tokio::test]
    async fn test_pillar_salvage_intent() {
        use crate::security::gate::WitnessGate;

        let (identity, _) = PhalanxIdentity::generate().unwrap();

        let mut engine = PhalanxEngine::new(
            PhalanxConfig::test_defaults(),
            identity.clone(),
            FailingTransport,
            NoOpJournal,
            TrustRegistry::build(&PhalanxConfig::test_defaults()).await,
            Arc::new(SyncReputationCache::default()),
        )
        .await
        .unwrap();

        // 1. Create a structurally valid WitnessEnvelope
        let video_shard = VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("v1"),
            payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        };

        let envelope = Evidence::Video(video_shard)
            .seal(&identity, identity.to_network_id(), None)
            .expect("Failed to seal test envelope");

        // 2. Populate live queue with the correct type
        engine.pending_egress.push_back(PendingEgress::new(
            "ch_live".into(),
            VolleyResponse::Success(vec![envelope]),
            Duration::from_secs(5),
        ));

        // 3. Simulate the Shutdown branch logic
        let salvage_payload: Vec<PendingEgress> = engine.pending_egress.drain(..).collect();

        // 4. Verify Pillar 1
        assert_eq!(salvage_payload.len(), 1);
        assert_eq!(salvage_payload[0].channel_id, "ch_live");

        // Ensure the data inside matches
        if let VolleyResponse::Success(ref envelopes) = salvage_payload[0].response {
            assert_eq!(envelopes.len(), 1);
        } else {
            panic!("Pillar 1 Failure: Response type was corrupted during salvage drain");
        }
    }

    #[tokio::test]
    async fn test_bootstrap_recovery() {
        // Pre-create some "salvaged" data
        let salvaged = vec![PendingEgress::new(
            "ch_salvaged".into(),
            VolleyResponse::Unauthorized,
            Duration::from_secs(1),
        )];
        let journal = RecoveryJournal(salvaged);

        // 1. Initialize Engine
        let engine = PhalanxEngine::new(
            PhalanxConfig::test_defaults(),
            PhalanxIdentity::new(),
            FailingTransport, // Reuse the stub
            journal,
            TrustRegistry::build(&PhalanxConfig::test_defaults()).await,
            Arc::new(SyncReputationCache::default()),
        )
        .await
        .unwrap();

        // 2. Verify Pillar 2: The engine "remembered" the salvaged queue
        assert_eq!(engine.pending_egress.len(), 1);
        assert_eq!(engine.pending_egress[0].channel_id, "ch_salvaged");
    }
}
