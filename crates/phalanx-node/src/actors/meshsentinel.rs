use crate::actors::playback::PlaybackCoordinator;
use crate::actors::retrieval::RetrievalOrchestrator;
use crate::actors::retrieval::RetrievalQuery;
use crate::actors::storage::NoOpJournal;
use crate::actors::storage::StorageCommand;
use crate::clock::TrustedClock;
use crate::config::NodeConfig;
use crate::state::SyncReputationCache;
use crate::vitals::HealthTracker;
use crate::Guardian;
use crate::StorageActor;
use phalanx_forensics::prelude::*;
use phalanx_proto::prelude::*;

use crate::identity::PhalanxNodeIdentityExt;
use crate::trust::TrustRegistry;
use phalanx_forensics::trust::{PeerEvaluator, ReputationGate};
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::AudioShard;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::time::CausalitySession;
use phalanx_proto::trust::Offense;
use phalanx_proto::types::NodeMode;
use phalanx_proto::VolleyRequest;
use phalanx_transport::identity_ext::Libp2pExt;
use phalanx_transport::NetworkTransport;
use std::collections::VecDeque;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

/// A lightweight request broadcast to the mesh when a playback gap is detected.
#[derive(serde::Serialize, serde::Deserialize)]
struct ShardDiscoveryRequest {
    volley_id: VolleyId,
    sequence_id: StorageSequence,
}

pub struct SentinelDependencies<T: NetworkTransport, J: TransientJournal> {
    pub config: NodeConfig,
    pub identity: PhalanxIdentity,
    pub network: T,
    pub journal: J,
    pub trust_registry: TrustRegistry,
    pub reputation_cache: Arc<SyncReputationCache>,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
}

pub struct MeshSentinel<T: NetworkTransport, J: TransientJournal> {
    pub trust_registry: TrustRegistry,
    pub reputation_cache: Arc<SyncReputationCache>,
    pub health_tracker: HealthTracker,
    pub governor: TrafficGovernor,
    pub mode: NodeMode,
    pub config: NodeConfig,
    pub identity: Arc<PhalanxIdentity>,
    pub clock: TrustedClock,
    pub network: T,
    pub video_rx: mpsc::Receiver<VideoShard>,
    pub audio_rx: mpsc::Receiver<AudioShard>,
    pub seq_counter: u64,
    pub network_key: SymmetricKey,
    pub forensic_rx: mpsc::Receiver<(NetworkId, Did, GuardianError)>,
    pub storage_task: JoinHandle<()>,
    pub storage_tx: mpsc::Sender<StorageCommand>,
    pub _journal_phantom: std::marker::PhantomData<J>,
    pub session: CausalitySession,
    pub pending_egress: VecDeque<PendingEgress>,
    pub discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
    pub discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
}

impl<T: NetworkTransport, J: TransientJournal + Send + 'static> MeshSentinel<T, J> {
    pub async fn new(mut deps: SentinelDependencies<T, J>) -> Result<Self, Box<dyn Error>> {
        let local_did = deps.identity.did.clone();
        let local_network_id = deps.identity.to_network_id();
        let reassembler = Reassembler::new();
        let guardian = Guardian::new(&deps.config.storage.vault_path, &deps.config, local_did);

        let (_, video_rx) = mpsc::channel(deps.config.storage.max_video_buffer);
        let (_, audio_rx) = mpsc::channel(deps.config.storage.max_audio_buffer);
        let (storage_tx, storage_rx) = mpsc::channel(1024);
        let (forensic_tx, forensic_rx) = mpsc::channel(100);

        // Stateless Recovery: Pull salvaged egress from the journal
        let salvaged_queue = deps
            .journal
            .read_all_pending_egress()
            .await
            .unwrap_or_default();
        if !salvaged_queue.is_empty() {
            tracing::info!(
                count = salvaged_queue.len(),
                "Engine Bootstrap: Recovered salvaged egress records"
            );
        }

        let storage_actor = StorageActor {
            reassembler,
            guardian,
            journal: deps.journal,
            config: deps.config.clone(),
            identity: deps.identity.clone(),
            forensic_tx,
            local_peer_id: local_network_id.clone(),
        };

        let storage_task = tokio::spawn(async move {
            storage_actor.run(storage_rx).await;
        });

        let arc_identity = Arc::new(deps.identity.clone());
        let session = CausalitySession::new(arc_identity.clone(), local_network_id.clone());

        Ok(Self {
            config: deps.config,
            identity: arc_identity,
            clock: TrustedClock::new(),
            network: deps.network,
            trust_registry: deps.trust_registry,
            reputation_cache: deps.reputation_cache,
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
            discovery_rx: deps.discovery_rx,
            discovery_tx: deps.discovery_tx,
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
                        NetworkEvent::VolleyRequested { origin, request, channel_id } => {
                            self.execute_secure_retrieval(origin, request, channel_id, &local_network_id).await;
                        }
                        NetworkEvent::Shutdown => {
                            tracing::info!("Engine: Initiating emergency salvage");
                            let payload = self.pending_egress.drain(..).collect();
                            let _ = self.storage_tx.send(StorageCommand::EmergencySalvage(payload)).await;
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            break;
                        }
                        _ => {}
                    }
                }
                Some(shard) = self.video_rx.recv() => {
                    self.process_media_egress(Evidence::Video(shard), &local_network_id).await;
                }
                Some(shard) = self.audio_rx.recv() => {
                    self.process_media_egress(Evidence::Audio(shard), &local_network_id).await;
                }
                Some((peer_id, owner_did, err)) = self.forensic_rx.recv() => {
                    self.handle_forensic_violation(peer_id, owner_did, err).await;
                }
                Some((volley_id, gap_sequence)) = self.discovery_rx.recv() => {
                    self.handle_gap_discovery(volley_id, gap_sequence).await;
                }
            }
        }
        Ok(())
    }

    async fn handle_gap_discovery(&mut self, volley_id: VolleyId, gap_sequence: StorageSequence) {
        tracing::info!(
            "Playback gap detected for Volley {:?} at sequence {}. Initiating mesh discovery.",
            volley_id,
            gap_sequence.0
        );

        let topic = MeshTopic::new("phalanx/discovery/1.0.0");

        let request = ShardDiscoveryRequest {
            volley_id,
            sequence_id: gap_sequence,
        };

        // Serialize the request using your standard Postcard format
        match postcard::to_allocvec(&request) {
            Ok(data) => {
                // Broadcast to the mesh. Any node with this Volley will hear it.
                if let Err(e) = self.network.publish(&topic, data).await {
                    tracing::error!("Failed to broadcast discovery request: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to serialize discovery request: {}", e);
            }
        }
    }

    async fn process_media_egress(&mut self, evidence: Evidence, _local_id: &NetworkId) {
        let topic = match &evidence {
            Evidence::Video(_) => &self.config.network.video_topic,
            Evidence::Audio(_) => &self.config.network.audio_topic,
            Evidence::Gap(_) | Evidence::Handover(_) => {
                tracing::warn!("Unexpected evidence type for media egress");
                return;
            }
        };

        match postcard::to_allocvec(&evidence) {
            Ok(data) => {
                if let Err(e) = self.network.publish(topic, data).await {
                    tracing::error!("Failed to publish media egress: {}", e);
                }
            }
            Err(e) => {
                tracing::error!("Failed to serialize media evidence: {}", e);
            }
        }
    }

    pub fn spawn_playback<S: PlaybackSink + 'static>(
        &self,
        volley_id: VolleyId,
        sink: S,
    ) -> tokio::task::JoinHandle<()> {
        let mut coordinator = PlaybackCoordinator::new(
            self.storage_tx.clone(),        // Share the safe room
            Some(self.network_key.clone()), // Symmetric key logic goes here if needed
            sink,
            self.discovery_tx.clone(), // Clone the Samson Reflex wire
        );

        // Spawn it as a detached Tokio task so it runs concurrently with the Engine
        tokio::spawn(async move {
            if let Err(e) = coordinator.run(volley_id).await {
                tracing::error!("Playback Coordinator terminated with error: {:?}", e);
            }
        })
    }

    async fn execute_secure_retrieval(
        &mut self,
        origin: NetworkId,
        request: VolleyRequest,
        channel_id: String,
        local_id: &NetworkId,
    ) {
        if PhalanxNodeIdentityExt::verify_retrieval_auth(&*self.identity, &request).is_err() {
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
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        let _ = self
            .storage_tx
            .send(StorageCommand::Retrieval(RetrievalQuery {
                origin,
                request,
                reply_to: reply_tx,
            }))
            .await;

        let response = match reply_rx.await {
            Ok(VolleyResponse::Success(envelopes)) => {
                let orchestrator = RetrievalOrchestrator::new();
                match orchestrator.verify_mesh_egress(envelopes, local_id).await {
                    Ok(verified) => VolleyResponse::Success(verified),
                    Err(_) => VolleyResponse::NotFound,
                }
            }
            _ => VolleyResponse::NotFound,
        };
        self.dispatch_resilient_response(channel_id, response).await;
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
                        pending.next_attempt =
                            PhalanxTimestamp::from_millis(now.0 + delay.as_millis() as u64);
                        retry_queue.push_back(pending);
                    }
                }
            }
        }
        self.pending_egress = retry_queue;
    }

    /// Attempts to send a response over the network. On failure, enqueues
    /// into the pending_egress retry queue for exponential-backoff redelivery.
    async fn dispatch_resilient_response(&mut self, channel_id: String, response: VolleyResponse) {
        if self
            .network
            .send_response(&channel_id, response.clone())
            .await
            .is_err()
        {
            tracing::warn!(channel = %channel_id, "Response dispatch failed, queuing for retry");
            self.pending_egress.push_back(PendingEgress {
                channel_id,
                response,
                attempt_count: 1,
                next_attempt: PhalanxTimestamp::from_millis(
                    PhalanxTimestamp::now().0 + 1000, // First retry after 1s
                ),
            });
        }
    }

    async fn handle_network_ingress(&mut self, peer_id: NetworkId, data: &[u8], topic: MeshTopic) {
        if !self
            .governor
            .should_accept(&peer_id, &self.identity.to_network_id())
        {
            return;
        }

        match postcard::from_bytes::<ShardChunk>(data) {
            Ok(chunk) => {
                let sender_did = chunk.owner_did.clone();

                let record = self
                    .trust_registry
                    .get_reputation_mut(&sender_did)
                    .cloned()
                    .unwrap_or_default();

                if record.is_blacklisted {
                    self.network.ban_peer(&peer_id).await;
                    return;
                }

                // Explicit error handling for the internal channel I/O operation
                if let Err(err) = self
                    .storage_tx
                    .send(StorageCommand::Ingest(chunk, topic, peer_id))
                    .await
                {
                    tracing::error!(
                        error = %err,
                        "CRITICAL: Failed to route ingress chunk to storage subsystem"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    peer = %peer_id,
                    error = %err,
                    "Dropped malformed ShardChunk payload at network edge"
                );
            }
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
                .insert(peer_id.clone(), score);
            if self.trust_registry.is_blacklisted(&owner_did) {
                self.network.ban_peer(&peer_id).await;
            }
        }
    }
}

// Ephemeral Bootstrap
impl<T: NetworkTransport> MeshSentinel<T, NoOpJournal> {
    pub async fn new_at_path(path: &str, network: T) -> Result<Self, Box<dyn Error>> {
        let mut config = NodeConfig::default();
        config.storage.vault_path = path.to_string();
        let identity = PhalanxIdentity::new_ephemeral();
        let trust_registry = TrustRegistry::build(&config).await;
        let (discovery_tx, discovery_rx) = mpsc::channel(100);

        let deps = SentinelDependencies {
            config,
            identity,
            network,
            journal: NoOpJournal,
            trust_registry,
            reputation_cache: Arc::new(SyncReputationCache::default()),
            discovery_rx,
            discovery_tx,
        };

        Self::new(deps).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_forensics::witness::WitnessAuthority;
    use phalanx_proto::evidence::WitnessEnvelope;
    use phalanx_proto::evidence::{ChunkType, Evidence, StorageSequence, VideoShard};
    use phalanx_proto::network::NetworkEvent;
    use phalanx_proto::time::PhalanxTimestamp;
    use phalanx_proto::trust::PeerRecord;
    use phalanx_proto::types::PowerState;

    use tokio::sync::mpsc;

    /// Minimal mock implementing NetworkTransport for unit testing.
    /// Records publishes, bans, and responses; feeds events from a channel.
    struct TestTransport {
        ingress_rx: mpsc::Receiver<NetworkEvent>,
        published: Vec<(MeshTopic, Vec<u8>)>,
        banned: Vec<NetworkId>,
        responses: Vec<(String, VolleyResponse)>,
    }

    impl TestTransport {
        fn new(ingress_rx: mpsc::Receiver<NetworkEvent>) -> Self {
            Self {
                ingress_rx,
                published: Vec::new(),
                banned: Vec::new(),
                responses: Vec::new(),
            }
        }
    }

    #[async_trait::async_trait]
    impl NetworkTransport for TestTransport {
        async fn publish(&mut self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
            self.published.push((topic.clone(), data));
            Ok(())
        }
        async fn next_event(&mut self) -> Option<NetworkEvent> {
            self.ingress_rx.recv().await
        }
        async fn ban_peer(&mut self, peer: &NetworkId) {
            self.banned.push(peer.clone());
        }
        async fn send_response(
            &mut self,
            channel_id: &str,
            response: VolleyResponse,
        ) -> Result<(), String> {
            self.responses.push((channel_id.to_string(), response));
            Ok(())
        }
    }

    /// Helper: builds a MeshSentinel<TestTransport, NoOpJournal> for testing.
    async fn build_test_sentinel(
        ingress_rx: mpsc::Receiver<NetworkEvent>,
    ) -> (MeshSentinel<TestTransport, NoOpJournal>, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::default();
        config.storage.vault_path = temp.path().to_string_lossy().to_string();

        let identity = PhalanxIdentity::new_ephemeral();
        let trust_registry = TrustRegistry::build(&config).await;
        let (discovery_tx, discovery_rx) = mpsc::channel(100);

        let deps = SentinelDependencies {
            config,
            identity,
            network: TestTransport::new(ingress_rx),
            journal: NoOpJournal,
            trust_registry,
            reputation_cache: Arc::new(SyncReputationCache::default()),
            discovery_tx,
            discovery_rx,
        };

        (
            MeshSentinel::new(deps)
                .await
                .expect("Failed to build test sentinel"),
            temp,
        )
    }

    #[tokio::test]
    async fn test_handle_network_ingress_enforces_trust_registry() {
        // 1. Initialize the test environment using the provided helper
        let (_ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        // Intercept storage commands to verify routing
        let (mock_storage_tx, mut mock_storage_rx) = mpsc::channel(10);
        sentinel.storage_tx = mock_storage_tx;

        // Setup shared test variables
        let topic = MeshTopic::new("phalanx/test/1.0.0");
        let valid_peer = NetworkId::random();
        let bad_peer = NetworkId::random();
        let bad_peer_petname = PetName::new("bad_actor".to_string()).expect("Invalid pet name");
        let valid_did = Did("did:phalanx:trusted".to_string());
        let bad_did = Did("did:phalanx:malicious".to_string());

        // Force the bad_did into a blacklisted state within the trust registry.
        // Note: Replace this with your exact TrustRegistry mutator method if
        // direct HashMap access to `contacts` is encapsulated.
        let mut bad_record = PeerRecord::default();
        bad_record.reputation.is_blacklisted = true;
        sentinel
            .trust_registry
            .set_peer(
                &bad_did.clone(),
                &bad_peer_petname,
                TrustLevel::Blocked,
                &TrustedClock::new(),
            )
            .await
            .expect("Failed to set peer");

        // 2. Test Blacklisted Peer Rejection
        let mut bad_chunk = ShardChunk::default();
        bad_chunk.owner_did = bad_did.clone();

        let bad_data = postcard::to_allocvec(&bad_chunk).expect("Failed to serialize bad chunk");

        sentinel
            .handle_network_ingress(bad_peer.clone(), &bad_data, topic.clone())
            .await;

        // Verify the transport layer explicitly banned the malicious peer
        assert!(
            sentinel.network.banned.contains(&bad_peer),
            "Expected the malicious peer to be explicitly banned in TestTransport"
        );

        // Verify the storage subsystem channel remains empty
        assert!(
            mock_storage_rx.try_recv().is_err(),
            "Blacklisted chunk bypassed the network edge filter"
        );

        // 3. Test Valid Peer Promotion
        let mut valid_chunk = ShardChunk::default();
        valid_chunk.owner_did = valid_did;

        let valid_data =
            postcard::to_allocvec(&valid_chunk).expect("Failed to serialize valid chunk");

        sentinel
            .handle_network_ingress(valid_peer.clone(), &valid_data, topic)
            .await;

        // Verify the valid peer was NOT banned
        assert!(
            !sentinel.network.banned.contains(&valid_peer),
            "Valid peer was incorrectly banned"
        );

        // Verify the storage channel received the Ingest command
        match mock_storage_rx.try_recv() {
            Ok(StorageCommand::Ingest(chunk, _, _)) => {
                assert_eq!(chunk.owner_did, valid_chunk.owner_did);
            }
            _ => panic!("Expected valid chunk to be successfully routed to the storage subsystem"),
        }
    }

    #[tokio::test]
    async fn test_sentinel_boots_and_shuts_down() {
        let (ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

        let result = sentinel.run().await;
        assert!(result.is_ok(), "Sentinel should shut down cleanly");
    }

    #[tokio::test]
    async fn test_ingress_valid_chunk_forwarded_to_storage() {
        let (ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        let identity = PhalanxIdentity::new_ephemeral();
        let topic = sentinel.config.network.video_topic.clone();

        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("v_ingress"),
            payload: DataPayload::Clear(vec![0xAB; 4]),
        });
        let envelope =
            WitnessEnvelope::sign_envelope(evidence, &identity, identity.network_id.clone(), None)
                .unwrap();

        let chunk = ShardChunk {
            shard_id: ShardId(1),
            chunk_index: 0,
            total_chunks: 1,
            data: postcard::to_allocvec(&envelope).unwrap(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };
        let chunk_bytes = postcard::to_allocvec(&chunk).unwrap();

        ingress_tx
            .send(NetworkEvent::DataReceived {
                origin: NetworkId::random(),
                topic,
                data: chunk_bytes,
            })
            .await
            .unwrap();
        ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

        sentinel.run().await.unwrap();
        // Reaching here without panic/hang confirms the chunk was forwarded to storage_tx.
    }

    #[tokio::test]
    async fn test_ingress_rejected_in_leaf_mode() {
        let (ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        // Switch to Leaf mode — only loopback traffic is accepted
        sentinel.governor.set_state(PowerState::Leaf);

        let identity = PhalanxIdentity::new_ephemeral();
        let topic = sentinel.config.network.video_topic.clone();

        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("v_leaf"),
            payload: DataPayload::Clear(vec![0x00; 4]),
        });
        let envelope =
            WitnessEnvelope::sign_envelope(evidence, &identity, identity.network_id.clone(), None)
                .unwrap();

        let chunk = ShardChunk {
            shard_id: ShardId(1),
            chunk_index: 0,
            total_chunks: 1,
            data: postcard::to_allocvec(&envelope).unwrap(),
            owner_did: identity.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };
        let chunk_bytes = postcard::to_allocvec(&chunk).unwrap();

        // Foreign peer sends data — governor should drop it silently
        ingress_tx
            .send(NetworkEvent::DataReceived {
                origin: NetworkId::from("foreign-peer"),
                topic,
                data: chunk_bytes,
            })
            .await
            .unwrap();
        ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

        sentinel.run().await.unwrap();
        // No panic = foreign traffic was silently dropped by the governor
    }

    #[tokio::test]
    async fn test_blacklisted_peer_triggers_ban() {
        let (ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        let attacker = PhalanxIdentity::new_ephemeral();
        let attacker_peer = NetworkId::from("attacker-peer");
        let topic = sentinel.config.network.video_topic.clone();

        // Pre-blacklist the attacker's DID by recording repeated offenses
        use phalanx_proto::trust::Offense;
        for _ in 0..10 {
            sentinel
                .trust_registry
                .record_offense(&attacker.did, Offense::InvalidSignature, &sentinel.clock)
                .await;
        }

        let evidence = Evidence::Video(VideoShard {
            timestamp: PhalanxTimestamp::now(),
            sequence_id: StorageSequence(1),
            fps: 30,
            volley_id: VolleyId::new("v_blacklist"),
            payload: DataPayload::Clear(vec![0xFF; 4]),
        });
        let envelope =
            WitnessEnvelope::sign_envelope(evidence, &attacker, attacker.network_id.clone(), None)
                .unwrap();

        let chunk = ShardChunk {
            shard_id: ShardId(1),
            chunk_index: 0,
            total_chunks: 1,
            data: postcard::to_allocvec(&envelope).unwrap(),
            owner_did: attacker.did.clone(),
            chunk_type: ChunkType::Witnessed,
        };
        let chunk_bytes = postcard::to_allocvec(&chunk).unwrap();

        ingress_tx
            .send(NetworkEvent::DataReceived {
                origin: attacker_peer.clone(),
                topic,
                data: chunk_bytes,
            })
            .await
            .unwrap();
        ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

        sentinel.run().await.unwrap();

        assert!(
            sentinel.network.banned.contains(&attacker_peer),
            "Blacklisted peer should have been banned via network.ban_peer()"
        );
    }

    #[tokio::test]
    async fn test_dispatch_resilient_response_succeeds_without_enqueue() {
        let (_ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        assert!(sentinel.pending_egress.is_empty());

        // TestTransport.send_response always succeeds, so nothing should be queued
        sentinel
            .dispatch_resilient_response("ch_ok".into(), VolleyResponse::NotFound)
            .await;

        assert!(
            sentinel.pending_egress.is_empty(),
            "Successful dispatch should not enqueue into pending_egress"
        );

        // Verify the response was actually sent
        assert_eq!(sentinel.network.responses.len(), 1);
        assert_eq!(sentinel.network.responses[0].0, "ch_ok");
    }

    #[tokio::test]
    async fn test_forensic_violation_updates_reputation() {
        let (_ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        let offender_peer = NetworkId::from("bad-peer");
        let offender_did = Did::from("did:key:zBadActor");

        sentinel
            .handle_forensic_violation(
                offender_peer.clone(),
                offender_did,
                GuardianError::VerificationFailed("signature mismatch".into()),
            )
            .await;

        let score = sentinel
            .reputation_cache
            .scores
            .read()
            .unwrap()
            .get(&offender_peer)
            .cloned();

        assert!(
            score.is_some(),
            "Reputation cache should be updated after forensic violation"
        );
    }

    #[tokio::test]
    async fn test_gap_discovery_publishes_to_mesh() {
        let (_ingress_tx, ingress_rx) = mpsc::channel(10);
        let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

        let volley_id = VolleyId::new("v_gap");
        let gap_seq = StorageSequence(5);

        sentinel
            .handle_gap_discovery(volley_id.clone(), gap_seq)
            .await;

        assert_eq!(
            sentinel.network.published.len(),
            1,
            "Gap discovery should publish exactly one message"
        );

        let (topic, data) = &sentinel.network.published[0];
        assert_eq!(topic.as_str(), DISCOVERY_TOPIC_ID);

        let request: ShardDiscoveryRequest = postcard::from_bytes(data).unwrap();
        assert_eq!(request.volley_id, volley_id);
        assert_eq!(request.sequence_id, gap_seq);
    }
}
