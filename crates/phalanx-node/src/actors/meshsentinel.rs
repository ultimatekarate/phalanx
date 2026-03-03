use crate::actors::playback::PlaybackCoordinator;
use crate::actors::storage::NoOpJournal;
use crate::config::NodeConfig;
use crate::state::SyncReputationCache;
use crate::vitals::HealthTracker;
use crate::Guardian;
use crate::StorageActor;

use crate::actors::storage::{RetrievalQuery, StorageCommand};
use phalanx_forensics::prelude::*;
use phalanx_proto::prelude::*;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::AudioShard;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::time::CausalitySession;
use phalanx_proto::trust::Offense;
use phalanx_proto::trust::TrustRegistry;
use phalanx_proto::types::NodeMode;
use phalanx_proto::VolleyRequest;
use phalanx_transport::NetworkTransport;
use std::collections::VecDeque;
use std::error::Error;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};

pub struct MeshSentinel<T: NetworkTransport, J: TransientJournal> {
    pub trust_registry: TrustRegistry,
    pub reputation_cache: Arc<SyncReputationCache>,
    pub health_tracker: HealthTracker,
    pub governor: TrafficGovernor,
    pub mode: NodeMode,
    pub config: NodeConfig,
    pub identity: Arc<PhalanxIdentity>,
    pub clock: dyn TrustedClock,
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
    pub async fn new(
        config: NodeConfig,
        identity: PhalanxIdentity,
        network: T,
        mut journal: J,
        trust_registry: TrustRegistry,
        reputation_cache: Arc<SyncReputationCache>,
        discovery_rx: mpsc::Receiver<(VolleyId, StorageSequence)>,
        discovery_tx: mpsc::Sender<(VolleyId, StorageSequence)>,
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
            discovery_rx,
            discovery_tx,
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
                Some((volley_id, gap_sequence)) = self.discovery_rx.recv() => {
                    tracing::info!("Mesh heal triggered for sequence {:?}", gap_sequence);
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
impl<T: NetworkTransport> MeshSentinel<T, NoOpJournal> {
    pub async fn new_at_path(path: &str, network: T) -> Result<Self, Box<dyn Error>> {
        let mut config = PhalanxConfig::default();
        config.storage.vault_path = path.to_string();
        let identity =
            init_identity(std::path::Path::new(path).join("identity.pem")).unwrap_or_default();
        let trust_registry = TrustRegistry::build(&config).await;
        let (discovery_tx, discovery_rx) = mpsc::channel(100);
        Self::new(
            config,
            identity,
            network,
            NoOpJournal,
            trust_registry,
            Arc::new(SyncReputationCache::default()),
            discovery_rx,
            discovery_tx,
        )
        .await
    }
}
