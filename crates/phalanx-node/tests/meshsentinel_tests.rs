use phalanx_forensics::gate::IntegrityGate;
use phalanx_forensics::gate::WitnessGate;
use phalanx_forensics::policy::EgressGovernor;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::meshsentinel::{MeshSentinel, SentinelDependencies};
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::Guardian;
use phalanx_node::state::SyncReputationCache;
use phalanx_node::trust::TrustRegistry;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::evidence::{
    ChunkType, DataPayload, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{Did, NetworkId, PhalanxIdentity, ShardId, VolleyId};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{ShardChunk, VolleyResponse};
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::trust::TrustLevel;
use phalanx_proto::types::{ForensicUnit, PowerState, SystemStress, Verified};
use phalanx_transport::NetworkTransport;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;

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
        system_governor: Arc::new(SystemGovernor::new()),
    };

    (
        MeshSentinel::new(deps)
            .await
            .expect("Failed to build test sentinel"),
        temp,
    )
}

fn build_test_actor<J: TransientJournal + Send + 'static>(
    config: NodeConfig,
    identity: PhalanxIdentity,
    journal: J,
    guardian: Guardian,
) -> (
    StorageActor<J>,
    mpsc::Receiver<StorageCommand>,
    mpsc::Sender<StorageCommand>,
) {
    let (storage_tx, storage_rx) = mpsc::channel::<StorageCommand>(10);

    let actor = StorageActor {
        reassembler: Reassembler::new(),
        guardian,
        journal,
        config: config.clone(),
        identity: identity.clone(),
    };

    (actor, storage_rx, storage_tx)
}

async fn setup_mock_storage() -> (
    StorageActor<NoOpJournal>,
    mpsc::Receiver<StorageCommand>,
    mpsc::Sender<StorageCommand>,
    tempfile::TempDir,
) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::test_defaults();
    config.storage.vault_path = temp.path().to_string_lossy().into_owned();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let guardian = Guardian::new(&config.storage.vault_path, &config, identity.did.clone());

    let (actor, cmd_rx, cmd_tx) = build_test_actor(config, identity, NoOpJournal, guardian);

    (actor, cmd_rx, cmd_tx, temp)
}

fn mock_valid_envelope() -> WitnessEnvelope {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let evidence = Evidence::Video(VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("mock"),
        payload: DataPayload::Clear(vec![]),
    });
    evidence
        .seal(&identity, identity.network_id.clone(), None)
        .unwrap()
}

#[tokio::test]
async fn test_handle_network_ingress_enforces_trust_registry() {
    let (_ingress_tx, ingress_rx) = mpsc::channel(10);
    let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

    let (mock_storage_tx, mut mock_storage_rx) = mpsc::channel(10);
    sentinel.storage_tx = mock_storage_tx;

    let topic = MeshTopic::from(sentinel.config.network.video_topic.clone());
    let valid_peer = NetworkId::random();
    let bad_peer = NetworkId::random();
    let valid_did = Did("did:phalanx:trusted".to_string());
    let bad_did = Did("did:phalanx:malicious".to_string());

    // 1. Setup Blacklist in Registry
    let mut record = phalanx_proto::trust::PeerRecord::default();
    record.reputation.score = -100;
    record.reputation.is_blacklisted = true;
    sentinel
        .trust_registry
        .contacts
        .insert(bad_did.clone(), record);

    // --- TEST CASE 1: BLACKLISTED PEER (Returns immediately, no deadlock) ---
    let mut bad_chunk = ShardChunk::default();
    bad_chunk.owner_did = bad_did.clone();
    let bad_data = postcard::to_allocvec(&bad_chunk).expect("Failed to serialize bad chunk");

    sentinel
        .handle_network_ingress(bad_peer.clone(), &bad_data, topic.clone())
        .await;

    assert!(
        sentinel.network.banned.contains(&bad_peer),
        "Malicious peer not banned"
    );
    assert!(
        mock_storage_rx.try_recv().is_err(),
        "Blacklisted chunk reached storage"
    );

    // --- TEST CASE 2: VALID PEER (Requires async response) ---
    let mut valid_chunk = ShardChunk::default();
    valid_chunk.owner_did = valid_did;
    let valid_data = postcard::to_allocvec(&valid_chunk).expect("Failed to serialize valid chunk");

    // We move the sentinel call to a background task so the test thread can respond
    let mut sentinel_task = sentinel;
    let v_peer = valid_peer.clone();
    let v_data = valid_data.clone();
    let v_topic = topic.clone();

    let task_handle = tokio::spawn(async move {
        sentinel_task
            .handle_network_ingress(v_peer, &v_data, v_topic)
            .await;
        sentinel_task // Send it back so we can inspect state
    });

    // 2. ACT AS THE VAULT: Intercept the message and send the 'Ok' reply
    match tokio::time::timeout(Duration::from_millis(500), mock_storage_rx.recv()).await {
        Ok(Some(StorageCommand::Ingest { chunk, reply_to })) => {
            assert_eq!(chunk.owner_did, valid_chunk.owner_did);
            let _ = reply_to.send(Ok(())); // UNBLOCKS THE SENTINEL
        }
        _ => panic!("Sentinel failed to route valid chunk to storage or timed out"),
    }

    // 3. RECLAIM SENTINEL AND VERIFY
    let sentinel = task_handle.await.expect("Sentinel task panicked");

    assert!(
        !sentinel.network.banned.contains(&valid_peer),
        "Valid peer was incorrectly banned"
    );
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
    let envelope = evidence
        .seal(&identity, identity.network_id.clone(), None)
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
}

#[tokio::test]
async fn test_ingress_rejected_in_leaf_mode() {
    let (ingress_tx, ingress_rx) = mpsc::channel(10);
    let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

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
    let envelope = evidence
        .seal(&identity, identity.network_id.clone(), None)
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
            origin: NetworkId::from("foreign-peer"),
            topic,
            data: chunk_bytes,
        })
        .await
        .unwrap();
    ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

    sentinel.run().await.unwrap();
}

#[tokio::test]
async fn test_dispatch_resilient_response_succeeds_without_enqueue() {
    let (_ingress_tx, ingress_rx) = mpsc::channel(10);
    let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;

    assert!(sentinel.pending_egress.is_empty());

    sentinel
        .dispatch_resilient_response("ch_ok".into(), VolleyResponse::NotFound)
        .await;

    assert!(
        sentinel.pending_egress.is_empty(),
        "Successful dispatch should not enqueue into pending_egress"
    );

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

    let (topic, _) = &sentinel.network.published[0];
    assert_eq!(topic.as_str(), "/phalanx/discovery/1.0.0");
}

#[tokio::test]
async fn test_pure_vault_retrieval_contract() {
    let (actor, cmd_rx, cmd_tx, _temp) = setup_mock_storage().await;

    tokio::spawn(async move {
        actor.run(cmd_rx).await;
    });

    let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
    let volley_id = VolleyId::new("v_pure_vault");

    // 1. Send pure command
    cmd_tx
        .send(StorageCommand::Retrieval {
            volley_id,
            reply_to: reply_tx,
        })
        .await
        .unwrap();

    // 2. VERIFICATION: The Vault returns Vec<WitnessEnvelope> (Raw data)
    let raw_envelopes = reply_rx.await.expect("Vault channel dropped");

    // This assertion proves the Vault is not responsible for typestate promotion
    assert!(raw_envelopes.is_empty());
}

#[tokio::test]
async fn test_sentinel_egress_promotion_logic() {
    // --- Setup Smart Guard Context ---
    let (my_id, _) = PhalanxIdentity::generate().unwrap();
    let local_net_id = my_id.network_id;
    let stress = SystemStress::Nominal;
    let trust = TrustLevel::Ally;

    // 1. Mock raw data from Vault
    let raw_env = mock_valid_envelope();

    // 2. Sentinel performs Gate 3: Integrity
    // (Simulated here as we are testing the promotion logic)
    let valid_env = raw_env
        .check_integrity(&local_net_id, PhalanxTimestamp::now(), 1000, None)
        .expect("Integrity check failed");

    // 3. Sentinel performs Gate 4: Policy Promotion
    let unit = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(valid_env);

    //
    let promotion_result = EgressGovernor::authorize(unit, &trust, &stress);

    // 4. VERIFICATION: Result MUST be a Sealed ForensicUnit
    assert!(promotion_result.is_ok());
    let sealed_unit = promotion_result.unwrap();

    // This proves the Sentinel (using the Lab) successfully "Sealed" the data
    // for VolleyResponse::Success
    let response = VolleyResponse::Success(vec![sealed_unit]);

    if let VolleyResponse::Success(units) = response {
        assert_eq!(units.len(), 1);
        // units[0] is of type ForensicUnit<WitnessEnvelope, Sealed>
    } else {
        panic!("Response should have been Success");
    }
}

#[tokio::test]
async fn test_sentinel_blocks_untrusted_egress() {
    let (my_id, _) = PhalanxIdentity::generate().unwrap();
    let local_net_id = my_id.network_id;

    // SOCIAL GATE: Blocked peer
    let trust = TrustLevel::Blocked;
    let stress = SystemStress::Nominal;

    let raw_env = mock_valid_envelope();
    let valid_env = raw_env
        .check_integrity(&local_net_id, PhalanxTimestamp::now(), 1000, None)
        .unwrap();
    let unit = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(valid_env);

    // ACT: Attempt promotion
    let result = EgressGovernor::authorize(unit, &trust, &stress);

    // ASSERT: Policy Gate must catch the untrusted requester
    assert!(result.is_err());
    match result.unwrap_err() {
        GuardianError::VerificationFailed(msg) => {
            assert!(msg.contains("trust clearance"));
        }
        _ => panic!("Expected trust clearance error"),
    }
}
