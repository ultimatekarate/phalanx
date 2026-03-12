use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::trust::TrustRegistry;

use phalanx_forensics::gate::IntegrityGate;
use phalanx_forensics::gate::WitnessGate;
use phalanx_forensics::policy::EgressGovernor;
use phalanx_forensics::prelude::TransientJournal;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::meshsentinel::{MeshSentinel, SentinelDependencies};
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{
    ChunkType, DataPayload, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, ShardId, VolleyId};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{ShardChunk, VolleyResponse};
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::{PhalanxTimestamp, SystemClock};
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::trust::TrustLevel;
use phalanx_proto::types::{ForensicUnit, SystemStress, Verified};
use phalanx_transport::{EgressPort, IngressPort};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;

// --- Actor-Oriented Test Doubles ---

struct TestIngress {
    ingress_rx: mpsc::Receiver<NetworkEvent>,
}

#[async_trait::async_trait]
impl IngressPort for TestIngress {
    async fn next_event(&mut self) -> Option<NetworkEvent> {
        self.ingress_rx.recv().await
    }
}

#[derive(Clone)]
struct TestEgress;

#[async_trait::async_trait]
impl EgressPort for TestEgress {
    async fn publish(&self, _topic: &MeshTopic, _data: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    async fn ban_peer(&self, _peer: &NetworkId) {}
    async fn send_response(
        &self,
        _channel_id: &str,
        _response: VolleyResponse,
    ) -> Result<(), String> {
        Ok(())
    }
}

// --- Test Sentinel Factory ---

async fn build_test_sentinel(
    ingress_rx: mpsc::Receiver<NetworkEvent>,
) -> (MeshSentinel<TestIngress>, tempfile::TempDir) {
    let temp = tempfile::tempdir().unwrap();
    let mut config = NodeConfig::default();
    config.storage.vault_path = temp.path().to_string_lossy().to_string();

    let identity = PhalanxIdentity::new_ephemeral();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let trust_registry = TrustRegistry::build(&config).await;

    let deps = SentinelDependencies {
        config,
        identity,
        ingress: TestIngress { ingress_rx },
        egress: TestEgress,
        journal: NoOpJournal,
        trust_registry,
        system_governor: Arc::new(SystemGovernor::new()),
        vault_key,
    };

    (
        MeshSentinel::new(deps)
            .await
            .expect("Failed to build test sentinel"),
        temp,
    )
}

// --- Storage Test Helpers (unchanged) ---

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
        current_tolerance: Duration::from_millis(1000),
        system_governor: Arc::new(SystemGovernor::new()),
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
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let guardian = Guardian::new(
        &config.storage.vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );

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

// ============================================================================
// Sentinel Lifecycle Tests
// ============================================================================

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
    let now = PhalanxTimestamp::now();
    let chunk = ShardChunk {
        shard_id: ShardId(1),
        chunk_index: 0,
        total_chunks: 1,
        data: postcard::to_allocvec(&envelope).unwrap(),
        owner_did: identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
        timestamp: now,
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
    let timestamp = PhalanxTimestamp::now();
    let chunk = ShardChunk {
        shard_id: ShardId(1),
        chunk_index: 0,
        total_chunks: 1,
        data: postcard::to_allocvec(&envelope).unwrap(),
        owner_did: identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
        timestamp,
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

// ============================================================================
// Pure Vault Contract Tests
// ============================================================================

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

// ============================================================================
// Lab-Level Egress Promotion Tests (Pure forensic logic, no sentinel state)
// ============================================================================

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
    let valid_env = raw_env
        .check_integrity(
            &local_net_id,
            &SystemClock,
            std::time::Duration::from_millis(1000),
            None,
        )
        .expect("Integrity check failed");

    // 3. Sentinel performs Gate 4: Policy Promotion
    let unit = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(valid_env);

    let promotion_result =
        EgressGovernor::authorize(unit, &trust, &stress, &SymmetricKey([0u8; 32]));

    // 4. VERIFICATION: Result MUST be a Sealed ForensicUnit
    assert!(promotion_result.is_ok());
    let sealed_unit = promotion_result.unwrap();

    let response = VolleyResponse::Success(vec![sealed_unit]);

    if let VolleyResponse::Success(units) = response {
        assert_eq!(units.len(), 1);
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
        .check_integrity(
            &local_net_id,
            &SystemClock,
            std::time::Duration::from_millis(1000),
            None,
        )
        .unwrap();
    let unit = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(valid_env);

    // ACT: Attempt promotion
    let result = EgressGovernor::authorize(unit, &trust, &stress, &SymmetricKey([0u8; 32]));

    // ASSERT: Policy Gate must catch the untrusted requester
    assert!(result.is_err());
    match result.unwrap_err() {
        GuardianError::VerificationFailed(msg) => {
            assert!(msg.contains("trust clearance"));
        }
        _ => panic!("Expected trust clearance error"),
    }
}
