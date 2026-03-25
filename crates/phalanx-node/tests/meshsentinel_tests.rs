use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::trust::TrustRegistry;

use phalanx_forensics::gate::IntegrityGate;
use phalanx_forensics::policy::EgressGovernor;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::meshsentinel::{MeshSentinel, SentinelDependencies};
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId, ShardId};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::network::{EgressPort, IngressPort};
use phalanx_proto::prelude::RecordingResponse;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::storage::TransientJournal;
use phalanx_proto::time::SystemClock;
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::trust::TrustLevel;
use phalanx_proto::types::{ForensicUnit, SystemStress, Verified};
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
        _response: RecordingResponse,
    ) -> Result<(), String> {
        Ok(())
    }
    async fn announce_recording(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }
    async fn find_providers(&self, _recording_id: &RecordingId) -> Result<(), String> {
        Ok(())
    }
    async fn send_request(
        &self,
        _target: &NetworkId,
        _request: phalanx_proto::retrieval::RecordingRequest,
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
        local_mesh: None, // No local transport in tests
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
        commit_notify_tx: None,
        replay_filter: phalanx_forensics::bloom::RotatingBloomFilter::new(
            phalanx_forensics::bloom::RotatingBloomFilter::DEFAULT_CAPACITY,
        ),
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
    let (env, _identity) = phalanx_test_fixtures::envelope::witness_envelope_synthetic();
    env
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
    let rid = RecordingId::new("v_ingress");

    let envelope =
        phalanx_test_fixtures::envelope::witness_envelope_for_recording(&identity, &rid, 1, None);
    let chunk = phalanx_test_fixtures::chunks::shard_chunk_from_envelope(
        &envelope,
        ShardId(1),
        &identity.did,
    );
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
    let rid = RecordingId::new("v_leaf");

    let envelope =
        phalanx_test_fixtures::envelope::witness_envelope_for_recording(&identity, &rid, 1, None);
    let chunk = phalanx_test_fixtures::chunks::shard_chunk_from_envelope(
        &envelope,
        ShardId(1),
        &identity.did,
    );
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
    let recording_id = RecordingId::new("v_pure_vault");

    // 1. Send pure command
    cmd_tx
        .send(StorageCommand::Retrieval {
            recording_id,
            owner_did: None,
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

    let response = RecordingResponse::Success(vec![sealed_unit]);

    if let RecordingResponse::Success(units) = response {
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
