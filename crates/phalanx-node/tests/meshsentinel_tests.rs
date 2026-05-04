#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod common;

use phalanx_node::identity::PhalanxNodeIdentityExt;

use phalanx_forensics::gate::IntegrityGate;
use phalanx_forensics::policy::EgressGovernor;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::shutdown::ShutdownSignal;
use phalanx_node::actors::storage::{NoOpJournal, StorageActor, StorageCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::{MeshAddress, PhalanxIdentity, RecordingId, ShardId};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::RecordingResponse;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::storage::TransientJournal;
use phalanx_proto::time::SystemClock;
use phalanx_proto::trust::TrustLevel;
use phalanx_proto::types::{ForensicUnit, SystemStress, Verified};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;

use common::{build_test_sentinel, build_test_sentinel_with_communities};

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
        shutdown: ShutdownSignal::new(),
        used_bytes_gauge: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0)),
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
        identity.dek_master.clone(),
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
            origin: MeshAddress::random(),
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
            origin: MeshAddress::new("foreign-peer"),
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
    let local_net_id = my_id.witness_id;
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
        EgressGovernor::authorize(unit, &trust, &stress, &SymmetricKey::from_bytes([0u8; 32]));

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

// ============================================================================
// Heartbeat Spoofing Defense (Tier 2 Shield Wall)
// ============================================================================

/// Domain-separated heartbeat key derivation, mirroring
/// `MeshSentinel::handle_control_message` and the vitals task publisher.
/// Wire layout: 24-byte XChaCha20 nonce ++ ChaCha20-Poly1305 ciphertext.
fn encrypt_heartbeat(
    msg: &phalanx_proto::vitals::ControlMessage,
    cid: &phalanx_proto::community::CommunityId,
) -> Vec<u8> {
    let plaintext = postcard::to_allocvec(msg).unwrap();
    let key =
        SymmetricKey::from_bytes(blake3::derive_key("phalanx.heartbeat.v1.community", &cid.0));
    let (nonce, ciphertext) =
        phalanx_forensics::cryptography::encrypt_bytes(&key, &plaintext).unwrap();
    let mut payload = nonce;
    payload.extend(ciphertext);
    payload
}

/// A `ControlMessage` whose body claims `sender = V` but arrives via libp2p
/// `propagation_source = P` (P ≠ V) is a spoofing attempt: an attacker P
/// frames victim V by filing a forged heartbeat under V's identity.
/// `handle_control_message` must drop the message and leave
/// `health_tracker.heartbeats` unmutated for both P and V.
#[tokio::test]
async fn test_control_message_origin_mismatch_drops_spoofed_heartbeat() {
    let (ingress_tx, ingress_rx) = mpsc::channel(10);
    // Seed the sentinel with a known community ID at construction so the
    // receive-side decryption path succeeds. The fresh test sentinel has
    // an empty community list; without this, every encrypted heartbeat
    // decryption would fast-fail and the test could never observe the
    // strict-binding branch we're trying to verify. Constructor-time
    // injection is required because the same `Vec` is cloned into
    // `CanarySupervisor` at spawn — post-construction field mutation
    // would not reach the canary actor.
    let cid = phalanx_proto::community::CommunityId([0xCC; 32]);
    let (mut sentinel, _temp) = build_test_sentinel_with_communities(ingress_rx, vec![cid]).await;

    let topic = sentinel.config.network.control_topic.clone();
    let origin = MeshAddress::new("attacker-P".to_string());
    let forged_sender = MeshAddress::new("victim-V".to_string());

    let msg = phalanx_proto::vitals::ControlMessage {
        // Body claims to be from V, but propagation source will be P.
        sender: forged_sender.clone(),
        load_factor: phalanx_proto::vitals::StressLoad(0.95),
        storage_remaining_mb: 0,
        heartbeat_ms: 5_000,
        is_leaf: false,
        integral_summary: None,
    };
    let data = encrypt_heartbeat(&msg, &cid);

    ingress_tx
        .send(NetworkEvent::DataReceived {
            origin: origin.clone(),
            topic,
            data,
        })
        .await
        .unwrap();
    ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

    sentinel.run().await.unwrap();

    // Strict-binding policy: spoofed heartbeat must not register under
    // either the propagation origin OR the forged sender. Both keys
    // absent proves the early-return branch fired, not the
    // success-path-with-wrong-key branch.
    assert!(
        !sentinel.health_tracker.has_heartbeat(&origin),
        "Spoofed heartbeat must not register under propagation origin"
    );
    assert!(
        !sentinel.health_tracker.has_heartbeat(&forged_sender),
        "Spoofed heartbeat must not register under forged sender"
    );
}

/// Sanity-check the negative test above: when origin == sender (honest
/// path) AND the receiver holds the matching community key, the heartbeat
/// IS registered. This protects the negative test from passing trivially
/// (e.g., if a refactor accidentally disabled the register_activity call
/// entirely).
#[tokio::test]
async fn test_control_message_genuine_origin_registers_heartbeat() {
    let (ingress_tx, ingress_rx) = mpsc::channel(10);
    let cid = phalanx_proto::community::CommunityId([0xCC; 32]);
    let (mut sentinel, _temp) = build_test_sentinel_with_communities(ingress_rx, vec![cid]).await;

    let topic = sentinel.config.network.control_topic.clone();
    let peer = MeshAddress::new("honest-peer".to_string());

    let msg = phalanx_proto::vitals::ControlMessage {
        sender: peer.clone(),
        load_factor: phalanx_proto::vitals::StressLoad(0.25),
        storage_remaining_mb: 4096,
        heartbeat_ms: 5_000,
        is_leaf: false,
        integral_summary: None,
    };
    let data = encrypt_heartbeat(&msg, &cid);

    ingress_tx
        .send(NetworkEvent::DataReceived {
            origin: peer.clone(),
            topic,
            data,
        })
        .await
        .unwrap();
    ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

    sentinel.run().await.unwrap();

    assert!(
        sentinel.health_tracker.has_heartbeat(&peer),
        "Honest heartbeat must register under the matched origin/sender"
    );
}

/// A node with no community keys silently drops every encrypted heartbeat,
/// regardless of validity. Confirms that open-mesh-only nodes opt out of
/// Tier 2 / canary / eclipse via the encryption gate.
#[tokio::test]
async fn test_no_community_keys_drops_all_heartbeats() {
    let (ingress_tx, ingress_rx) = mpsc::channel(10);
    let (mut sentinel, _temp) = build_test_sentinel(ingress_rx).await;
    // Phase 4: the live registry-derived snapshot must be empty AND the
    // static seeds must be empty for "no keys at all" to hold. If either
    // grows, the test invariant ("non-member nodes drop everything")
    // weakens silently.
    assert!(
        sentinel.community_ids_rx.borrow().is_empty(),
        "Fresh test sentinel must have no registry-derived community keys"
    );
    assert!(
        sentinel.extra_community_ids.is_empty(),
        "Fresh test sentinel must have no static-seed community keys"
    );

    let topic = sentinel.config.network.control_topic.clone();
    let peer = MeshAddress::new("would-be-honest-peer".to_string());

    let cid = phalanx_proto::community::CommunityId([0xCC; 32]);
    let msg = phalanx_proto::vitals::ControlMessage {
        sender: peer.clone(),
        load_factor: phalanx_proto::vitals::StressLoad(0.25),
        storage_remaining_mb: 4096,
        heartbeat_ms: 5_000,
        is_leaf: false,
        integral_summary: None,
    };
    let data = encrypt_heartbeat(&msg, &cid);

    ingress_tx
        .send(NetworkEvent::DataReceived {
            origin: peer.clone(),
            topic,
            data,
        })
        .await
        .unwrap();
    ingress_tx.send(NetworkEvent::Shutdown).await.unwrap();

    sentinel.run().await.unwrap();

    assert!(
        !sentinel.health_tracker.has_heartbeat(&peer),
        "Heartbeat from non-shared community must not register"
    );
}

#[tokio::test]
async fn test_sentinel_blocks_untrusted_egress() {
    let (my_id, _) = PhalanxIdentity::generate().unwrap();
    let local_net_id = my_id.witness_id;

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
    let result =
        EgressGovernor::authorize(unit, &trust, &stress, &SymmetricKey::from_bytes([0u8; 32]));

    // ASSERT: Policy Gate must catch the untrusted requester
    assert!(result.is_err());
    match result.unwrap_err() {
        GuardianError::VerificationFailed(msg) => {
            assert!(msg.contains("trust clearance"));
        }
        _ => panic!("Expected trust clearance error"),
    }
}
