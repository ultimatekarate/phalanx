use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, read_encrypted_file, Guardian};
use phalanx_node::vitals::init_observability;
use phalanx_proto::evidence::{
    EnvelopeState, Evidence, ForensicMetrics, Recording, StorageSequence, WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId};
use phalanx_proto::prelude::GuardianError;
use phalanx_proto::storage::HandoverProof;
use phalanx_proto::time::{PhalanxTimestamp, SystemClock, TrustedClock};
use std::sync::Arc;
use std::time::Duration;
use tracing::info;
// Extension traits needed for method resolution
use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::reassembler::create_video_shard;
use phalanx_forensics::storage::handover::HandoverAuthority;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_proto::types::Fps;

#[tokio::test]
async fn test_legal_identity_handover() {
    init_observability();

    let temp_dir = tempfile::tempdir().unwrap();
    let config = NodeConfig::test_defaults();

    // Setup Identities (The Relay and the Target)
    let (identity_a, _) = PhalanxIdentity::generate().expect("Failed to generate Old DID");
    let (identity_b, _) = PhalanxIdentity::generate().expect("Failed to generate New DID");

    let peer_id = NetworkId::random();
    let vid = RecordingId::new("handover_stream_01");

    // Initialize Guardian (Vault) under Identity A's ownership
    let vault_key = derive_vault_key(&identity_a, &[0u8; 32]);
    let mut guardian = Guardian::new(
        temp_dir.path().to_string_lossy().as_ref(),
        &config,
        identity_a.did.clone(),
        Arc::new(SystemClock),
        vault_key.clone(),
    );

    // PHASE 1: Identity A owns the stream
    let shard_1 = create_video_shard(
        vec![vec![0x01]],
        StorageSequence(1),
        Fps::new(30),
        vid.clone(),
        ForensicMetrics::default(),
        SystemClock.now(),
    )
    .unwrap();
    let env_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity_a,
        peer_id.clone(),
        None,
    )
    .unwrap();
    let hash_1 = env_1.signature_hash();

    // PHASE 2: The Cryptographic Handover (The Bridge)
    let handover_proof = HandoverProof::generate(
        &identity_a,
        &identity_b,
        vid.clone(),
        StorageSequence(2),
        hash_1,
    )
    .expect("Failed to generate dual-signed HandoverProof");

    let env_2 = WitnessEnvelope::sign_envelope(
        Evidence::Handover(handover_proof),
        &identity_a,
        peer_id.clone(),
        Some(hash_1),
    )
    .unwrap();
    let hash_2 = env_2.signature_hash();

    // PHASE 3: Identity B takes over seamlessly
    let shard_3 = create_video_shard(
        vec![vec![0x03]],
        StorageSequence(3),
        Fps::new(30),
        vid.clone(),
        ForensicMetrics::default(),
        SystemClock.now(),
    )
    .unwrap();
    let env_3 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_3),
        &identity_b,
        peer_id.clone(),
        Some(hash_2),
    )
    .unwrap();

    // VERIFICATION
    assert!(guardian
        .ingest_envelope(EnvelopeState::Intact(env_1), Duration::from_secs(1))
        .await
        .is_ok());
    assert!(guardian
        .ingest_envelope(EnvelopeState::Intact(env_2), Duration::from_secs(1))
        .await
        .is_ok());
    assert!(guardian
        .ingest_envelope(EnvelopeState::Intact(env_3), Duration::from_secs(1))
        .await
        .is_ok());

    guardian.salvage().await.expect("Salvage failed");

    let expected_path = temp_dir
        .path()
        .join(identity_b.did.to_safe_name())
        .join("handover_stream_01.recording");

    assert!(
        expected_path.exists(),
        "Recording was not saved under the new Identity's storage silo"
    );

    let saved_bytes = read_encrypted_file(&expected_path, &vault_key)
        .await
        .unwrap();
    let saved_recording: Recording = postcard::from_bytes(&saved_bytes).unwrap();

    assert_eq!(
        saved_recording.artifacts.len(),
        3,
        "Recording should contain all 3 envelopes"
    );
    assert_eq!(
        saved_recording.owner_did, identity_b.did,
        "Recording ownership did not transfer to Identity B"
    );
}

#[tokio::test]
async fn test_illegal_identity_swap_rejected() {
    init_observability();

    let identity_a = PhalanxIdentity::new_ephemeral();
    let identity_b = PhalanxIdentity::new_ephemeral();
    let peer_id = NetworkId::random();
    let vid = RecordingId::new("illegal_stream");

    let config = NodeConfig::test_defaults();
    let vault_key = derive_vault_key(&identity_a, &[0u8; 32]);
    let mut guardian = Guardian::new(
        "sim_vault/illegal_test",
        &config,
        identity_a.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );

    // -- Frame 1 (Identity A) --
    let shard_1 = create_video_shard(
        vec![vec![0x01]],
        StorageSequence(0),
        Fps::new(30),
        vid.clone(),
        ForensicMetrics::default(),
        SystemClock.now(),
    )
    .unwrap();
    let env_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity_a,
        peer_id.clone(),
        None,
    )
    .unwrap();
    let hash_1 = env_1.signature_hash();

    // -- Frame 2 (Identity B - THE ATTACKER) --
    let shard_2 = create_video_shard(
        vec![vec![0x02]],
        StorageSequence(2),
        Fps::new(30),
        vid.clone(),
        ForensicMetrics::default(),
        SystemClock.now(),
    )
    .unwrap();
    let env_2 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_2),
        &identity_b,
        peer_id.clone(),
        Some(hash_1),
    )
    .unwrap();

    // 1. First frame should succeed and establish ownership
    guardian
        .ingest_envelope(EnvelopeState::Intact(env_1), Duration::from_secs(1))
        .await
        .expect("Genesis frame should be accepted");

    // 2. Second frame should be REJECTED.
    // We remove the .unwrap() and match the specific GuardianError.
    let result = guardian
        .ingest_envelope(EnvelopeState::Intact(env_2), Duration::from_secs(1))
        .await;

    assert!(
        result.is_err(),
        "Guardian should have rejected the unauthorized identity swap"
    );

    if let Err(GuardianError::PolicyViolation(msg)) = result {
        assert!(
            msg.contains("Identity Mismatch"),
            "Error should report Identity Mismatch"
        );
        info!("Forensic success: Guardian blocked identity swap: {}", msg);
    } else {
        panic!("Expected PolicyViolation, got {:?}", result);
    }

    // 3. Verify the state wasn't poisoned
    let active_session = guardian.get_active_recording_shards(&vid).unwrap();
    assert_eq!(
        active_session.len(),
        1,
        "Crucible state should only contain the first valid frame"
    );
}
