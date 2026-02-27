use phalanx_core::base::config::PhalanxConfig;
use phalanx_core::primitives::identity::{NetworkId, PhalanxIdentity};
use phalanx_core::primitives::shards::{
    create_video_shard, EnvelopeState, Evidence, HandoverProof, StorageSequence, Volley, VolleyId,
    WitnessEnvelope,
};
use phalanx_core::storage::vault::Guardian;

#[tokio::test]
async fn test_legal_identity_handover() {
    let _ = phalanx_core::security::telemetry::init_observability();

    let temp_dir = tempfile::tempdir().unwrap();
    let config = PhalanxConfig::test_defaults();

    // 1. Setup Identities (The Relay and the Target)
    let (identity_a, _) = PhalanxIdentity::generate().expect("Failed to generate Old DID");
    let (identity_b, _) = PhalanxIdentity::generate().expect("Failed to generate New DID");

    let peer_id = NetworkId::random();
    let vid = VolleyId::new("handover_stream_01");

    // Initialize Guardian (Vault) under Identity A's ownership
    let mut guardian = Guardian::new(
        temp_dir.path().to_string_lossy().as_ref(),
        &config,
        identity_a.did.clone(),
    );

    // ----------------------------------------------------------------------
    // PHASE 1: Identity A owns the stream
    // ----------------------------------------------------------------------
    let shard_1 =
        create_video_shard(vec![vec![0x01]], StorageSequence(1), 30, vid.clone()).unwrap();
    let env_1 =
        WitnessEnvelope::new(Evidence::Video(shard_1), &identity_a, peer_id.clone(), None).unwrap();

    // We must capture the hash to anchor the next unit
    let hash_1 = env_1.signature_hash();

    // ----------------------------------------------------------------------
    // PHASE 2: The Cryptographic Handover (The Bridge)
    // ----------------------------------------------------------------------
    // TARGET API: HandoverProof::generate(...) requires both keys to sign a common payload
    let handover_proof = HandoverProof::generate(
        &identity_a,
        &identity_b,
        vid.clone(),
        StorageSequence(2),
        hash_1, // Anchored to Identity A's last frame
    )
    .expect("Failed to generate dual-signed HandoverProof");

    // Identity A seals the handover as their final act in this timeline
    let env_2 = WitnessEnvelope::new(
        Evidence::Handover(handover_proof),
        &identity_a,
        peer_id.clone(),
        Some(hash_1),
    )
    .unwrap();

    let hash_2 = env_2.signature_hash();

    // ----------------------------------------------------------------------
    // PHASE 3: Identity B takes over seamlessly
    // ----------------------------------------------------------------------
    let shard_3 =
        create_video_shard(vec![vec![0x03]], StorageSequence(3), 30, vid.clone()).unwrap();

    // Identity B seals the next unit, anchoring it to the Handover envelope!
    let env_3 = WitnessEnvelope::new(
        Evidence::Video(shard_3),
        &identity_b,
        peer_id.clone(),
        Some(hash_2),
    )
    .unwrap();

    // ----------------------------------------------------------------------
    // VERIFICATION
    // ----------------------------------------------------------------------
    // The Guardian should ingest all three without throwing a Causality Breach
    assert!(guardian
        .ingest_envelope(EnvelopeState::Intact(env_1))
        .await
        .is_ok());
    assert!(guardian
        .ingest_envelope(EnvelopeState::Intact(env_2))
        .await
        .is_ok());
    assert!(guardian
        .ingest_envelope(EnvelopeState::Intact(env_3))
        .await
        .is_ok());

    // Force salvage to verify the Volley state
    guardian.salvage().await.expect("Salvage failed");

    // Read the file to ensure the ownership successfully transferred
    let expected_path = temp_dir
        .path()
        .join(identity_b.did.to_safe_name()) // It should now live in Identity B's folder!
        .join("handover_stream_01.volley");

    assert!(
        expected_path.exists(),
        "Volley was not saved under the new Identity's storage silo"
    );

    let saved_bytes = std::fs::read(&expected_path).unwrap();
    let saved_volley: Volley = postcard::from_bytes(&saved_bytes).unwrap();

    assert_eq!(
        saved_volley.artifacts.len(),
        3,
        "Volley should contain all 3 envelopes"
    );
    assert_eq!(
        saved_volley.owner_did, identity_b.did,
        "Volley ownership did not transfer to Identity B"
    );
}

#[tokio::test]
async fn test_illegal_identity_swap_rejected() {
    let (identity_a, _) = PhalanxIdentity::generate().unwrap();
    let (identity_b, _) = PhalanxIdentity::generate().unwrap();
    let peer_id = NetworkId::random();
    let vid = VolleyId::new("illegal_stream");

    let config = PhalanxConfig::test_defaults();
    let mut guardian = Guardian::new("sim_vault/illegal_test", &config, identity_a.did.clone());

    // Identity A creates frame 1
    let shard_1 =
        create_video_shard(vec![vec![0x01]], StorageSequence(1), 30, vid.clone()).unwrap();
    let env_1 =
        WitnessEnvelope::new(Evidence::Video(shard_1), &identity_a, peer_id.clone(), None).unwrap();
    let hash_1 = env_1.signature_hash();

    // Identity B tries to hijack the stream WITHOUT a HandoverProof
    let shard_2 =
        create_video_shard(vec![vec![0x02]], StorageSequence(2), 30, vid.clone()).unwrap();

    // B anchors to A's hash, but signs with B's key
    let env_2 = WitnessEnvelope::new(
        Evidence::Video(shard_2),
        &identity_b,
        peer_id.clone(),
        Some(hash_1),
    )
    .unwrap();

    guardian
        .ingest_envelope(EnvelopeState::Intact(env_1))
        .await
        .unwrap();

    // This should fail silently or return an error depending on your Guardian pipeline,
    // but the Crucible should DEFINITELY drop it.
    guardian
        .ingest_envelope(EnvelopeState::Intact(env_2))
        .await
        .unwrap();

    // Verify the Crucible refused to append env_2
    let active_session = guardian.get_active_volley_shards(&vid).unwrap();
    assert_eq!(
        active_session.len(),
        1,
        "Crucible accepted an illegal identity swap! Causality Breach failed to trigger."
    );
}
