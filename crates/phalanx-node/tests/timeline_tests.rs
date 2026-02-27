#[tokio::test]
async fn test_reliability_timeline_integrity() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = PhalanxConfig::default();

    // Test the Guardian directly to assert exact Error enums
    let mut guardian = Guardian::new(&vault_path, &config, identity.did.clone());
    let volley_id = VolleyId::new("v_timeline");

    // 1. ANCHOR: Establish the legitimate start of the timeline (Sequence 1)
    let anchor_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Anchor Frame".to_vec()),
    };
    let anchor_envelope = WitnessEnvelope::new(
        Evidence::Video(anchor_shard),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let anchor_hash = anchor_envelope.signature_hash(); // Get the true hash

    guardian
        .ingest_envelope(EnvelopeState::Intact(anchor_envelope))
        .await
        .expect("Anchor should be accepted");

    let valid_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Hijacked Frame".to_vec()),
    };

    let valid_envelope = WitnessEnvelope::new(
        Evidence::Video(valid_shard),
        &identity,
        NetworkId::random(),
        Some(anchor_hash),
    )
    .unwrap();

    // verify guardian doesn't just reject everything
    guardian
        .ingest_envelope(EnvelopeState::Intact(valid_envelope.clone()))
        .await
        .expect("Guardian should accept a valid cryptographic link");

    // THE ATTACK: Attempt a "Hash Link Collision" on Sequence 2
    let bogus_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(3),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Hijacked Frame".to_vec()),
    };

    // We intentionally forge the causality chain by pointing to a bogus hash instead of anchor_hash
    let hijacked_envelope = WitnessEnvelope::new(
        Evidence::Video(bogus_shard),
        &identity,
        NetworkId::random(),
        Some(anchor_hash),
    )
    .unwrap();

    // 3. VERIFICATION: The Guardian MUST catch the chain break.
    let attack_result = guardian
        .ingest_envelope(EnvelopeState::Intact(hijacked_envelope))
        .await;

    match attack_result {
        // Match the specific variant directly
        Err(GuardianError::ChainIntegrityViolation) => {
            info!("Reliability: Guardian successfully detected and rejected timeline hijack.");
        }
        // Fallback for debugging if the variant is wrapped
        Err(e) if format!("{:?}", e).contains("ChainIntegrity") => {
            info!("Reliability: Guardian rejected via debug match.");
        }
        other => panic!("Expected ChainIntegrityViolation, but got: {:?}", other),
    }
}
