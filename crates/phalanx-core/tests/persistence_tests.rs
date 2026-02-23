use phalanx_core::primitives::identity::PhalanxIdentity;
use phalanx_core::primitives::shards::{DataPayload, Evidence, VideoShard, WitnessEnvelope};
use phalanx_core::security::retrieval::RetrievalOrchestrator;

#[tokio::test]
async fn test_forensic_gate_tamper_detection_v2() {
    // 1. Setup Identities & PeerId
    let (witness_identity, _) = PhalanxIdentity::generate().unwrap();
    let witness_peer_id = witness_identity.to_network_id();
    let orchestrator = RetrievalOrchestrator::new();

    // 2. Properly initialize the envelope using YOUR constructor
    // We use mock video data as the 'Evidence'
    let original_evidence = Evidence::Video(VideoShard::default());

    let mut envelope = WitnessEnvelope::new(
        original_evidence,
        &witness_identity,
        witness_peer_id.clone(),
    )
    .expect("Failed to initialize valid WitnessEnvelope");

    // 3. BASELINE: Ensure valid data passes the primitive's own check
    assert!(envelope.verify(), "Self-verification failed on clean data");

    // 4. TAMPER: Modify the evidence directly
    // If Evidence is an enum, we swap it or modify internal fields.
    // This changes the bytes that WOULD be produced by postcard serialization.
    match &mut envelope.evidence {
        Evidence::Video(shard) => {
            if let DataPayload::Clear(ref mut bytes) = shard.payload {
                bytes.push(0xFF); // Successfully injected "malicious" byte
            } else {
                panic!("Expected Clear payload for tampering test");
            } // Inject a "malicious" byte
        }
        _ => panic!("Expected Video evidence"),
    }

    // 5. THE TEST: Does .verify() catch that the evidence no longer matches the signature?
    // Your code re-serializes evidence in the .verify() call.
    let is_valid = envelope.verify();

    // 6. ASSERTION: This must be FALSE now.
    assert!(
        !is_valid,
        "INTEGRITY BREACH: WitnessEnvelope::verify() accepted modified evidence!"
    );

    // 7. ORCHESTRATOR TEST: Ensure the high-level gate also fails
    let result = orchestrator
        .verify_mesh_egress(vec![envelope], &witness_peer_id)
        .await;

    assert!(
        result.is_err(),
        "Orchestrator allowed tampered data to pass egress."
    );

    println!("Forensic Gate: Successfully caught evidence tampering.");
}
