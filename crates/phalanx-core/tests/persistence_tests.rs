use phalanx_core::primitives::identity::PhalanxIdentity;
use phalanx_core::primitives::shards::{
    DataPayload, Evidence, StorageSequence, VideoShard, VolleyId, WitnessEnvelope,
};
use phalanx_core::primitives::time::PhalanxTimestamp;
use phalanx_core::security::retrieval::RetrievalOrchestrator;

use tracing::info;

#[tokio::test]
async fn test_forensic_gate_tamper_detection_v3() {
    // 1. Setup Identities & PeerId
    let (witness_identity, _) = PhalanxIdentity::generate().unwrap();
    let witness_peer_id = witness_identity.to_network_id();
    let orchestrator = RetrievalOrchestrator::new();
    let vid = VolleyId::new("test_stream_01");

    // 2. Properly initialize a valid VideoShard
    let original_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(100),
        fps: 30,
        volley_id: vid,
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    };

    let original_evidence = Evidence::Video(original_shard);

    // FIX: 4-argument constructor with 'None' for the causality anchor (start of chain)
    let mut envelope = WitnessEnvelope::new(
        original_evidence,
        &witness_identity,
        witness_peer_id.clone(),
        None,
    )
    .expect("Failed to initialize valid WitnessEnvelope");

    // 3. BASELINE: Verify returns Result<(), ShardError>
    assert!(
        envelope.verify(),
        "Self-verification failed on clean data: {:?}",
        envelope.verify()
    );

    // 4. TAMPER: Modify the evidence bytes
    match &mut envelope.evidence {
        Evidence::Video(shard) => {
            if let DataPayload::Clear(ref mut bytes) = shard.payload {
                bytes.push(0xFF); // Injected corruption
            } else {
                panic!("Expected Clear payload for tampering test");
            }
        }
        _ => panic!("Expected Video evidence"),
    }

    // 5. THE TEST: verify() re-serializes and compares against the stored signature
    let verification_result = envelope.verify();

    // 6. ASSERTION: Must fail with a verification/signature error
    assert!(
        !verification_result,
        "INTEGRITY BREACH: WitnessEnvelope::verify() accepted modified evidence!"
    );

    // 7. ORCHESTRATOR TEST: High-level gate check
    // verify_mesh_egress ensures the high-level ForensicGate catches the breach
    let result = orchestrator
        .verify_mesh_egress(vec![envelope], &witness_peer_id)
        .await;

    assert!(
        result.is_err(),
        "Orchestrator allowed tampered data to pass egress."
    );

    info!("Forensic Gate: Successfully caught and blocked evidence tampering.");
}
