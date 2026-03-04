use phalanx_forensics::witness::WitnessAuthority;
use phalanx_node::actors::retrieval::RetrievalOrchestrator;
use phalanx_proto::evidence::Evidence;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::VideoShard;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::prelude::*;
use tracing::info;

#[tokio::test]
async fn test_forensic_gate_tamper_detection_v3() {
    // 1. Setup Identities & PeerId
    let witness_identity = PhalanxIdentity::new_ephemeral();
    let witness_peer_id = witness_identity.network_id.clone();
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

    let mut envelope = WitnessEnvelope::sign_envelope(
        original_evidence,
        &witness_identity,
        witness_peer_id.clone(),
        None,
    )
    .expect("Failed to initialize valid WitnessEnvelope");

    // 3. BASELINE: verify_envelope returns bool
    assert!(
        envelope.verify_envelope(),
        "Self-verification failed on clean data"
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

    // 5. THE TEST: verify_envelope re-serializes and compares against the stored signature
    assert!(
        !envelope.verify_envelope(),
        "INTEGRITY BREACH: verify_envelope() accepted modified evidence!"
    );

    // 6. ORCHESTRATOR TEST: High-level gate check
    // verify_mesh_egress calls check_integrity internally, which also verifies the signature
    let result = orchestrator
        .verify_mesh_egress(vec![envelope], &witness_peer_id)
        .await;

    assert!(
        result.is_err(),
        "Orchestrator allowed tampered data to pass egress."
    );

    info!("Forensic Gate: Successfully caught and blocked evidence tampering.");
}
