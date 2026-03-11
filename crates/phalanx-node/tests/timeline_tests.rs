use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_proto::evidence::{
    DataPayload, EnvelopeState, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, VolleyId};
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::{PhalanxTimestamp, SystemClock};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tracing::info;

#[tokio::test]
async fn test_reliability_timeline_integrity() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let vault_key = derive_vault_key(&identity);
    let config = NodeConfig::default();

    let mut guardian = Guardian::new(
        &vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    );
    let volley_id = VolleyId::new("v_timeline");

    // 1. ANCHOR: Establish the legitimate start of the timeline
    let anchor_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Anchor Frame".to_vec()),
    };
    let anchor_envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(anchor_shard),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let anchor_hash = anchor_envelope.signature_hash();

    guardian
        .ingest_envelope(
            EnvelopeState::Intact(anchor_envelope),
            Duration::from_secs(1),
        )
        .await
        .expect("Anchor should be accepted");

    let valid_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(2),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Valid Frame".to_vec()),
    };
    let valid_envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(valid_shard),
        &identity,
        NetworkId::random(),
        Some(anchor_hash),
    )
    .unwrap();

    guardian
        .ingest_envelope(
            EnvelopeState::Intact(valid_envelope.clone()),
            Duration::from_secs(1),
        )
        .await
        .expect("Guardian should accept a valid cryptographic link");

    // THE ATTACK: Attempt a "Hash Link Collision" on Sequence 3
    let bogus_shard = VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(3),
        fps: 30,
        volley_id: volley_id.clone(),
        payload: DataPayload::Clear(b"Hijacked Frame".to_vec()),
    };
    // Intentionally forge the causality chain by pointing to anchor_hash instead of valid_envelope's hash
    let hijacked_envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(bogus_shard),
        &identity,
        NetworkId::random(),
        Some(anchor_hash),
    )
    .unwrap();

    // VERIFICATION: The Guardian MUST catch the chain break
    let attack_result = guardian
        .ingest_envelope(
            EnvelopeState::Intact(hijacked_envelope),
            Duration::from_secs(1),
        )
        .await;

    match attack_result {
        Err(GuardianError::ChainIntegrityViolation(_)) => {
            info!("Reliability: Guardian successfully detected and rejected timeline hijack.");
        }
        Err(e) if format!("{:?}", e).contains("ChainIntegrity") => {
            info!("Reliability: Guardian rejected via debug match.");
        }
        other => panic!("Expected ChainIntegrityViolation, but got: {:?}", other),
    }
}
