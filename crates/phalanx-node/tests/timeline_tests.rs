#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_proto::evidence::{
    DataPayload, EnvelopeState, Evidence, ForensicMetrics, StorageSequence, VideoShard,
    WitnessEnvelope,
};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId, WitnessId};
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::{SystemClock, TrustedClock};
use phalanx_proto::types::Fps;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tracing::info;

#[tokio::test]
async fn test_reliability_timeline_integrity() {
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let config = NodeConfig::default();

    let mut guardian = Guardian::new(
        &vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
        identity.dek_master.clone(),
    );
    let recording_id = RecordingId::new("v_timeline");

    // 1. ANCHOR: Establish the legitimate start of the timeline
    let anchor_shard = VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(b"Anchor Frame".to_vec()),
        lens_metrics: ForensicMetrics::default(),
    };
    let anchor_envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(anchor_shard),
        &identity,
        WitnessId::random(),
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
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(2),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(b"Valid Frame".to_vec()),
        lens_metrics: ForensicMetrics::default(),
    };
    let valid_envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(valid_shard),
        &identity,
        WitnessId::random(),
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
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(3),
        fps: Fps::new(30),
        recording_id: recording_id.clone(),
        payload: DataPayload::Clear(b"Hijacked Frame".to_vec()),
        lens_metrics: ForensicMetrics::default(),
    };
    // Intentionally forge the causality chain by pointing to anchor_hash instead of valid_envelope's hash
    let hijacked_envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(bogus_shard),
        &identity,
        WitnessId::random(),
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
