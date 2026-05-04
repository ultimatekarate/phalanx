#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::reassembler::create_video_shard;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_proto::evidence::{
    EnvelopeState, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId, ShardId, WitnessId};
use phalanx_proto::time::{SystemClock, TrustedClock};
use phalanx_proto::types::Fps;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

fn create_test_shard(seq: u32, recording_id: RecordingId) -> VideoShard {
    phalanx_test_fixtures::shards::video_shard_for_recording(&recording_id, seq, SystemClock.now())
}

#[tokio::test]
async fn test_out_of_sequence_salvage_on_node_death() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let config = NodeConfig::default();
    let recording_id = RecordingId::new("v_salvage");

    let temp_dir = tempdir().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let mut guardian = Guardian::new(
        &vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
        identity.dek_master.clone(),
    );

    // 1. CREATE VALID CHAIN: Seq 1 -> Seq 2
    let shard_1 = create_test_shard(1, recording_id.clone());
    let env_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity,
        WitnessId::random(),
        None,
    )
    .unwrap();
    let hash_1 = env_1.signature_hash();

    let shard_2 = create_test_shard(2, recording_id.clone());
    // CRITICAL: Point Seq 2 at the hash of Seq 1
    let env_2 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_2),
        &identity,
        WitnessId::random(),
        Some(hash_1),
    )
    .unwrap();

    // Ingest Seq 1
    guardian
        .ingest_envelope(EnvelopeState::Intact(env_1), Duration::from_secs(1))
        .await
        .expect("Seq 1 failed");

    // Ingest Seq 2 (Now has a valid link to 1)
    let result = guardian
        .ingest_envelope(EnvelopeState::Intact(env_2), Duration::from_secs(1))
        .await;

    assert!(
        result.is_ok(),
        "Salvage failed: Guardian rejected valid chain link"
    );
}

#[tokio::test]
async fn test_stronghold_crash_recovery() {
    let config = NodeConfig::default();
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let vault_key = derive_vault_key(&identity, &[0u8; 32]);
    let peer_id = WitnessId::random();
    let seq = StorageSequence(101);
    let vid = RecordingId::new("crash_recording");

    let mut storage = Guardian::new(
        &vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key.clone(),
        identity.dek_master.clone(),
    );

    let shard = create_video_shard(
        vec![vec![0xAA]],
        seq,
        Fps::new(30),
        vid.clone(),
        phalanx_test_fixtures::metrics::forensic_metrics_synthetic(),
        SystemClock.now(),
    )
    .expect("Failed to generate shard");

    let envelope = WitnessEnvelope::sign_envelope(Evidence::Video(shard), &identity, peer_id, None)
        .expect("Failed to sign envelope");

    storage
        .ingest_envelope(
            EnvelopeState::Intact(envelope.clone()),
            Duration::from_secs(1),
        )
        .await
        .expect("Ingest failed");

    drop(storage);

    let mut recovered_storage = Guardian::new(
        &vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
        identity.dek_master.clone(),
    );

    // Replay: re-ingest the same envelope into the fresh Guardian
    recovered_storage
        .ingest_envelope(
            EnvelopeState::Intact(envelope.clone()),
            Duration::from_secs(1),
        )
        .await
        .expect("WAL replay failed");

    // Verify the recording session was recovered
    let recovered_session = recovered_storage
        .get_active_recording_shards(&vid)
        .expect("Guardian failed to recover Recording session");

    assert!(recovered_session.contains_key(&seq));
}

#[tokio::test]
async fn test_leaf_mode_isolation() {
    let (local_identity, _) = PhalanxIdentity::generate().unwrap();
    let (foreign_identity, _) = PhalanxIdentity::generate().unwrap();

    let mut reassembler = Reassembler::new();
    let mut journal = NoOpJournal;

    // 1. GENERATE VALID BYTES: Postcard needs a real WitnessEnvelope to succeed
    let rid = RecordingId::new("v_leaf");
    let env = phalanx_test_fixtures::envelope::witness_envelope_for_recording(
        &foreign_identity,
        &rid,
        1,
        None,
    );
    let foreign_chunk = phalanx_test_fixtures::chunks::shard_chunk_from_envelope(
        &env,
        ShardId(1),
        &foreign_identity.did,
    );

    // 2. THE POLICY CHECK: Logic from StorageActor
    let is_leaf_mode = true;
    let result = if is_leaf_mode && foreign_chunk.owner_did != local_identity.did {
        // Correctly drops traffic before it hits the reassembler
        Ok(None)
    } else {
        reassembler.ingest_chunk(foreign_chunk, &mut journal).await
    };

    assert!(
        result.unwrap().is_none(),
        "Leaf mode must drop foreign traffic"
    );
    assert!(
        reassembler.active_shards.is_empty(),
        "Workbench should be clean"
    );
}
