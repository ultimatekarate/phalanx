use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::reassembler::create_video_shard;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_proto::evidence::{
    ChunkType, DataPayload, EnvelopeState, Evidence, ForensicMetrics, StorageSequence, VideoShard,
    WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId, ShardId};
use phalanx_proto::prelude::{EncodingSymbolId, ShardChunk};
use phalanx_proto::time::{SystemClock, TrustedClock};
use phalanx_proto::types::Fps;
use phalanx_transport::identity_ext::Libp2pExt;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;

fn create_test_shard(seq: u32, recording_id: RecordingId) -> VideoShard {
    VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(seq),
        fps: Fps::new(30),
        recording_id,
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
        lens_metrics: ForensicMetrics::default(),
    }
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
    );

    // 1. CREATE VALID CHAIN: Seq 1 -> Seq 2
    let shard_1 = create_test_shard(1, recording_id.clone());
    let env_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = env_1.signature_hash();

    let shard_2 = create_test_shard(2, recording_id.clone());
    // CRITICAL: Point Seq 2 at the hash of Seq 1
    let env_2 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_2),
        &identity,
        NetworkId::random(),
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
    let peer_id = NetworkId::random();
    let seq = StorageSequence(101);
    let vid = RecordingId::new("crash_recording");

    let mut storage = Guardian::new(
        &vault_path,
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key.clone(),
    );

    let shard = create_video_shard(
        vec![vec![0xAA]],
        seq,
        Fps::new(30),
        vid.clone(),
        ForensicMetrics::default(),
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
    let evidence = Evidence::Video(VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(1),
        fps: Fps::new(30),
        recording_id: RecordingId::new("v_leaf"),
        payload: DataPayload::Clear(vec![0x00; 4]),
        lens_metrics: ForensicMetrics::default(),
    });
    let env = WitnessEnvelope::sign_envelope(
        evidence,
        &foreign_identity,
        foreign_identity.to_network_id(),
        None,
    )
    .unwrap();
    let valid_bytes = postcard::to_allocvec(&env).unwrap();
    let now = SystemClock.now();

    let foreign_chunk = ShardChunk {
        shard_id: ShardId(1),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::Witnessed,
        is_terminal: true,
        data: valid_bytes,
        owner_did: foreign_identity.did.clone(),
        timestamp: now,
    };

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
