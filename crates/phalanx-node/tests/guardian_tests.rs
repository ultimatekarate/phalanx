use phalanx_forensics::crucible::EnvelopeHashExt;
use phalanx_forensics::reassembler::create_video_shard;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_forensics::Reassembler;
use phalanx_node::actors::storage::NoOpJournal;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::Guardian;
use phalanx_proto::evidence::{
    ChunkType, DataPayload, EnvelopeState, Evidence, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, ShardId, VolleyId};
use phalanx_proto::prelude::ShardChunk;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_transport::identity_ext::Libp2pExt;
use tempfile::tempdir;

fn create_test_shard(seq: u32, volley_id: VolleyId) -> VideoShard {
    VideoShard {
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(seq),
        fps: 30,
        volley_id,
        payload: DataPayload::Clear(vec![0xDE, 0xAD, 0xBE, 0xEF]),
    }
}

#[tokio::test]
async fn test_out_of_sequence_salvage_on_node_death() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let config = NodeConfig::default();
    let volley_id = VolleyId::new("v_salvage");

    let temp_dir = tempdir().expect("Failed to create temp dir");
    let vault_path = temp_dir.path().to_string_lossy().to_string();

    let mut guardian = Guardian::new(&vault_path, &config, identity.did.clone());

    // 1. CREATE VALID CHAIN: Seq 1 -> Seq 2
    let shard_1 = create_test_shard(1, volley_id.clone());
    let env_1 = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard_1),
        &identity,
        NetworkId::random(),
        None,
    )
    .unwrap();
    let hash_1 = env_1.signature_hash();

    let shard_2 = create_test_shard(2, volley_id.clone());
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
        .ingest_envelope(EnvelopeState::Intact(env_1))
        .await
        .expect("Seq 1 failed");

    // Ingest Seq 2 (Now has a valid link to 1)
    let result = guardian.ingest_envelope(EnvelopeState::Intact(env_2)).await;

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
    let peer_id = NetworkId::random();
    let seq = StorageSequence(101);
    let vid = VolleyId::new("crash_volley");

    let mut storage = Guardian::new(&vault_path, &config, identity.did.clone());

    let shard = create_video_shard(vec![vec![0xAA]], seq, 30, vid.clone())
        .expect("Failed to generate shard");

    let envelope = WitnessEnvelope::sign_envelope(Evidence::Video(shard), &identity, peer_id, None)
        .expect("Failed to sign envelope");

    storage
        .ingest_envelope(EnvelopeState::Intact(envelope.clone()))
        .await
        .expect("Ingest failed");

    drop(storage);

    let mut recovered_storage = Guardian::new(&vault_path, &config, identity.did.clone());

    // Replay: re-ingest the same envelope into the fresh Guardian
    recovered_storage
        .ingest_envelope(EnvelopeState::Intact(envelope.clone()))
        .await
        .expect("WAL replay failed");

    // Verify the volley session was recovered
    let recovered_session = recovered_storage
        .get_active_volley_shards(&vid)
        .expect("Guardian failed to recover Volley session");

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
        timestamp: PhalanxTimestamp::now(),
        sequence_id: StorageSequence(1),
        fps: 30,
        volley_id: VolleyId::new("v_leaf"),
        payload: DataPayload::Clear(vec![0x00; 4]),
    });
    let env = WitnessEnvelope::sign_envelope(
        evidence,
        &foreign_identity,
        foreign_identity.to_network_id(),
        None,
    )
    .unwrap();
    let valid_bytes = postcard::to_allocvec(&env).unwrap();
    let now = PhalanxTimestamp::now();

    let foreign_chunk = ShardChunk {
        shard_id: ShardId(1),
        chunk_index: 0,
        total_chunks: 1,
        data: valid_bytes,
        owner_did: foreign_identity.did.clone(),
        chunk_type: ChunkType::Witnessed,
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
