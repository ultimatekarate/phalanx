use phalanx_forensics::crucible::EvidenceExt;
use phalanx_forensics::gate::WitnessGate;
use phalanx_forensics::reassembler::create_video_shard;
use phalanx_node::config::NodeConfig;
use phalanx_node::identity::PhalanxNodeIdentityExt;
use phalanx_node::persistence::vault::{derive_vault_key, Guardian};
use phalanx_proto::evidence::{Evidence, ForensicMetrics, StorageSequence, WitnessEnvelope};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity, RecordingId};
use phalanx_proto::time::{PhalanxTimestamp, SystemClock};
use phalanx_proto::types::Fps;
use std::sync::Arc;

/// Helper: create a sealed WitnessEnvelope for a given recording and sequence.
fn make_envelope(
    identity: &PhalanxIdentity,
    recording_id: &RecordingId,
    seq: u32,
    payload: Vec<u8>,
) -> WitnessEnvelope {
    let shard = create_video_shard(
        vec![payload],
        StorageSequence(seq),
        Fps::new(30),
        recording_id.clone(),
        ForensicMetrics::default(),
        PhalanxTimestamp::from_millis(1_700_000_000_000),
    )
    .unwrap();
    Evidence::Video(shard)
        .seal(identity, NetworkId::random(), None)
        .unwrap()
}

/// Helper: set up a Guardian with a temp vault directory.
fn setup_guardian(identity: &PhalanxIdentity, temp: &tempfile::TempDir) -> Guardian {
    let config = NodeConfig::test_defaults();
    let vault_key = derive_vault_key(identity, &[0u8; 32]);
    Guardian::new(
        &temp.path().to_string_lossy(),
        &config,
        identity.did.clone(),
        Arc::new(SystemClock),
        vault_key,
    )
}

// ============================================================================
// T2-1: Recording Log Roundtrip
// ============================================================================

#[tokio::test]
async fn test_recording_log_roundtrip() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut guardian = setup_guardian(&identity, &temp);
    let rid = RecordingId::new("roundtrip_01");

    // Append a shard
    let env = make_envelope(&identity, &rid, 1, vec![0xDE, 0xAD]);
    guardian.append_shard(&env).await.unwrap();

    // Read it back by sequence
    let recovered = guardian
        .read_shard(&rid, StorageSequence(1), None)
        .await
        .unwrap();

    assert_eq!(recovered.evidence.sequence_id(), StorageSequence(1));
    assert_eq!(
        recovered.evidence.recording_id(),
        env.evidence.recording_id()
    );
}

// ============================================================================
// T2-2: Read All Shards (multiple, out-of-order)
// ============================================================================

#[tokio::test]
async fn test_recording_log_read_all() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut guardian = setup_guardian(&identity, &temp);
    let rid = RecordingId::new("readall_01");

    // Append 3 shards out of sequence order
    let env3 = make_envelope(&identity, &rid, 3, vec![0x03]);
    let env1 = make_envelope(&identity, &rid, 1, vec![0x01]);
    let env2 = make_envelope(&identity, &rid, 2, vec![0x02]);

    guardian.append_shard(&env3).await.unwrap();
    guardian.append_shard(&env1).await.unwrap();
    guardian.append_shard(&env2).await.unwrap();

    // Read all — should return sorted by sequence_id
    let all = guardian.read_all_shards(&rid, None).await.unwrap();

    assert_eq!(all.len(), 3);
    assert_eq!(all[0].evidence.sequence_id(), StorageSequence(1));
    assert_eq!(all[1].evidence.sequence_id(), StorageSequence(2));
    assert_eq!(all[2].evidence.sequence_id(), StorageSequence(3));
}

// ============================================================================
// T2-3: Shard Not Found
// ============================================================================

#[tokio::test]
async fn test_recording_log_shard_not_found() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut guardian = setup_guardian(&identity, &temp);
    let rid = RecordingId::new("notfound_01");

    // Append one shard
    let env = make_envelope(&identity, &rid, 1, vec![0xAA]);
    guardian.append_shard(&env).await.unwrap();

    // Attempt to read a nonexistent sequence
    let result = guardian.read_shard(&rid, StorageSequence(99), None).await;
    assert!(result.is_err(), "Should fail for nonexistent sequence");

    // Attempt to read from a nonexistent recording
    let result = guardian
        .read_shard(&RecordingId::new("ghost"), StorageSequence(1), None)
        .await;
    assert!(result.is_err(), "Should fail for nonexistent recording");
}

// ============================================================================
// T2-4: Crash Recovery (rebuild index from file)
// ============================================================================

#[tokio::test]
async fn test_recording_log_crash_recovery() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let rid = RecordingId::new("crash_recovery_01");

    // Phase 1: Write shards with first guardian
    {
        let mut guardian = setup_guardian(&identity, &temp);
        for seq in 1..=5 {
            let env = make_envelope(&identity, &rid, seq, vec![seq as u8; 4]);
            guardian.append_shard(&env).await.unwrap();
        }
        // Guardian drops here — simulates crash
    }

    // Phase 2: New guardian starts fresh, hydrates from disk
    {
        let mut guardian = setup_guardian(&identity, &temp);

        // Before hydration, the recording log map is empty
        assert!(guardian.list_recordings().is_empty());

        // Hydrate from disk
        guardian.hydrate_recording_logs().await.unwrap();

        // Now all recordings should be discoverable
        let recordings = guardian.list_recordings();
        assert_eq!(recordings.len(), 1);
        assert!(recordings.contains(&rid));

        // All 5 shards should be accessible
        let all = guardian.read_all_shards(&rid, None).await.unwrap();
        assert_eq!(all.len(), 5);

        // Each shard should have the correct sequence
        for (i, env) in all.iter().enumerate() {
            assert_eq!(env.evidence.sequence_id(), StorageSequence((i + 1) as u32));
        }

        // O(1) random access should work too
        let shard3 = guardian
            .read_shard(&rid, StorageSequence(3), None)
            .await
            .unwrap();
        assert_eq!(shard3.evidence.sequence_id(), StorageSequence(3));
    }
}

// ============================================================================
// T2-5: List Recordings (multiple recordings)
// ============================================================================

#[tokio::test]
async fn test_list_recordings() {
    let (identity, _) = PhalanxIdentity::generate().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let mut guardian = setup_guardian(&identity, &temp);

    let rid_a = RecordingId::new("stream_alpha");
    let rid_b = RecordingId::new("stream_beta");
    let rid_c = RecordingId::new("stream_gamma");

    // Append one shard to each recording
    guardian
        .append_shard(&make_envelope(&identity, &rid_a, 1, vec![0x0A]))
        .await
        .unwrap();
    guardian
        .append_shard(&make_envelope(&identity, &rid_b, 1, vec![0x0B]))
        .await
        .unwrap();
    guardian
        .append_shard(&make_envelope(&identity, &rid_c, 1, vec![0x0C]))
        .await
        .unwrap();

    let mut recordings = guardian.list_recordings();
    recordings.sort();

    assert_eq!(recordings.len(), 3);
    assert!(recordings.contains(&rid_a));
    assert!(recordings.contains(&rid_b));
    assert!(recordings.contains(&rid_c));
}
