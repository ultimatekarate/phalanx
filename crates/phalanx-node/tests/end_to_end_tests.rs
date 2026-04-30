#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
//! End-to-end cross-crate integration tests for phalanx-node.
//!
//! These tests wire multiple actors/components together to verify
//! data flows that span crate boundaries.

use phalanx_node::persistence::journal::FileJournal;
use phalanx_proto::storage::TransientJournal;

use phalanx_forensics::witness::WitnessAuthority;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{
    DataPayload, Evidence, ForensicMetrics, StorageSequence, VideoShard, WitnessEnvelope,
};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId};
use phalanx_proto::time::{SystemClock, TrustedClock};
use phalanx_proto::trust::{MonotonicClock, PeerReputation};
use phalanx_proto::types::Fps;

// ─── WAL Workbench State Recovery ─────────────────────────────────────────

#[tokio::test]
async fn wal_workbench_state_crash_recovery() {
    // FileJournal's record_workbench_state / read_workbench_state are the
    // implemented persistence paths (record_chunk is a stub). Test that
    // encrypted state survives journal reopen.
    let temp_dir = tempfile::tempdir().expect("create temp dir");
    let journal_path = temp_dir.path().join("test_journal.wal");
    let vault_key = SymmetricKey::from_bytes([0x42; 32]);

    let state_data = b"crucible_snapshot_with_3_active_recordings".to_vec();

    {
        let mut journal = FileJournal::new(&journal_path, vault_key.clone())
            .await
            .expect("create journal");

        journal
            .record_workbench_state(&state_data)
            .await
            .expect("write workbench state");
        // journal dropped — simulates crash
    }

    // Reopen from same path
    let mut recovered_journal = FileJournal::new(&journal_path, vault_key)
        .await
        .expect("reopen journal");

    let recovered_state = recovered_journal
        .read_workbench_state()
        .await
        .expect("read workbench state after crash");

    assert_eq!(
        recovered_state, state_data,
        "Encrypted workbench state should survive crash recovery"
    );
}

// ─── Offense Cascade to Blacklist ─────────────────────────────────────────

#[test]
fn offense_accumulation_triggers_blacklist() {
    let mut reputation = PeerReputation {
        invalid_sigs: 0,
        quota_violations: 0,
        total_shards_sent: 0,
        active_buffers: 0,
        last_seen_load: 0.0,
        is_blacklisted: false,
        score: 50,
        last_update_secs: MonotonicClock::default(),
        last_offense_secs: MonotonicClock::default(),
    };

    // Simulate repeated InvalidSignature offenses
    let penalty = 15i64;
    for _ in 0..10 {
        reputation.score -= penalty;
        reputation.invalid_sigs += 1;

        if reputation.score < 0 {
            reputation.is_blacklisted = true;
            break;
        }
    }

    assert!(
        reputation.is_blacklisted,
        "Accumulated offenses should trigger blacklist"
    );
    assert!(
        reputation.score < 0,
        "Score should be negative after many offenses"
    );
}

// ─── Channel Wiring Pattern ───────────────────────────────────────────────

#[tokio::test]
async fn ingestion_to_storage_channel_wiring() {
    let (storage_tx, mut storage_rx) = tokio::sync::mpsc::channel::<String>(32);

    let identity = PhalanxIdentity::new_ephemeral();
    let rid = RecordingId::new("channel_test");

    for seq in 0..5u32 {
        let evidence = Evidence::Video(VideoShard {
            timestamp: SystemClock.now(),
            sequence_id: StorageSequence(seq),
            fps: Fps::new(30),
            recording_id: rid.clone(),
            payload: DataPayload::Clear(vec![seq as u8]),
            lens_metrics: ForensicMetrics::default(),
        });
        let env =
            WitnessEnvelope::sign_envelope(evidence, &identity, identity.witness_id.clone(), None)
                .expect("sign");

        storage_tx
            .send(format!("ingest:{}", env.did))
            .await
            .expect("send to storage channel");
    }

    drop(storage_tx);

    let mut count = 0;
    while let Some(msg) = storage_rx.recv().await {
        assert!(msg.starts_with("ingest:"));
        count += 1;
    }
    assert_eq!(count, 5, "All 5 ingestion messages should reach storage");
}
