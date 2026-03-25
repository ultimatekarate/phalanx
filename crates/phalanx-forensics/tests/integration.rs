#![allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
//! Integration tests for phalanx-forensics.
//!
//! These tests exercise security-critical verification logic that has zero
//! integration test coverage. Every test models either a realistic happy-path
//! workflow or a realistic adversarial condition.

use std::time::Duration;

use phalanx_forensics::crucible::{Crucible, EnvelopeHashExt, RecordingAmalgam};
use phalanx_forensics::gate::{unmarshal, IntegrityGate, PromotionGate};
use phalanx_forensics::judge::PayloadCipher;
use phalanx_forensics::reassembler::{create_video_shard, FountainChunkifier, Reassembler};
use phalanx_forensics::storage::handover::HandoverAuthority;
use phalanx_forensics::witness::WitnessAuthority;

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{
    DataPayload, Evidence, ForensicMetrics, ShardChunk, StorageSequence, VideoShard,
    WitnessEnvelope,
};
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::prelude::{RecordingId, ShardError, ShardId};
use phalanx_proto::storage::HandoverProof;
use phalanx_proto::time::{PhalanxTimestamp, SystemClock, TrustedClock};
use phalanx_proto::types::{ForensicUnit, Fps, RepairRatio, SymbolSize, Unverified, Verified};

use phalanx_test_fixtures::envelope::{
    verified_unit_for_recording, video_evidence_for_recording, witness_envelope_for_recording,
};

// ─── Helpers ──────────────────────────────────────────────────────────────

fn test_identity() -> PhalanxIdentity {
    PhalanxIdentity::new_ephemeral()
}

// ─── Group A: Crucible with real RecordingAmalgam ─────────────────────────

#[test]
fn amalgam_seals_at_threshold() {
    // Feed 100 signed envelopes for one recording → process() returns Some(Recording)
    let identity = test_identity();
    let rid = RecordingId::new("seal_test");
    let mut crucible = Crucible::new(RecordingAmalgam, Duration::from_secs(1), 1000);

    let mut prev_hash = None;
    let mut sealed = false;
    for seq in 0..100u32 {
        let unit = verified_unit_for_recording(&identity, &rid, seq, prev_hash);
        prev_hash = Some(unit.data.signature_hash());
        match crucible.process(unit) {
            Ok(Some(_recording)) => {
                sealed = true;
                break;
            }
            Ok(None) => {}
            Err(e) => panic!("process() failed at seq {seq}: {e:?}"),
        }
    }
    assert!(
        sealed,
        "Crucible should seal at RECORDING_SIZE_THRESHOLD=100"
    );
}

#[test]
fn amalgam_flush_all_returns_partial() {
    // Feed 5 envelopes (below threshold), flush_all() → assembled Recording
    let identity = test_identity();
    let rid = RecordingId::new("partial_test");
    let mut crucible = Crucible::new(RecordingAmalgam, Duration::from_secs(1), 1000);

    let mut prev_hash = None;
    for seq in 0..5u32 {
        let unit = verified_unit_for_recording(&identity, &rid, seq, prev_hash);
        prev_hash = Some(unit.data.signature_hash());
        let result = crucible.process(unit);
        assert!(
            result.unwrap().is_none(),
            "Should not seal with only {seq} envelopes"
        );
    }

    let recordings = crucible.flush_all();
    assert_eq!(recordings.len(), 1, "Should have one partial recording");
    assert_eq!(recordings[0].artifacts.len(), 5);
}

#[test]
fn amalgam_rejects_sequence_conflict() {
    // Insert envelope at seq 5 with sig A, then different envelope at seq 5 with sig B
    let identity = test_identity();
    let rid = RecordingId::new("conflict_test");
    let mut crucible = Crucible::new(RecordingAmalgam, Duration::from_secs(1), 1000);

    // First envelope at seq 0 to establish the recording
    let unit_0 = verified_unit_for_recording(&identity, &rid, 0, None);
    let hash_0 = unit_0.data.signature_hash();
    crucible.process(unit_0).unwrap();

    // First envelope at seq 5
    let unit_a = verified_unit_for_recording(&identity, &rid, 5, Some(hash_0));
    let hash_a = unit_a.data.signature_hash();
    crucible.process(unit_a).unwrap();

    // Different envelope at seq 5 (different content → different signature)
    let evidence_b = Evidence::Video(VideoShard {
        timestamp: SystemClock.now(),
        sequence_id: StorageSequence(5),
        fps: Fps::new(30),
        recording_id: rid.clone(),
        payload: DataPayload::Clear(vec![0xFF, 0xFF, 0xFF]),
        lens_metrics: phalanx_test_fixtures::metrics::forensic_metrics_synthetic(),
    });
    let env_b = WitnessEnvelope::sign_envelope(
        evidence_b,
        &identity,
        identity.network_id.clone(),
        Some(hash_a),
    )
    .expect("sign should not fail");
    let unit_b = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(env_b);

    let result = crucible.process(unit_b);
    assert!(
        result.is_err(),
        "Should reject conflicting envelope at same seq"
    );
}

#[test]
fn amalgam_handover_transfers_ownership() {
    // Chain from DID-A (seq 0-2), handover A→B, then frames from DID-B (seq 4-6)
    let identity_a = test_identity();
    let identity_b = test_identity();
    let rid = RecordingId::new("handover_test");
    let mut crucible = Crucible::new(RecordingAmalgam, Duration::from_secs(1), 1000);

    // DID-A frames: seq 0, 1, 2
    let mut prev_hash = None;
    for seq in 0..3u32 {
        let unit = verified_unit_for_recording(&identity_a, &rid, seq, prev_hash);
        prev_hash = Some(unit.data.signature_hash());
        crucible.process(unit).unwrap();
    }

    // Handover proof (dual-signed) at seq 3
    let handover_proof = HandoverProof::generate(
        &identity_a,
        &identity_b,
        rid.clone(),
        StorageSequence(3),
        prev_hash.unwrap(),
    )
    .expect("handover generation should not fail");

    let env_handover = WitnessEnvelope::sign_envelope(
        Evidence::Handover(handover_proof),
        &identity_a,
        identity_a.network_id.clone(),
        prev_hash,
    )
    .expect("sign handover should not fail");
    prev_hash = Some(env_handover.signature_hash());
    let unit_handover = ForensicUnit::<WitnessEnvelope, Verified>::new_verified(env_handover);
    crucible.process(unit_handover).unwrap();

    // DID-B frames: seq 4, 5, 6
    for seq in 4..7u32 {
        let unit = verified_unit_for_recording(&identity_b, &rid, seq, prev_hash);
        prev_hash = Some(unit.data.signature_hash());
        let result = crucible.process(unit);
        assert!(
            result.is_ok(),
            "DID-B should be accepted after handover at seq {seq}"
        );
    }

    let recordings = crucible.flush_all();
    assert_eq!(recordings.len(), 1);
    assert_eq!(recordings[0].owner_did, identity_b.did);
}

#[test]
fn amalgam_freeze_thaw_continues_ingestion() {
    let identity = test_identity();
    let rid = RecordingId::new("freeze_test");
    let mut crucible = Crucible::new(RecordingAmalgam, Duration::from_secs(1), 1000);

    // Ingest 3 envelopes
    let mut prev_hash = None;
    for seq in 0..3u32 {
        let unit = verified_unit_for_recording(&identity, &rid, seq, prev_hash);
        prev_hash = Some(unit.data.signature_hash());
        crucible.process(unit).unwrap();
    }

    // Freeze → thaw
    let frozen = crucible.freeze().expect("freeze should not fail");
    let mut restored =
        Crucible::<RecordingAmalgam>::thaw_with_config(&frozen, Duration::from_secs(1), 1000)
            .expect("thaw should not fail");

    // Continue ingestion from seq 3
    for seq in 3..6u32 {
        let unit = verified_unit_for_recording(&identity, &rid, seq, prev_hash);
        prev_hash = Some(unit.data.signature_hash());
        restored.process(unit).unwrap();
    }

    let recordings = restored.flush_all();
    assert_eq!(recordings.len(), 1);
    assert_eq!(recordings[0].artifacts.len(), 6);
}

#[test]
fn amalgam_capacity_exhausted() {
    let identity = test_identity();
    let mut crucible = Crucible::new(RecordingAmalgam, Duration::from_secs(1), 2);

    // Fill 2 recording slots
    let rid_1 = RecordingId::new("cap_1");
    let rid_2 = RecordingId::new("cap_2");
    let unit_1 = verified_unit_for_recording(&identity, &rid_1, 0, None);
    let unit_2 = verified_unit_for_recording(&identity, &rid_2, 0, None);
    crucible.process(unit_1).unwrap();
    crucible.process(unit_2).unwrap();

    // 3rd recording should fail
    let rid_3 = RecordingId::new("cap_3");
    let unit_3 = verified_unit_for_recording(&identity, &rid_3, 0, None);
    let result = crucible.process(unit_3);
    assert!(result.is_err(), "Should reject when capacity exhausted");
}

// ─── Group B: IntegrityGate + PromotionGate ───────────────────────────────

#[test]
fn integrity_gate_accepts_valid_envelope() {
    let identity = test_identity();
    let rid = RecordingId::new("integrity_ok");
    let env = witness_envelope_for_recording(&identity, &rid, 0, None);
    let clock = SystemClock;

    let result = env.check_integrity(&identity.network_id, &clock, Duration::from_secs(30), None);
    assert!(result.is_ok(), "Valid envelope should pass integrity gate");
}

#[test]
fn integrity_gate_rejects_tampered_signature() {
    let identity = test_identity();
    let rid = RecordingId::new("tamper_test");
    let mut env = witness_envelope_for_recording(&identity, &rid, 0, None);

    // Flip one byte in signature
    if let Some(byte) = env.witness_signature.first_mut() {
        *byte ^= 0xFF;
    }

    let clock = SystemClock;
    let result = env.check_integrity(&identity.network_id, &clock, Duration::from_secs(30), None);
    assert!(result.is_err(), "Tampered signature should be rejected");
}

#[test]
fn integrity_gate_rejects_stale_timestamp() {
    let identity = test_identity();
    let rid = RecordingId::new("stale_test");

    // Create evidence with old timestamp (1 hour ago)
    let old_time =
        PhalanxTimestamp::from_millis(SystemClock.now().as_u64().saturating_sub(3_600_000));
    let evidence = video_evidence_for_recording(&rid, 0, old_time);
    let env =
        WitnessEnvelope::sign_envelope(evidence, &identity, identity.network_id.clone(), None)
            .expect("sign should not fail");

    let clock = SystemClock;
    let result = env.check_integrity(
        &identity.network_id,
        &clock,
        Duration::from_secs(30), // 30s tolerance, timestamp is 1h old
        None,
    );
    assert!(result.is_err(), "Stale timestamp should be rejected");
}

#[test]
fn promotion_gate_full_pipeline() {
    let identity = test_identity();
    let rid = RecordingId::new("promote_test");
    let env = witness_envelope_for_recording(&identity, &rid, 0, None);
    let unit = ForensicUnit::<WitnessEnvelope, Unverified>::new(env);

    let clock = SystemClock;
    let result = unit.promote(&identity.network_id, &clock, Duration::from_secs(30), None);
    assert!(result.is_ok(), "Valid unit should promote to Verified");

    let verified = result.unwrap();
    assert_eq!(verified.data.did, identity.did);
}

// ─── Group C: unmarshal trust boundary ────────────────────────────────────

#[test]
fn unmarshal_rejects_oversized_input() {
    // Attack: memory bomb — 65MB buffer
    let oversized = vec![0u8; 65 * 1024 * 1024];
    let result = unmarshal::<ShardChunk>(&oversized, "test_oversized");
    assert!(result.is_err(), "65MB input should be rejected");
}

#[test]
fn unmarshal_garbage_bytes_fails() {
    // Attack: arbitrary data injection
    let garbage: Vec<u8> = (0..120)
        .map(|i| [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE][i % 6])
        .collect();
    let result = unmarshal::<WitnessEnvelope>(&garbage, "test_garbage");
    assert!(result.is_err(), "Random bytes should not deserialize");
}

#[test]
fn unmarshal_truncated_payload_fails() {
    // Attack: network truncation
    let identity = test_identity();
    let rid = RecordingId::new("truncate_test");
    let env = witness_envelope_for_recording(&identity, &rid, 0, None);

    let serialized = postcard::to_allocvec(&env).expect("serialize should not fail");
    let truncated = &serialized[..serialized.len() / 2];

    let result = unmarshal::<WitnessEnvelope>(truncated, "test_truncated");
    assert!(
        result.is_err(),
        "Truncated payload should fail deserialization"
    );
}

#[test]
fn unmarshal_valid_roundtrip() {
    let identity = test_identity();
    let rid = RecordingId::new("roundtrip_test");
    let env = witness_envelope_for_recording(&identity, &rid, 0, None);

    let serialized = postcard::to_allocvec(&env).expect("serialize should not fail");
    let recovered: WitnessEnvelope =
        unmarshal(&serialized, "test_roundtrip").expect("unmarshal should succeed");

    assert_eq!(recovered.did, env.did);
    assert_eq!(recovered.witness_signature, env.witness_signature);
    assert_eq!(recovered.evidence_hash, env.evidence_hash);
}

// ─── Group D: Adversarial state injection ─────────────────────────────────

#[test]
fn zero_length_signature_rejected() {
    let identity = test_identity();
    let rid = RecordingId::new("empty_sig_test");
    let mut env = witness_envelope_for_recording(&identity, &rid, 0, None);

    // Zero out the signature
    env.witness_signature = vec![];

    let clock = SystemClock;
    let result = env.check_integrity(&identity.network_id, &clock, Duration::from_secs(30), None);
    assert!(
        result.is_err(),
        "Empty signature should be rejected by integrity gate"
    );
}

#[test]
fn max_sequence_id_no_overflow() {
    let identity = test_identity();
    let rid = RecordingId::new("overflow_test");
    let mut crucible = Crucible::new(RecordingAmalgam, Duration::from_secs(1), 1000);

    let unit = verified_unit_for_recording(&identity, &rid, u32::MAX, None);
    let result = crucible.process(unit);
    // Should not panic — either Ok or Err is acceptable, just no panic
    let _ = result;
}

// ─── Group E: Reassembler integration path ────────────────────────────────

struct MockJournal;

#[async_trait::async_trait]
impl phalanx_proto::storage::TransientJournal for MockJournal {
    async fn record_chunk(&mut self, _chunk: &ShardChunk) -> Result<(), ShardError> {
        Ok(())
    }
    async fn sync(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_chunks(&mut self) -> Result<Vec<ShardChunk>, ShardError> {
        Ok(vec![])
    }
    async fn clear(&mut self) -> Result<(), ShardError> {
        Ok(())
    }
    async fn record_pending_egress(
        &mut self,
        _pending: &[phalanx_proto::storage::PendingEgress],
    ) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_all_pending_egress(
        &mut self,
    ) -> Result<Vec<phalanx_proto::storage::PendingEgress>, ShardError> {
        Ok(vec![])
    }
    async fn record_workbench_state(&mut self, _: &[u8]) -> Result<(), ShardError> {
        Ok(())
    }
    async fn read_workbench_state(&mut self) -> Result<Vec<u8>, ShardError> {
        Ok(vec![])
    }
}

#[tokio::test]
async fn reassembler_ingest_chunk_assembles_envelope() {
    let identity = test_identity();
    let rid = RecordingId::new("reassemble_test");
    let env = witness_envelope_for_recording(&identity, &rid, 0, None);

    // Serialize the envelope, then fountain-encode it
    let serialized = postcard::to_allocvec(&env).expect("serialize");
    let shard_id = ShardId(42);
    let chunks = serialized
        .fountain_chunkify(
            shard_id,
            identity.did.clone(),
            SymbolSize(256),
            phalanx_proto::evidence::ChunkType::Witnessed,
            RepairRatio::default(),
            PhalanxTimestamp::from_millis(1_700_000_000_000),
        )
        .expect("fountain chunkify should not fail");

    assert!(!chunks.is_empty(), "Should produce at least one chunk");

    // Feed all chunks through the Reassembler
    let mut reassembler = Reassembler::new();
    let mut journal = MockJournal;
    let mut assembled = None;

    for chunk in chunks {
        match reassembler.ingest_chunk(chunk, &mut journal).await {
            Ok(Some(envelope_state)) => {
                assembled = Some(envelope_state);
                break;
            }
            Ok(None) => {}
            Err(e) => panic!("ingest_chunk failed: {e:?}"),
        }
    }

    assert!(
        assembled.is_some(),
        "Reassembler should assemble envelope from fountain chunks"
    );
}

#[tokio::test]
async fn reassembler_per_peer_quota_enforcement() {
    let identity = test_identity();
    let mut reassembler = Reassembler::new();
    let mut journal = MockJournal;

    // Open MAX_CONTEXTS_PER_PEER + 1 distinct shard IDs for the same peer.
    // Each shard gets one real fountain-encoded chunk (won't complete, just opens a context).
    let max_contexts = 50; // MAX_CONTEXTS_PER_PEER

    for i in 0..=max_contexts {
        // Create a unique envelope per shard with large payload so fountain encoding
        // produces multiple chunks (single chunk would complete immediately, clearing the context)
        let rid = RecordingId::new(&format!("quota_test_{i}"));
        let large_evidence = Evidence::Video(VideoShard {
            timestamp: SystemClock.now(),
            sequence_id: StorageSequence(0),
            fps: Fps::new(30),
            recording_id: rid,
            payload: DataPayload::Clear(vec![0xAB; 4096]), // Large payload → many chunks
            lens_metrics: phalanx_test_fixtures::metrics::forensic_metrics_synthetic(),
        });
        let env = WitnessEnvelope::sign_envelope(
            large_evidence,
            &identity,
            identity.network_id.clone(),
            None,
        )
        .expect("sign");
        let serialized = postcard::to_allocvec(&env).expect("serialize");

        let shard_id = ShardId(i as u64);
        let chunks = serialized
            .fountain_chunkify(
                shard_id,
                identity.did.clone(),
                SymbolSize(64), // Small symbols → many chunks needed
                phalanx_proto::evidence::ChunkType::Witnessed,
                RepairRatio::default(),
                PhalanxTimestamp::from_millis(1_700_000_000_000),
            )
            .expect("fountain chunkify");

        assert!(
            chunks.len() > 2,
            "Need multiple chunks for incomplete assembly, got {}",
            chunks.len()
        );

        // Feed only the first chunk to open a context without completing
        let first_chunk = chunks
            .into_iter()
            .next()
            .expect("should have at least one chunk");
        let result = reassembler.ingest_chunk(first_chunk, &mut journal).await;

        if i == max_contexts {
            assert!(
                result.is_err(),
                "Should reject when per-peer context limit exceeded"
            );
        } else {
            // Earlier chunks should succeed (or at least not fail due to quota)
            let _ = result;
        }
    }
}

#[tokio::test]
async fn reassembler_stale_context_eviction() {
    let identity = test_identity();
    let rid = RecordingId::new("stale_evict_test");
    let env = witness_envelope_for_recording(&identity, &rid, 0, None);

    // Create fountain chunks with small symbol size to get multiple chunks
    let serialized = postcard::to_allocvec(&env).expect("serialize");
    let shard_id = ShardId(99);
    let chunks = serialized
        .fountain_chunkify(
            shard_id,
            identity.did.clone(),
            SymbolSize(128),
            phalanx_proto::evidence::ChunkType::Witnessed,
            RepairRatio::default(),
            PhalanxTimestamp::from_millis(1_700_000_000_000),
        )
        .expect("fountain chunkify");

    let mut reassembler = Reassembler::new();
    let mut journal = MockJournal;

    // Ingest first chunk only (opens context but doesn't complete)
    let first_chunk = chunks.into_iter().next().expect("should have chunks");
    let _ = reassembler.ingest_chunk(first_chunk, &mut journal).await;

    // The context should exist now (ShardMold creates it on first ingest)
    let ctx_count = reassembler.active_shards.contexts.len();
    assert_eq!(ctx_count, 1, "Should have one active context");

    // Manually set last_activity to 60 seconds ago (past SHARD_INACTIVITY_TIMEOUT=30s)
    for ctx in reassembler.active_shards.contexts.values_mut() {
        ctx.accumulator.last_activity = std::time::Instant::now() - Duration::from_secs(60);
    }

    let evicted = reassembler.evict_stale_contexts();
    assert_eq!(evicted, 1, "Should evict the stale context");
    assert!(
        reassembler.active_shards.contexts.is_empty(),
        "No contexts should remain"
    );
}

// ─── Group F: Encryption under adversarial conditions ─────────────────────

#[test]
fn decrypt_wrong_key_fails() {
    let mut shard = create_video_shard(
        vec![vec![1, 2, 3]],
        StorageSequence(1),
        Fps::new(30),
        "decrypt_test".into(),
        ForensicMetrics::default(),
        PhalanxTimestamp::from_millis(1_700_000_000_000),
    )
    .expect("create shard should not fail");

    let key_a = SymmetricKey([0x42; 32]);
    let key_b = SymmetricKey([0x99; 32]);

    shard
        .payload
        .apply_encryption(&key_a)
        .expect("encrypt should not fail");

    let result = shard.payload.reveal(&key_b);
    assert!(result.is_err(), "Decryption with wrong key should fail");
}

#[test]
fn sign_verify_tampered_envelope() {
    let identity = test_identity();
    let rid = RecordingId::new("verify_test");
    let env = witness_envelope_for_recording(&identity, &rid, 0, None);

    // Verify original is valid
    assert!(env.verify_envelope(), "Original envelope should verify");

    // Tamper with signature and verify it fails
    let mut tampered = env;
    if let Some(byte) = tampered.witness_signature.first_mut() {
        *byte ^= 0xFF;
    }
    assert!(
        !tampered.verify_envelope(),
        "Tampered envelope should not verify"
    );
}
