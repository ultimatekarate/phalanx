#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap
)]
// crates/phalanx-sim/tests/t1_clock_skew_rejects_future_evidence.rs
//
// T1/T3 FIX — end-to-end integration test.
//
// T1 (clock fallback to last_known_good instead of epoch-zero) and T3
// (the temporal gate ALWAYS runs, even for "sticky-trust" anchored units)
// together form the temporal defense perimeter. Unit tests cover each
// in isolation (see phalanx-node/src/clock.rs and phalanx-forensics/
// src/verification/gate.rs). This test drives real future-dated
// `WitnessEnvelope`s through a live Guardian and proves the invariant
// at the actor-level contract:
//
//   `seed_envelope` (which routes through StorageCommand::WriteShard and
//   exposes the storage actor's accept/reject reply) must treat a
//   far-future envelope differently from a wall-clock envelope signed by
//   the same identity.
//
// NOTE on scope: the seed_envelope contract is the accept/reject reply,
// not the on-disk state — a rejected WriteShard may still land bytes on
// disk via tracing or partial-commit paths, which is a storage-layer
// concern orthogonal to the temporal defense. The load-bearing assertion
// here is the reply-level rejection: anything that selectively rejects
// only the future-dated envelope must be a temporal check, since the
// signer, signature, and payload shape are otherwise identical.

use phalanx_forensics::pipeline::witness::WitnessAuthority;
use phalanx_node::config::NodeConfig;
use phalanx_proto::evidence::{Evidence, StorageSequence, VideoShard, WitnessEnvelope};
use phalanx_proto::identity::{NodeRole, PhalanxIdentity, RecordingId};
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_sim::physics::PhalanxPhysics;
use phalanx_sim::SimulationHarness;

use std::time::Duration;

const REPLICATION_STEP: Duration = Duration::from_millis(50);
const REPLICATION_ATTEMPTS: usize = 40;

/// Real wall-clock millis. The guardian's temporal-tolerance filter
/// compares against `TrustedClock::now()` which is bound to wall time;
/// a hardcoded stale timestamp would fail for reasons unrelated to the
/// test's invariant.
fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Build a single-chunk recording signed by `signer` at `timestamp_ms`.
/// Pattern mirrors `evidence_byzantine_tolerance::seed_authentic_recording`,
/// but parametrises the timestamp so callers can craft future-dated evidence.
fn signed_envelope_at(
    signer: &PhalanxIdentity,
    recording_id: &RecordingId,
    timestamp_ms: u64,
) -> WitnessEnvelope {
    let shard = VideoShard {
        timestamp: PhalanxTimestamp::from_millis(timestamp_ms),
        recording_id: recording_id.clone(),
        sequence_id: StorageSequence(0),
        ..Default::default()
    };
    let envelope = WitnessEnvelope::sign_envelope(
        Evidence::Video(shard),
        signer,
        signer.witness_id.clone(),
        None,
    )
    .expect("sign_envelope");
    assert!(
        envelope.verify_envelope(),
        "crafted envelope fails verify_envelope — test primitive is broken, not the gate"
    );
    envelope
}

/// Ten minutes is comfortably outside any reasonable temporal-tolerance
/// window. HomeostaticConfig::max_temporal_tolerance defaults to ~10s
/// (2 × NORMAL_TICK_SECS), so 10 minutes is ~60× the ceiling.
const FAR_FUTURE_OFFSET_MS: u64 = 10 * 60 * 1000;

#[tokio::test]
async fn storage_actor_rejects_future_dated_envelope_but_accepts_legit() {
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    // One receiver is enough — the test proves the gate, not a mesh.
    let receiver = harness
        .spawn_node("T1-Receiver", NodeRole::Guardian)
        .await
        .expect("spawn receiver");

    harness.advance_time(Duration::from_millis(100)).await;

    // Ad-hoc signer — not registered in the receiver's trust graph, which
    // means any rejection cannot be misattributed to a blacklist. Matches
    // evidence_byzantine_tolerance.rs's pattern of signer != spawned peer.
    let signer = PhalanxIdentity::new_ephemeral();
    let rid = RecordingId::new("t1-clock-skew-probe");

    // ── Part 1: Future-dated envelope ──────────────────────────────────
    let future_ts = now_ms() + FAR_FUTURE_OFFSET_MS;
    let future_env = signed_envelope_at(&signer, &rid, future_ts);

    let accepted_future = harness.seed_envelope(future_env.clone()).await;

    // ── Part 2: Legitimate envelope (same signer, wall-clock timestamp) ─
    // Using a fresh recording id keeps the two paths independent — if the
    // first envelope somehow slipped past the gate, it can't pollute the
    // second's retrieval.
    let legit_rid = RecordingId::new("t1-clock-skew-control");
    let legit_env = signed_envelope_at(&signer, &legit_rid, now_ms());
    let accepted_legit = harness.seed_envelope(legit_env.clone()).await;

    // Let the actors settle so honest_retrieve sees committed state.
    let _counts = harness
        .await_replication(&legit_rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;

    // ── Assertions ─────────────────────────────────────────────────────
    // Legitimate path MUST work — otherwise our test primitive is broken
    // for reasons unrelated to the invariant under test.
    assert_eq!(
        accepted_legit.len(),
        1,
        "legitimate envelope must be accepted by the one spawned guardian"
    );
    let legit_retrieved = harness.retrieve_evidence(&receiver, &legit_rid).await;
    assert_eq!(
        legit_retrieved.len(),
        1,
        "legitimate envelope must be retrievable from storage"
    );

    // Future-dated envelope must be REJECTED by the storage actor's
    // reply. If the T1/T3 temporal gate short-circuits — e.g., someone
    // removes verify_freshness or gates it behind anchored-only fast-path —
    // this assertion fires because the WriteShard reply will now be Ok(Ok).
    assert_eq!(
        accepted_future.len(),
        0,
        "far-future envelope must be rejected by the temporal gate (T1/T3 FIX); \
         got {} accept(s) for envelope {FAR_FUTURE_OFFSET_MS}ms in the future",
        accepted_future.len(),
    );

    // Cross-check: the two envelopes came from the same signer with the
    // same payload shape — only the timestamp differs. The only thing
    // that can selectively reject one and accept the other is a temporal
    // check. (The bloom filter rejects by evidence_hash, which differs,
    // but would also reject the legit envelope equivalently.)
}

#[tokio::test]
async fn receiver_survives_stream_of_future_dated_envelopes() {
    // Load variant: the guardian must stay healthy under a sustained
    // stream of temporally-invalid envelopes — otherwise an attacker
    // can DoS us by flooding future-dated shards.
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let receiver = harness
        .spawn_node("T1-LoadVictim", NodeRole::Guardian)
        .await
        .expect("spawn receiver");

    harness.advance_time(Duration::from_millis(100)).await;

    let signer = PhalanxIdentity::new_ephemeral();

    // 20 future-dated envelopes, each with a distinct recording id so
    // they're not deduped by the bloom filter on evidence_hash.
    for i in 0..20u32 {
        let rid = RecordingId::new(format!("t1-flood-{i}"));
        let env = signed_envelope_at(&signer, &rid, now_ms() + FAR_FUTURE_OFFSET_MS);
        let _ = harness.seed_envelope(env).await;
    }

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // Survival: the receiver still processes a legitimate envelope after
    // the flood. This is the load-bearing assertion — rejection telemetry
    // is nice-to-have, but a wedged actor would silently fail this.
    let rid = RecordingId::new("t1-flood-survivor");
    let legit = signed_envelope_at(&signer, &rid, now_ms());
    let accepted = harness.seed_envelope(legit).await;
    assert_eq!(
        accepted.len(),
        1,
        "legitimate envelope must be accepted after future-dated flood"
    );
    let retrieved = harness.retrieve_evidence(&receiver, &rid).await;
    assert_eq!(
        retrieved.len(),
        1,
        "legitimate envelope must be retrievable after flood"
    );
}
