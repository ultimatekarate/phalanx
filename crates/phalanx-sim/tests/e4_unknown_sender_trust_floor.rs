#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-sim/tests/e4_unknown_sender_trust_floor.rs
//
// E4 / E6 FIX — end-to-end integration test.
//
// E4: unknown peers start at trust score 0.1 (the minimum), NOT 1.0.
//     A pre-E4 node would briefly grant full trust to a first-contact
//     Sybil peer.
// E6: the peer registry is rate-limited (MAX_LAZY_REGISTRATIONS = 10_000)
//     so a flood of unique DIDs cannot fill the trust map indefinitely.
//
// Unit tests cover the reputation arithmetic in isolation (see
// phalanx-node/src/trust.rs). This test proves the end-to-end behaviour:
// an envelope from an unknown signer successfully traverses the full
// guardian ingest path (signature gate, temporal gate, storage) without
// requiring prior registration — AND the guardian keeps serving
// subsequent traffic under a flood of unique-signer envelopes.
//
// Scope follows the plan's fallback narrowing: we do NOT assert on the
// reputation value itself (the harness exposes `governor_for(did)` but
// not a `trust_registry_for` accessor, and landing a new accessor is out
// of scope for this tranche). Instead we assert the observable, integration-
// level consequences of E4/E6:
//   1. A single unknown-signer envelope is accepted on first contact.
//   2. A flood of ~100 unique-signer envelopes does not wedge or crash
//      the receiver — it still processes a follow-up legitimate envelope
//      correctly.

use phalanx_forensics::pipeline::witness::WitnessAuthority;
use phalanx_node::config::NodeConfig;
use phalanx_proto::evidence::{Evidence, StorageSequence, VideoShard, WitnessEnvelope};
use phalanx_proto::identity::{NodeRole, PhalanxIdentity, RecordingId};
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_sim::SimulationHarness;
use phalanx_sim::physics::PhalanxPhysics;

use std::time::Duration;

const REPLICATION_STEP: Duration = Duration::from_millis(50);
const REPLICATION_ATTEMPTS: usize = 40;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before UNIX epoch")
        .as_millis() as u64
}

/// Sign a single-chunk recording with the given ad-hoc identity.
fn signed_envelope_from(signer: &PhalanxIdentity, recording_id: &RecordingId) -> WitnessEnvelope {
    let shard = VideoShard {
        timestamp: PhalanxTimestamp::from_millis(now_ms()),
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
        "crafted envelope fails verify_envelope — test primitive is broken"
    );
    envelope
}

#[tokio::test]
async fn unknown_signer_envelope_is_accepted_on_first_contact() {
    // Invariant: a valid envelope from a signer the node has never seen
    // must pass the guardian's ingestion path. If E4 instead *rejected*
    // unknown signers outright (rather than seeding them at 0.1 trust),
    // the whole first-contact flow would break and this test would fail.
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let receiver = harness
        .spawn_node("E4-Receiver", NodeRole::Guardian)
        .await
        .expect("spawn receiver");

    harness.advance_time(Duration::from_millis(100)).await;

    // The signer is not the spawned node — its DID is brand-new to the
    // receiver's TrustRegistry.
    let stranger = PhalanxIdentity::new_ephemeral();
    let rid = RecordingId::new("e4-first-contact");
    let envelope = signed_envelope_from(&stranger, &rid);

    let accepted = harness.seed_envelope(envelope).await;
    assert_eq!(
        accepted.len(),
        1,
        "first-contact envelope from unknown signer must be accepted"
    );

    let _ = harness
        .await_replication(&rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;
    let retrieved = harness.retrieve_evidence(&receiver, &rid).await;
    assert_eq!(
        retrieved.len(),
        1,
        "first-contact envelope must be retrievable from storage"
    );
}

#[tokio::test]
async fn receiver_survives_flood_of_unique_unknown_signers() {
    // E6 FIX: MAX_LAZY_REGISTRATIONS caps the peer map at 10_000 entries.
    // A small burst (~100) must not wedge the actor. We don't assert on
    // the cap itself here (too expensive for a smoke test); we assert
    // the actor stays responsive, which is the observable E6 contract.
    let (mut harness, _collector) =
        SimulationHarness::init_mesh(NodeConfig::default(), PhalanxPhysics::test_profile());

    let receiver = harness
        .spawn_node("E6-FloodVictim", NodeRole::Guardian)
        .await
        .expect("spawn receiver");

    harness.advance_time(Duration::from_millis(100)).await;

    // Flood: 100 unique signers, one envelope each. Each new signer DID
    // triggers lazy registration in the receiver's TrustRegistry.
    const FLOOD_SIZE: u32 = 100;
    for i in 0..FLOOD_SIZE {
        let signer = PhalanxIdentity::new_ephemeral();
        let rid = RecordingId::new(format!("e6-flood-{i}"));
        let envelope = signed_envelope_from(&signer, &rid);
        let _ = harness.seed_envelope(envelope).await;
    }

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // Survival: after the flood, a fresh envelope from a NEW stranger is
    // still accepted and retrievable. A wedged actor would silently fail.
    let post_flood_signer = PhalanxIdentity::new_ephemeral();
    let rid = RecordingId::new("e6-post-flood-survivor");
    let envelope = signed_envelope_from(&post_flood_signer, &rid);
    let accepted = harness.seed_envelope(envelope).await;
    assert_eq!(
        accepted.len(),
        1,
        "receiver must still accept new-signer envelopes after lazy-registration flood"
    );

    let _ = harness
        .await_replication(&rid, 1, REPLICATION_ATTEMPTS, REPLICATION_STEP)
        .await;
    let retrieved = harness.retrieve_evidence(&receiver, &rid).await;
    assert_eq!(
        retrieved.len(),
        1,
        "post-flood envelope must be retrievable — actor is healthy"
    );
}
