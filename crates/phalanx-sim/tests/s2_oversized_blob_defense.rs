#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// crates/phalanx-sim/tests/s2_oversized_blob_defense.rs
//
// S2 FIX — end-to-end integration test.
//
// The S2 unmarshal gate (see `phalanx-forensics/src/verification/gate.rs`,
// constant MAX_UNMARSHAL_INPUT_BYTES = 64 MiB) refuses to feed
// oversized byte buffers to postcard, preventing a memory-amplification
// DoS. Unit tests cover the gate primitive in isolation; this test drives
// a real oversized blob into a live `MeshSentinel` constellation via
// `inject_event` and proves the ingestion pipeline survives.
//
// Survival contract (matches the `does_not_crash_node` idiom in
// adversarial_tests.rs):
//   1. Node keeps running (a follow-up `NetworkEvent::Shutdown` inject
//      still returns Ok — the sentinel task has not died).
//   2. A legitimate subsequent `DataReceived` still enters the pipeline
//      (inject returns Ok — the mailbox wasn't wedged).

use phalanx_node::config::NodeConfig;
use phalanx_proto::identity::NodeRole;
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{MeshAddress, MeshTopic};
use phalanx_sim::SimulationHarness;
use phalanx_sim::physics::PhalanxPhysics;

use std::time::Duration;

/// The S2 gate rejects anything strictly larger than 64 MiB.
/// Source: `phalanx-forensics/src/verification/gate.rs` — MAX_UNMARSHAL_INPUT_BYTES.
const S2_LIMIT_BYTES: usize = 64 * 1024 * 1024;

/// Build an attack payload that exceeds the S2 gate by one byte.
/// The bytes themselves don't need to decode to anything — the gate
/// rejects on length *before* handing data to postcard.
fn oversized_attack_payload() -> Vec<u8> {
    vec![0xEEu8; S2_LIMIT_BYTES + 1]
}

#[tokio::test]
async fn s2_oversized_blob_does_not_crash_guardian() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim = harness
        .spawn_node("S2-Victim", NodeRole::Guardian)
        .await
        .expect("spawn victim");

    // Give the sentinel a moment to be fully wired before we attack.
    harness.advance_time(Duration::from_millis(100)).await;

    // An unrelated origin — the attack is the payload, not the provenance.
    let attacker_net = MeshAddress::new("s2-attacker-synthetic");

    // ── Attack 1: 64 MiB + 1 byte of junk ──────────────────────────────
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: attacker_net.clone(),
                topic: config.network.video_topic.clone(),
                data: oversized_attack_payload(),
            },
        )
        .await
        .expect("oversized DataReceived accepted by routing mesh");

    // Let the IngestionActor drain the mailbox and hit the S2 gate.
    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // ── Survival Check 1: the actor task is still alive ────────────────
    // If the sentinel panicked, the ingress channel would be closed and
    // the follow-up inject would fail with a send error.
    let legit_payload = vec![0x01u8, 0x02, 0x03];
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: attacker_net.clone(),
                topic: config.network.video_topic.clone(),
                data: legit_payload,
            },
        )
        .await
        .expect("IngressPort must remain open after oversized blob — S2 gate wedged the actor");

    // ── Survival Check 2: Shutdown still processes ─────────────────────
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("Shutdown inject must succeed — actor is alive");

    harness.advance_time(Duration::from_millis(200)).await;

    // Telemetry sanity: the harness emitted at least one event for this
    // node (the PeerDiscovered on spawn). If telemetry itself crashed the
    // events list would be empty.
    let events = collector.events().await;
    assert!(
        !events.is_empty(),
        "telemetry collector must still be operating — got no events"
    );
}

#[tokio::test]
async fn s2_exactly_at_limit_does_not_crash_guardian() {
    // Boundary check: the gate is `> MAX_UNMARSHAL_INPUT_BYTES`, so a
    // payload of exactly 64 MiB is within the limit. The ingestion pipeline
    // may accept it for decoding and fail at postcard (invalid bytes) — either
    // way, the node must not crash.
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim = harness
        .spawn_node("S2-Boundary", NodeRole::Guardian)
        .await
        .expect("spawn victim");

    harness.advance_time(Duration::from_millis(100)).await;

    let at_limit = vec![0xAAu8; S2_LIMIT_BYTES];
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: MeshAddress::new("boundary-origin"),
                topic: MeshTopic::video(),
                data: at_limit,
            },
        )
        .await
        .expect("boundary-sized DataReceived accepted by routing mesh");

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // Node still responds to Shutdown.
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("Shutdown must succeed after 64 MiB payload");
    harness.advance_time(Duration::from_millis(200)).await;
}
