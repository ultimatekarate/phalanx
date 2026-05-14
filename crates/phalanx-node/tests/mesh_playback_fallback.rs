#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
//! Mesh-fallback E2E test: pin the
//! discovery → providers → request → response loop.
//!
//! This test verifies that the playback singleton refactor actually wires
//! mesh fallback end-to-end — not just that the SpawnPlayback command
//! dispatches successfully (which is covered by `engine_facade.rs`).
//!
//! Scenario: a recording's shards are absent from local storage but seeded
//! on a synthetic "remote peer" via `MeshTestEgress`. When the coordinator
//! retries on the missing shard, `discovery_tx` reaches the sentinel, which
//! dispatches `EgressCommand::FindProviders` to the egress port. The test
//! egress synthesizes `NetworkEvent::ProvidersDiscovered` back through the
//! ingress channel. The coordinator then issues `RequestShards` against the
//! synthetic peer; the test egress synthesizes
//! `NetworkEvent::ShardResponseReceived` with the seeded envelope. The
//! sentinel routes that to `StorageCommand::WriteShard`, the storage actor
//! persists, the coordinator's next `GetShard` hits, and a decoded frame
//! arrives on the test's `video_rx`.
//!
//! If the test observes a frame on `video_rx` within 5 seconds AND both
//! call counters (`find_providers_calls`, `send_request_calls`) ≥ 1, every
//! link in the chain worked. If it times out, the diff that regressed it
//! is the diff under audit.

mod common;

use common::build_mesh_test_deps;
use phalanx_forensics::reassembler::create_video_shard;
use phalanx_forensics::witness::WitnessAuthority;
use phalanx_node::actors::meshsentinel::{AlreadyPlaying, SentinelCommand};
use phalanx_node::{UnspawnedEngine, VideoPlayerSink};
use phalanx_proto::evidence::{Evidence, ForensicMetrics, StorageSequence, WitnessEnvelope};
use phalanx_proto::identity::{PhalanxIdentity, RecordingId, WitnessId};
use phalanx_proto::playback::PlaybackSink;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::types::Fps;
use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Build a signed `WitnessEnvelope` whose payload is the canonical
/// LZ4-compressed postcard-encoded `Vec<Vec<u8>>` of JPEG frames. The
/// envelope is signed with `identity` so it passes the Promotion Gate's
/// Integrity check in `StorageActor::handle_write_shard`.
///
/// Skips `apply_encryption` — the payload stays `DataPayload::Compressed`,
/// which `decode_payload` handles without a key (just LZ4 decompress).
/// This sidesteps the encryption path entirely so mesh-fallback wiring is
/// the only thing under test.
fn build_clear_video_envelope(
    rec_id: &RecordingId,
    seq: u32,
    identity: &PhalanxIdentity,
) -> WitnessEnvelope {
    let frames: Vec<Vec<u8>> = vec![vec![0xFFu8, 0xD8, 0xFF, 0xE0]];
    let shard = create_video_shard(
        frames,
        StorageSequence(seq),
        Fps::new(30),
        rec_id.clone(),
        ForensicMetrics::default(),
        PhalanxTimestamp::from_millis(1_700_000_000_000 + u64::from(seq) * 33),
    )
    .expect("create_video_shard succeeds for non-empty frames");

    WitnessEnvelope::sign_envelope(Evidence::Video(shard), identity, WitnessId::random(), None)
        .expect("sign_envelope succeeds for valid input")
}

#[test]
fn engine_facade_mesh_fallback_delivers_remote_shard() {
    // Drive everything on a multi-thread runtime — the sentinel's run loop
    // is spawned via `UnspawnedEngine::spawn(&runtime)` and the test uses
    // blocking_send / block_on from this sync test body.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("multi_thread runtime builds");

    // 1. Build the simulated remote peer's identity. This identity signs
    //    the shard AND becomes the source of the synthetic MeshAddress in
    //    MeshTestEgress (distinct from build_mesh_test_deps's local
    //    identity, so handle_providers_discovered's self-filter doesn't
    //    drop the synthesized event).
    let peer_identity = PhalanxIdentity::new_ephemeral();

    // 2. Build a synthetic shard for sequence 1, signed by the peer.
    let rec_id = RecordingId::new("mesh-fallback-test");
    let envelope = build_clear_video_envelope(&rec_id, 1, &peer_identity);

    // 3. Seed the mesh egress with that shard.
    let mut seeded = HashMap::new();
    seeded.insert(rec_id.clone(), vec![envelope]);
    let mesh_deps = runtime.block_on(build_mesh_test_deps(seeded, &peer_identity));

    let find_providers_calls = mesh_deps.find_providers_calls.clone();
    let send_request_calls = mesh_deps.send_request_calls.clone();

    // 4. Boot the engine.
    let unspawned = runtime
        .block_on(UnspawnedEngine::build(mesh_deps.deps))
        .expect("UnspawnedEngine::build succeeds for a healthy test bootstrap");
    let (engine, lifecycle) = unspawned.spawn(&runtime);

    // 5. Construct sinks; keep the receivers so we can observe what the
    //    sentinel-spawned coordinator pushes through them.
    let (video_tx, mut video_rx) = mpsc::channel::<Vec<u8>>(8);
    let (audio_tx, _audio_rx) = mpsc::channel::<Vec<u8>>(8);
    let video_sink: Box<dyn PlaybackSink + Send + Sync + 'static> =
        Box::new(VideoPlayerSink::new(video_tx));
    let audio_sink: Box<dyn PlaybackSink + Send + Sync + 'static> =
        Box::new(VideoPlayerSink::new(audio_tx));

    // 6. Dispatch SpawnPlayback through the engine's command channel.
    let cmd_tx = engine.sentinel_cmd_tx();
    let (reply_tx, reply_rx) = oneshot::channel::<Result<(), AlreadyPlaying>>();
    cmd_tx
        .blocking_send(SentinelCommand::SpawnPlayback {
            recording_id: rec_id.clone(),
            video_sink,
            audio_sink,
            reply_to: reply_tx,
        })
        .expect("sentinel command channel is open");

    let dispatch_result = runtime
        .block_on(async {
            tokio::time::timeout(Duration::from_secs(3), reply_rx)
                .await
                .expect("dispatch reply within deadline")
        })
        .expect("dispatch oneshot delivered");
    assert!(
        dispatch_result.is_ok(),
        "first SpawnPlayback dispatch should succeed (got {dispatch_result:?})"
    );

    // 7. Wait for a frame within 5s. Discovery fires on retry 1 (within
    //    ~100ms of the first storage miss); allowing for the
    //    ProvidersDiscovered round-trip + the ShardResponseReceived
    //    round-trip + the next GetShard hit, well under 500ms is typical.
    //    Sequence 1 has a 400ms budget (retries 1-4 × 100ms each) before
    //    the gap-skip branch advances to sequence 2. 5s is generous
    //    against scheduling jitter on loaded CI runners.
    let first_frame = runtime
        .block_on(async { tokio::time::timeout(Duration::from_secs(5), video_rx.recv()).await });
    assert!(
        matches!(first_frame, Ok(Some(_))),
        "expected a decoded frame within 5s (got {first_frame:?}); find_providers_calls={}, send_request_calls={}",
        find_providers_calls.load(Ordering::Acquire),
        send_request_calls.load(Ordering::Acquire),
    );

    // 8. Assert the chain actually fired through the mesh (not via some
    //    accidental local hit). These prove the wiring, not just the
    //    end-to-end happy path.
    assert!(
        find_providers_calls.load(Ordering::Acquire) >= 1,
        "EgressPort::find_providers must have been called at least once"
    );
    assert!(
        send_request_calls.load(Ordering::Acquire) >= 1,
        "EgressPort::send_request must have been called at least once"
    );

    // 9. Cleanup. Lifecycle shutdown aborts any in-flight coordinator task
    //    as part of runtime drop.
    runtime
        .block_on(async {
            tokio::time::timeout(
                Duration::from_secs(5),
                lifecycle.shutdown(Duration::from_secs(3)),
            )
            .await
            .expect("shutdown returns within outer 5s window")
        })
        .expect("EngineLifecycle::shutdown returns Ok within deadline");
}
