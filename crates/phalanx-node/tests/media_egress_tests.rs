#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-node/tests/media_egress_tests.rs
//
// Unit tests for the MediaEgressActor's publishing pipeline:
// topic routing, hash chain continuity, WAL retry, storage pressure feedback.

use phalanx_node::actors::media_egress::{MediaEgressActor, MediaEgressConfig};
use phalanx_node::actors::shutdown::ShutdownSignal;
use phalanx_node::clock::TrustedClock;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::corroboration::ProximityWitness;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, VideoShard};
use phalanx_proto::identity::{MeshAddress, PhalanxIdentity, WitnessId};
use phalanx_proto::network::EgressPort;
use phalanx_proto::prelude::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;

// --- Test Doubles ---

/// An egress port that records all published payloads. `publish_count` keeps
/// the cheap-to-load fast path; `published_bytes` is the slow path used by
/// bundling tests that need to inspect wire-format structure.
#[derive(Clone)]
struct RecordingEgress {
    publish_count: Arc<AtomicUsize>,
    published_bytes: Arc<std::sync::Mutex<Vec<Vec<u8>>>>,
}

impl RecordingEgress {
    fn new(publish_count: Arc<AtomicUsize>) -> Self {
        Self {
            publish_count,
            published_bytes: Arc::new(std::sync::Mutex::new(Vec::new())),
        }
    }
}

#[async_trait::async_trait]
impl EgressPort for RecordingEgress {
    async fn publish(&self, _: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        self.publish_count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut buf) = self.published_bytes.lock() {
            buf.push(data);
        }
        Ok(())
    }
    async fn ban_peer(&self, _: &MeshAddress) {}
    async fn send_response(&self, _: &str, _: RecordingResponse) -> Result<(), String> {
        Ok(())
    }
    async fn announce_recording(&self, _: &RecordingId) -> Result<(), String> {
        Ok(())
    }
    async fn find_providers(&self, _: &RecordingId) -> Result<(), String> {
        Ok(())
    }
    async fn send_request(
        &self,
        _: &MeshAddress,
        _: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        Ok(())
    }
}

/// An egress port that always fails publish (forces WAL enqueue).
#[derive(Clone)]
struct FailingEgress;

#[async_trait::async_trait]
impl EgressPort for FailingEgress {
    async fn publish(&self, _: &MeshTopic, _: Vec<u8>) -> Result<(), String> {
        Err("transport down".to_string())
    }
    async fn ban_peer(&self, _: &MeshAddress) {}
    async fn send_response(&self, _: &str, _: RecordingResponse) -> Result<(), String> {
        Err("transport down".to_string())
    }
    async fn announce_recording(&self, _: &RecordingId) -> Result<(), String> {
        Err("transport down".to_string())
    }
    async fn find_providers(&self, _: &RecordingId) -> Result<(), String> {
        Err("transport down".to_string())
    }
    async fn send_request(
        &self,
        _: &MeshAddress,
        _: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        Err("transport down".to_string())
    }
}

/// Build a MediaEgressActor with the default bundle size (1, no bundling).
async fn build_media_egress<E: EgressPort + 'static>(
    egress: E,
) -> (
    mpsc::Sender<VideoShard>,
    mpsc::Sender<AudioShard>,
    tokio::task::JoinHandle<()>,
) {
    build_media_egress_with_bundle_size(egress, phalanx_proto::types::SymbolBundleSize::default())
        .await
}

/// Build a MediaEgressActor with a configurable bundle size — used by the
/// bundling tests to verify wire-format behavior at non-default values. Drops
/// the proximity sender (these tests exercise the media path only).
async fn build_media_egress_with_bundle_size<E: EgressPort + 'static>(
    egress: E,
    symbol_bundle_size: phalanx_proto::types::SymbolBundleSize,
) -> (
    mpsc::Sender<VideoShard>,
    mpsc::Sender<AudioShard>,
    tokio::task::JoinHandle<()>,
) {
    let (video_tx, audio_tx, _proximity_tx, handle) =
        build_media_egress_full(egress, symbol_bundle_size).await;
    (video_tx, audio_tx, handle)
}

/// Build a MediaEgressActor, returning every input sender including the
/// proximity-witness sender. The media-only helpers wrap this and drop the
/// proximity sender; the proximity test uses it directly.
async fn build_media_egress_full<E: EgressPort + 'static>(
    egress: E,
    symbol_bundle_size: phalanx_proto::types::SymbolBundleSize,
) -> (
    mpsc::Sender<VideoShard>,
    mpsc::Sender<AudioShard>,
    mpsc::Sender<ProximityWitness>,
    tokio::task::JoinHandle<()>,
) {
    let (video_tx, video_rx) = mpsc::channel(32);
    let (audio_tx, audio_rx) = mpsc::channel(32);
    let (proximity_tx, proximity_rx) = mpsc::channel(32);
    let temp = tempdir().expect("Failed to create temp dir");
    let gov = Arc::new(SystemGovernor::new());
    let identity = Arc::new(PhalanxIdentity::new_ephemeral());
    let local_id = WitnessId::new("local-node");

    let config = MediaEgressConfig {
        video_rx,
        audio_rx,
        proximity_rx,
        video_topic: MeshTopic::new("/phalanx/video/test"),
        audio_topic: MeshTopic::new("/phalanx/audio/test"),
        symbol_size: SymbolSize::default(),
        repair_ratio: RepairRatio::default(),
        symbol_bundle_size,
        wal_dir: temp.path().to_path_buf(),
        system_governor: gov,
        max_storage_bytes: 100_000_000,
        vault_key: SymmetricKey::from_bytes([0u8; 32]),
        content_key_rx: tokio::sync::watch::channel(None).1,
        clock: Arc::new(TrustedClock::new()),
        prnu_posterior: std::sync::Arc::new(std::sync::Mutex::new(
            phalanx_proto::evidence::PrnuPosterior::new_uninformed(),
        )),
        storage_tx: tokio::sync::mpsc::channel(16).0,
    };

    let actor = MediaEgressActor::new(egress, identity, local_id, config, ShutdownSignal::new())
        .await
        .expect("Failed to create MediaEgressActor");

    // Leak temp so WAL directory lives for the actor's lifetime
    std::mem::forget(temp);

    let handle = tokio::spawn(actor.run());
    (video_tx, audio_tx, proximity_tx, handle)
}

fn make_video_shard(payload_bytes: usize) -> VideoShard {
    phalanx_test_fixtures::shards::video_shard_synthetic(payload_bytes)
}

fn make_audio_shard(payload_bytes: usize) -> AudioShard {
    phalanx_test_fixtures::shards::audio_shard_synthetic(payload_bytes)
}

// =====================================================================
// Happy Path: Video and Audio Publishing
// =====================================================================

/// A video shard should be sealed, fountain-encoded, and published.
#[tokio::test]
async fn test_video_shard_published() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (video_tx, _audio_tx, handle) =
        build_media_egress(RecordingEgress::new(counter.clone())).await;

    video_tx.send(make_video_shard(256)).await.unwrap();
    // Give actor time to seal + fountain encode + publish
    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = counter.load(Ordering::Relaxed);
    assert!(
        count > 0,
        "Video shard should produce at least one published symbol, got {}",
        count
    );

    drop(video_tx);
    drop(_audio_tx);
    // Actor exits when both channels close and queue empty
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
}

/// An audio shard should be sealed, fountain-encoded, and published.
#[tokio::test]
async fn test_audio_shard_published() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (_video_tx, audio_tx, handle) =
        build_media_egress(RecordingEgress::new(counter.clone())).await;

    audio_tx.send(make_audio_shard(256)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = counter.load(Ordering::Relaxed);
    assert!(
        count > 0,
        "Audio shard should produce at least one published symbol, got {}",
        count
    );

    drop(_video_tx);
    drop(audio_tx);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
}

/// Multiple shards in sequence should each produce published symbols.
#[tokio::test]
async fn test_multiple_shards_sequenced() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (video_tx, audio_tx, handle) =
        build_media_egress(RecordingEgress::new(counter.clone())).await;

    // 3 video + 2 audio
    for _ in 0..3u32 {
        video_tx.send(make_video_shard(128)).await.unwrap();
    }
    for _ in 0..2u32 {
        audio_tx.send(make_audio_shard(128)).await.unwrap();
    }

    tokio::time::sleep(Duration::from_millis(500)).await;

    let count = counter.load(Ordering::Relaxed);
    // Each shard produces at least 1 symbol, so expect >= 5
    assert!(
        count >= 5,
        "5 shards should produce at least 5 published symbols, got {}",
        count
    );

    drop(video_tx);
    drop(audio_tx);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
}

// =====================================================================
// Graceful Shutdown
// =====================================================================

/// Actor exits when both capture channels close and the retry queue is empty.
#[tokio::test]
async fn test_actor_exits_on_channel_close() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (video_tx, audio_tx, handle) =
        build_media_egress(RecordingEgress::new(counter.clone())).await;

    // Close both channels immediately
    drop(video_tx);
    drop(audio_tx);

    // Actor should exit within a reasonable time
    let result = tokio::time::timeout(Duration::from_secs(10), handle).await;
    assert!(result.is_ok(), "Actor should exit when both channels close");
}

// =====================================================================
// Failed Publish → WAL Enqueue
// =====================================================================

/// When publish fails, the symbol should be enqueued in the outbound WAL for retry.
/// The actor should NOT crash — it continues processing.
#[tokio::test]
async fn test_failed_publish_enqueues_to_wal() {
    let (video_tx, audio_tx, handle) = build_media_egress(FailingEgress).await;

    // Send a video shard — all symbols will fail to publish
    video_tx.send(make_video_shard(256)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Actor should still be alive (not crashed)
    assert!(
        !handle.is_finished(),
        "Actor should survive publish failures"
    );

    // Close channels — actor won't exit immediately because WAL has entries
    drop(video_tx);
    drop(audio_tx);

    // The actor won't exit cleanly because the queue is never drained (FailingEgress
    // always fails), so we abort after confirming it stayed alive.
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(
        !handle.is_finished(),
        "Actor should keep running while WAL has pending entries"
    );
    handle.abort();
}

// =====================================================================
// Bundling: wire-format and cardinality
// =====================================================================
//
// These tests verify that publish_fountain_symbols emits a postcard-encoded
// `Vec<ShardChunk>` per egress.publish() call (the new wire format), and that
// `symbol_bundle_size` controls the cardinality of each bundle.
//
// We don't predict the exact chunk count fountain_chunkify produces for a
// given payload — RaptorQ's repair-symbol count varies with the source-block
// size. We assert structural properties: every published payload deserializes
// as `Vec<ShardChunk>` (not bare `ShardChunk`), and bundle cardinality stays
// within the configured `bundle_size` upper bound.

use phalanx_proto::evidence::ShardChunk;

/// Default bundle size 1: every published payload is a length-1
/// `Vec<ShardChunk>`. Confirms the wire format is consistent even when no
/// bundling occurs (single-chunk publishes are still wrapped).
#[tokio::test]
async fn test_default_bundle_size_emits_length_1_vec() {
    let counter = Arc::new(AtomicUsize::new(0));
    let egress = RecordingEgress::new(counter.clone());
    let bytes_handle = egress.published_bytes.clone();
    let (video_tx, _audio_tx, handle) = build_media_egress(egress).await;

    video_tx.send(make_video_shard(256)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let buf = bytes_handle.lock().unwrap().clone();
    assert!(!buf.is_empty(), "expected at least one publish");

    for (i, payload) in buf.iter().enumerate() {
        let bundle: Vec<ShardChunk> = postcard::from_bytes(payload)
            .unwrap_or_else(|e| panic!("publish #{i} did not deserialize as Vec<ShardChunk>: {e}"));
        assert_eq!(
            bundle.len(),
            1,
            "publish #{i}: bundle_size=1 must emit length-1 Vec, got {}",
            bundle.len()
        );
    }

    drop(video_tx);
    drop(_audio_tx);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
}

/// Larger bundle size produces fewer publishes carrying multiple chunks each.
/// With a moderately-sized shard and bundle_size=10, we expect at least one
/// publish with cardinality > 1, and total chunk count summed across bundles
/// should equal the same count as the unbundled (default) baseline.
#[tokio::test]
async fn test_bundling_packs_multiple_chunks_per_publish() {
    use phalanx_proto::types::SymbolBundleSize;

    // Bundle size 10 — small enough to fit any shard size we might generate
    // here, large enough that we should see multi-chunk bundles.
    let counter_bundled = Arc::new(AtomicUsize::new(0));
    let egress_bundled = RecordingEgress::new(counter_bundled.clone());
    let bytes_bundled = egress_bundled.published_bytes.clone();
    let (video_tx, _audio_tx, handle) =
        build_media_egress_with_bundle_size(egress_bundled, SymbolBundleSize::new(10)).await;

    // 8 KB shard — large enough to chunk into several RaptorQ symbols at 1200 B each.
    video_tx.send(make_video_shard(8192)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let buf = bytes_bundled.lock().unwrap().clone();
    assert!(!buf.is_empty(), "expected at least one publish");

    let mut total_chunks_bundled = 0usize;
    let mut max_bundle_seen = 0usize;
    for (i, payload) in buf.iter().enumerate() {
        let bundle: Vec<ShardChunk> = postcard::from_bytes(payload)
            .unwrap_or_else(|e| panic!("publish #{i} did not deserialize as Vec<ShardChunk>: {e}"));
        assert!(
            bundle.len() <= 10,
            "publish #{i}: bundle_size=10 cap exceeded, got {}",
            bundle.len()
        );
        total_chunks_bundled += bundle.len();
        max_bundle_seen = max_bundle_seen.max(bundle.len());
    }

    assert!(
        max_bundle_seen > 1,
        "expected at least one multi-chunk bundle with bundle_size=10 on an \
         8 KB shard, but every publish had <= 1 chunk"
    );

    drop(video_tx);
    drop(_audio_tx);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;

    // Compare against unbundled run with the same input — total chunk counts
    // should match (bundling doesn't change how many symbols fountain_chunkify
    // produces, only how many publishes they're spread across).
    let counter_baseline = Arc::new(AtomicUsize::new(0));
    let egress_baseline = RecordingEgress::new(counter_baseline.clone());
    let bytes_baseline = egress_baseline.published_bytes.clone();
    let (video_tx2, _audio_tx2, handle2) = build_media_egress(egress_baseline).await;
    video_tx2.send(make_video_shard(8192)).await.unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let total_chunks_baseline = bytes_baseline
        .lock()
        .unwrap()
        .iter()
        .filter_map(|p| postcard::from_bytes::<Vec<ShardChunk>>(p).ok())
        .map(|v| v.len())
        .sum::<usize>();

    assert_eq!(
        total_chunks_bundled, total_chunks_baseline,
        "total chunk count differs between bundled ({}) and baseline ({}) — \
         bundling changed semantics, not just transport batching",
        total_chunks_bundled, total_chunks_baseline
    );

    drop(video_tx2);
    drop(_audio_tx2);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle2).await;
}

// =====================================================================
// Proximity: witnesses sealed and published with the recording
// =====================================================================

/// A proximity witness should be sealed into a signed `Evidence::Proximity`
/// envelope, fountain-encoded, and published — the egress half of the
/// corroboration path (the Stronghold's `collect_proximity` is the other half).
#[tokio::test]
async fn test_proximity_witness_published() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (_video_tx, _audio_tx, proximity_tx, handle) = build_media_egress_full(
        RecordingEgress::new(counter.clone()),
        phalanx_proto::types::SymbolBundleSize::default(),
    )
    .await;

    let witness = ProximityWitness {
        local_did: phalanx_proto::identity::Did::new("did:key:zlocal"),
        remote_did: phalanx_proto::identity::Did::new("did:key:zremote"),
        recording_id: RecordingId::new("prox-test"),
        observed_at: phalanx_proto::time::PhalanxTimestamp::from_millis(1_000),
        transport: phalanx_proto::topology::TransportClass::LocalMesh,
    };
    proximity_tx.send(witness).await.unwrap();
    // Give the actor time to seal + fountain encode + publish.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let count = counter.load(Ordering::Relaxed);
    assert!(
        count > 0,
        "Proximity witness should produce at least one published symbol, got {}",
        count
    );

    drop(_video_tx);
    drop(_audio_tx);
    drop(proximity_tx);
    let _ = tokio::time::timeout(Duration::from_secs(10), handle).await;
}
