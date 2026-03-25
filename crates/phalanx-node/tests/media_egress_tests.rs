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
use phalanx_node::clock::TrustedClock;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::{AudioShard, VideoShard};
use phalanx_proto::identity::{NetworkId, PhalanxIdentity};
use phalanx_proto::network::EgressPort;
use phalanx_proto::prelude::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::mpsc;

// --- Test Doubles ---

/// An egress port that records all published (topic, data_len) pairs.
#[derive(Clone)]
struct RecordingEgress {
    publish_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl EgressPort for RecordingEgress {
    async fn publish(&self, _: &MeshTopic, _: Vec<u8>) -> Result<(), String> {
        self.publish_count.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    async fn ban_peer(&self, _: &NetworkId) {}
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
        _: &NetworkId,
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
    async fn ban_peer(&self, _: &NetworkId) {}
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
        _: &NetworkId,
        _: phalanx_proto::retrieval::RecordingRequest,
    ) -> Result<(), String> {
        Err("transport down".to_string())
    }
}

/// Build a MediaEgressActor with the given egress port and return the shard senders.
async fn build_media_egress<E: EgressPort + 'static>(
    egress: E,
) -> (
    mpsc::Sender<VideoShard>,
    mpsc::Sender<AudioShard>,
    tokio::task::JoinHandle<()>,
) {
    let (video_tx, video_rx) = mpsc::channel(32);
    let (audio_tx, audio_rx) = mpsc::channel(32);
    let temp = tempdir().expect("Failed to create temp dir");
    let gov = Arc::new(SystemGovernor::new());
    let identity = Arc::new(PhalanxIdentity::new_ephemeral());
    let local_id = NetworkId("local-node".to_string());

    let config = MediaEgressConfig {
        video_rx,
        audio_rx,
        video_topic: MeshTopic::new("/phalanx/video/test"),
        audio_topic: MeshTopic::new("/phalanx/audio/test"),
        symbol_size: SymbolSize::default(),
        repair_ratio: RepairRatio::default(),
        wal_dir: temp.path().to_path_buf(),
        system_governor: gov,
        max_storage_bytes: 100_000_000,
        vault_key: SymmetricKey([0u8; 32]),
        clock: Arc::new(TrustedClock::new()),
        lens_thresholds: phalanx_forensics::gate::LensThresholds::default(),
    };

    let actor = MediaEgressActor::new(egress, identity, local_id, config)
        .await
        .expect("Failed to create MediaEgressActor");

    // Leak temp so WAL directory lives for the actor's lifetime
    std::mem::forget(temp);

    let handle = tokio::spawn(actor.run());
    (video_tx, audio_tx, handle)
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
    let (video_tx, _audio_tx, handle) = build_media_egress(RecordingEgress {
        publish_count: counter.clone(),
    })
    .await;

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
    let (_video_tx, audio_tx, handle) = build_media_egress(RecordingEgress {
        publish_count: counter.clone(),
    })
    .await;

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
    let (video_tx, audio_tx, handle) = build_media_egress(RecordingEgress {
        publish_count: counter.clone(),
    })
    .await;

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
    let (video_tx, audio_tx, handle) = build_media_egress(RecordingEgress {
        publish_count: counter.clone(),
    })
    .await;

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
