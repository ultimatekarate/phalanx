#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-node/tests/egress_tests.rs
//
// Unit tests for the EgressActor's retry state machine,
// dedup window, queue shedding, and dispatch behavior.

use phalanx_node::actors::egress::{EgressActor, EgressCommand};
use phalanx_node::actors::shutdown::ShutdownSignal;
use phalanx_node::clock::TrustedClock;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::identity::{MeshAddress, RecordingId};
use phalanx_proto::network::EgressPort;
use phalanx_proto::prelude::{MeshTopic, PhalanxTimestamp, RecordingResponse};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

// --- Test Doubles ---

/// An egress port that always succeeds.
#[derive(Clone)]
struct SuccessEgress;

#[async_trait::async_trait]
impl EgressPort for SuccessEgress {
    async fn publish(&self, _: &MeshTopic, _: Vec<u8>) -> Result<(), String> {
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

/// An egress port that always fails.
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

/// An egress port that counts successful dispatches.
#[derive(Clone)]
struct CountingEgress {
    dispatch_count: Arc<AtomicUsize>,
}

#[async_trait::async_trait]
impl EgressPort for CountingEgress {
    async fn publish(&self, _: &MeshTopic, _: Vec<u8>) -> Result<(), String> {
        Ok(())
    }
    async fn ban_peer(&self, _: &MeshAddress) {}
    async fn send_response(&self, _: &str, _: RecordingResponse) -> Result<(), String> {
        self.dispatch_count.fetch_add(1, Ordering::Relaxed);
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

// =====================================================================
// Successful Dispatch
// =====================================================================

/// A dispatch to a healthy transport should succeed immediately without retries.
#[tokio::test]
async fn test_dispatch_success_no_retry() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel(32);
    let gov = Arc::new(SystemGovernor::new());

    let actor = EgressActor::new(
        CountingEgress {
            dispatch_count: counter.clone(),
        },
        rx,
        vec![],
        gov,
        Arc::new(TrustedClock::new()),
        phalanx_proto::topic::MeshTopic::new("/phalanx/control"),
        ShutdownSignal::new(),
    );
    let handle = tokio::spawn(actor.run());

    tx.send(EgressCommand::Dispatch {
        channel_id: "ch-1".to_string(),
        response: RecordingResponse::Unauthorized,
    })
    .await
    .unwrap_or_default();

    // Give actor time to process
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        counter.load(Ordering::Relaxed),
        1,
        "Should dispatch exactly once on success"
    );

    handle.abort();
}

// =====================================================================
// Failed Dispatch Queues for Retry
// =====================================================================

/// A dispatch to a failing transport should queue the message for retry.
/// After DrainForSalvage, we should get the pending items back.
#[tokio::test]
async fn test_dispatch_failure_queues_for_retry() {
    let (tx, rx) = mpsc::channel(32);
    let gov = Arc::new(SystemGovernor::new());

    let actor = EgressActor::new(
        FailingEgress,
        rx,
        vec![],
        gov,
        Arc::new(TrustedClock::new()),
        phalanx_proto::topic::MeshTopic::new("/phalanx/control"),
        ShutdownSignal::new(),
    );
    let handle = tokio::spawn(actor.run());

    // Send a dispatch that will fail
    tx.send(EgressCommand::Dispatch {
        channel_id: "ch-fail".to_string(),
        response: RecordingResponse::Unauthorized,
    })
    .await
    .unwrap_or_default();

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drain and verify the pending queue
    let (drain_tx, drain_rx) = oneshot::channel();
    tx.send(EgressCommand::DrainForSalvage { reply_to: drain_tx })
        .await
        .unwrap_or_default();

    let pending = drain_rx.await.unwrap_or_default();
    assert_eq!(
        pending.len(),
        1,
        "Failed dispatch should be queued for retry"
    );
    assert_eq!(pending[0].channel_id, "ch-fail");
    assert_eq!(pending[0].attempt_count, 1);

    let _ = handle.await;
}

// =====================================================================
// DHT Announce Deduplication
// =====================================================================

/// Duplicate DHT announces within the 30s window should be suppressed.
#[tokio::test]
async fn test_dht_announce_dedup() {
    let counter = Arc::new(AtomicUsize::new(0));
    let (tx, rx) = mpsc::channel(32);
    let gov = Arc::new(SystemGovernor::new());

    // Use a custom port that counts announce calls
    #[derive(Clone)]
    struct AnnounceCounter(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl EgressPort for AnnounceCounter {
        async fn publish(&self, _: &MeshTopic, _: Vec<u8>) -> Result<(), String> {
            Ok(())
        }
        async fn ban_peer(&self, _: &MeshAddress) {}
        async fn send_response(&self, _: &str, _: RecordingResponse) -> Result<(), String> {
            Ok(())
        }
        async fn announce_recording(&self, _: &RecordingId) -> Result<(), String> {
            self.0.fetch_add(1, Ordering::Relaxed);
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

    let actor = EgressActor::new(
        AnnounceCounter(counter.clone()),
        rx,
        vec![],
        gov,
        Arc::new(TrustedClock::new()),
        phalanx_proto::topic::MeshTopic::new("/phalanx/control"),
        ShutdownSignal::new(),
    );
    let handle = tokio::spawn(actor.run());

    let recording = RecordingId::new("rec-1");

    // Send the same announce 3 times
    for _ in 0..3u32 {
        tx.send(EgressCommand::AnnounceRecording(recording.clone()))
            .await
            .unwrap_or_default();
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        counter.load(Ordering::Relaxed),
        1,
        "Duplicate announces within 30s window should be deduplicated"
    );

    handle.abort();
}

// =====================================================================
// Salvage: Drain Pending Queue
// =====================================================================

/// Salvaged items passed at construction should be available via DrainForSalvage.
#[tokio::test]
async fn test_salvaged_items_restored() {
    let (tx, rx) = mpsc::channel(32);
    let gov = Arc::new(SystemGovernor::new());

    let salvaged = vec![phalanx_proto::storage::PendingEgress {
        channel_id: "salvaged-ch".to_string(),
        response: RecordingResponse::Unauthorized,
        attempt_count: 2,
        next_attempt: PhalanxTimestamp::from_millis(0),
    }];

    let actor = EgressActor::new(
        SuccessEgress,
        rx,
        salvaged,
        gov,
        Arc::new(TrustedClock::new()),
        phalanx_proto::topic::MeshTopic::new("/phalanx/control"),
        ShutdownSignal::new(),
    );
    let handle = tokio::spawn(actor.run());

    let (drain_tx, drain_rx) = oneshot::channel();
    tx.send(EgressCommand::DrainForSalvage { reply_to: drain_tx })
        .await
        .unwrap_or_default();

    let pending = drain_rx.await.unwrap_or_default();
    assert_eq!(pending.len(), 1, "Salvaged items should be restored");
    assert_eq!(pending[0].channel_id, "salvaged-ch");
    assert_eq!(pending[0].attempt_count, 2);

    let _ = handle.await;
}

// =====================================================================
// PublishHeartbeat
// =====================================================================

type PublishLog = Arc<std::sync::Mutex<Vec<(MeshTopic, Vec<u8>)>>>;

/// Captures every publish() call so we can assert the topic and decoded
/// payload after PublishHeartbeat is handled.
#[derive(Clone)]
struct RecordingEgress {
    publishes: PublishLog,
}

#[async_trait::async_trait]
impl EgressPort for RecordingEgress {
    async fn publish(&self, topic: &MeshTopic, data: Vec<u8>) -> Result<(), String> {
        self.publishes
            .lock()
            .expect("publish recorder poisoned")
            .push((topic.clone(), data));
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

/// `EgressCommand::PublishHeartbeat(msg)` must invoke `port.publish` exactly
/// once on the configured control topic with a postcard-decodable
/// `ControlMessage` payload.
#[tokio::test]
async fn test_publish_heartbeat_emits_one_postcard_publish_on_control_topic() {
    let publishes = Arc::new(std::sync::Mutex::new(Vec::new()));
    let port = RecordingEgress {
        publishes: publishes.clone(),
    };
    let (tx, rx) = mpsc::channel(8);
    let gov = Arc::new(SystemGovernor::new());
    let control_topic = MeshTopic::new("/phalanx/control");

    let actor = EgressActor::new(
        port,
        rx,
        vec![],
        gov,
        Arc::new(TrustedClock::new()),
        control_topic.clone(),
        ShutdownSignal::new(),
    );
    let handle = tokio::spawn(actor.run());

    let msg = phalanx_proto::vitals::ControlMessage {
        sender: MeshAddress::new("peer-A".to_string()),
        load_factor: phalanx_proto::vitals::StressLoad(0.42),
        storage_remaining_mb: 4096,
        heartbeat_ms: 5_000,
        is_leaf: false,
        integral_summary: None,
    };
    tx.send(EgressCommand::PublishHeartbeat(msg.clone()))
        .await
        .unwrap();

    // Drain the actor so we can inspect the recorder.
    let (drain_tx, drain_rx) = oneshot::channel();
    tx.send(EgressCommand::DrainForSalvage { reply_to: drain_tx })
        .await
        .unwrap();
    let _ = drain_rx.await;
    let _ = handle.await;

    let recorded = publishes.lock().expect("recorder poisoned").clone();
    assert_eq!(
        recorded.len(),
        1,
        "PublishHeartbeat must invoke port.publish exactly once"
    );
    let (topic, data) = &recorded[0];
    assert_eq!(
        topic.as_str(),
        control_topic.as_str(),
        "Heartbeat must publish on the configured control topic"
    );
    let decoded: phalanx_proto::vitals::ControlMessage =
        postcard::from_bytes(data).expect("payload must be postcard-decodable");
    assert_eq!(decoded.sender, msg.sender);
    // postcard is byte-identical for `f32`, so the round-trip preserves bits.
    assert_eq!(
        decoded.load_factor.as_f32().to_bits(),
        msg.load_factor.as_f32().to_bits()
    );
    assert_eq!(decoded.storage_remaining_mb, msg.storage_remaining_mb);
    assert_eq!(decoded.heartbeat_ms, msg.heartbeat_ms);
    assert_eq!(decoded.is_leaf, msg.is_leaf);
}
