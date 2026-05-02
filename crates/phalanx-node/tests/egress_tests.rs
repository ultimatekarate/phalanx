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

// `EgressCommand::PublishHeartbeat` was removed when heartbeats moved to
// per-community encryption — see `vitals_handle` in `meshsentinel.rs`,
// which now derives a community key, encrypts via ChaCha20-Poly1305, and
// emits `EgressCommand::PublishMesh { topic, data }` exactly like canary
// alerts. End-to-end heartbeat publish-and-receive coverage lives in the
// Phase 3 simulation tests.
