#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::float_cmp
)]
//! End-to-end round-trip for the directed archive PUSH protocol
//! (`/phalanx/archive/1.0.0`).
//!
//! Proves the full unicast path composes over real libp2p swarms: A sends an
//! `ArchiveRequest` (the initiator carries the payload — unlike retrieval), B's
//! ingress yields `ArchiveRequested` with a `channel_id`, B replies via
//! `send_archive_response`, and A's ingress yields `ArchiveReceiptReceived`.
//! The request is unsigned here — signature verification lives at the receiver
//! (sentinel/forensics) layer, not the transport.

use std::time::Duration;

use phalanx_proto::archive::{ArchiveReceipt, ArchiveRequest};
use phalanx_proto::identity::{Did, PhalanxIdentity, RecordingId};
use phalanx_proto::network::{EgressPort, IngressPort, NetworkEvent};
use phalanx_transport::adapters::libp2p::{AdapterConfig, Libp2pIngress};
use phalanx_transport::config::MeshTransportConfig;
use phalanx_transport::factory::build_mesh_transport;
use phalanx_transport::identity_ext::Libp2pExt;

const SETUP_WAIT: Duration = Duration::from_secs(8);
const POLL_TIMEOUT: Duration = Duration::from_millis(100);

fn make_config(port: u16, ip_octet: u8, bootstrap: Vec<String>) -> MeshTransportConfig {
    MeshTransportConfig {
        listen_addresses: vec![format!("/ip4/127.0.0.{ip_octet}/tcp/{port}")],
        bootstrap_peers: bootstrap,
        subscribe_topics: vec![],
        adapter: AdapterConfig::default(),
        ..MeshTransportConfig::default()
    }
}

fn make_push() -> ArchiveRequest {
    ArchiveRequest {
        recording_id: RecordingId::new("archive-recording"),
        envelopes: vec![],
        sender_did: Did::new("did:test:pusher"),
        signature: vec![],
    }
}

async fn drain(ingress: &mut Libp2pIngress) {
    while tokio::time::timeout(Duration::from_millis(10), ingress.next_event())
        .await
        .is_ok()
    {}
}

async fn await_event<F>(
    ingress: &mut Libp2pIngress,
    timeout: Duration,
    matcher: F,
) -> Option<NetworkEvent>
where
    F: Fn(&NetworkEvent) -> bool,
{
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let step = remaining.min(POLL_TIMEOUT);
        match tokio::time::timeout(step, ingress.next_event()).await {
            Ok(Some(ev)) if matcher(&ev) => return Some(ev),
            Ok(Some(_)) => continue,
            Ok(None) => return None,
            Err(_) => continue,
        }
    }
}

#[tokio::test]
async fn archive_push_round_trip_delivers_receipt() {
    const PORT_A: u16 = 39830;
    const PORT_B: u16 = 39831;

    let identity_a = PhalanxIdentity::new_ephemeral();
    let identity_b = PhalanxIdentity::new_ephemeral();
    let mesh_addr_b = identity_b.to_mesh_address();

    let (mut ingress_a, egress_a) =
        build_mesh_transport(&identity_a, &make_config(PORT_A, 1, vec![]))
            .expect("Node A failed to build");

    let (mut ingress_b, egress_b) = build_mesh_transport(
        &identity_b,
        &make_config(PORT_B, 2, vec![format!("/ip4/127.0.0.1/tcp/{PORT_A}")]),
    )
    .expect("Node B failed to build");

    tokio::time::sleep(SETUP_WAIT).await;
    drain(&mut ingress_a).await;
    drain(&mut ingress_b).await;

    // A pushes a recording to B (the custody target).
    egress_a
        .send_archive_request(&mesh_addr_b, make_push())
        .await
        .expect("send_archive_request");

    // B's ingress should yield ArchiveRequested with a channel_id.
    let event = await_event(&mut ingress_b, Duration::from_secs(15), |ev| {
        matches!(ev, NetworkEvent::ArchiveRequested { .. })
    })
    .await
    .expect("Node B did not receive ArchiveRequested");
    let channel_id = match event {
        NetworkEvent::ArchiveRequested { channel_id, .. } => channel_id,
        _ => unreachable!(),
    };

    // B replies with a custody receipt on that channel.
    egress_b
        .send_archive_response(&channel_id, ArchiveReceipt::Busy)
        .await
        .expect("send_archive_response");

    // A's ingress should now receive ArchiveReceiptReceived.
    let receipt = await_event(&mut ingress_a, Duration::from_secs(15), |ev| {
        matches!(ev, NetworkEvent::ArchiveReceiptReceived { .. })
    })
    .await
    .expect("Node A did not receive ArchiveReceiptReceived");

    match receipt {
        NetworkEvent::ArchiveReceiptReceived { receipt, .. } => {
            assert!(
                matches!(receipt, ArchiveReceipt::Busy),
                "expected the Busy receipt to round-trip, got {receipt:?}"
            );
        }
        _ => unreachable!(),
    }
}
