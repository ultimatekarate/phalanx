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
//! End-to-end retrieval request/response round-trip tests.
//!
//! These cover the `Libp2pEgress::send_response` fix: previously a no-op,
//! now wired through to libp2p's `request_response::Behaviour::send_response`.
//! Without this fix, every `RecordingRequested` event produced a silently-
//! dropped reply on the wire and the requester would time out at 20s.
//!
//! `RR1` proves the full path composes: A sends a `RecordingRequest`, B's
//! ingress yields `RecordingRequested`, B replies via `send_response`,
//! A's ingress yields `ShardResponseReceived`. Uses
//! `RecordingResponse::Success(vec![])` to round-trip a typed payload through
//! libp2p's request_response codec without needing real `WitnessEnvelope`
//! fixtures (the empty-vec branch of the translation arm at libp2p.rs).
//!
//! `RR2` is a fail-soft check: calling `send_response` with an unknown
//! `channel_id` must increment the `response_channels_lost` counter and not
//! panic.

use std::sync::atomic::Ordering;
use std::time::Duration;

use phalanx_proto::evidence::retrieval::{RecordingRequest, RecordingResponse};
use phalanx_proto::identity::crypto::{GrantPermissions, SealedLocator};
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

fn make_request() -> RecordingRequest {
    let recording_id = RecordingId::new("test-recording");
    let recipient = Did::new("did:test:recipient");
    let sender = Did::new("did:test:sender");
    RecordingRequest {
        target_did: sender.clone(),
        recording_id: recording_id.clone(),
        locator: SealedLocator {
            target: recording_id,
            recipient,
            sender,
            sealed_key: vec![],
            nonce: vec![],
            permissions: GrantPermissions::default(),
        },
        signature: vec![],
    }
}

/// Drain any pending events from an ingress without blocking.
async fn drain(ingress: &mut Libp2pIngress) {
    while tokio::time::timeout(Duration::from_millis(10), ingress.next_event())
        .await
        .is_ok()
    {}
}

/// Wait for a specific NetworkEvent variant from an ingress, returning it on success.
/// Returns None if the timeout elapses without a matching event. Other event
/// variants are discarded.
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
async fn rr1_request_response_round_trip_delivers_reply() {
    // Bring up two libp2p nodes on disjoint loopback IPs so gossipsub's
    // ip-colocation penalty doesn't fire. Node B bootstraps from Node A.
    const PORT_A: u16 = 39810;
    const PORT_B: u16 = 39811;

    let identity_a = PhalanxIdentity::new_ephemeral();
    let identity_b = PhalanxIdentity::new_ephemeral();
    // Note: must use `Libp2pExt::to_network_id()` (PeerId multihash base58), not
    // `identity.network_id` (raw pubkey base58). They produce different strings;
    // only the former round-trips through `PeerMapper::from_network_id`.
    let network_id_b = identity_b.to_mesh_address();

    let (mut ingress_a, egress_a) =
        build_mesh_transport(&identity_a, &make_config(PORT_A, 1, vec![]))
            .expect("Node A failed to build");

    let (mut ingress_b, egress_b) = build_mesh_transport(
        &identity_b,
        &make_config(PORT_B, 2, vec![format!("/ip4/127.0.0.1/tcp/{PORT_A}")]),
    )
    .expect("Node B failed to build");

    // Let mDNS / bootstrap establish a connection.
    tokio::time::sleep(SETUP_WAIT).await;
    drain(&mut ingress_a).await;
    drain(&mut ingress_b).await;

    // A sends a RecordingRequest addressed to B.
    egress_a
        .send_request(&network_id_b, make_request())
        .await
        .expect("send_request");

    // B's ingress should yield RecordingRequested with a channel_id.
    let event = await_event(&mut ingress_b, Duration::from_secs(15), |ev| {
        matches!(ev, NetworkEvent::RecordingRequested { .. })
    })
    .await
    .expect("Node B did not receive RecordingRequested");
    let channel_id = match event {
        NetworkEvent::RecordingRequested { channel_id, .. } => channel_id,
        _ => unreachable!(),
    };

    // B replies on that channel with an empty Success payload.
    egress_b
        .send_response(&channel_id, RecordingResponse::Success(vec![]))
        .await
        .expect("send_response");

    // A's ingress should now receive ShardResponseReceived with empty envelopes.
    let response = await_event(&mut ingress_a, Duration::from_secs(15), |ev| {
        matches!(ev, NetworkEvent::ShardResponseReceived { .. })
    })
    .await
    .expect("Node A did not receive ShardResponseReceived (libp2p send_response is broken)");

    match response {
        NetworkEvent::ShardResponseReceived { envelopes, .. } => {
            assert!(
                envelopes.is_empty(),
                "expected empty envelopes for Success(vec![])"
            );
        }
        _ => unreachable!(),
    }

    // Lost-counter should be 0 — the round-trip succeeded, no expirations.
    assert_eq!(
        egress_b.response_channels_lost().load(Ordering::Relaxed),
        0,
        "Node B's lost-counter should be 0 after a successful round trip"
    );
}

#[tokio::test]
async fn rr2_send_response_with_unknown_channel_id_increments_lost_counter() {
    const PORT: u16 = 39820;

    let identity = PhalanxIdentity::new_ephemeral();
    let (_ingress, egress) = build_mesh_transport(&identity, &make_config(PORT, 1, vec![]))
        .expect("Node failed to build");

    // No request has arrived, so no channel_id is registered. The actor will
    // log a warning and increment the lost-counter.
    egress
        .send_response("nonexistent-channel-id", RecordingResponse::Success(vec![]))
        .await
        .expect("send_response should enqueue successfully");

    // Give the actor a moment to process the command.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_eq!(
        egress.response_channels_lost().load(Ordering::Relaxed),
        1,
        "lost-counter should bump exactly once for an unknown channel_id"
    );
}
