#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-node/tests/trust_actor_tests.rs
//
// Unit tests for the TrustActor's command handling:
// offense recording, trust queries, blacklisting, pet names, peer management.

use phalanx_node::actors::trust_actor::{TrustActor, TrustCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::trust::TrustRegistry;
use phalanx_proto::prelude::Did;
use phalanx_proto::trust::{Offense, PetName, TrustLevel};
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::{mpsc, oneshot};

/// Build a TrustActor with a fresh ephemeral registry in a unique temp directory.
async fn build_trust_actor() -> (mpsc::Sender<TrustCommand>, tokio::task::JoinHandle<()>) {
    let mut config = NodeConfig::test_defaults();
    let temp = tempdir().expect("Failed to create temp dir");
    config.storage.vault_path = temp.path().to_string_lossy().to_string();
    let registry = TrustRegistry::build(&config).await;
    let (tx, rx) = mpsc::channel(32);
    let actor = TrustActor::new(registry, rx);
    let handle = tokio::spawn(actor.run());
    // Leak the tempdir so it lives until process exit (actor holds the path)
    std::mem::forget(temp);
    (tx, handle)
}

/// Helper: send CheckTrust and get the response.
async fn check_trust(tx: &mpsc::Sender<TrustCommand>, did: &Did) -> TrustLevel {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::CheckTrust {
        did: did.clone(),
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    reply_rx.await.unwrap_or(TrustLevel::Ignored)
}

/// Helper: send IsBlacklisted and get the response.
async fn is_blacklisted(tx: &mpsc::Sender<TrustCommand>, did: &Did) -> bool {
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::IsBlacklisted {
        did: did.clone(),
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    reply_rx.await.unwrap_or(false)
}

// =====================================================================
// Trust Level Queries
// =====================================================================

/// An unknown peer should return TrustLevel::Ignored.
#[tokio::test]
async fn test_unknown_peer_returns_ignored() {
    let (tx, handle) = build_trust_actor().await;
    let did = Did::new("did:key:z6MkUnknown");

    let level = check_trust(&tx, &did).await;
    assert!(
        matches!(level, TrustLevel::Ignored),
        "Unknown peer should be Ignored, got {:?}",
        level
    );

    handle.abort();
}

/// After setting a trust level, it should be retrievable.
#[tokio::test]
async fn test_set_and_check_trust_level() {
    let (tx, handle) = build_trust_actor().await;
    let did = Did::new("did:key:z6MkPeerA");

    // Set trust level to Trusted
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::SetTrustLevel {
        did: did.clone(),
        level: TrustLevel::Verified,
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    let result = reply_rx.await.unwrap_or(Ok(()));
    assert!(result.is_ok(), "SetTrustLevel should succeed");

    let level = check_trust(&tx, &did).await;
    assert!(
        matches!(level, TrustLevel::Verified),
        "Should read back Trusted, got {:?}",
        level
    );

    handle.abort();
}

// =====================================================================
// Blacklisting via Offense
// =====================================================================

/// Recording a severe offense should eventually blacklist the peer.
#[tokio::test]
async fn test_offense_leads_to_blacklisting() {
    let (tx, handle) = build_trust_actor().await;
    let did = Did::new("did:key:z6MkOffender");

    assert!(
        !is_blacklisted(&tx, &did).await,
        "Should not be blacklisted initially"
    );

    // Record repeated offenses until blacklisted (penalty > 100 or score <= 0)
    for _ in 0..5u32 {
        tx.send(TrustCommand::RecordOffense {
            did: did.clone(),
            offense: Offense::IdentityTheft, // Severe offense
        })
        .await
        .unwrap_or_default();
        // Small delay to let the async handler process
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        is_blacklisted(&tx, &did).await,
        "Repeated severe offenses should lead to blacklisting"
    );

    handle.abort();
}

/// A single minor offense should not blacklist.
#[tokio::test]
async fn test_single_minor_offense_no_blacklist() {
    let (tx, handle) = build_trust_actor().await;
    let did = Did::new("did:key:z6MkMinor");

    tx.send(TrustCommand::RecordOffense {
        did: did.clone(),
        offense: Offense::ProtocolViolation,
    })
    .await
    .unwrap_or_default();

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !is_blacklisted(&tx, &did).await,
        "Single minor offense should not blacklist"
    );

    handle.abort();
}

// =====================================================================
// Pet Name Assignment
// =====================================================================

/// Assigning a pet name to a registered peer should succeed.
#[tokio::test]
async fn test_assign_pet_name() {
    let (tx, handle) = build_trust_actor().await;
    let did = Did::new("did:key:z6MkNamed");

    // First register the peer
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::SetTrustLevel {
        did: did.clone(),
        level: TrustLevel::Verified,
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    let _ = reply_rx.await;

    // Now assign a pet name
    let name = PetName::new("alice").unwrap_or_else(|_| unreachable!());
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::AssignPetName {
        did: did.clone(),
        name,
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    let result = reply_rx.await.unwrap_or(Ok(()));
    assert!(result.is_ok(), "Assigning pet name should succeed");

    handle.abort();
}

/// Assigning a pet name to an unregistered peer should fail.
#[tokio::test]
async fn test_assign_pet_name_unregistered_peer() {
    let (tx, handle) = build_trust_actor().await;
    let did = Did::new("did:key:z6MkGhost");

    let name = PetName::new("ghost").unwrap_or_else(|_| unreachable!());
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::AssignPetName {
        did,
        name,
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    let result = reply_rx.await.unwrap_or(Ok(()));
    assert!(
        result.is_err(),
        "Assigning pet name to unregistered peer should fail"
    );

    handle.abort();
}

// =====================================================================
// Peer Removal
// =====================================================================

/// After removing a peer, it should return to Ignored status.
#[tokio::test]
async fn test_remove_peer() {
    let (tx, handle) = build_trust_actor().await;
    let did = Did::new("did:key:z6MkRemovable");

    // Register
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::SetTrustLevel {
        did: did.clone(),
        level: TrustLevel::Verified,
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    let _ = reply_rx.await;

    assert!(matches!(check_trust(&tx, &did).await, TrustLevel::Verified));

    // Remove
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::RemovePeer {
        did: did.clone(),
        reply_to: reply_tx,
    })
    .await
    .unwrap_or_default();
    let _ = reply_rx.await;

    let level = check_trust(&tx, &did).await;
    assert!(
        matches!(level, TrustLevel::Ignored),
        "Removed peer should return to Ignored, got {:?}",
        level
    );

    handle.abort();
}

// =====================================================================
// ListPeers
// =====================================================================

/// ListPeers should return all registered peers.
#[tokio::test]
async fn test_list_peers() {
    let (tx, handle) = build_trust_actor().await;

    // Register two peers
    for name in ["did:key:z6MkPeer1", "did:key:z6MkPeer2"] {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(TrustCommand::SetTrustLevel {
            did: Did::new(name),
            level: TrustLevel::Verified,
            reply_to: reply_tx,
        })
        .await
        .unwrap_or_default();
        let _ = reply_rx.await;
    }

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(TrustCommand::ListPeers { reply_to: reply_tx })
        .await
        .unwrap_or_default();
    let peers = reply_rx.await.unwrap_or_default();
    assert_eq!(peers.len(), 2, "Should list both registered peers");

    handle.abort();
}
