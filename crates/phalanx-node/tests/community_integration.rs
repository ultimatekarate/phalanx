#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-node/tests/community_integration.rs
//
// Phase 6 actor-level integration coverage for Trusted Communities.
//
// The FFI surface (`phalanx_import_community`, `phalanx_list_communities`,
// `phalanx_get_community`, `phalanx_dissolve_community`, `phalanx_preview_community`)
// routes every write through `TrustCommand::*`. These tests exercise the
// actor directly, bypassing the C-ABI marshaling layer — FFI-only concerns
// (the two-call buffer protocol, version envelope) are covered by the
// inline test module in `crates/phalanx-ffi/src/community.rs`.
//
// The actor uses a concrete `SystemClock` internally (see
// `trust_actor.rs::run_maintenance`), so maintenance-tick semantics are
// tested against `TrustRegistry::dissolve_expired_communities` directly.

use ed25519_dalek::SigningKey;
use phalanx_forensics::identity::{assemble_community, sign_vouch, CommunityAssemblyParams};
use phalanx_node::actors::trust_actor::{TrustActor, TrustCommand};
use phalanx_node::config::NodeConfig;
use phalanx_node::trust::TrustRegistry;
use phalanx_proto::community::{
    CeremonyMember, CommunityGrants, CommunityId, CommunityVerifyError, DissolveOutcome,
    ImportOutcome, Quorum,
};
use phalanx_proto::identity::Did;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::{PetName, TrustLevel};
use rand_core::OsRng;
use std::time::Duration;
use tempfile::tempdir;
use tokio::sync::{mpsc, oneshot};

// ─── Harness helpers ───────────────────────────────────────────────────

async fn build_actor() -> (mpsc::Sender<TrustCommand>, tokio::task::JoinHandle<()>) {
    let mut config = NodeConfig::test_defaults();
    let temp = tempdir().expect("tempdir");
    config.storage.vault_path = temp.path().to_string_lossy().to_string();
    let registry = TrustRegistry::build(&config).await;
    let (tx, rx) = mpsc::channel(32);
    let actor = TrustActor::new(registry, rx);
    let handle = tokio::spawn(actor.run());
    // Leak so the vault dir outlives this scope — actor owns the path.
    std::mem::forget(temp);
    (tx, handle)
}

fn make_identity() -> (Did, SigningKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let did = Did::derive_did_key(&sk.verifying_key().to_bytes());
    (did, sk)
}

/// Build a fully-signed `Community` with the given expiration, using the
/// canonical ceremony verb so vouches cryptographically verify.
fn build_valid_community(
    name: &str,
    now: PhalanxTimestamp,
    expires_at: PhalanxTimestamp,
) -> phalanx_proto::community::Community {
    let (voucher_a_did, voucher_a_sk) = make_identity();
    let (voucher_b_did, voucher_b_sk) = make_identity();
    let (member_did, _) = make_identity();

    let pet = PetName::new(name).expect("valid pet name");
    let quorum = Quorum::new(2).expect("quorum 2");

    let tentative = CommunityId::compute(&pet, quorum, std::slice::from_ref(&member_did));
    let vouch_a = sign_vouch(&voucher_a_sk, &voucher_a_did, &member_did, &tentative, now);
    let vouch_b = sign_vouch(&voucher_b_sk, &voucher_b_did, &member_did, &tentative, now);

    let params = CommunityAssemblyParams {
        name: pet,
        quorum,
        joined_at: now,
        expires_at,
        stronghold_did: None,
        baseline_trust: TrustLevel::Verified,
        grants: CommunityGrants::default(),
        members: vec![CeremonyMember {
            did: member_did,
            vouches: vec![vouch_a, vouch_b],
        }],
    };
    assemble_community(params, now).expect("assembly")
}

fn now_millis() -> PhalanxTimestamp {
    use phalanx_proto::time::{SystemClock, TrustedClock};
    SystemClock.now()
}

// ─── Happy path — import, list, get, dissolve ──────────────────────────

#[tokio::test]
async fn import_list_get_dissolve_roundtrip() {
    let (tx, handle) = build_actor().await;
    let now = now_millis();
    // 10-minute window keeps us well inside [MIN_EXPIRES_SECS, MAX_EXPIRES_SECS].
    let expires = PhalanxTimestamp(now.0 + 10 * 60_000);
    let community = build_valid_community("ACLU-Portland", now, expires);
    let expected_id = community.fingerprint;

    // ── ImportCommunity ──
    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::ImportCommunity {
        community,
        reply_to: r_tx,
    })
    .await
    .unwrap();
    match r_rx.await.unwrap() {
        ImportOutcome::Ok(id) => assert_eq!(id, expected_id),
        ImportOutcome::Err(e) => panic!("import should succeed, got {e:?}"),
    }

    // ── ListCommunities ──
    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::ListCommunities { reply_to: r_tx })
        .await
        .unwrap();
    let summaries = r_rx.await.unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(summaries[0].id, expected_id);
    assert_eq!(summaries[0].member_count, 1);

    // ── GetCommunity ──
    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::GetCommunity {
        community_id: expected_id,
        reply_to: r_tx,
    })
    .await
    .unwrap();
    let roster = r_rx.await.unwrap().expect("roster present");
    assert_eq!(roster.summary.id, expected_id);
    assert_eq!(roster.members.len(), 1);

    // ── DissolveCommunity ──
    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::DissolveCommunity {
        community_id: expected_id,
        reply_to: r_tx,
    })
    .await
    .unwrap();
    match r_rx.await.unwrap() {
        DissolveOutcome::Ok(id) => assert_eq!(id, expected_id),
        other => panic!("dissolve should succeed, got {other:?}"),
    }

    // ── ListCommunities again — empty ──
    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::ListCommunities { reply_to: r_tx })
        .await
        .unwrap();
    let summaries = r_rx.await.unwrap();
    assert!(summaries.is_empty(), "registry empty after dissolve");

    handle.abort();
}

// ─── Unknown community id paths ────────────────────────────────────────

#[tokio::test]
async fn get_community_unknown_returns_none() {
    let (tx, handle) = build_actor().await;

    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::GetCommunity {
        community_id: CommunityId([0xAB; 32]),
        reply_to: r_tx,
    })
    .await
    .unwrap();
    assert!(r_rx.await.unwrap().is_none());

    handle.abort();
}

#[tokio::test]
async fn dissolve_unknown_returns_not_found() {
    let (tx, handle) = build_actor().await;

    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::DissolveCommunity {
        community_id: CommunityId([0xAB; 32]),
        reply_to: r_tx,
    })
    .await
    .unwrap();
    match r_rx.await.unwrap() {
        DissolveOutcome::NotFound => {}
        other => panic!("expected NotFound, got {other:?}"),
    }

    handle.abort();
}

// ─── Import rejection paths — bad vouch, expired ───────────────────────

#[tokio::test]
async fn import_expired_rejected_with_expired_error() {
    let (tx, handle) = build_actor().await;
    let now = now_millis();
    let expires = PhalanxTimestamp(now.0 + 10 * 60_000);
    let community = build_valid_community("Fleeting", now, expires);

    // Rewind `expires_at` past wall-clock `now` — signatures remain valid
    // because they bind to (member_did, fingerprint, joined_at), not
    // expires_at. The actor's verify pass should see `now > expires_at`
    // and return Expired.
    let mut tampered = community;
    tampered.expires_at = PhalanxTimestamp(now.0.saturating_sub(1));

    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::ImportCommunity {
        community: tampered,
        reply_to: r_tx,
    })
    .await
    .unwrap();
    match r_rx.await.unwrap() {
        ImportOutcome::Err(CommunityVerifyError::Expired { .. }) => {}
        other => panic!("expected Expired, got {other:?}"),
    }

    handle.abort();
}

#[tokio::test]
async fn import_bad_vouch_rejected_with_bad_vouch_error() {
    // Construct a community whose vouches are cryptographically valid
    // against a *different* fingerprint than the one the Community declares.
    // `MemberEntry::new_validated` enforces quorum count only; signature
    // binding is the Laboratory's job — and it's exactly that check we
    // want the actor to reject.
    use phalanx_proto::community::{Community, MemberEntry};

    let (tx, handle) = build_actor().await;
    let now = now_millis();
    let expires = PhalanxTimestamp(now.0 + 10 * 60_000);

    let (voucher_a_did, voucher_a_sk) = make_identity();
    let (voucher_b_did, voucher_b_sk) = make_identity();
    let (member_did, _) = make_identity();

    let name = PetName::new("BadSig").expect("pet name");
    let quorum = Quorum::new(2).expect("quorum");

    // The declared fingerprint the `Community` struct will carry.
    let real_id = CommunityId::compute(&name, quorum, std::slice::from_ref(&member_did));
    // Vouches sign against *this* id — intentionally different from `real_id`.
    let wrong_id = CommunityId([0xFF; 32]);

    let vouch_a = sign_vouch(&voucher_a_sk, &voucher_a_did, &member_did, &wrong_id, now);
    let vouch_b = sign_vouch(&voucher_b_sk, &voucher_b_did, &member_did, &wrong_id, now);

    let entry = MemberEntry::new_validated(member_did, now, vec![vouch_a, vouch_b], quorum)
        .expect("quorum satisfied");

    let tampered = Community {
        fingerprint: real_id,
        name,
        quorum,
        members: vec![entry],
        stronghold_did: None,
        baseline_trust: TrustLevel::Verified,
        grants: CommunityGrants::default(),
        expires_at: expires,
    };

    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::ImportCommunity {
        community: tampered,
        reply_to: r_tx,
    })
    .await
    .unwrap();
    match r_rx.await.unwrap() {
        ImportOutcome::Err(CommunityVerifyError::BadVouch { .. }) => {}
        other => panic!("expected BadVouch, got {other:?}"),
    }

    handle.abort();
}

// ─── Registry-level maintenance sweep ─────────────────────────────────
//
// `TrustActor::run_maintenance` uses `SystemClock` internally, so we can't
// trivially mock its tick. Instead we exercise the underlying registry verb
// directly — the actor delegates to it verbatim.

#[tokio::test]
async fn registry_dissolve_expired_removes_expired_community() {
    let mut config = NodeConfig::test_defaults();
    let temp = tempdir().expect("tempdir");
    config.storage.vault_path = temp.path().to_string_lossy().to_string();
    let mut registry = TrustRegistry::build(&config).await;

    let now = now_millis();
    let expires = PhalanxTimestamp(now.0 + 10 * 60_000);
    let community = build_valid_community("Transient", now, expires);
    let id = community.fingerprint;

    // Insert by hand — the import logic is already covered above.
    registry.communities.insert(id, community);
    assert_eq!(registry.communities.len(), 1);

    // Advance the sweep clock past `expires_at`; the entry should be gone.
    registry.dissolve_expired_communities(PhalanxTimestamp(expires.0 + 1));
    assert!(
        registry.communities.is_empty(),
        "expired community should be swept"
    );
    // Keep the temp alive until end of scope.
    drop(temp);
}

// ─── Reply-channel close semantics ─────────────────────────────────────

#[tokio::test]
async fn actor_drops_reply_channel_when_receiver_gone() {
    // If the caller drops its reply_rx before the actor processes, the
    // actor must not panic. This is a regression guard on the
    // `let _ = reply_to.send(...)` idiom.
    let (tx, handle) = build_actor().await;
    let (r_tx, r_rx) = oneshot::channel();
    drop(r_rx);
    tx.send(TrustCommand::ListCommunities { reply_to: r_tx })
        .await
        .unwrap();
    // Let the actor drain the command.
    tokio::time::sleep(Duration::from_millis(20)).await;
    // The actor is still alive — follow-up commands succeed.
    let (r_tx, r_rx) = oneshot::channel();
    tx.send(TrustCommand::ListCommunities { reply_to: r_tx })
        .await
        .unwrap();
    let summaries = r_rx.await.unwrap();
    assert!(summaries.is_empty());
    handle.abort();
}
