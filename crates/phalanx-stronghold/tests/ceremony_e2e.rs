#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// End-to-end integration for the Phase 7.B trusted-community ceremony.
//
// Exercises the Stronghold-coordinated, mobile-signed ceremony flow per
// plan `cached-wibbling-dove.md` Phase 7.D:
//
//   1. Primary scenario — self-contained demo shape (N=3, K=2). Three
//      members A, B, C at quorum 2. The v1 roster-order-wrap rule gives
//      six (member, voucher) slots — vouchers-for-A = {B, C},
//      vouchers-for-B = {C, A}, vouchers-for-C = {A, B}. The test drives
//      all six VerifyVouchResponse commands and one AssembleAndImport,
//      and confirms the resulting community carries the coordinator's
//      stronghold_did. This is exactly the shape the ACLU demo will
//      produce on stage.
//
//   2. Secondary scenario — external vouchers. The v1 UX does not expose
//      off-roster vouchers, but the Dictionary types admit them. One
//      member D, two external vouchers E and F; proves the wire
//      protocol accepts the shape so future UX can expose it without a
//      schema migration.
//
//   3. Rejection paths — one per CeremonyError variant on the ceremony
//      flow: FingerprintMismatch (tampered tentative), ResponseStale
//      (pure-verb freshness check), VoucherMismatch (wrong signing
//      key picks up the request). Each ensures the protocol fails
//      closed rather than admitting tampered inputs to
//      `assemble_community`.
//
// Signing is a pure verb call per Phase 7 R1 — no mobile actor
// instances are spawned. The test uses standalone `SigningKey`s to
// impersonate each voucher's phone.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;

use phalanx_forensics::identity::{
    sign_vouch_response, verify_vouch_response, CommunityAssemblyParams,
};
use phalanx_proto::community::{
    CeremonyError, CeremonyMember, CeremonyNonce, CommunityGrants, CommunityId, Quorum,
    VouchRequest, VouchResponse, CEREMONY_RESPONSE_FRESHNESS_SECS,
};
use phalanx_proto::identity::Did;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::{PetName, TrustLevel};

use phalanx_stronghold::actors::community::{CommunityActor, CommunityCommand};

// ── Helpers ────────────────────────────────────────────────────────────

/// Fresh (DID, signing key) pair. Mirrors the phone's bootstrap: every
/// mobile device derives its DID deterministically from its keypair via
/// `Did::derive_did_key`, and `sign_vouch_response` round-trips that
/// derivation to enforce slot integrity.
fn make_identity() -> (Did, SigningKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let did = Did::derive_did_key(&sk.verifying_key().to_bytes());
    (did, sk)
}

/// Wall-clock timestamp. Aligns with what the actor's
/// `VerifyVouchResponse` / `AssembleAndImport` handlers sample
/// internally, so freshness windows line up when the test runs at
/// real-time speed.
fn now_ts() -> PhalanxTimestamp {
    PhalanxTimestamp::from_millis(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
    )
}

/// Deterministic ceremony nonce for tests. Production uses
/// `CeremonyNonce::random()` to disambiguate aborted-and-restarted
/// ceremonies; the E2E tests want stable `request_id`s so they can
/// poke the actor with a known value.
fn test_nonce() -> CeremonyNonce {
    CeremonyNonce([0x5Au8; 16])
}

/// Build the full `(member, voucher)` slot set under the v1
/// self-contained rule: for each member at index `i`, the K vouchers
/// are the members at `i+1, …, i+K` modulo `n`. Mirrors the
/// `build_request_slots` helper in `gui/panels/ceremony.rs` — inlined
/// here to keep the E2E test free of the `gui` feature gate.
fn self_contained_requests(
    members: &[Did],
    quorum: Quorum,
    tentative: CommunityId,
    ceremony_nonce: &CeremonyNonce,
    name: &PetName,
    issued_at: PhalanxTimestamp,
    member_joined_at: PhalanxTimestamp,
) -> Vec<VouchRequest> {
    let k = usize::from(quorum.value());
    let n = members.len();
    let mut out = Vec::with_capacity(n * k);
    for (i, member_did) in members.iter().enumerate() {
        for j in 1..=k {
            let voucher_idx = (i + j) % n;
            if voucher_idx == i {
                continue;
            }
            let voucher_did = &members[voucher_idx];
            out.push(VouchRequest {
                request_id: VouchRequest::compute_id(
                    &tentative,
                    ceremony_nonce,
                    voucher_did,
                    member_did,
                ),
                tentative_fingerprint: tentative,
                ceremony_nonce: *ceremony_nonce,
                name: name.clone(),
                quorum,
                members: members.to_vec(),
                member_did: member_did.clone(),
                voucher_did: voucher_did.clone(),
                issued_at,
                member_joined_at,
            });
        }
    }
    out
}

/// Group verified responses back into `CeremonyMember`s by matching
/// each response to its issuing request's `member_did`. Mirrors the
/// core of `collect_members_from_responses` in the panel (minus the
/// gui-gated roster-integrity checks — inputs here are test-controlled).
fn group_responses(
    requests: &[VouchRequest],
    responses: &HashMap<[u8; 32], VouchResponse>,
    roster: &[Did],
) -> Vec<CeremonyMember> {
    roster
        .iter()
        .map(|member_did| CeremonyMember {
            did: member_did.clone(),
            vouches: requests
                .iter()
                .filter(|r| &r.member_did == member_did)
                .filter_map(|r| responses.get(&r.request_id).map(|resp| resp.vouch.clone()))
                .collect(),
        })
        .collect()
}

// ═══════════════════════════════════════════════════════════════════════
// Primary scenario — self-contained demo shape (N=3, K=2)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ceremony_self_contained_n3_k2_happy_path() {
    // ── Spin up the Stronghold's CommunityActor. One actor, one vault
    //    dir — the demo shape. Mobile signers are pure-verb calls. ──
    let (tx, rx) = tokio::sync::mpsc::channel(32);
    let actor = CommunityActor::new(rx);
    tokio::spawn(actor.run());

    // ── Three member identities with standalone signing keys. ──
    let (a_did, a_sk) = make_identity();
    let (b_did, b_sk) = make_identity();
    let (c_did, c_sk) = make_identity();
    let members_roster = vec![a_did.clone(), b_did.clone(), c_did.clone()];

    // Stronghold's own DID. The coordinator never signs a vouch; its
    // DID is bound into `stronghold_did` so mobile imports can anchor
    // corroboration against it (verifies 7.B.4's auto-populate).
    let (stronghold_did, _stronghold_sk) = make_identity();

    let name = PetName::new("ACLU Portland").unwrap();
    let quorum = Quorum::new(2).unwrap();
    let now = now_ts();
    let tentative = CommunityId::compute(&name, quorum, &members_roster);

    // ── Build six VouchRequests under self-contained (i+j) mod n. ──
    //    vouchers-for-A = {B, C}
    //    vouchers-for-B = {C, A}
    //    vouchers-for-C = {A, B}
    let requests = self_contained_requests(
        &members_roster,
        quorum,
        tentative,
        &test_nonce(),
        &name,
        now,
        now,
    );
    assert_eq!(requests.len(), 6, "N=3 × K=2 yields six slots");

    // ── Sign each request on its addressed voucher's key. ──
    let mut responses: HashMap<[u8; 32], VouchResponse> = HashMap::new();
    for request in &requests {
        let voucher_sk = if request.voucher_did == a_did {
            &a_sk
        } else if request.voucher_did == b_did {
            &b_sk
        } else if request.voucher_did == c_did {
            &c_sk
        } else {
            panic!("no signing key for {:?}", request.voucher_did);
        };
        let response = sign_vouch_response(voucher_sk, request, now)
            .expect("sign_vouch_response should succeed for well-formed request");
        responses.insert(response.request_id, response);
    }
    assert_eq!(responses.len(), 6);

    // ── Drive each response through the actor's VerifyVouchResponse. ──
    for request in &requests {
        let response = responses.get(&request.request_id).unwrap().clone();
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(CommunityCommand::VerifyVouchResponse {
            request: Box::new(request.clone()),
            response: Box::new(response),
            reply_to: reply_tx,
        })
        .await
        .unwrap();
        reply_rx
            .await
            .unwrap()
            .expect("actor must accept verified response");
    }

    // ── Assemble + import. ──
    let ceremony_members = group_responses(&requests, &responses, &members_roster);
    let params = CommunityAssemblyParams {
        name: name.clone(),
        quorum,
        joined_at: now,
        // +10 minutes — above MIN_EXPIRES_SECS (300s), well below
        // MAX_EXPIRES_SECS (30d).
        expires_at: PhalanxTimestamp::from_millis(now.0 + 10 * 60_000),
        stronghold_did: Some(stronghold_did.clone()),
        baseline_trust: TrustLevel::Verified,
        grants: CommunityGrants::default(),
        members: ceremony_members,
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(CommunityCommand::AssembleAndImport {
        params: Box::new(params),
        reply_to: reply_tx,
    })
    .await
    .unwrap();
    let (community_id, community) = reply_rx
        .await
        .unwrap()
        .expect("AssembleAndImport must succeed with six verified responses");

    assert_eq!(
        community_id, tentative,
        "tentative fingerprint must match assembled fingerprint"
    );
    assert_eq!(
        community.stronghold_did.as_ref(),
        Some(&stronghold_did),
        "panel's stronghold_did auto-populate must reach the installed community"
    );
    assert_eq!(community.members.len(), 3);
    for member in &community.members {
        assert_eq!(
            member.vouches().len(),
            2,
            "each member carries K=2 vouches under self-contained rule"
        );
    }

    // ── Verify via ListCommunities round-trip — the freshly assembled
    //    community must be queryable through the same surface
    //    externally-imported communities use. ──
    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(CommunityCommand::ListCommunities { reply_to: reply_tx })
        .await
        .unwrap();
    let listed = reply_rx.await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].0, community_id);
    assert_eq!(listed[0].1, "ACLU Portland");
}

// ═══════════════════════════════════════════════════════════════════════
// Secondary scenario — external vouchers (Dictionary-level flexibility)
// ═══════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn ceremony_external_vouchers_assemble() {
    let (tx, rx) = tokio::sync::mpsc::channel(16);
    let actor = CommunityActor::new(rx);
    tokio::spawn(actor.run());

    // One member D, two external vouchers E and F not on the roster.
    // `CommunityId::compute` binds only the member roster — external
    // vouchers are identified by DID alone.
    let (d_did, _d_sk) = make_identity();
    let (e_did, e_sk) = make_identity();
    let (f_did, f_sk) = make_identity();
    let (stronghold_did, _) = make_identity();

    let name = PetName::new("External Panel").unwrap();
    let quorum = Quorum::new(2).unwrap();
    let now = now_ts();
    let members_roster = vec![d_did.clone()];
    let tentative = CommunityId::compute(&name, quorum, &members_roster);

    // Two requests for D's slot, targeting two external vouchers.
    let nonce = test_nonce();
    let req_e = VouchRequest {
        request_id: VouchRequest::compute_id(&tentative, &nonce, &e_did, &d_did),
        tentative_fingerprint: tentative,
        ceremony_nonce: nonce,
        name: name.clone(),
        quorum,
        members: members_roster.clone(),
        member_did: d_did.clone(),
        voucher_did: e_did.clone(),
        issued_at: now,
        member_joined_at: now,
    };
    let req_f = VouchRequest {
        request_id: VouchRequest::compute_id(&tentative, &nonce, &f_did, &d_did),
        tentative_fingerprint: tentative,
        ceremony_nonce: nonce,
        name: name.clone(),
        quorum,
        members: members_roster.clone(),
        member_did: d_did.clone(),
        voucher_did: f_did.clone(),
        issued_at: now,
        member_joined_at: now,
    };
    let resp_e = sign_vouch_response(&e_sk, &req_e, now).unwrap();
    let resp_f = sign_vouch_response(&f_sk, &req_f, now).unwrap();

    for (request, response) in [(&req_e, &resp_e), (&req_f, &resp_f)] {
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(CommunityCommand::VerifyVouchResponse {
            request: Box::new(request.clone()),
            response: Box::new(response.clone()),
            reply_to: reply_tx,
        })
        .await
        .unwrap();
        reply_rx
            .await
            .unwrap()
            .expect("external-voucher response must verify");
    }

    let params = CommunityAssemblyParams {
        name: name.clone(),
        quorum,
        joined_at: now,
        expires_at: PhalanxTimestamp::from_millis(now.0 + 10 * 60_000),
        stronghold_did: Some(stronghold_did),
        baseline_trust: TrustLevel::Verified,
        grants: CommunityGrants::default(),
        members: vec![CeremonyMember {
            did: d_did.clone(),
            vouches: vec![resp_e.vouch.clone(), resp_f.vouch.clone()],
        }],
    };

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(CommunityCommand::AssembleAndImport {
        params: Box::new(params),
        reply_to: reply_tx,
    })
    .await
    .unwrap();
    let (_id, community) = reply_rx
        .await
        .unwrap()
        .expect("assembly must succeed with external vouchers");
    assert_eq!(community.members.len(), 1);
    assert_eq!(community.members[0].vouches().len(), 2);
    // Both vouches come from DIDs outside the member roster — the
    // protocol does not conflate member DIDs with voucher DIDs.
    for vouch in community.members[0].vouches() {
        assert_ne!(vouch.voucher_did, d_did);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// Rejection paths — one per CeremonyError variant
// ═══════════════════════════════════════════════════════════════════════

/// A voucher signs against the real tentative. An attacker rewrites
/// `tentative_fingerprint` on the request handed to the actor, leaving
/// `request_id` intact (it was computed before tampering). The
/// signature binds the original fingerprint, so Ed25519 verification
/// against the tampered fingerprint fails → `FingerprintMismatch`.
#[tokio::test]
async fn ceremony_rejects_tampered_tentative_fingerprint() {
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let actor = CommunityActor::new(rx);
    tokio::spawn(actor.run());

    let (member_did, _) = make_identity();
    let (voucher_did, voucher_sk) = make_identity();
    let members_roster = vec![member_did.clone()];
    let name = PetName::new("Tamper Test").unwrap();
    let quorum = Quorum::new(1).unwrap();
    let now = now_ts();
    let tentative = CommunityId::compute(&name, quorum, &members_roster);

    let nonce = test_nonce();
    let request = VouchRequest {
        request_id: VouchRequest::compute_id(&tentative, &nonce, &voucher_did, &member_did),
        tentative_fingerprint: tentative,
        ceremony_nonce: nonce,
        name,
        quorum,
        members: members_roster,
        member_did,
        voucher_did,
        issued_at: now,
        member_joined_at: now,
    };
    let response = sign_vouch_response(&voucher_sk, &request, now).unwrap();

    // Tamper: rewrite the request's fingerprint, keep request_id.
    let mut tampered = request.clone();
    tampered.tentative_fingerprint = CommunityId([0xAAu8; 32]);

    let (reply_tx, reply_rx) = oneshot::channel();
    tx.send(CommunityCommand::VerifyVouchResponse {
        request: Box::new(tampered),
        response: Box::new(response),
        reply_to: reply_tx,
    })
    .await
    .unwrap();
    let result = reply_rx.await.unwrap();
    assert!(
        matches!(result, Err(CeremonyError::FingerprintMismatch)),
        "tampered fingerprint must produce FingerprintMismatch, got {:?}",
        result,
    );
}

/// Pure-verb freshness check. The actor uses `SystemTime::now()`
/// internally, but `verify_vouch_response` takes `now` as an argument —
/// so simulate arrival 3601s after signing by passing a synthetic
/// future `now` to the verb directly. This exercises the same code
/// path the actor delegates to (`verify_vouch_response`) without
/// racing against real wall-clock time.
#[test]
fn ceremony_rejects_stale_response() {
    let (member_did, _) = make_identity();
    let (voucher_did, voucher_sk) = make_identity();
    let name = PetName::new("Stale Test").unwrap();
    let quorum = Quorum::new(1).unwrap();
    let signed_at = PhalanxTimestamp::from_millis(1_000_000);
    let tentative = CommunityId::compute(&name, quorum, std::slice::from_ref(&member_did));

    let nonce = test_nonce();
    let request = VouchRequest {
        request_id: VouchRequest::compute_id(&tentative, &nonce, &voucher_did, &member_did),
        tentative_fingerprint: tentative,
        ceremony_nonce: nonce,
        name,
        quorum,
        members: vec![member_did.clone()],
        member_did,
        voucher_did,
        issued_at: signed_at,
        member_joined_at: signed_at,
    };
    let response = sign_vouch_response(&voucher_sk, &request, signed_at).unwrap();

    // Verify with `now = signed_at + (window + 1) seconds` — one
    // second past the freshness window, so the age is strictly greater
    // than `CEREMONY_RESPONSE_FRESHNESS_SECS`.
    let stale_now =
        PhalanxTimestamp::from_millis(signed_at.0 + (CEREMONY_RESPONSE_FRESHNESS_SECS + 1) * 1000);
    let result = verify_vouch_response(&request, &response, stale_now);
    assert!(
        matches!(result, Err(CeremonyError::ResponseStale { .. })),
        "verify beyond freshness window must produce ResponseStale, got {:?}",
        result,
    );
}

/// Voucher B picks up a request addressed to C's slot and tries to
/// sign it. `sign_vouch_response` compares the signing key's derived
/// DID against `request.voucher_did` and rejects with
/// `VoucherMismatch` before producing any signature bytes. Pure-verb
/// test — the rejection fires on the mobile side before anything
/// reaches the actor.
#[test]
fn ceremony_rejects_voucher_signing_wrong_slot() {
    let (b_did, b_sk) = make_identity();
    let (c_did, _c_sk) = make_identity();
    let (member_did, _) = make_identity();

    let name = PetName::new("Slot Test").unwrap();
    let quorum = Quorum::new(1).unwrap();
    let now = now_ts();
    let tentative = CommunityId::compute(&name, quorum, std::slice::from_ref(&member_did));

    // Request is addressed to C.
    let nonce = test_nonce();
    let request_for_c = VouchRequest {
        request_id: VouchRequest::compute_id(&tentative, &nonce, &c_did, &member_did),
        tentative_fingerprint: tentative,
        ceremony_nonce: nonce,
        name,
        quorum,
        members: vec![member_did.clone()],
        member_did,
        voucher_did: c_did.clone(),
        issued_at: now,
        member_joined_at: now,
    };

    // B attempts to sign — should fail before producing bytes.
    let err = sign_vouch_response(&b_sk, &request_for_c, now)
        .expect_err("B must not be able to sign a request addressed to C");
    match err {
        CeremonyError::VoucherMismatch { expected, actual } => {
            assert_eq!(expected, c_did, "request's target slot should be preserved");
            assert_eq!(actual, b_did, "actual signer DID should be reported");
        }
        other => panic!("expected VoucherMismatch, got {:?}", other),
    }
}
