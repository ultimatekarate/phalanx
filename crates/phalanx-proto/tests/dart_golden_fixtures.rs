#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
//! Golden-byte fixtures for the hand-rolled Dart postcard decoders in
//! `flutter_app/lib/ffi/community_models.dart`.
//!
//! **Why this exists.** The Dart side has no compile-time cross-check
//! against Rust's serde derives — a field added or reordered in
//! `phalanx-proto::community` silently drifts the Dart decoder until a
//! runtime `FormatException` fires (or worse, decodes to the wrong
//! field). The golden-bytes pattern closes that gap:
//!
//!   1. This file constructs a canonical value for each decoded type
//!      and asserts that `postcard::to_allocvec(canonical)` equals a
//!      hard-coded `EXPECTED_BYTES` literal. A Rust-side schema change
//!      fails this test.
//!   2. `flutter_app/test/ffi/community_models_golden_test.dart`
//!      embeds the *same* byte literals, decodes them, and asserts
//!      field-by-field against the canonical Dart values. A Dart-side
//!      decoder change (or a Rust change the Dart did not track) fails
//!      that test.
//!
//! Either side drifting trips a red CI signal. Neither alone would.
//!
//! **Updating a fixture.** If a test fails with the *Rust side* needing
//! an update (i.e. you intentionally changed the schema): run
//! `cargo test -p phalanx-proto --test dart_golden_fixtures`, copy the
//! `left:` bytes from the assertion failure into the matching
//! `EXPECTED_BYTES` literal, then update the paired Dart golden test
//! with the same bytes and the new canonical field values. Both sides
//! ship in one PR.

use phalanx_proto::identity::community::{
    CeremonyError, CommunityAssemblyError, CommunityGrants, CommunityId, CommunityRoster,
    CommunitySummary, CommunityVerifyError, MemberSummary, Quorum, VouchRequestPreview,
};
use phalanx_proto::identity::Did;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::PetName;

// ── Canonical constructors ─────────────────────────────────────────────
//
// Fixed inputs with tiny strings and simple byte patterns — keeps the
// golden literals short enough to eyeball.

fn canonical_community_id() -> CommunityId {
    CommunityId([0x01; 32])
}

fn canonical_fingerprint() -> CommunityId {
    CommunityId([0x03; 32])
}

fn canonical_summary() -> CommunitySummary {
    CommunitySummary {
        id: canonical_community_id(),
        name: PetName::new("Demo").unwrap(),
        member_count: 3,
        expires_at: PhalanxTimestamp::from_u64(1_700_000_000),
        quorum: Quorum::new(2).unwrap(),
    }
}

fn canonical_members() -> Vec<MemberSummary> {
    vec![
        MemberSummary {
            did: Did::new("did:key:zA"),
            joined_at: PhalanxTimestamp::from_u64(1_500_000_000),
            vouch_count: 2,
            pet_name: None,
        },
        MemberSummary {
            did: Did::new("did:key:zB"),
            joined_at: PhalanxTimestamp::from_u64(1_500_000_001),
            vouch_count: 2,
            pet_name: Some(PetName::new("Bob").unwrap()),
        },
    ]
}

fn canonical_grants() -> CommunityGrants {
    CommunityGrants {
        export_to_stronghold: true,
        mesh_trust_elevation: false,
    }
}

fn canonical_roster() -> CommunityRoster {
    CommunityRoster {
        summary: canonical_summary(),
        members: canonical_members(),
        grants: canonical_grants(),
        stronghold_did: Some(Did::new("did:key:zS")),
    }
}

fn canonical_preview() -> VouchRequestPreview {
    VouchRequestPreview {
        request_id: [0x02; 32],
        tentative_fingerprint: canonical_fingerprint(),
        name: PetName::new("Demo").unwrap(),
        quorum: Quorum::new(2).unwrap(),
        members: vec![Did::new("did:key:zA"), Did::new("did:key:zB")],
        member_did: Did::new("did:key:zA"),
        issued_at: PhalanxTimestamp::from_u64(1_700_000_000),
        member_joined_at: PhalanxTimestamp::from_u64(1_700_000_100),
    }
}

// ── Golden assertions ──────────────────────────────────────────────────

/// `CommunityRoster` — the top-level shape returned by
/// `phalanx_get_community` / `phalanx_preview_community`. Exercises
/// every Dart primitive the module defines: fixed byte arrays, varints,
/// strings, `Vec<T>`, `Option<T>`, and `bool`.
#[test]
fn community_roster_golden() {
    const EXPECTED_BYTES: &[u8] = &[
        1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
        1, 1, 4, 68, 101, 109, 111, 3, 128, 226, 207, 170, 6, 2, 2, 10, 100, 105, 100, 58, 107,
        101, 121, 58, 122, 65, 128, 222, 160, 203, 5, 2, 0, 10, 100, 105, 100, 58, 107, 101, 121,
        58, 122, 66, 129, 222, 160, 203, 5, 2, 1, 3, 66, 111, 98, 1, 0, 1, 10, 100, 105, 100, 58,
        107, 101, 121, 58, 122, 83,
    ];
    let bytes = postcard::to_allocvec(&canonical_roster()).unwrap();
    assert_eq!(
        bytes.as_slice(),
        EXPECTED_BYTES,
        "CommunityRoster golden drift — update EXPECTED_BYTES and the paired Dart fixture"
    );
}

/// `VouchRequestPreview` — exercises the fixed 32-byte `request_id`,
/// the embedded `CommunityId`, a `Vec<Did>`, and two `PhalanxTimestamp`
/// varints.
#[test]
fn vouch_request_preview_golden() {
    const EXPECTED_BYTES: &[u8] = &[
        2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
        2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3,
        3, 3, 3, 3, 4, 68, 101, 109, 111, 2, 2, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65,
        10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 66, 10, 100, 105, 100, 58, 107, 101, 121,
        58, 122, 65, 128, 226, 207, 170, 6, 228, 226, 207, 170, 6,
    ];
    let bytes = postcard::to_allocvec(&canonical_preview()).unwrap();
    assert_eq!(
        bytes.as_slice(),
        EXPECTED_BYTES,
        "VouchRequestPreview golden drift — update EXPECTED_BYTES and the paired Dart fixture"
    );
}

// ── CeremonyError variants ────────────────────────────────────────────

#[test]
fn ceremony_error_request_id_mismatch_golden() {
    const EXPECTED_BYTES: &[u8] = &[0];
    let bytes = postcard::to_allocvec(&CeremonyError::RequestIdMismatch).unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "RequestIdMismatch drift");
}

#[test]
fn ceremony_error_response_stale_golden() {
    const EXPECTED_BYTES: &[u8] = &[1, 160, 56];
    let bytes = postcard::to_allocvec(&CeremonyError::ResponseStale { age_seconds: 7200 }).unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "ResponseStale drift");
}

#[test]
fn ceremony_error_unsupported_version_golden() {
    const EXPECTED_BYTES: &[u8] = &[2, 2];
    let bytes =
        postcard::to_allocvec(&CeremonyError::UnsupportedVersion { version: 0x02 }).unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "UnsupportedVersion drift");
}

#[test]
fn ceremony_error_fingerprint_mismatch_golden() {
    const EXPECTED_BYTES: &[u8] = &[3];
    let bytes = postcard::to_allocvec(&CeremonyError::FingerprintMismatch).unwrap();
    assert_eq!(
        bytes.as_slice(),
        EXPECTED_BYTES,
        "FingerprintMismatch drift"
    );
}

#[test]
fn ceremony_error_duplicate_voucher_golden() {
    const EXPECTED_BYTES: &[u8] = &[4, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65];
    let bytes = postcard::to_allocvec(&CeremonyError::DuplicateVoucher {
        voucher: Did::new("did:key:zA"),
    })
    .unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "DuplicateVoucher drift");
}

#[test]
fn ceremony_error_unknown_slot_golden() {
    const EXPECTED_BYTES: &[u8] = &[5, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 77];
    let bytes = postcard::to_allocvec(&CeremonyError::UnknownSlot {
        member: Did::new("did:key:zM"),
    })
    .unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "UnknownSlot drift");
}

#[test]
fn ceremony_error_voucher_mismatch_golden() {
    const EXPECTED_BYTES: &[u8] = &[
        6, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 69, 10, 100, 105, 100, 58, 107, 101, 121,
        58, 122, 65,
    ];
    let bytes = postcard::to_allocvec(&CeremonyError::VoucherMismatch {
        expected: Did::new("did:key:zE"),
        actual: Did::new("did:key:zA"),
    })
    .unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "VoucherMismatch drift");
}

/// `CeremonyError::Verify(CommunityVerifyError::Expired { .. })` —
/// also pins the embedded `CommunityVerifyError` discriminant order.
#[test]
fn ceremony_error_verify_expired_golden() {
    const EXPECTED_BYTES: &[u8] = &[
        7, 0, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4,
        4, 4, 4, 4, 128, 226, 207, 170, 6, 128, 160, 248, 250, 5,
    ];
    let inner = CommunityVerifyError::Expired {
        community_id: CommunityId([0x04; 32]),
        now: PhalanxTimestamp::from_u64(1_700_000_000),
        expires_at: PhalanxTimestamp::from_u64(1_600_000_000),
    };
    let bytes = postcard::to_allocvec(&CeremonyError::Verify(inner)).unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "Verify(Expired) drift");
}

/// `CeremonyError::Assembly(..)` — Dart decodes this variant opaquely
/// (no per-variant `CommunityAssemblyError` decoder on the Dart side),
/// but the *discriminant byte* has to stay at 8. Pinning the full
/// serialized form catches both a discriminant shift and any silent
/// reshape of `CommunityAssemblyError` that would change the length
/// the opaque decoder reads.
#[test]
fn ceremony_error_assembly_golden() {
    const EXPECTED_BYTES: &[u8] = &[
        8, 0, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65, 160, 56,
    ];
    let inner = CommunityAssemblyError::VouchStale {
        voucher: Did::new("did:key:zA"),
        age_seconds: 7200,
    };
    let bytes = postcard::to_allocvec(&CeremonyError::Assembly(inner)).unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "Assembly drift");
}

#[test]
fn ceremony_error_import_failed_golden() {
    const EXPECTED_BYTES: &[u8] = &[
        9, 17, 115, 116, 114, 111, 110, 103, 104, 111, 108, 100, 32, 108, 111, 99, 107, 101, 100,
    ];
    let bytes = postcard::to_allocvec(&CeremonyError::ImportFailed {
        reason: "stronghold locked".to_string(),
    })
    .unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "ImportFailed drift");
}

// ── CommunityVerifyError standalone variants ──────────────────────────
//
// `CommunityVerifyError` is the payload of `ImportOutcome::Err` and
// `PreviewOutcome::Err`. Pinning each variant here locks the
// discriminant order independently of the `CeremonyError::Verify` wrap.

#[test]
fn community_verify_error_bad_vouch_golden() {
    const EXPECTED_BYTES: &[u8] = &[
        1, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65, 10, 100, 105, 100, 58, 107, 101, 121,
        58, 122, 66,
    ];
    let bytes = postcard::to_allocvec(&CommunityVerifyError::BadVouch {
        member: Did::new("did:key:zA"),
        voucher: Did::new("did:key:zB"),
    })
    .unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "BadVouch drift");
}

#[test]
fn community_verify_error_quorum_violation_golden() {
    const EXPECTED_BYTES: &[u8] = &[2, 10, 100, 105, 100, 58, 107, 101, 121, 58, 122, 65];
    let bytes = postcard::to_allocvec(&CommunityVerifyError::QuorumViolation {
        member: Did::new("did:key:zA"),
    })
    .unwrap();
    assert_eq!(bytes.as_slice(), EXPECTED_BYTES, "QuorumViolation drift");
}

#[test]
fn community_verify_error_unsupported_version_golden() {
    const EXPECTED_BYTES: &[u8] = &[3, 2];
    let bytes =
        postcard::to_allocvec(&CommunityVerifyError::UnsupportedVersion { version: 0x02 }).unwrap();
    assert_eq!(
        bytes.as_slice(),
        EXPECTED_BYTES,
        "VerifyError::UnsupportedVersion drift"
    );
}
