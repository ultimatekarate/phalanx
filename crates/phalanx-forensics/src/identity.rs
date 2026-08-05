use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use phalanx_proto::community::{
    CEREMONY_RESPONSE_FRESHNESS_SECS, COMMUNITY_PAYLOAD_VERSION, CeremonyError, CeremonyMember,
    Community, CommunityAssemblyError, CommunityGrants, CommunityId, CommunityVerifyError,
    MemberEntry, Quorum, VOUCH_REQUEST_VERSION, VOUCH_RESPONSE_VERSION, Vouch, VouchRequest,
    VouchRequestPreview, VouchResponse, VouchSignature,
};
use phalanx_proto::crypto::CryptoError;
use phalanx_proto::prelude::*;
use phalanx_proto::time::PhalanxTimestamp;
use phalanx_proto::trust::{PetName, TrustLevel};

// ── Community Ceremony Thresholds ───────────────────────────────────────

/// Maximum age of a vouch relative to `now`. Vouches signed earlier than
/// `now - VOUCH_FRESHNESS_WINDOW_SECS` are stale and rejected.
pub const VOUCH_FRESHNESS_WINDOW_SECS: u64 = 3600; // 1 hour

/// Maximum forward clock skew tolerated. A vouch whose `joined_at` is later
/// than `now + CLOCK_SKEW_TOLERANCE_SECS` is treated as a replay attempt
/// against a future window (or a broken signer clock).
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 300; // 5 minutes

/// Minimum community lifetime (seconds). Floor guards against accidental
/// near-zero expirations that would expire before the ceremony completes.
pub const MIN_EXPIRES_SECS: u64 = 300; // 5 minutes

/// Maximum community lifetime (seconds). Ceiling closes the "immortal
/// community" gap — tokens older than 30 days must be re-issued.
pub const MAX_EXPIRES_SECS: u64 = 30 * 86_400; // 30 days

/// Soft warning ceiling on serialized community payload size, aligned with
/// QR v40 alphanumeric capacity after base64url expansion.
pub const QR_PAYLOAD_BUDGET_BYTES: usize = 2800;

/// Maximum founding members in a ceremony.
pub const MAX_CEREMONY_MEMBERS: usize = 256;

/// Maximum vouches per member during a ceremony.
pub const MAX_VOUCHES_PER_MEMBER: usize = 256;

pub fn resolve_did_public_key(did: &Did) -> Result<[u8; 32], CryptoError> {
    // Safe Prefix Handling (Zero-Panic)
    // Replaces: let multibase_str = &s["did:key:".len()..];
    let multibase_str = did
        .as_str()
        .strip_prefix("did:key:")
        .ok_or(CryptoError::DidResolutionFailure)?;

    // Safe Multibase Detection
    // Replaces: if !multibase_str.starts_with('z') ... decode(&multibase_str[1..])
    let encoded_key = multibase_str
        .strip_prefix('z')
        .ok_or(CryptoError::DidResolutionFailure)?;

    let bytes = bs58::decode(encoded_key)
        .into_vec()
        .map_err(|_| CryptoError::DidResolutionFailure)?;

    // Safe Multicodec Extraction (Zero-Panic)
    // Replaces: if bytes.len() == 34 && bytes[0] == 0xed ... copy_from_slice(&bytes[2..])
    match bytes.as_slice() {
        [0xed, 0x01, key_bytes @ ..] if key_bytes.len() == 32 => {
            let mut key = [0u8; 32];
            key.copy_from_slice(key_bytes);
            Ok(key)
        }
        _ => Err(CryptoError::DidResolutionFailure),
    }
}

// ── Vouch Signature Verification ────────────────────────────────────────

/// Verify a single vouch: Ed25519 signature over (member_did || community_fingerprint || joined_at).
/// Pure logic — no IO.
pub fn verify_vouch(
    vouch: &Vouch,
    member_did: &Did,
    community_id: &CommunityId,
    joined_at: PhalanxTimestamp,
) -> Result<(), CryptoError> {
    let pk_bytes = resolve_did_public_key(&vouch.voucher_did)?;
    let verifying_key =
        VerifyingKey::from_bytes(&pk_bytes).map_err(|_| CryptoError::DidResolutionFailure)?;

    let sig_bytes: [u8; 64] = vouch
        .signature
        .as_bytes()
        .try_into()
        .map_err(|_| CryptoError::InvalidKeyLength)?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Reconstruct the signed message: member_did || community_fingerprint || joined_at
    let mut message = Vec::new();
    message.extend_from_slice(member_did.as_ref().as_bytes());
    message.extend_from_slice(&community_id.0);
    message.extend_from_slice(&joined_at.0.to_le_bytes());

    verifying_key
        .verify(&message, &signature)
        .map_err(|_| CryptoError::DecryptionFailure)
}

// ── Community-Level Verification ────────────────────────────────────────

/// Verify an entire community token: expiration, every member's quorum,
/// every vouch signature. Pure verb — no IO, no clock held internally.
///
/// `now` must be supplied by the caller from a `TrustedClock` (§III
/// Temporal Agreement of `linguistic-code-model.md`).
///
/// Returns the first rejection reason encountered. On success, the community
/// has a live membership graph whose every vouch is cryptographically valid.
pub fn verify_community_vouches(
    community: &Community,
    now: PhalanxTimestamp,
) -> Result<(), CommunityVerifyError> {
    if community.is_expired(now) {
        return Err(CommunityVerifyError::Expired {
            community_id: community.fingerprint,
            now,
            expires_at: community.expires_at,
        });
    }

    let quorum = community.quorum.value() as usize;

    for member in &community.members {
        // Quorum re-check — belt-and-suspenders alongside `MemberEntry::new_validated`.
        let unique_external: std::collections::HashSet<&str> = member
            .vouches()
            .iter()
            .filter(|v| v.voucher_did.as_str() != member.did().as_str())
            .map(|v| v.voucher_did.as_str())
            .collect();
        if unique_external.len() < quorum {
            return Err(CommunityVerifyError::QuorumViolation {
                member: member.did().clone(),
            });
        }

        for vouch in member.vouches() {
            verify_vouch(vouch, member.did(), &community.fingerprint, member.joined()).map_err(
                |_| CommunityVerifyError::BadVouch {
                    member: member.did().clone(),
                    voucher: vouch.voucher_did.clone(),
                },
            )?;
        }
    }
    Ok(())
}

/// Strip the `[COMMUNITY_PAYLOAD_VERSION]` prefix and return the inner
/// postcard body. Returns [`CommunityVerifyError::UnsupportedVersion`] if the
/// first byte does not match the current envelope version.
///
/// Pure function — no deserialization performed here.
pub fn strip_payload_version(bytes: &[u8]) -> Result<&[u8], CommunityVerifyError> {
    let (&version, rest) = bytes
        .split_first()
        .ok_or(CommunityVerifyError::UnsupportedVersion { version: 0 })?;
    if version != COMMUNITY_PAYLOAD_VERSION {
        return Err(CommunityVerifyError::UnsupportedVersion { version });
    }
    Ok(rest)
}

/// Prepend the envelope version byte to an already-serialized community.
/// Companion to [`strip_payload_version`].
#[must_use]
pub fn wrap_payload_version(postcard_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(postcard_bytes.len().saturating_add(1));
    out.push(COMMUNITY_PAYLOAD_VERSION);
    out.extend_from_slice(postcard_bytes);
    out
}

// ── Ceremony envelope helpers ───────────────────────────────────────────
//
// `VouchRequest` and `VouchResponse` travel over QR / file surfaces that
// must survive future protocol rev bumps. Every ceremony byte stream is
// wrapped `[VERSION_BYTE] || postcard(T)` — the same shape as the
// community-payload envelope above. These helpers centralise the
// version-byte arithmetic so the Stronghold panel and the mobile FFI
// never reach for raw `[version_byte]` slicing.
//
// A missing or mismatched version byte is reported as
// `CeremonyError::UnsupportedVersion { version }` — distinct from
// `CommunityVerifyError::UnsupportedVersion` so ceremony callers can
// surface ceremony-specific UX copy without inspecting the inner enum.

/// Strip the `[VOUCH_REQUEST_VERSION]` prefix from a wrapped request
/// envelope. Returns the raw postcard body on success.
///
/// Pure function — no deserialization performed here. A zero-length
/// input is reported as `UnsupportedVersion { version: 0 }`, matching
/// the `strip_payload_version` convention.
pub fn strip_vouch_request(bytes: &[u8]) -> Result<&[u8], CeremonyError> {
    let (&version, rest) = bytes
        .split_first()
        .ok_or(CeremonyError::UnsupportedVersion { version: 0 })?;
    if version != VOUCH_REQUEST_VERSION {
        return Err(CeremonyError::UnsupportedVersion { version });
    }
    Ok(rest)
}

/// Prepend `[VOUCH_REQUEST_VERSION]` to an already-postcard-serialized
/// request body. Companion to [`strip_vouch_request`].
#[must_use]
pub fn wrap_vouch_request(postcard_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(postcard_bytes.len().saturating_add(1));
    out.push(VOUCH_REQUEST_VERSION);
    out.extend_from_slice(postcard_bytes);
    out
}

/// Strip the `[VOUCH_RESPONSE_VERSION]` prefix from a wrapped response
/// envelope. Returns the raw postcard body on success.
///
/// Pure function — no deserialization performed here.
pub fn strip_vouch_response(bytes: &[u8]) -> Result<&[u8], CeremonyError> {
    let (&version, rest) = bytes
        .split_first()
        .ok_or(CeremonyError::UnsupportedVersion { version: 0 })?;
    if version != VOUCH_RESPONSE_VERSION {
        return Err(CeremonyError::UnsupportedVersion { version });
    }
    Ok(rest)
}

/// Prepend `[VOUCH_RESPONSE_VERSION]` to an already-postcard-serialized
/// response body. Companion to [`strip_vouch_response`].
#[must_use]
pub fn wrap_vouch_response(postcard_bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(postcard_bytes.len().saturating_add(1));
    out.push(VOUCH_RESPONSE_VERSION);
    out.extend_from_slice(postcard_bytes);
    out
}

// ── Community Assembly (Ceremony) ───────────────────────────────────────

/// Inputs for the ceremony assembly verb. Every field is a Dictionary Noun;
/// construction errors are the caller's responsibility (e.g. `PetName::new`).
#[derive(Debug, Clone)]
pub struct CommunityAssemblyParams {
    pub name: PetName,
    pub quorum: Quorum,
    pub joined_at: PhalanxTimestamp,
    pub expires_at: PhalanxTimestamp,
    pub stronghold_did: Option<Did>,
    pub baseline_trust: TrustLevel,
    pub grants: CommunityGrants,
    pub members: Vec<CeremonyMember>,
}

/// Assemble a community from ceremony inputs, validating every invariant
/// the existing inline logic covered plus the new 30-day expiration ceiling.
///
/// Pure verb. `now` is supplied by the caller so this code never holds a clock.
///
/// Invariants enforced (in declaration order):
/// 1. `joined_at` freshness and skew against `now`.
/// 2. `expires_at - now` is within `[MIN_EXPIRES_SECS, MAX_EXPIRES_SECS]`.
/// 3. Non-empty member list below `MAX_CEREMONY_MEMBERS`.
/// 4. Each member's vouches under `MAX_VOUCHES_PER_MEMBER`.
/// 5. Every vouch cryptographically verifies (via `verify_vouch`).
/// 6. Quorum satisfied for every member (via `MemberEntry::new_validated`).
/// 7. Serialized payload ≤ `QR_PAYLOAD_BUDGET_BYTES`.
pub fn assemble_community(
    params: CommunityAssemblyParams,
    now: PhalanxTimestamp,
) -> Result<Community, CommunityAssemblyError> {
    // ── Invariant 1: vouch freshness / skew ──
    let now_ms = now.0;
    let joined_ms = params.joined_at.0;
    let vouch_freshness_ms = VOUCH_FRESHNESS_WINDOW_SECS.saturating_mul(1000);
    let clock_skew_ms = CLOCK_SKEW_TOLERANCE_SECS.saturating_mul(1000);

    // Saturating arithmetic guarantees no underflow on either branch.
    if joined_ms <= now_ms {
        let age_ms = now_ms.saturating_sub(joined_ms);
        if age_ms > vouch_freshness_ms {
            // Report first member as the "voucher" anchor — age applies to the
            // ceremony's joined_at, which is shared by all vouches by construction.
            let voucher = params
                .members
                .first()
                .map(|m| m.did.clone())
                .unwrap_or_else(|| Did::new(""));
            return Err(CommunityAssemblyError::VouchStale {
                voucher,
                age_seconds: age_ms / 1000,
            });
        }
    } else {
        let skew_ms = joined_ms.saturating_sub(now_ms);
        if skew_ms > clock_skew_ms {
            let voucher = params
                .members
                .first()
                .map(|m| m.did.clone())
                .unwrap_or_else(|| Did::new(""));
            return Err(CommunityAssemblyError::VouchFuture {
                voucher,
                skew_seconds: skew_ms / 1000,
            });
        }
    }

    // ── Invariant 2: expiration window ──
    let lifetime_ms = params.expires_at.0.saturating_sub(now_ms);
    let min_lifetime_ms = MIN_EXPIRES_SECS.saturating_mul(1000);
    let max_lifetime_ms = MAX_EXPIRES_SECS.saturating_mul(1000);
    if lifetime_ms < min_lifetime_ms {
        return Err(CommunityAssemblyError::ExpirationTooSoon {
            seconds: lifetime_ms / 1000,
        });
    }
    if lifetime_ms > max_lifetime_ms {
        return Err(CommunityAssemblyError::ExpirationTooFar {
            seconds: lifetime_ms / 1000,
        });
    }

    // ── Invariant 3 & 4: bounded member / vouch counts ──
    if params.members.is_empty() || params.members.len() > MAX_CEREMONY_MEMBERS {
        return Err(CommunityAssemblyError::QuorumUnsatisfiable {
            member: Did::new(""),
            needed: params.quorum.value(),
            available: 0,
        });
    }
    for cm in &params.members {
        if cm.vouches.len() > MAX_VOUCHES_PER_MEMBER {
            return Err(CommunityAssemblyError::QuorumUnsatisfiable {
                member: cm.did.clone(),
                needed: params.quorum.value(),
                #[allow(clippy::cast_possible_truncation)]
                available: cm.vouches.len().min(u8::MAX as usize) as u8,
            });
        }
    }

    // ── Compute deterministic fingerprint from member DIDs ──
    let member_dids: Vec<Did> = params.members.iter().map(|cm| cm.did.clone()).collect();
    let fingerprint = CommunityId::compute(&params.name, params.quorum, &member_dids);

    // ── Invariant 5 & 6: per-vouch signature, per-member quorum ──
    let mut members = Vec::with_capacity(params.members.len());
    for cm in params.members {
        for vouch in &cm.vouches {
            verify_vouch(vouch, &cm.did, &fingerprint, params.joined_at).map_err(|_| {
                CommunityAssemblyError::Verify(CommunityVerifyError::BadVouch {
                    member: cm.did.clone(),
                    voucher: vouch.voucher_did.clone(),
                })
            })?;
        }

        #[allow(clippy::cast_possible_truncation)]
        let available_unique = {
            let set: std::collections::HashSet<&str> = cm
                .vouches
                .iter()
                .filter(|v| v.voucher_did.as_str() != cm.did.as_str())
                .map(|v| v.voucher_did.as_str())
                .collect();
            set.len().min(u8::MAX as usize) as u8
        };

        let entry =
            MemberEntry::new_validated(cm.did.clone(), params.joined_at, cm.vouches, params.quorum)
                .ok_or_else(|| CommunityAssemblyError::QuorumUnsatisfiable {
                    member: cm.did.clone(),
                    needed: params.quorum.value(),
                    available: available_unique,
                })?;
        members.push(entry);
    }

    let community = Community {
        fingerprint,
        name: params.name,
        quorum: params.quorum,
        members,
        stronghold_did: params.stronghold_did,
        baseline_trust: params.baseline_trust,
        grants: params.grants,
        expires_at: params.expires_at,
    };

    // ── Invariant 7: QR budget ──
    let body = postcard::to_allocvec(&community).map_err(|_| {
        CommunityAssemblyError::QrBudgetExceeded {
            bytes: usize::MAX, // encoding failure treated as ceiling violation
        }
    })?;
    // Include version byte in the budget check — that is what we actually ship.
    let payload_len = body.len().saturating_add(1);
    if payload_len > QR_PAYLOAD_BUDGET_BYTES {
        return Err(CommunityAssemblyError::QrBudgetExceeded { bytes: payload_len });
    }

    Ok(community)
}

// ── Vouch Signing ──────────────────────────────────────────────────────

/// Sign a vouch: Ed25519 signature over (member_did || community_fingerprint || joined_at).
/// Pure logic — no IO. The inverse of [`verify_vouch`].
pub fn sign_vouch(
    signer: &SigningKey,
    signer_did: &Did,
    member_did: &Did,
    community_id: &CommunityId,
    joined_at: PhalanxTimestamp,
) -> Vouch {
    let mut message = Vec::new();
    message.extend_from_slice(member_did.as_ref().as_bytes());
    message.extend_from_slice(&community_id.0);
    message.extend_from_slice(&joined_at.0.to_le_bytes());

    let signature = signer.sign(&message);
    Vouch {
        voucher_did: signer_did.clone(),
        signature: VouchSignature::new(signature.to_bytes()),
    }
}

// ── Ceremony Verbs ──────────────────────────────────────────────────────
//
// These three verbs thread `request_id` + freshness + slot-integrity
// checks on top of `sign_vouch` / `verify_vouch`. Layering the
// ceremony-level bookkeeping here (not inside the primitives) keeps
// `sign_vouch` reusable for code paths that already know the member
// and fingerprint directly.

/// Project a [`VouchRequest`] to its review-safe preview shape. Pure
/// copy — drops `voucher_did` so the preview type cannot be fed back
/// into [`sign_vouch_response`] (the type system enforces the
/// projection direction).
#[must_use]
pub fn preview_vouch_request(request: &VouchRequest) -> VouchRequestPreview {
    VouchRequestPreview {
        request_id: request.request_id,
        tentative_fingerprint: request.tentative_fingerprint,
        name: request.name.clone(),
        quorum: request.quorum,
        members: request.members.clone(),
        member_did: request.member_did.clone(),
        issued_at: request.issued_at,
        member_joined_at: request.member_joined_at,
    }
}

/// Produce a [`VouchResponse`] for a received [`VouchRequest`].
///
/// Fails with [`CeremonyError::VoucherMismatch`] if the signing key
/// does not match `request.voucher_did` — i.e., the caller picked up
/// a request addressed to a different device. The ceremony protocol
/// assumes every vouch is signed by the key the initiator expects, so
/// this eager check prevents a voucher from producing a signature that
/// would later fail `verify_vouch_response`.
///
/// Fails with [`CeremonyError::ResponseStale`] when the signed
/// `member_joined_at` is already older than
/// [`CEREMONY_RESPONSE_FRESHNESS_SECS`] at sign time. The voucher's
/// phone clock says "this request has already aged out, don't produce
/// a doomed response" — verification will reject a stale response
/// anyway, but catching it at sign time yields a cleaner UX on the
/// voucher's device.
///
/// The signature binds `(request.member_did ||
/// request.tentative_fingerprint || request.member_joined_at)` — the
/// same pre-image as [`sign_vouch`] and [`verify_vouch`]. Pure logic —
/// no IO, no ambient clock.
pub fn sign_vouch_response(
    voucher_sk: &SigningKey,
    request: &VouchRequest,
    now: PhalanxTimestamp,
) -> Result<VouchResponse, CeremonyError> {
    // 1. Voucher identity: derive the signer's DID from the key and
    //    compare to the slot this request targets. A mismatch here
    //    means the key-holder picked up someone else's request.
    let pk_bytes = voucher_sk.verifying_key().to_bytes();
    let signer_did = Did::derive_did_key(&pk_bytes);
    if signer_did != request.voucher_did {
        return Err(CeremonyError::VoucherMismatch {
            expected: request.voucher_did.clone(),
            actual: signer_did,
        });
    }

    // 2. Eager freshness check on the signed `member_joined_at`. We
    //    refuse to produce a response that is already too old to
    //    verify — saves a round-trip.
    let age_ms = now.0.saturating_sub(request.member_joined_at.0);
    let window_ms = CEREMONY_RESPONSE_FRESHNESS_SECS.saturating_mul(1000);
    if age_ms > window_ms {
        return Err(CeremonyError::ResponseStale {
            age_seconds: age_ms / 1000,
        });
    }

    // 3. Produce the signature via the existing primitive.
    let vouch = sign_vouch(
        voucher_sk,
        &signer_did,
        &request.member_did,
        &request.tentative_fingerprint,
        request.member_joined_at,
    );
    Ok(VouchResponse {
        request_id: request.request_id,
        vouch,
    })
}

/// Verify a received [`VouchResponse`] against the
/// [`VouchRequest`] the initiator issued.
///
/// Checks, in order:
/// 1. `response.request_id == request.request_id` — response is for
///    a request we actually issued. Typical failure: stray response
///    from an aborted-and-restarted ceremony.
/// 2. Freshness: `now - request.member_joined_at <
///    CEREMONY_RESPONSE_FRESHNESS_SECS`. Freshness is gated by the
///    *signed* `member_joined_at` — never the unsigned
///    `issued_at` — because a replay attacker could forge the latter
///    to defeat the window.
/// 3. Slot integrity: `response.vouch.voucher_did == request.voucher_did`.
///    A voucher cannot sign one slot and submit the response as if it
///    were for another.
/// 4. Signature verification via [`verify_vouch`] against
///    `(request.member_did, request.tentative_fingerprint,
///    request.member_joined_at)`. Failure here means the voucher
///    signed a different fingerprint (tampered tentative) or a
///    different member — surface as [`CeremonyError::FingerprintMismatch`].
///
/// Pure logic — no IO, no ambient clock. `now` must come from a
/// [`TrustedClock`] (§III Temporal Agreement).
///
/// [`TrustedClock`]: phalanx_proto::prelude::TrustedClock
pub fn verify_vouch_response(
    request: &VouchRequest,
    response: &VouchResponse,
    now: PhalanxTimestamp,
) -> Result<(), CeremonyError> {
    // 1. request_id match.
    if response.request_id != request.request_id {
        return Err(CeremonyError::RequestIdMismatch);
    }

    // 2. Freshness on the signed member_joined_at.
    let age_ms = now.0.saturating_sub(request.member_joined_at.0);
    let window_ms = CEREMONY_RESPONSE_FRESHNESS_SECS.saturating_mul(1000);
    if age_ms > window_ms {
        return Err(CeremonyError::ResponseStale {
            age_seconds: age_ms / 1000,
        });
    }

    // 3. Slot integrity — voucher in response must match the slot
    //    the request targets.
    if response.vouch.voucher_did != request.voucher_did {
        return Err(CeremonyError::VoucherMismatch {
            expected: request.voucher_did.clone(),
            actual: response.vouch.voucher_did.clone(),
        });
    }

    // 4. Signature verification. Ed25519 rejection here implies the
    //    voucher signed a different fingerprint or member_did — both
    //    roll up under FingerprintMismatch for UX purposes.
    verify_vouch(
        &response.vouch,
        &request.member_did,
        &request.tentative_fingerprint,
        request.member_joined_at,
    )
    .map_err(|_| CeremonyError::FingerprintMismatch)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
mod tests {
    use super::*;
    use phalanx_proto::community::CeremonyNonce;
    use phalanx_proto::identity::Did;
    use rand_core::OsRng;

    fn make_identity() -> (Did, SigningKey) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let pk_bytes = signing_key.verifying_key().to_bytes();
        let did = Did::derive_did_key(&pk_bytes);
        (did, signing_key)
    }

    #[test]
    fn sign_then_verify_roundtrip() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        let vouch = sign_vouch(
            &voucher_sk,
            &voucher_did,
            &member_did,
            &community_id,
            joined_at,
        );
        assert!(verify_vouch(&vouch, &member_did, &community_id, joined_at).is_ok());
    }

    #[test]
    fn sign_vouch_wrong_community_fails() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let wrong_id = CommunityId([99u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        let vouch = sign_vouch(
            &voucher_sk,
            &voucher_did,
            &member_did,
            &community_id,
            joined_at,
        );
        // Verify against wrong community — should fail
        assert!(verify_vouch(&vouch, &member_did, &wrong_id, joined_at).is_err());
    }

    #[test]
    fn vouch_verification_valid() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        // Build the message and sign it
        let mut msg = Vec::new();
        msg.extend_from_slice(member_did.as_ref().as_bytes());
        msg.extend_from_slice(&community_id.0);
        msg.extend_from_slice(&joined_at.0.to_le_bytes());

        let sig = voucher_sk.sign(&msg);

        let vouch = Vouch {
            voucher_did: voucher_did.clone(),
            signature: VouchSignature::new(sig.to_bytes()),
        };

        assert!(verify_vouch(&vouch, &member_did, &community_id, joined_at).is_ok());
    }

    #[test]
    fn vouch_verification_wrong_member_fails() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let (wrong_did, _) = make_identity();
        let community_id = CommunityId([42u8; 32]);
        let joined_at = PhalanxTimestamp(1000);

        let mut msg = Vec::new();
        msg.extend_from_slice(member_did.as_ref().as_bytes());
        msg.extend_from_slice(&community_id.0);
        msg.extend_from_slice(&joined_at.0.to_le_bytes());

        let sig = voucher_sk.sign(&msg);

        let vouch = Vouch {
            voucher_did,
            signature: VouchSignature::new(sig.to_bytes()),
        };

        // Verify against wrong member DID — should fail
        assert!(verify_vouch(&vouch, &wrong_did, &community_id, joined_at).is_err());
    }

    // ── Community Assembly & Verification Tests ─────────────────────────

    fn build_ceremony_member(
        signer_sk: &SigningKey,
        signer_did: &Did,
        member_did: &Did,
        community_id: &CommunityId,
        joined_at: PhalanxTimestamp,
    ) -> CeremonyMember {
        let vouch = sign_vouch(signer_sk, signer_did, member_did, community_id, joined_at);
        CeremonyMember {
            did: member_did.clone(),
            vouches: vec![vouch],
        }
    }

    #[test]
    fn assemble_community_happy_path() {
        let (voucher_a_did, voucher_a_sk) = make_identity();
        let (voucher_b_did, voucher_b_sk) = make_identity();
        let (member_did, _) = make_identity();

        let name = PetName::new("ACLU Portland").unwrap();
        let quorum = Quorum::new(2).unwrap();
        let now = PhalanxTimestamp(1_000_000);
        let joined_at = now;
        let expires_at = PhalanxTimestamp(now.0 + 10 * 60_000); // +10 minutes

        // Pre-compute fingerprint using the member list that assembly will use.
        let tentative_fingerprint =
            CommunityId::compute(&name, quorum, std::slice::from_ref(&member_did));

        let vouch_a = sign_vouch(
            &voucher_a_sk,
            &voucher_a_did,
            &member_did,
            &tentative_fingerprint,
            joined_at,
        );
        let vouch_b = sign_vouch(
            &voucher_b_sk,
            &voucher_b_did,
            &member_did,
            &tentative_fingerprint,
            joined_at,
        );

        let params = CommunityAssemblyParams {
            name: name.clone(),
            quorum,
            joined_at,
            expires_at,
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: vec![CeremonyMember {
                did: member_did.clone(),
                vouches: vec![vouch_a, vouch_b],
            }],
        };

        let community = assemble_community(params, now).expect("happy path");
        assert_eq!(community.fingerprint, tentative_fingerprint);
        assert_eq!(community.members.len(), 1);

        // Verify round-trips cleanly.
        verify_community_vouches(&community, now).expect("valid community");
    }

    #[test]
    fn assemble_community_rejects_expired_too_soon() {
        let (_, _) = make_identity();
        let (member_did, _) = make_identity();
        let name = PetName::new("too-brief").unwrap();
        let quorum = Quorum::new(1).unwrap();
        let now = PhalanxTimestamp(1_000_000);
        let params = CommunityAssemblyParams {
            name,
            quorum,
            joined_at: now,
            // 1 second after now — below MIN_EXPIRES_SECS
            expires_at: PhalanxTimestamp(now.0 + 1000),
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: vec![CeremonyMember {
                did: member_did,
                vouches: vec![],
            }],
        };

        let err = assemble_community(params, now).unwrap_err();
        assert!(matches!(
            err,
            CommunityAssemblyError::ExpirationTooSoon { .. }
        ));
    }

    #[test]
    fn assemble_community_rejects_expiration_too_far() {
        let (member_did, _) = make_identity();
        let name = PetName::new("immortal").unwrap();
        let quorum = Quorum::new(1).unwrap();
        let now = PhalanxTimestamp(1_000_000);
        // 31 days out — above MAX_EXPIRES_SECS
        let expires_at = PhalanxTimestamp(now.0 + (31u64 * 86_400 * 1000));

        let params = CommunityAssemblyParams {
            name,
            quorum,
            joined_at: now,
            expires_at,
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: vec![CeremonyMember {
                did: member_did,
                vouches: vec![],
            }],
        };

        let err = assemble_community(params, now).unwrap_err();
        assert!(matches!(
            err,
            CommunityAssemblyError::ExpirationTooFar { .. }
        ));
    }

    #[test]
    fn assemble_community_rejects_stale_vouch() {
        let (member_did, _) = make_identity();
        let name = PetName::new("stale").unwrap();
        let quorum = Quorum::new(1).unwrap();
        let now = PhalanxTimestamp(10 * 60 * 60 * 1000); // 10 hours
        // joined_at 2h earlier — outside the 1h freshness window.
        let joined_at = PhalanxTimestamp(now.0 - 2 * 60 * 60 * 1000);
        let expires_at = PhalanxTimestamp(now.0 + 10 * 60_000);

        let params = CommunityAssemblyParams {
            name,
            quorum,
            joined_at,
            expires_at,
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: vec![CeremonyMember {
                did: member_did,
                vouches: vec![],
            }],
        };

        let err = assemble_community(params, now).unwrap_err();
        assert!(matches!(err, CommunityAssemblyError::VouchStale { .. }));
    }

    #[test]
    fn assemble_community_rejects_future_vouch() {
        let (member_did, _) = make_identity();
        let name = PetName::new("future").unwrap();
        let quorum = Quorum::new(1).unwrap();
        let now = PhalanxTimestamp(10 * 60 * 60 * 1000);
        // joined_at 10 minutes *after* now — > 5-minute skew tolerance.
        let joined_at = PhalanxTimestamp(now.0 + 10 * 60_000);
        let expires_at = PhalanxTimestamp(now.0 + 30 * 60_000);

        let params = CommunityAssemblyParams {
            name,
            quorum,
            joined_at,
            expires_at,
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: vec![CeremonyMember {
                did: member_did,
                vouches: vec![],
            }],
        };

        let err = assemble_community(params, now).unwrap_err();
        assert!(matches!(err, CommunityAssemblyError::VouchFuture { .. }));
    }

    #[test]
    fn assemble_community_rejects_quorum_unsatisfiable() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let name = PetName::new("lonely").unwrap();
        let quorum = Quorum::new(2).unwrap(); // needs 2 unique vouchers
        let now = PhalanxTimestamp(1_000_000);
        let expires_at = PhalanxTimestamp(now.0 + 10 * 60_000);

        let tentative_fingerprint =
            CommunityId::compute(&name, quorum, std::slice::from_ref(&member_did));
        let vouch = sign_vouch(
            &voucher_sk,
            &voucher_did,
            &member_did,
            &tentative_fingerprint,
            now,
        );

        let params = CommunityAssemblyParams {
            name,
            quorum,
            joined_at: now,
            expires_at,
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            members: vec![CeremonyMember {
                did: member_did,
                vouches: vec![vouch],
            }],
        };

        let err = assemble_community(params, now).unwrap_err();
        assert!(matches!(
            err,
            CommunityAssemblyError::QuorumUnsatisfiable { .. }
        ));
    }

    #[test]
    fn verify_community_vouches_rejects_expired() {
        let (voucher_did, voucher_sk) = make_identity();
        let (member_did, _) = make_identity();
        let name = PetName::new("expired").unwrap();
        let quorum = Quorum::new(1).unwrap();
        let joined_at = PhalanxTimestamp(1_000_000);
        let expires_at = PhalanxTimestamp(joined_at.0 + 10 * 60_000);

        let tentative_fingerprint =
            CommunityId::compute(&name, quorum, std::slice::from_ref(&member_did));
        let vouch = sign_vouch(
            &voucher_sk,
            &voucher_did,
            &member_did,
            &tentative_fingerprint,
            joined_at,
        );
        let community = assemble_community(
            CommunityAssemblyParams {
                name,
                quorum,
                joined_at,
                expires_at,
                stronghold_did: None,
                baseline_trust: TrustLevel::Verified,
                grants: CommunityGrants::default(),
                members: vec![CeremonyMember {
                    did: member_did,
                    vouches: vec![vouch],
                }],
            },
            joined_at,
        )
        .expect("assemble OK");

        // Verify at a timestamp past expiration.
        let past_expiry = PhalanxTimestamp(expires_at.0 + 1);
        let err = verify_community_vouches(&community, past_expiry).unwrap_err();
        assert!(matches!(err, CommunityVerifyError::Expired { .. }));
    }

    #[test]
    fn payload_envelope_roundtrip() {
        let body = vec![1u8, 2, 3, 4, 5];
        let wrapped = wrap_payload_version(&body);
        assert_eq!(wrapped[0], COMMUNITY_PAYLOAD_VERSION);
        let inner = strip_payload_version(&wrapped).expect("valid envelope");
        assert_eq!(inner, body.as_slice());
    }

    #[test]
    fn payload_envelope_rejects_unknown_version() {
        let mut wrapped = vec![0x02u8];
        wrapped.extend_from_slice(&[9, 9, 9]);
        let err = strip_payload_version(&wrapped).unwrap_err();
        assert!(matches!(
            err,
            CommunityVerifyError::UnsupportedVersion { version: 0x02 }
        ));
    }

    #[test]
    fn payload_envelope_rejects_empty() {
        let err = strip_payload_version(&[]).unwrap_err();
        assert!(matches!(
            err,
            CommunityVerifyError::UnsupportedVersion { version: 0 }
        ));
    }

    // ── Ceremony envelope helper tests ──────────────────────────────

    #[test]
    fn vouch_request_envelope_roundtrip() {
        let body = vec![7u8, 8, 9, 10, 11];
        let wrapped = wrap_vouch_request(&body);
        assert_eq!(wrapped[0], VOUCH_REQUEST_VERSION);
        assert_eq!(wrapped.len(), body.len() + 1);
        let inner = strip_vouch_request(&wrapped).expect("valid request envelope");
        assert_eq!(inner, body.as_slice());
    }

    #[test]
    fn vouch_request_envelope_rejects_unknown_version() {
        let mut wrapped = vec![0x99u8];
        wrapped.extend_from_slice(&[1, 2, 3]);
        let err = strip_vouch_request(&wrapped).unwrap_err();
        assert!(matches!(
            err,
            CeremonyError::UnsupportedVersion { version: 0x99 }
        ));
    }

    #[test]
    fn vouch_request_envelope_rejects_empty() {
        let err = strip_vouch_request(&[]).unwrap_err();
        assert!(matches!(
            err,
            CeremonyError::UnsupportedVersion { version: 0 }
        ));
    }

    #[test]
    fn vouch_response_envelope_roundtrip() {
        let body = vec![42u8; 96]; // approximate vouch signature size
        let wrapped = wrap_vouch_response(&body);
        assert_eq!(wrapped[0], VOUCH_RESPONSE_VERSION);
        let inner = strip_vouch_response(&wrapped).expect("valid response envelope");
        assert_eq!(inner, body.as_slice());
    }

    #[test]
    fn vouch_response_envelope_rejects_unknown_version() {
        let mut wrapped = vec![0xAAu8];
        wrapped.extend_from_slice(&[4, 5, 6]);
        let err = strip_vouch_response(&wrapped).unwrap_err();
        assert!(matches!(
            err,
            CeremonyError::UnsupportedVersion { version: 0xAA }
        ));
    }

    #[test]
    fn vouch_response_envelope_rejects_empty() {
        let err = strip_vouch_response(&[]).unwrap_err();
        assert!(matches!(
            err,
            CeremonyError::UnsupportedVersion { version: 0 }
        ));
    }

    /// Request envelope accepts only `VOUCH_REQUEST_VERSION`, not the
    /// response version. The two streams are distinct by design — a
    /// mis-labelled envelope must fail fast rather than silently
    /// decoding into the wrong Noun.
    #[test]
    fn request_envelope_rejects_response_version_byte() {
        // Hand-construct: response version byte + arbitrary body.
        assert_ne!(
            VOUCH_REQUEST_VERSION,
            VOUCH_RESPONSE_VERSION.wrapping_add(1)
        );
        // If the two constants ever diverge (e.g., request bumps to v2
        // while response stays at v1), this test's premise needs revisiting.
        // For v1 both are 0x01, so we cross-check with a synthetic 0x02.
        let mut wrapped = vec![0x02u8];
        wrapped.extend_from_slice(&[0u8; 4]);
        let err = strip_vouch_request(&wrapped).unwrap_err();
        assert!(matches!(
            err,
            CeremonyError::UnsupportedVersion { version: 0x02 }
        ));
    }

    // ── Ceremony verb tests ─────────────────────────────────────────

    /// Construct a well-formed `VouchRequest` the voucher signs.
    /// Returns `(request, voucher_sk)` so tests can produce responses.
    /// The `ceremony_nonce` is fixed (all-zero) inside tests — randomness
    /// only matters for disambiguating ceremony restarts in production;
    /// deterministic bytes keep the test assertions stable.
    fn make_vouch_request(
        member_did: &Did,
        tentative: CommunityId,
        now: PhalanxTimestamp,
    ) -> (VouchRequest, SigningKey) {
        let (voucher_did, voucher_sk) = make_identity();
        let name = PetName::new("ceremony-verb-test").unwrap();
        let quorum = Quorum::new(1).unwrap();
        let ceremony_nonce = CeremonyNonce([0u8; 16]);
        let request_id =
            VouchRequest::compute_id(&tentative, &ceremony_nonce, &voucher_did, member_did);
        let request = VouchRequest {
            request_id,
            tentative_fingerprint: tentative,
            ceremony_nonce,
            name,
            quorum,
            members: vec![member_did.clone()],
            member_did: member_did.clone(),
            voucher_did,
            issued_at: now,
            member_joined_at: now,
        };
        (request, voucher_sk)
    }

    #[test]
    fn preview_vouch_request_drops_voucher_did() {
        let (member_did, _) = make_identity();
        let now = PhalanxTimestamp(1_000_000);
        let (request, _sk) = make_vouch_request(&member_did, CommunityId([7u8; 32]), now);
        let preview = preview_vouch_request(&request);
        // Every review-relevant field round-trips.
        assert_eq!(preview.request_id, request.request_id);
        assert_eq!(preview.tentative_fingerprint, request.tentative_fingerprint);
        assert_eq!(preview.name, request.name);
        assert_eq!(preview.quorum, request.quorum);
        assert_eq!(preview.members, request.members);
        assert_eq!(preview.member_did, request.member_did);
        assert_eq!(preview.issued_at, request.issued_at);
        assert_eq!(preview.member_joined_at, request.member_joined_at);
        // `voucher_did` is intentionally absent from the preview — the
        // type system (no such field on `VouchRequestPreview`) already
        // enforces this at compile time; no runtime check required.
    }

    #[test]
    fn sign_then_verify_vouch_response_roundtrip() {
        let (member_did, _) = make_identity();
        let now = PhalanxTimestamp(1_000_000);
        let (request, voucher_sk) = make_vouch_request(&member_did, CommunityId([7u8; 32]), now);

        let response = sign_vouch_response(&voucher_sk, &request, now).expect("sign");
        assert_eq!(response.request_id, request.request_id);
        assert_eq!(response.vouch.voucher_did, request.voucher_did);

        verify_vouch_response(&request, &response, now).expect("verify");
    }

    #[test]
    fn sign_vouch_response_rejects_voucher_mismatch() {
        let (member_did, _) = make_identity();
        let now = PhalanxTimestamp(1_000_000);
        let (request, _correct_sk) = make_vouch_request(&member_did, CommunityId([7u8; 32]), now);

        // A different signer tries to sign this slot.
        let (_wrong_did, wrong_sk) = make_identity();
        let err = sign_vouch_response(&wrong_sk, &request, now).unwrap_err();
        assert!(matches!(err, CeremonyError::VoucherMismatch { .. }));
    }

    #[test]
    fn sign_vouch_response_rejects_stale_request() {
        let (member_did, _) = make_identity();
        let signed_at = PhalanxTimestamp(1_000_000);
        let (request, voucher_sk) =
            make_vouch_request(&member_did, CommunityId([7u8; 32]), signed_at);

        // now is 2 hours past member_joined_at — outside the 1h window.
        let now = PhalanxTimestamp(signed_at.0 + 2 * 60 * 60 * 1000);
        let err = sign_vouch_response(&voucher_sk, &request, now).unwrap_err();
        match err {
            CeremonyError::ResponseStale { age_seconds } => {
                assert!(age_seconds >= CEREMONY_RESPONSE_FRESHNESS_SECS);
            }
            other => panic!("expected ResponseStale, got {other:?}"),
        }
    }

    #[test]
    fn verify_vouch_response_rejects_request_id_mismatch() {
        let (member_did, _) = make_identity();
        let now = PhalanxTimestamp(1_000_000);
        let (request, voucher_sk) = make_vouch_request(&member_did, CommunityId([7u8; 32]), now);

        let mut response = sign_vouch_response(&voucher_sk, &request, now).unwrap();
        // Tamper with the request_id so verify can no longer match.
        response.request_id = [0xFFu8; 32];

        let err = verify_vouch_response(&request, &response, now).unwrap_err();
        assert!(matches!(err, CeremonyError::RequestIdMismatch));
    }

    #[test]
    fn verify_vouch_response_rejects_stale_response() {
        let (member_did, _) = make_identity();
        let signed_at = PhalanxTimestamp(1_000_000);
        let (request, voucher_sk) =
            make_vouch_request(&member_did, CommunityId([7u8; 32]), signed_at);
        // Produce the response at signed_at — legitimate at sign time.
        let response = sign_vouch_response(&voucher_sk, &request, signed_at).unwrap();

        // Verify hours later — past the freshness window.
        let verify_at = PhalanxTimestamp(signed_at.0 + 2 * 60 * 60 * 1000);
        let err = verify_vouch_response(&request, &response, verify_at).unwrap_err();
        assert!(matches!(err, CeremonyError::ResponseStale { .. }));
    }

    #[test]
    fn verify_vouch_response_rejects_fingerprint_mismatch() {
        let (member_did, _) = make_identity();
        let now = PhalanxTimestamp(1_000_000);
        let (request, voucher_sk) = make_vouch_request(&member_did, CommunityId([7u8; 32]), now);
        let response = sign_vouch_response(&voucher_sk, &request, now).unwrap();

        // Feed verify a request whose fingerprint the signature does
        // not commit to — signature verification fails →
        // FingerprintMismatch.
        let mut tampered = request.clone();
        tampered.tentative_fingerprint = CommunityId([0xAAu8; 32]);
        // Keep `request_id` consistent with the (new) tentative so the
        // request_id check passes and we reach the signature check.
        tampered.request_id = VouchRequest::compute_id(
            &tampered.tentative_fingerprint,
            &tampered.ceremony_nonce,
            &tampered.voucher_did,
            &tampered.member_did,
        );
        // Response's request_id must match this tampered view for the
        // test to reach the signature step.
        let mut tampered_response = response.clone();
        tampered_response.request_id = tampered.request_id;

        let err = verify_vouch_response(&tampered, &tampered_response, now).unwrap_err();
        assert!(matches!(err, CeremonyError::FingerprintMismatch));
    }

    #[test]
    fn verify_vouch_response_rejects_slot_voucher_mismatch() {
        let (member_did, _) = make_identity();
        let now = PhalanxTimestamp(1_000_000);
        let (request, voucher_sk) = make_vouch_request(&member_did, CommunityId([7u8; 32]), now);
        let response = sign_vouch_response(&voucher_sk, &request, now).unwrap();

        // Tamper with the response's voucher_did (as if a malicious
        // intermediary swapped it). Slot-integrity check fires before
        // the signature check.
        let mut tampered_response = response.clone();
        let (other_did, _) = make_identity();
        tampered_response.vouch.voucher_did = other_did;

        let err = verify_vouch_response(&request, &tampered_response, now).unwrap_err();
        assert!(matches!(err, CeremonyError::VoucherMismatch { .. }));
    }

    // suppress unused warning — fixture is imported for symmetry with other tests.
    #[allow(dead_code)]
    fn _unused_fixture() -> CeremonyMember {
        let (sk, _) = (SigningKey::generate(&mut OsRng), ());
        let did = Did::new("did:key:zExample");
        build_ceremony_member(
            &sk,
            &did,
            &did,
            &CommunityId([0u8; 32]),
            PhalanxTimestamp(0),
        )
    }

    // ── DID resolution hardening ────────────────────────────────────────

    #[test]
    fn resolve_did_public_key_roundtrips_ephemeral_identity() {
        // Positive path: an identity's own DID must resolve to its own
        // verifying key bytes. If this drifts, locally-signed envelopes
        // become unverifiable on the mesh.
        use phalanx_proto::prelude::PhalanxIdentity;
        let identity = PhalanxIdentity::new_ephemeral();
        let recovered = resolve_did_public_key(&identity.did)
            .expect("ephemeral identity's own DID must resolve");
        assert_eq!(recovered, identity.keypair.verifying_key().to_bytes());
    }

    #[test]
    fn resolve_did_public_key_rejects_missing_did_key_prefix() {
        // A `did:web:` or bare string must not be accepted by a `did:key:`-only resolver.
        let bad = Did("did:web:example.com".into());
        assert!(matches!(
            resolve_did_public_key(&bad),
            Err(CryptoError::DidResolutionFailure)
        ));
    }

    #[test]
    fn resolve_did_public_key_rejects_missing_z_multibase() {
        // Non-`z` multibase (e.g. `m` for base64) is not supported by this resolver.
        let bad = Did("did:key:mABCDEF".into());
        assert!(matches!(
            resolve_did_public_key(&bad),
            Err(CryptoError::DidResolutionFailure)
        ));
    }

    #[test]
    fn resolve_did_public_key_rejects_wrong_multicodec() {
        // Multicodec 0xec,0x01 is X25519, not Ed25519 (0xed,0x01). A resolver
        // that accepts the wrong codec would let X25519 keys masquerade as
        // Ed25519 signers.
        let mut wrong = vec![0xec, 0x01];
        wrong.extend_from_slice(&[7u8; 32]);
        let encoded = bs58::encode(&wrong).into_string();
        let bad = Did(format!("did:key:z{encoded}"));
        assert!(matches!(
            resolve_did_public_key(&bad),
            Err(CryptoError::DidResolutionFailure)
        ));
    }

    #[test]
    fn resolve_did_public_key_rejects_wrong_key_length() {
        // Multicodec header is correct but the key bytes are 16 instead of 32.
        // Silent acceptance here would write a truncated buffer.
        let mut bad_bytes = vec![0xed, 0x01];
        bad_bytes.extend_from_slice(&[3u8; 16]);
        let encoded = bs58::encode(&bad_bytes).into_string();
        let bad = Did(format!("did:key:z{encoded}"));
        assert!(matches!(
            resolve_did_public_key(&bad),
            Err(CryptoError::DidResolutionFailure)
        ));
    }

    #[test]
    fn resolve_did_public_key_rejects_non_base58_payload() {
        // Valid prefix, valid `z`, but the payload contains characters that
        // Base58 does not accept (e.g. `0`, `O`, `l`). Must fail cleanly.
        let bad = Did("did:key:z0OIl".into());
        assert!(matches!(
            resolve_did_public_key(&bad),
            Err(CryptoError::DidResolutionFailure)
        ));
    }
}
