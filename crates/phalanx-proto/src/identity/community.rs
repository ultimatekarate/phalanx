// crates/phalanx-proto/src/community.rs
//
// The Shield Wall: Trusted Communities.
//
// Dictionary layer — inert nouns. No IO, no tokio, no libp2p.
// A community is a web of trust with no central key. Identity
// emerges from the membership graph. Members are admitted when
// k existing members vouch for them.

use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::identity::Did;
use crate::time::PhalanxTimestamp;
use crate::trust::{PetName, TrustLevel};

// ── Payload Envelope Version ────────────────────────────────────────────

/// Version byte prepended to postcard-encoded community tokens.
/// `payload_bytes = [COMMUNITY_PAYLOAD_VERSION] || postcard_bytes(Community)`.
/// Incrementing this value must be matched with a new `CommunityVerifyError`
/// variant and a compatible decoder. Unknown version bytes are rejected via
/// [`CommunityVerifyError::UnsupportedVersion`].
pub const COMMUNITY_PAYLOAD_VERSION: u8 = 0x01;

// ── Community Identity ──────────────────────────────────────────────────

/// Deterministic community identity — no keypair.
/// BLAKE3 hash with domain separation:
/// `BLAKE3("PhalanxCommunityId/v1" || len(name) || name || quorum || member_count || len(did_i) || did_i ...)`.
/// DIDs are sorted lexicographically before hashing for order-independence.
/// Canary alert key derivation depends on this being high-entropy —
/// do not replace with human-readable strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommunityId(pub [u8; 32]);

impl CommunityId {
    /// Compute the deterministic community fingerprint from founding parameters.
    ///
    /// Domain-separated BLAKE3 with length-prefixed variable fields to ensure
    /// the encoding is injective (no two distinct inputs produce the same pre-image).
    /// Compute the deterministic community fingerprint.
    ///
    /// # Panics
    /// Panics if name or DID strings exceed 4 GiB (impossible in practice
    /// since `PetName` is capped at 64 chars and DIDs at 512 bytes).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // PetName ≤ 64 chars, DID ≤ 512 bytes, members ≤ 256
    pub fn compute(name: &PetName, quorum: Quorum, founding_dids: &[Did]) -> Self {
        let mut sorted: Vec<&Did> = founding_dids.iter().collect();
        sorted.sort_by(|a, b| a.as_str().cmp(b.as_str()));

        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PhalanxCommunityId/v1");

        let name_bytes = name.as_str().as_bytes();
        hasher.update(&(name_bytes.len() as u32).to_le_bytes());
        hasher.update(name_bytes);
        hasher.update(&[quorum.value()]);
        hasher.update(&(sorted.len() as u32).to_le_bytes());
        for did in &sorted {
            let did_bytes = did.as_str().as_bytes();
            hasher.update(&(did_bytes.len() as u32).to_le_bytes());
            hasher.update(did_bytes);
        }
        Self(*hasher.finalize().as_bytes())
    }
}

/// Minimum vouches required for membership. Must be > 0.
/// Constructed via `Quorum::new(n) -> Option<Self>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quorum(u8);

impl Quorum {
    /// Create a quorum threshold. Returns None if n == 0.
    pub fn new(n: u8) -> Option<Self> {
        if n == 0 { None } else { Some(Self(n)) }
    }

    pub fn value(&self) -> u8 {
        self.0
    }
}

// ── Vouch ───────────────────────────────────────────────────────────────

/// Ed25519 vouch signature. Fixed 64 bytes.
/// Stored as Vec<u8> for serde compatibility; length validated on construction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchSignature(Vec<u8>);

impl VouchSignature {
    /// Create a VouchSignature from exactly 64 bytes.
    pub fn new(bytes: [u8; 64]) -> Self {
        Self(bytes.to_vec())
    }

    /// Try to create from a slice. Returns None if not exactly 64 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == 64 {
            Some(Self(bytes.to_vec()))
        } else {
            None
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// A single vouch — one member attesting another's membership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Vouch {
    pub voucher_did: Did,
    /// Ed25519 signature over (member_did || community_fingerprint || joined_at).
    pub signature: VouchSignature,
}

// ── Member Entry (Sealed Constructor) ───────────────────────────────────

/// A validated member entry — vouch signatures verified, count >= quorum.
///
/// Private fields prevent construction without validation. The only way
/// to obtain a `MemberEntry` is through `MemberEntry::validate()`, which
/// verifies all vouch signatures and enforces the quorum threshold.
/// Correct by construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberEntry {
    member_did: Did,
    joined_at: PhalanxTimestamp,
    vouches: Vec<Vouch>,
}

impl MemberEntry {
    /// The only way to construct a MemberEntry.
    ///
    /// Enforces:
    /// 1. Unique *external* vouchers >= quorum (self-vouches don't count)
    /// 2. Duplicate voucher DIDs are collapsed (same signer cannot satisfy quorum twice)
    ///
    /// Signature verification is delegated to the Laboratory layer
    /// (phalanx-forensics) — this constructor accepts pre-verified vouches
    /// and enforces the quorum count invariant.
    /// Self-vouches are retained in the vec for audit trail but excluded
    /// from the quorum check.
    pub fn new_validated(
        member_did: Did,
        joined_at: PhalanxTimestamp,
        vouches: Vec<Vouch>,
        quorum: Quorum,
    ) -> Option<Self> {
        // Count unique external vouchers — self-vouches and duplicates excluded
        let external_unique: HashSet<&str> = vouches
            .iter()
            .filter(|v| v.voucher_did.as_str() != member_did.as_str())
            .map(|v| v.voucher_did.as_str())
            .collect();
        if external_unique.len() < quorum.value() as usize {
            return None;
        }
        Some(Self {
            member_did,
            joined_at,
            vouches,
        })
    }

    pub fn did(&self) -> &Did {
        &self.member_did
    }

    pub fn joined(&self) -> PhalanxTimestamp {
        self.joined_at
    }

    pub fn vouch_count(&self) -> usize {
        self.vouches.len()
    }

    pub fn vouches(&self) -> &[Vouch] {
        &self.vouches
    }
}

// ── Ceremony Staging ───────────────────────────────────────────────────

/// Pre-validation staging type for community ceremony assembly.
///
/// This is NOT a validated member — use [`MemberEntry::new_validated`] to
/// produce a quorum-enforced, dedup-checked member from this input.
/// Must not be persisted, transmitted on the mesh, or stored in any registry.
///
/// `joined_at` is intentionally absent — it is a ceremony-level parameter
/// passed to the assembly function, not a per-member property.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CeremonyMember {
    pub did: Did,
    pub vouches: Vec<Vouch>,
}

// ── Community Grants ────────────────────────────────────────────────────

/// What community membership conveys.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityGrants {
    /// Members' recordings are exportable by the community Stronghold.
    pub export_to_stronghold: bool,
    /// Members inherit baseline trust on the mesh.
    pub mesh_trust_elevation: bool,
}

impl Default for CommunityGrants {
    fn default() -> Self {
        Self {
            export_to_stronghold: true,
            mesh_trust_elevation: true,
        }
    }
}

// ── Community ───────────────────────────────────────────────────────────

/// A trusted community — e.g., "ACLU Portland Legal Observers".
///
/// No community-level keypair. Identity emerges from the membership graph.
/// A member is admitted when k existing members vouch for them.
///
/// Communities are ephemeral: `expires_at` determines when the community
/// auto-dissolves. Dissolution is ownership consumption + secure erasure
/// via `Zeroize`. The absence of the object IS the dissolved state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Community {
    /// Deterministic fingerprint: BLAKE3 with domain separation. See [`CommunityId::compute`].
    pub fingerprint: CommunityId,
    /// Human-readable community name.
    pub name: PetName,
    /// Minimum vouches required for membership.
    pub quorum: Quorum,
    /// Validated members.
    pub members: Vec<MemberEntry>,
    /// The Stronghold's DID — a vouched member that receives auto-grants.
    /// Optional: communities can exist without a Stronghold (phones only).
    pub stronghold_did: Option<Did>,
    /// The trust floor granted to verified members on the mesh.
    pub baseline_trust: TrustLevel,
    /// Permissions community membership conveys.
    pub grants: CommunityGrants,
    /// Community lifetime. After expiration, the community dissolves.
    pub expires_at: PhalanxTimestamp,
}

impl Community {
    /// Check if the community has expired.
    pub fn is_expired(&self, now: PhalanxTimestamp) -> bool {
        now.0 >= self.expires_at.0
    }

    /// Check if a DID is a validated member of this community.
    pub fn is_member(&self, did: &Did) -> bool {
        self.members.iter().any(|m| m.did() == did)
    }

    /// Dissolve the community. Consumes self, securely erases sensitive data.
    /// The caller must remove the community from any HashMap/storage.
    pub fn dissolve(mut self) {
        // Zeroize the fingerprint (community identity)
        self.fingerprint.0.zeroize();
        // Clear and drop all member credentials
        for member in &mut self.members {
            for vouch in &mut member.vouches {
                vouch.signature.0.zeroize(); // Vec<u8> implements Zeroize
            }
            member.vouches.clear();
        }
        self.members.clear();
        // Clear stronghold DID if present
        self.stronghold_did = None;
        // self is dropped here — no dissolved object exists
    }
}

// ── Error Surfaces ──────────────────────────────────────────────────────

/// Errors that can arise when verifying a community token (import or preview).
///
/// `#[non_exhaustive]` keeps the wire ABI stable as new rejection reasons are
/// added — older decoders see a fallback variant without breaking.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CommunityVerifyError {
    /// Community has already expired by `now` ≥ `expires_at`.
    #[error("community {community_id:?} expired at {expires_at:?} (now={now:?})")]
    Expired {
        community_id: CommunityId,
        now: PhalanxTimestamp,
        expires_at: PhalanxTimestamp,
    },
    /// A vouch signature failed Ed25519 verification.
    #[error("bad vouch: voucher {voucher} on member {member}")]
    BadVouch { member: Did, voucher: Did },
    /// A member has fewer unique external vouchers than the community quorum.
    #[error("quorum violation for member {member}")]
    QuorumViolation { member: Did },
    /// Payload envelope version is not recognized by this build.
    #[error("unsupported community payload version {version}")]
    UnsupportedVersion { version: u8 },
}

/// Errors that can arise when assembling a fresh community during a ceremony.
///
/// Emitted by the `assemble_community` verb in `phalanx-forensics`. Carries
/// enough context that a CLI / GUI caller can surface a specific message to
/// the operator — all variants report the offending value.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CommunityAssemblyError {
    /// A vouch was signed too long ago (≤ `joined_at < now` by > 1 h).
    #[error("vouch from {voucher} is stale ({age_seconds}s old)")]
    VouchStale { voucher: Did, age_seconds: u64 },
    /// A vouch was signed too far in the future (> 5 min clock skew).
    #[error("vouch from {voucher} is {skew_seconds}s in the future")]
    VouchFuture { voucher: Did, skew_seconds: u64 },
    /// `expires_at` is less than `MIN_EXPIRES_SECS` after `now`.
    #[error("community expires too soon ({seconds}s)")]
    ExpirationTooSoon { seconds: u64 },
    /// `expires_at` is more than `MAX_EXPIRES_SECS` after `now`.
    #[error("community expires too far in the future ({seconds}s)")]
    ExpirationTooFar { seconds: u64 },
    /// Not enough unique external vouchers to satisfy quorum for this member.
    #[error("quorum unsatisfiable for {member}: need {needed}, have {available}")]
    QuorumUnsatisfiable {
        member: Did,
        needed: u8,
        available: u8,
    },
    /// Serialized payload exceeds QR v40 alphanumeric capacity (~2800 bytes).
    #[error("QR payload budget exceeded ({bytes} bytes)")]
    QrBudgetExceeded { bytes: usize },
    /// Propagated verification failure from the inner Verify step.
    #[error("verification failed: {0}")]
    Verify(#[from] CommunityVerifyError),
}

// ── Wire Types (UI projections) ─────────────────────────────────────────

/// Compact community summary used by list views.
///
/// Reuses existing Dictionary Nouns (`PetName`, `PhalanxTimestamp`, `Quorum`,
/// `CommunityId`) — no new scalar newtypes required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunitySummary {
    pub id: CommunityId,
    pub name: PetName,
    pub member_count: u16,
    pub expires_at: PhalanxTimestamp,
    pub quorum: Quorum,
}

/// Per-member row in a [`CommunityRoster`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberSummary {
    pub did: Did,
    pub joined_at: PhalanxTimestamp,
    pub vouch_count: u16,
    /// Local alias assigned in the TrustRegistry, if any.
    pub pet_name: Option<PetName>,
}

/// Full community roster surfaced to the UI. The only shape that exposes
/// member DIDs to the outside world.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommunityRoster {
    pub summary: CommunitySummary,
    pub members: Vec<MemberSummary>,
    pub grants: CommunityGrants,
    /// Optional Stronghold DID associated with the community.
    pub stronghold_did: Option<Did>,
}

/// Outcome of `phalanx_import_community`. Domain error on the failure path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportOutcome {
    Ok(CommunityId),
    Err(CommunityVerifyError),
}

/// Outcome of `phalanx_dissolve_community`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DissolveOutcome {
    Ok(CommunityId),
    NotFound,
}

// ── Ceremony Nouns ──────────────────────────────────────────────────────
//
// A ceremony is the multi-device protocol that produces a fresh
// Community. The Stronghold coordinates; mobile devices sign. Each
// (member, voucher) pair gets one `VouchRequest`, travelling QR- or
// file-shaped to the voucher's phone. The voucher signs and returns a
// `VouchResponse`. Once quorum is met for every member, the initiator
// assembles the `Community` and emits a join QR.
//
// The Dictionary defines only the data shapes and the pure derivation
// of `request_id`. All signature production and verification lives in
// the Laboratory (`phalanx-forensics::identity`).

/// Version byte prepended to postcard-encoded `VouchRequest` payloads.
/// Envelope: `[VOUCH_REQUEST_VERSION] || postcard(VouchRequest)`.
pub const VOUCH_REQUEST_VERSION: u8 = 0x01;

/// Version byte prepended to postcard-encoded `VouchResponse` payloads.
/// Envelope: `[VOUCH_RESPONSE_VERSION] || postcard(VouchResponse)`.
pub const VOUCH_RESPONSE_VERSION: u8 = 0x01;

/// Maximum age of a signed vouch response, measured from the
/// `member_joined_at` timestamp bound in the signature. Matches
/// `VOUCH_FRESHNESS_WINDOW_SECS` in the Laboratory so a response that
/// verifies at ceremony time also verifies at assembly time.
pub const CEREMONY_RESPONSE_FRESHNESS_SECS: u64 = 3_600;

/// Per-ceremony entropy mixed into every `VouchRequest::request_id`.
///
/// Disambiguates two ceremonies with identical `(name, quorum,
/// members)`: without it, re-issuing a ceremony after abort produces
/// identical request_ids to the aborted run, and the initiator's
/// dedup table cannot tell a fresh signature from a replay of the
/// aborted-ceremony responses. With a fresh 128-bit nonce per
/// ceremony, two such ceremonies always produce different
/// request_ids — the response-side `RequestIdMismatch` check then
/// automatically rejects any carryover responses.
///
/// Not a security primitive in its own right: the voucher's
/// signature binds `(member, tentative_fingerprint, joined_at)`,
/// which is identical across two ceremonies with the same shape,
/// so the nonce only protects the initiator's bookkeeping — it
/// does not need to be signed. 128 bits is ample headroom against
/// birthday collisions within a single organizer's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CeremonyNonce(pub [u8; 16]);

impl CeremonyNonce {
    /// Generate a fresh random nonce via the OS CSPRNG. Called once
    /// per ceremony on the coordinator; every request issued in that
    /// ceremony carries the same nonce.
    #[must_use]
    pub fn random() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }
}

/// A voucher-directed request issued by the ceremony initiator.
///
/// Each request binds a single (member, voucher) slot. The initiator
/// produces one `VouchRequest` per slot at the start of the ceremony
/// and surfaces each as a QR / file for the target voucher. Voucher
/// devices consume the request, project it via
/// [`preview_vouch_request`] for Review UI, then sign via
/// `sign_vouch_response` to produce a `VouchResponse`.
///
/// `member_joined_at` is the timestamp the voucher's signature binds.
/// Every voucher for the same member signs the same value, so the
/// assembled `MemberEntry` has a single coherent `joined_at`. It is
/// set once per ceremony by the initiator and *cannot* be chosen
/// independently by each voucher — doing so would fracture the
/// MemberEntry signatures.
///
/// [`preview_vouch_request`]: fn@crate::identity::community
// (crate-level anchor — the verb lives in phalanx-forensics)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchRequest {
    /// Deterministic id: `BLAKE3("PhalanxVouchRequestId/v2" || tentative
    /// || ceremony_nonce || voucher_did || member_did)`. Re-issuing
    /// the same logical request within the same ceremony produces the
    /// same id (convenient for the initiator's dedup table); a fresh
    /// ceremony with an independent `ceremony_nonce` produces
    /// different ids even when `(name, quorum, members)` match a
    /// prior run. See [`VouchRequest::compute_id`].
    pub request_id: [u8; 32],
    /// Pre-computed community fingerprint the voucher's signature
    /// binds. Must equal `CommunityId::compute(&name, quorum, members)`.
    pub tentative_fingerprint: CommunityId,
    /// Proposed community name. Shown at Review for human sanity-check.
    pub name: PetName,
    /// Proposed quorum threshold. Shown at Review.
    pub quorum: Quorum,
    /// Full ceremony roster. Shown at Review so the voucher knows who
    /// else is in the web of trust.
    pub members: Vec<Did>,
    /// The member this request vouches *for*.
    pub member_did: Did,
    /// The slot this request targets — the device holding the matching
    /// signing key. Mobile FFI rejects requests whose `voucher_did`
    /// does not match the handle's DID with `VoucherMismatch`.
    pub voucher_did: Did,
    /// Wall-clock time the initiator issued the request. Unsigned;
    /// drives only the freshness countdown in the UI. Security-relevant
    /// freshness uses `member_joined_at` below.
    pub issued_at: PhalanxTimestamp,
    /// The `joined_at` value bound in every voucher's signature for
    /// this member. Checked against `CEREMONY_RESPONSE_FRESHNESS_SECS`
    /// by `verify_vouch_response`.
    pub member_joined_at: PhalanxTimestamp,
    /// Per-ceremony entropy — identical across every request in the
    /// same ceremony, fresh every time a new ceremony starts. See
    /// [`CeremonyNonce`] for the rationale.
    pub ceremony_nonce: CeremonyNonce,
}

impl VouchRequest {
    /// Compute the deterministic request id for the given slot.
    ///
    /// Domain-separated BLAKE3 with length-prefixed variable fields
    /// (mirrors `CommunityId::compute`). Same inputs → same id;
    /// different inputs → different id with overwhelming probability.
    /// `ceremony_nonce` is part of the pre-image so two ceremonies
    /// with identical `(tentative, voucher, member)` but distinct
    /// nonces produce distinct request_ids — see [`CeremonyNonce`].
    #[must_use]
    pub fn compute_id(
        tentative: &CommunityId,
        ceremony_nonce: &CeremonyNonce,
        voucher_did: &Did,
        member_did: &Did,
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"PhalanxVouchRequestId/v2");
        hasher.update(&tentative.0);
        hasher.update(&ceremony_nonce.0);
        let v = voucher_did.as_str().as_bytes();
        let m = member_did.as_str().as_bytes();
        // Length prefixes prevent (voucher_did || member_did) concatenation
        // collisions, e.g. ("ab", "c") vs. ("a", "bc") producing the same
        // pre-image.
        #[allow(clippy::cast_possible_truncation)] // Did is capped at 512 bytes, fits u32.
        {
            hasher.update(&(v.len() as u32).to_le_bytes());
        }
        hasher.update(v);
        #[allow(clippy::cast_possible_truncation)]
        {
            hasher.update(&(m.len() as u32).to_le_bytes());
        }
        hasher.update(m);
        *hasher.finalize().as_bytes()
    }
}

/// Projection of a [`VouchRequest`] safe to render on the voucher's
/// device. Carries every field the voucher needs to review at sign
/// time and nothing more.
///
/// Deliberately distinct from `VouchRequest` so the FFI preview
/// return type cannot be fed back into `sign_vouch_response` by
/// accident — the type system enforces the projection direction.
/// `voucher_did` is intentionally absent: the voucher's own DID is
/// implicit (the device already knows who it is) and a preview that
/// omits it cannot be misused to sign on behalf of another device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchRequestPreview {
    pub request_id: [u8; 32],
    pub tentative_fingerprint: CommunityId,
    pub name: PetName,
    pub quorum: Quorum,
    pub members: Vec<Did>,
    pub member_did: Did,
    pub issued_at: PhalanxTimestamp,
    pub member_joined_at: PhalanxTimestamp,
}

/// A voucher's signed reply. Wraps the existing [`Vouch`] verbatim so
/// `assemble_community` consumes it unchanged; `request_id` lets the
/// initiator match the response to the request it issued.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VouchResponse {
    /// Must equal the `request_id` of the originating `VouchRequest`.
    pub request_id: [u8; 32],
    /// The signed vouch. The signature is over
    /// `(request.member_did || request.tentative_fingerprint ||
    /// request.member_joined_at)` — same pre-image as `sign_vouch`.
    pub vouch: Vouch,
}

/// Ceremony-level error surface. Union across signing-side
/// (`sign_vouch_response`) and verification-side
/// (`verify_vouch_response`, duplicate-voucher checks in the initiator
/// panel) errors; the variant tells the caller which layer rejected.
///
/// `#[non_exhaustive]` keeps the wire ABI stable — older decoders see
/// a fallback variant when a new rejection reason ships.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum CeremonyError {
    /// Response's `request_id` does not match the id of any request
    /// the initiator issued. Typical cause: response carried over
    /// from an aborted-and-restarted ceremony, or a spoofed payload.
    #[error("vouch response carries unknown request_id")]
    RequestIdMismatch,
    /// Response's signed `member_joined_at` is more than
    /// `CEREMONY_RESPONSE_FRESHNESS_SECS` seconds old.
    #[error("vouch response is stale ({age_seconds}s old)")]
    ResponseStale { age_seconds: u64 },
    /// Envelope version byte not recognised by this build.
    #[error("unsupported ceremony payload version {version}")]
    UnsupportedVersion { version: u8 },
    /// Response's signature binds a different community fingerprint
    /// than the request's. Can only happen if the voucher device
    /// tampered with the tentative before signing.
    #[error("vouch response fingerprint does not match request")]
    FingerprintMismatch,
    /// The initiator already holds a response from this voucher for
    /// this slot. Eager check in the Ceremony panel before handing
    /// off to `assemble_community`.
    #[error("duplicate vouch from {voucher}")]
    DuplicateVoucher { voucher: Did },
    /// `response.vouch.voucher_did` does not correspond to any of the
    /// roster slots in the ceremony. Emitted by the marshaling helper
    /// when grouping responses by member.
    #[error("response refers to unknown member slot {member}")]
    UnknownSlot { member: Did },
    /// The voucher's device DID does not match
    /// `request.voucher_did`. Raised by `sign_vouch_response` when the
    /// signer attempts to sign a request addressed to someone else.
    #[error("voucher mismatch: request addressed {expected}, signer is {actual}")]
    VoucherMismatch { expected: Did, actual: Did },
    /// Signature verification failed or quorum unsatisfied — bubbled
    /// up from the Laboratory.
    #[error("community verification failed: {0}")]
    Verify(#[from] CommunityVerifyError),
    /// Assembly-side invariant violation — bubbled up from
    /// `assemble_community`. Carries the full Laboratory error so the
    /// panel can render a specific operator message (e.g. "payload
    /// exceeds QR budget", "expires_at too far"). Distinct from
    /// `Verify` because assembly errors include QR-budget and
    /// expiration-window violations that signature verification alone
    /// never raises.
    #[error("community assembly failed: {0}")]
    Assembly(#[from] CommunityAssemblyError),
    /// Post-assembly import into the Stronghold vault failed. The
    /// Laboratory produced a valid `Community` but the Hands-layer
    /// bookkeeping rejected it — typically an unreachable invariant
    /// (signatures passed verify but the vault is wedged, or the
    /// in-memory routing table is inconsistent). Carries the
    /// `Display` rendering of the underlying `StrongholdError` as a
    /// human-readable reason; the concrete error type lives in the
    /// Hands layer and is not serialized across the FFI boundary.
    /// Distinct from `Verify` so the panel never has to fabricate
    /// fake `CommunityId` / `Did` values to fit a type-shape that
    /// doesn't apply to import-time failures.
    #[error("community import into Stronghold failed: {reason}")]
    ImportFailed { reason: String },
}

#[cfg(test)]
#[allow(
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
mod tests {
    use super::*;

    #[test]
    fn quorum_zero_is_unrepresentable() {
        assert!(Quorum::new(0).is_none());
    }

    #[test]
    fn quorum_nonzero_is_valid() {
        let q = Quorum::new(3).unwrap();
        assert_eq!(q.value(), 3);
    }

    #[test]
    fn member_entry_rejects_insufficient_vouches() {
        let quorum = Quorum::new(3).unwrap();
        let vouches = vec![
            Vouch {
                voucher_did: Did::new("did:key:z1"),
                signature: VouchSignature::new([0u8; 64]),
            },
            Vouch {
                voucher_did: Did::new("did:key:z2"),
                signature: VouchSignature::new([0u8; 64]),
            },
        ];

        let entry = MemberEntry::new_validated(
            Did::new("did:key:zmember"),
            PhalanxTimestamp::now(),
            vouches,
            quorum,
        );
        assert!(entry.is_none(), "2 vouches should not satisfy quorum of 3");
    }

    #[test]
    fn member_entry_accepts_sufficient_vouches() {
        let quorum = Quorum::new(2).unwrap();
        let vouches = vec![
            Vouch {
                voucher_did: Did::new("did:key:z1"),
                signature: VouchSignature::new([0u8; 64]),
            },
            Vouch {
                voucher_did: Did::new("did:key:z2"),
                signature: VouchSignature::new([0u8; 64]),
            },
        ];

        let entry = MemberEntry::new_validated(
            Did::new("did:key:zmember"),
            PhalanxTimestamp::now(),
            vouches,
            quorum,
        );
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().vouch_count(), 2);
    }

    #[test]
    fn community_id_is_deterministic() {
        let name = PetName::new("ACLU Portland").unwrap();
        let quorum = Quorum::new(2).unwrap();
        let dids = vec![Did::new("did:key:zA"), Did::new("did:key:zB")];
        let id1 = CommunityId::compute(&name, quorum, &dids);
        let id2 = CommunityId::compute(&name, quorum, &dids);
        assert_eq!(id1, id2);
    }

    #[test]
    fn community_id_is_order_independent() {
        let name = PetName::new("ACLU Portland").unwrap();
        let quorum = Quorum::new(2).unwrap();
        let dids_ab = vec![Did::new("did:key:zA"), Did::new("did:key:zB")];
        let dids_ba = vec![Did::new("did:key:zB"), Did::new("did:key:zA")];
        assert_eq!(
            CommunityId::compute(&name, quorum, &dids_ab),
            CommunityId::compute(&name, quorum, &dids_ba),
        );
    }

    #[test]
    fn community_id_differs_on_name_change() {
        let quorum = Quorum::new(2).unwrap();
        let dids = vec![Did::new("did:key:zA"), Did::new("did:key:zB")];
        let id1 = CommunityId::compute(&PetName::new("ACLU Portland").unwrap(), quorum, &dids);
        let id2 = CommunityId::compute(&PetName::new("ACLU Seattle").unwrap(), quorum, &dids);
        assert_ne!(id1, id2);
    }

    #[test]
    fn duplicate_voucher_dids_rejected() {
        let quorum = Quorum::new(2).unwrap();
        // Same voucher DID twice — should NOT satisfy quorum of 2
        let vouches = vec![
            Vouch {
                voucher_did: Did::new("did:key:z1"),
                signature: VouchSignature::new([0u8; 64]),
            },
            Vouch {
                voucher_did: Did::new("did:key:z1"),
                signature: VouchSignature::new([0u8; 64]),
            },
        ];
        let entry = MemberEntry::new_validated(
            Did::new("did:key:zmember"),
            PhalanxTimestamp::now(),
            vouches,
            quorum,
        );
        assert!(
            entry.is_none(),
            "duplicate voucher DIDs must not satisfy quorum"
        );
    }

    #[test]
    fn self_vouch_excluded_from_quorum() {
        let quorum = Quorum::new(2).unwrap();
        // One external vouch + one self-vouch = only 1 external unique
        let member_did = Did::new("did:key:zmember");
        let vouches = vec![
            Vouch {
                voucher_did: Did::new("did:key:z1"),
                signature: VouchSignature::new([0u8; 64]),
            },
            Vouch {
                voucher_did: member_did.clone(),
                signature: VouchSignature::new([0u8; 64]),
            },
        ];
        let entry =
            MemberEntry::new_validated(member_did, PhalanxTimestamp::now(), vouches, quorum);
        assert!(entry.is_none(), "self-vouch must not count toward quorum");
    }

    #[test]
    fn import_outcome_postcard_roundtrip() {
        let id = CommunityId([7u8; 32]);
        let ok = ImportOutcome::Ok(id);
        let bytes = postcard::to_allocvec(&ok).unwrap();
        let decoded: ImportOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, ok);

        let err = ImportOutcome::Err(CommunityVerifyError::UnsupportedVersion { version: 2 });
        let bytes = postcard::to_allocvec(&err).unwrap();
        let decoded: ImportOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, err);
    }

    #[test]
    fn dissolve_outcome_postcard_roundtrip() {
        let id = CommunityId([3u8; 32]);
        let ok = DissolveOutcome::Ok(id);
        let bytes = postcard::to_allocvec(&ok).unwrap();
        let decoded: DissolveOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, ok);

        let nf = DissolveOutcome::NotFound;
        let bytes = postcard::to_allocvec(&nf).unwrap();
        let decoded: DissolveOutcome = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, nf);
    }

    #[test]
    fn community_summary_postcard_roundtrip() {
        let summary = CommunitySummary {
            id: CommunityId([0xAA; 32]),
            name: PetName::new("ACLU Portland").unwrap(),
            member_count: 12,
            expires_at: PhalanxTimestamp(999_999),
            quorum: Quorum::new(3).unwrap(),
        };
        let bytes = postcard::to_allocvec(&summary).unwrap();
        let decoded: CommunitySummary = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, summary);
    }

    #[test]
    fn community_verify_error_variants_serialize() {
        let variants = vec![
            CommunityVerifyError::Expired {
                community_id: CommunityId([1u8; 32]),
                now: PhalanxTimestamp(100),
                expires_at: PhalanxTimestamp(50),
            },
            CommunityVerifyError::BadVouch {
                member: Did::new("did:key:z1"),
                voucher: Did::new("did:key:z2"),
            },
            CommunityVerifyError::QuorumViolation {
                member: Did::new("did:key:z1"),
            },
            CommunityVerifyError::UnsupportedVersion { version: 0xFF },
        ];
        for v in variants {
            let bytes = postcard::to_allocvec(&v).unwrap();
            let decoded: CommunityVerifyError = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn community_expiration() {
        let community = Community {
            fingerprint: CommunityId([0u8; 32]),
            name: PetName::new("test").unwrap(),
            quorum: Quorum::new(2).unwrap(),
            members: vec![],
            stronghold_did: None,
            baseline_trust: TrustLevel::Verified,
            grants: CommunityGrants::default(),
            expires_at: PhalanxTimestamp(1000),
        };

        assert!(!community.is_expired(PhalanxTimestamp(999)));
        assert!(community.is_expired(PhalanxTimestamp(1000)));
        assert!(community.is_expired(PhalanxTimestamp(1001)));
    }

    // ── Ceremony Noun tests ────────────────────────────────────────────

    fn sample_tentative() -> CommunityId {
        CommunityId([0x42; 32])
    }

    /// Fixed nonce used across the sample_request helper and
    /// equality-roundtrip tests. Pinned to a known value so the
    /// roundtrip tests are deterministic; separate tests below cover
    /// the randomness of `CeremonyNonce::random`.
    fn sample_nonce() -> CeremonyNonce {
        CeremonyNonce([0x11; 16])
    }

    fn sample_request() -> VouchRequest {
        let tentative = sample_tentative();
        let nonce = sample_nonce();
        let voucher = Did::new("did:key:zVoucher");
        let member = Did::new("did:key:zMember");
        VouchRequest {
            request_id: VouchRequest::compute_id(&tentative, &nonce, &voucher, &member),
            tentative_fingerprint: tentative,
            name: PetName::new("ACLU Portland").unwrap(),
            quorum: Quorum::new(2).unwrap(),
            members: vec![member.clone(), voucher.clone(), Did::new("did:key:zC")],
            member_did: member,
            voucher_did: voucher,
            issued_at: PhalanxTimestamp(1_000),
            member_joined_at: PhalanxTimestamp(1_000),
            ceremony_nonce: nonce,
        }
    }

    #[test]
    fn vouch_request_id_is_deterministic_and_domain_separated() {
        let tentative = sample_tentative();
        let nonce = sample_nonce();
        let voucher = Did::new("did:key:zVoucher");
        let member = Did::new("did:key:zMember");
        let id1 = VouchRequest::compute_id(&tentative, &nonce, &voucher, &member);
        let id2 = VouchRequest::compute_id(&tentative, &nonce, &voucher, &member);
        assert_eq!(id1, id2, "deterministic under identical inputs");

        // Swapping voucher/member produces a different id — catches
        // collisions in the length-prefix scheme.
        let swapped = VouchRequest::compute_id(&tentative, &nonce, &member, &voucher);
        assert_ne!(id1, swapped, "member/voucher swap must not collide");
    }

    #[test]
    fn vouch_request_id_nonce_disambiguates_restarted_ceremonies() {
        // Abort-and-restart: same (tentative, voucher, member), but a
        // fresh nonce on the restart. The request_ids must differ so
        // the initiator's dedup table cannot confuse a replayed
        // aborted-run response with a fresh signature.
        let tentative = sample_tentative();
        let voucher = Did::new("did:key:zVoucher");
        let member = Did::new("did:key:zMember");
        let nonce_a = CeremonyNonce([0x01; 16]);
        let nonce_b = CeremonyNonce([0x02; 16]);
        let id_a = VouchRequest::compute_id(&tentative, &nonce_a, &voucher, &member);
        let id_b = VouchRequest::compute_id(&tentative, &nonce_b, &voucher, &member);
        assert_ne!(id_a, id_b, "distinct nonces must produce distinct ids");
    }

    #[test]
    fn ceremony_nonce_random_produces_distinct_values() {
        // Not a statistical test — just a sanity check that
        // `CeremonyNonce::random` actually reads entropy each call.
        // Two back-to-back calls colliding on 128 bits is
        // astronomically unlikely; a failure almost certainly means
        // the implementation returns a constant.
        let n1 = CeremonyNonce::random();
        let n2 = CeremonyNonce::random();
        assert_ne!(n1, n2);
    }

    #[test]
    fn vouch_request_id_length_prefix_prevents_collision() {
        // Distinct (voucher, member) pairs whose naive concatenation
        // would overlap must produce distinct ids — validates the
        // length prefix in compute_id.
        let t = sample_tentative();
        let nonce = sample_nonce();
        let a1 = Did::new("did:key:ab");
        let b1 = Did::new("did:key:c");
        let a2 = Did::new("did:key:a");
        let b2 = Did::new("did:key:bc");
        assert_ne!(
            VouchRequest::compute_id(&t, &nonce, &a1, &b1),
            VouchRequest::compute_id(&t, &nonce, &a2, &b2),
        );
    }

    #[test]
    fn vouch_request_postcard_roundtrip() {
        let req = sample_request();
        let bytes = postcard::to_allocvec(&req).unwrap();
        let decoded: VouchRequest = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, req);
    }

    #[test]
    fn vouch_request_preview_postcard_roundtrip() {
        let req = sample_request();
        let preview = VouchRequestPreview {
            request_id: req.request_id,
            tentative_fingerprint: req.tentative_fingerprint,
            name: req.name.clone(),
            quorum: req.quorum,
            members: req.members.clone(),
            member_did: req.member_did.clone(),
            issued_at: req.issued_at,
            member_joined_at: req.member_joined_at,
        };
        let bytes = postcard::to_allocvec(&preview).unwrap();
        let decoded: VouchRequestPreview = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, preview);
    }

    #[test]
    fn vouch_response_postcard_roundtrip() {
        let response = VouchResponse {
            request_id: [0xAB; 32],
            vouch: Vouch {
                voucher_did: Did::new("did:key:zV"),
                signature: VouchSignature::new([0xCC; 64]),
            },
        };
        let bytes = postcard::to_allocvec(&response).unwrap();
        let decoded: VouchResponse = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, response);
    }

    #[test]
    fn ceremony_error_variants_serialize() {
        let variants = vec![
            CeremonyError::RequestIdMismatch,
            CeremonyError::ResponseStale { age_seconds: 4_000 },
            CeremonyError::UnsupportedVersion { version: 0x02 },
            CeremonyError::FingerprintMismatch,
            CeremonyError::DuplicateVoucher {
                voucher: Did::new("did:key:zV"),
            },
            CeremonyError::UnknownSlot {
                member: Did::new("did:key:zM"),
            },
            CeremonyError::VoucherMismatch {
                expected: Did::new("did:key:zE"),
                actual: Did::new("did:key:zA"),
            },
            CeremonyError::Verify(CommunityVerifyError::UnsupportedVersion { version: 0xFF }),
            CeremonyError::Assembly(CommunityAssemblyError::QrBudgetExceeded { bytes: 4096 }),
            CeremonyError::ImportFailed {
                reason: "vault wedged".to_owned(),
            },
        ];
        for v in variants {
            let bytes = postcard::to_allocvec(&v).unwrap();
            let decoded: CeremonyError = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(decoded, v);
        }
    }

    #[test]
    fn ceremony_freshness_window_matches_laboratory() {
        // The ceremony window must not exceed the Laboratory's
        // assembly freshness window — otherwise a response that
        // verifies at ceremony time could fail at assembly time.
        // The Laboratory constant is defined in phalanx-forensics;
        // we duplicate the expected value here rather than pull a
        // cross-crate dependency into a Dictionary test. Keep these
        // two constants in lock-step.
        const EXPECTED_LABORATORY_WINDOW_SECS: u64 = 3_600;
        assert!(CEREMONY_RESPONSE_FRESHNESS_SECS <= EXPECTED_LABORATORY_WINDOW_SECS);
    }
}
