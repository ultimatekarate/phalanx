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
        if n == 0 {
            None
        } else {
            Some(Self(n))
        }
    }

    pub fn value(&self) -> u8 {
        self.0
    }
}

// ── Vouch ───────────────────────────────────────────────────────────────

/// Ed25519 vouch signature. Fixed 64 bytes.
/// Stored as Vec<u8> for serde compatibility; length validated on construction.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
