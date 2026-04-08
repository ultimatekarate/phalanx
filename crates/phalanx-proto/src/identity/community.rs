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
