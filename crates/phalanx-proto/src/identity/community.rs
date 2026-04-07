// crates/phalanx-proto/src/community.rs
//
// The Shield Wall: Trusted Communities.
//
// Dictionary layer — inert nouns. No IO, no tokio, no libp2p.
// A community is a web of trust with no central key. Identity
// emerges from the membership graph. Members are admitted when
// k existing members vouch for them.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::identity::Did;
use crate::time::PhalanxTimestamp;
use crate::trust::{PetName, TrustLevel};

// ── Community Identity ──────────────────────────────────────────────────

/// Deterministic community identity — no keypair.
/// Hash of (name || quorum || sorted founding member DIDs).
/// The hash algorithm is determined by the mobile client; Rust receives
/// the opaque 32-byte result. Canary alert key derivation depends on
/// this being high-entropy — do not replace with human-readable strings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CommunityId(pub [u8; 32]);

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
    /// Verifies:
    /// 1. All vouch signatures are valid Ed25519 signatures over
    ///    (member_did || community_fingerprint || joined_at)
    /// 2. The number of valid vouches >= quorum
    ///
    /// Returns None if any signature fails or insufficient vouches.
    /// Signature verification is delegated to the Laboratory layer
    /// (phalanx-forensics) — this constructor accepts pre-verified vouches
    /// and enforces the quorum count invariant.
    pub fn new_validated(
        member_did: Did,
        joined_at: PhalanxTimestamp,
        vouches: Vec<Vouch>,
        quorum: Quorum,
    ) -> Option<Self> {
        if vouches.len() < quorum.value() as usize {
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
    /// Deterministic fingerprint: SHA-256(name || quorum || sorted founding DIDs).
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
