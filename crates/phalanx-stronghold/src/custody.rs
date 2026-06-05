// crates/phalanx-stronghold/src/custody.rs
//
// CustodyLedger: per-owner storage fairness for the Stronghold custody buffer
// (the "balancing ratio"). Policy-layer admission accounting — NOT part of the
// homeostatic integral path; these are hard caps at the config→actor boundary
// (like `target_fps`), the floor of last resort beneath the soft storage scaler.
//
// The buffer is transient/cycling (custody TTL reclaims bytes), so the per-owner
// cap bounds PEAK occupancy: it stops one member (one DID) flooding the buffer
// and crowding out others' export windows. Sybil resistance is provided
// elsewhere (community vouching `Quorum`, the `SybilEndowment` entry-pressure
// control); this ledger only governs within-membership byte fairness.

use std::collections::HashMap;

use phalanx_proto::community::CommunityId;
use phalanx_proto::identity::Did;

/// Hard storage caps for the custody buffer. Read from `StorageConfig`.
#[derive(Debug, Clone, Copy)]
pub struct CustodyCaps {
    pub max_storage_bytes: u64,
    pub max_per_community_bytes: u64,
    pub max_bytes_per_owner: u64,
    pub owner_fair_share_ratio: f64,
}

impl CustodyCaps {
    /// The effective per-owner ceiling: the absolute cap, tightened by the
    /// fair-share fraction of the community quota. `min` of the two.
    #[must_use]
    pub fn per_owner_ceiling(&self) -> u64 {
        // Clamp the ratio to [0, 1] then scale the community quota.
        let ratio = self.owner_fair_share_ratio.clamp(0.0, 1.0);
        #[allow(
            clippy::cast_precision_loss,
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss
        )]
        // Byte quotas are far below f64's exact-integer range; the round-trip is
        // a policy threshold, not exact accounting.
        let ratio_share = (self.max_per_community_bytes as f64 * ratio) as u64;
        self.max_bytes_per_owner.min(ratio_share)
    }
}

/// Why an admission request was refused (or admitted). Maps onto the
/// `ArchiveReceipt` reject variants at the call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmitDecision {
    Admit,
    /// The owner's per-DID fair share within this community is full.
    PerOwnerFull,
    /// The community quota is full.
    PerCommunityFull,
    /// The global storage cap is full.
    GlobalFull,
}

impl AdmitDecision {
    #[must_use]
    pub fn is_admitted(self) -> bool {
        matches!(self, AdmitDecision::Admit)
    }
}

/// Cumulative byte accounting keyed per `(community, owner)`, with rolled-up
/// per-community and global totals. The Stronghold analogue of the node's
/// `foreign_bytes_by_owner` ledger.
#[derive(Debug)]
pub struct CustodyLedger {
    caps: CustodyCaps,
    by_owner: HashMap<(CommunityId, Did), u64>,
    by_community: HashMap<CommunityId, u64>,
    total: u64,
}

impl CustodyLedger {
    #[must_use]
    pub fn new(caps: CustodyCaps) -> Self {
        Self {
            caps,
            by_owner: HashMap::new(),
            by_community: HashMap::new(),
            total: 0,
        }
    }

    /// Admission decision for `incoming` bytes from `owner` in `community`.
    /// Order (fail-closed, most-specific first): per-owner share → per-community
    /// → global. Does not mutate; call `record` on a successful persist.
    #[must_use]
    pub fn check_admit(
        &self,
        community: &CommunityId,
        owner: &Did,
        incoming: u64,
    ) -> AdmitDecision {
        let owner_bytes = self.owner_bytes(community, owner);
        if owner_bytes.saturating_add(incoming) > self.caps.per_owner_ceiling() {
            return AdmitDecision::PerOwnerFull;
        }
        let community_bytes = self.by_community.get(community).copied().unwrap_or(0);
        if community_bytes.saturating_add(incoming) > self.caps.max_per_community_bytes {
            return AdmitDecision::PerCommunityFull;
        }
        if self.total.saturating_add(incoming) > self.caps.max_storage_bytes {
            return AdmitDecision::GlobalFull;
        }
        AdmitDecision::Admit
    }

    /// Record `bytes` admitted and persisted for `(community, owner)`.
    pub fn record(&mut self, community: &CommunityId, owner: &Did, bytes: u64) {
        let key = (*community, owner.clone());
        let e = self.by_owner.entry(key).or_insert(0);
        *e = e.saturating_add(bytes);
        let c = self.by_community.entry(*community).or_insert(0);
        *c = c.saturating_add(bytes);
        self.total = self.total.saturating_add(bytes);
    }

    /// Release `bytes` (custody expiry/eviction) for `(community, owner)`.
    /// Saturating — never underflows below zero.
    pub fn release(&mut self, community: &CommunityId, owner: &Did, bytes: u64) {
        let key = (*community, owner.clone());
        if let Some(e) = self.by_owner.get_mut(&key) {
            *e = e.saturating_sub(bytes);
            if *e == 0 {
                self.by_owner.remove(&key);
            }
        }
        if let Some(c) = self.by_community.get_mut(community) {
            *c = c.saturating_sub(bytes);
            if *c == 0 {
                self.by_community.remove(community);
            }
        }
        self.total = self.total.saturating_sub(bytes);
    }

    /// Cumulative bytes held for a specific `(community, owner)`.
    #[must_use]
    pub fn owner_bytes(&self, community: &CommunityId, owner: &Did) -> u64 {
        self.by_owner
            .get(&(*community, owner.clone()))
            .copied()
            .unwrap_or(0)
    }

    /// Total bytes held across all communities/owners.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.total
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn caps() -> CustodyCaps {
        CustodyCaps {
            max_storage_bytes: 1_000,
            max_per_community_bytes: 400,
            max_bytes_per_owner: 200,
            owner_fair_share_ratio: 0.25, // 0.25 * 400 = 100 → tighter than 200
        }
    }

    fn community() -> CommunityId {
        CommunityId([1u8; 32])
    }

    #[test]
    fn ceiling_is_min_of_absolute_and_fair_share() {
        // 0.25 * 400 = 100 is tighter than the 200 absolute cap.
        assert_eq!(caps().per_owner_ceiling(), 100);
    }

    #[test]
    fn per_owner_isolation_one_floods_other_still_admitted() {
        let mut ledger = CustodyLedger::new(caps());
        let alice = Did::new("did:key:zAlice");
        let bob = Did::new("did:key:zBob");
        let cid = community();

        // Alice fills her 100-byte share.
        assert_eq!(ledger.check_admit(&cid, &alice, 100), AdmitDecision::Admit);
        ledger.record(&cid, &alice, 100);

        // Alice's next byte is refused — per-owner, not global.
        assert_eq!(
            ledger.check_admit(&cid, &alice, 1),
            AdmitDecision::PerOwnerFull
        );

        // Bob is unaffected — proves isolation, not just a global cap.
        assert_eq!(ledger.check_admit(&cid, &bob, 100), AdmitDecision::Admit);
    }

    #[test]
    fn cumulative_drip_is_capped() {
        let mut ledger = CustodyLedger::new(caps());
        let alice = Did::new("did:key:zAlice");
        let cid = community();
        // Many small admits accumulate toward the cap.
        for _ in 0..100 {
            if ledger.check_admit(&cid, &alice, 1).is_admitted() {
                ledger.record(&cid, &alice, 1);
            }
        }
        assert_eq!(ledger.owner_bytes(&cid, &alice), 100);
        assert_eq!(
            ledger.check_admit(&cid, &alice, 1),
            AdmitDecision::PerOwnerFull
        );
    }

    #[test]
    fn per_community_cap_enforced_across_owners() {
        // Community cap 400; per-owner ceiling 100 → 4 owners fill the community.
        let mut ledger = CustodyLedger::new(caps());
        let cid = community();
        for i in 0..4 {
            let did = Did::new(format!("did:key:zOwner{i}"));
            assert_eq!(ledger.check_admit(&cid, &did, 100), AdmitDecision::Admit);
            ledger.record(&cid, &did, 100);
        }
        // A 5th owner is refused at the community cap (their own share is free).
        let fifth = Did::new("did:key:zOwner5");
        assert_eq!(
            ledger.check_admit(&cid, &fifth, 100),
            AdmitDecision::PerCommunityFull
        );
    }

    #[test]
    fn release_reclaims_capacity() {
        let mut ledger = CustodyLedger::new(caps());
        let alice = Did::new("did:key:zAlice");
        let cid = community();
        ledger.record(&cid, &alice, 100);
        assert_eq!(
            ledger.check_admit(&cid, &alice, 1),
            AdmitDecision::PerOwnerFull
        );
        // Custody expiry frees the bytes; the owner can be admitted again.
        ledger.release(&cid, &alice, 100);
        assert_eq!(ledger.owner_bytes(&cid, &alice), 0);
        assert_eq!(ledger.total_bytes(), 0);
        assert_eq!(ledger.check_admit(&cid, &alice, 100), AdmitDecision::Admit);
    }

    #[test]
    fn release_is_saturating() {
        let mut ledger = CustodyLedger::new(caps());
        let alice = Did::new("did:key:zAlice");
        let cid = community();
        ledger.record(&cid, &alice, 50);
        ledger.release(&cid, &alice, 9_999); // over-release must not underflow
        assert_eq!(ledger.owner_bytes(&cid, &alice), 0);
        assert_eq!(ledger.total_bytes(), 0);
    }
}
