// crates/phalanx-forensics/src/topology_gate.rs
//
// Per-peer topology admission gate. Enforces subnet diversity, transport quotas,
// IWFQ preemption, and anchor persistence. Pure logic — no IO, no tokio, no libp2p.
//
// Separate from IngressGovernor, which is a per-chunk concurrency limiter owned
// by IngestionActor. TopologyGate is owned by MeshSentinel and checks admission
// once per PeerDiscovered event.

use phalanx_proto::prelude::*;
use std::collections::HashMap;

// ─── Proof Tokens ──────────────────────────────────────────────────

/// Proof that a peer passed subnet-diversity and transport-quota checks.
/// Only `TopologyGate::try_admit()` can construct this (private `_seal` field).
/// Consumed (dropped) by MeshSentinel after admission decision.
#[derive(Debug)]
pub struct AdmissionTicket {
    peer: NetworkId,
    transport: TransportClass,
    _seal: (),
}

impl AdmissionTicket {
    pub fn peer(&self) -> &NetworkId {
        &self.peer
    }
    pub fn transport(&self) -> TransportClass {
        self.transport
    }
}

/// A reputation score verified to meet anchor threshold (≥ 0.5 normalized).
/// Only constructible through `AnchorEligible::try_from_score()`.
/// Uses f32 to match `ReputationProjection::evaluate_reputation()` return type.
#[derive(Debug, Clone, Copy)]
pub struct AnchorEligible(#[allow(dead_code)] f32);

impl AnchorEligible {
    pub const THRESHOLD: f32 = 0.5;

    pub fn try_from_score(score: f32) -> Option<Self> {
        if score >= Self::THRESHOLD {
            Some(Self(score))
        } else {
            None
        }
    }
}

// ─── Error Type ────────────────────────────────────────────────────

/// Typed error for admission denial. Replaces `&'static str`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionDenied {
    SubnetQuotaExceeded {
        bucket: SubnetBucket,
        current: usize,
        limit: usize,
    },
    TransportQuotaExceeded {
        transport: TransportClass,
        current: usize,
        limit: usize,
    },
    CapacityFull,
}

impl std::fmt::Display for AdmissionDenied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubnetQuotaExceeded {
                bucket,
                current,
                limit,
            } => write!(f, "Subnet quota exceeded for {bucket}: {current}/{limit}"),
            Self::TransportQuotaExceeded {
                transport,
                current,
                limit,
            } => write!(
                f,
                "Transport quota exceeded for {transport:?}: {current}/{limit}"
            ),
            Self::CapacityFull => write!(f, "All peer slots full, no evictable peers"),
        }
    }
}

impl std::error::Error for AdmissionDenied {}

// ─── Dynamic Transport Balance ─────────────────────────────────────

/// Dynamic slot allocation between transport classes.
/// Ratio is expressed as a fraction of total_capacity for local mesh (0.1–0.5).
/// The Hands derive this from SystemGovernor signals; the Laboratory uses it.
#[derive(Clone, Copy, Debug)]
pub struct TransportBalance {
    local_mesh_fraction: f32,
}

impl TransportBalance {
    pub const DEFAULT: Self = Self {
        local_mesh_fraction: 0.25,
    };

    /// Construct with clamping to [0.1, 0.5]. No panics possible.
    pub fn new(fraction: f32) -> Self {
        Self {
            local_mesh_fraction: fraction.clamp(0.1, 0.5),
        }
    }

    pub fn max_local_mesh(&self, total: usize) -> usize {
        ((total as f32) * self.local_mesh_fraction).ceil() as usize
    }

    pub fn max_internet(&self, total: usize) -> usize {
        total.saturating_sub(self.max_local_mesh(total))
    }
}

// ─── Per-Peer Slot ─────────────────────────────────────────────────

/// All per-peer topology state consolidated in one place.
struct PeerSlot {
    bucket: SubnetBucket,
    transport: TransportClass,
    trust: TrustLevel,
    anchored: bool,
}

// ─── TopologyGate ──────────────────────────────────────────────────

/// Per-peer topology admission gate.
/// One entry per connected peer. Enforces subnet diversity, transport quotas,
/// IWFQ preemption, and anchor persistence.
pub struct TopologyGate {
    peers: HashMap<NetworkId, PeerSlot>,
    subnet_counts: HashMap<SubnetBucket, usize>,
    subnet_quota: SubnetQuota,
    total_capacity: usize,
    max_anchors: usize,
}

impl TopologyGate {
    pub fn new(total_capacity: usize, subnet_quota: SubnetQuota, max_anchors: usize) -> Self {
        Self {
            peers: HashMap::with_capacity(total_capacity),
            subnet_counts: HashMap::new(),
            subnet_quota,
            total_capacity,
            max_anchors,
        }
    }

    /// Number of currently admitted peers.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Read-only access to subnet distribution for eclipse fingerprinting.
    pub fn subnet_counts(&self) -> &HashMap<SubnetBucket, usize> {
        &self.subnet_counts
    }

    /// Iterate over admitted peer IDs.
    pub fn peer_ids(&self) -> impl Iterator<Item = &NetworkId> {
        self.peers.keys()
    }

    /// Check if a peer is currently admitted.
    pub fn is_admitted(&self, peer: &NetworkId) -> bool {
        self.peers.contains_key(peer)
    }

    /// Admit a peer, enforcing subnet diversity, transport quotas, and IWFQ preemption.
    /// Returns an `AdmissionTicket` (proof of admission) or a typed error.
    /// If a lower-trust peer was evicted to make room, the second element is `Some(evicted)`.
    pub fn try_admit(
        &mut self,
        peer: NetworkId,
        level: TrustLevel,
        bucket: SubnetBucket,
        transport: TransportClass,
        balance: TransportBalance,
    ) -> Result<(AdmissionTicket, Option<NetworkId>), AdmissionDenied> {
        // Idempotent: already admitted
        if self.peers.contains_key(&peer) {
            return Ok((
                AdmissionTicket {
                    peer,
                    transport,
                    _seal: (),
                },
                None,
            ));
        }

        // Subnet diversity check (skip for local mesh — inherently proximity-limited)
        if transport != TransportClass::LocalMesh {
            let current = self.subnet_counts.get(&bucket).copied().unwrap_or(0);
            let limit = self.subnet_quota.limit();
            if current >= limit {
                return Err(AdmissionDenied::SubnetQuotaExceeded {
                    bucket,
                    current,
                    limit,
                });
            }
        }

        // Transport quota check
        let (transport_count, transport_limit) = self.transport_usage_and_limit(transport, balance);
        if transport_count >= transport_limit {
            // IWFQ preemption: find lowest-trust, non-anchored peer in same transport pool
            if let Some(evicted) = self.find_evictable(transport, level) {
                self.remove_peer(&evicted);
                self.insert_peer(peer.clone(), bucket, transport, level);
                return Ok((
                    AdmissionTicket {
                        peer,
                        transport,
                        _seal: (),
                    },
                    Some(evicted),
                ));
            }
            return Err(AdmissionDenied::TransportQuotaExceeded {
                transport,
                current: transport_count,
                limit: transport_limit,
            });
        }

        // Total capacity check
        if self.peers.len() >= self.total_capacity {
            if let Some(evicted) = self.find_evictable(transport, level) {
                self.remove_peer(&evicted);
                self.insert_peer(peer.clone(), bucket, transport, level);
                return Ok((
                    AdmissionTicket {
                        peer,
                        transport,
                        _seal: (),
                    },
                    Some(evicted),
                ));
            }
            return Err(AdmissionDenied::CapacityFull);
        }

        self.insert_peer(peer.clone(), bucket, transport, level);
        Ok((
            AdmissionTicket {
                peer,
                transport,
                _seal: (),
            },
            None,
        ))
    }

    /// Release a peer slot. No-op if the peer is anchored (must `demote_anchor()` first).
    pub fn release(&mut self, peer: &NetworkId) {
        if let Some(slot) = self.peers.get(peer) {
            if slot.anchored {
                return; // Anchored peers cannot be released — demote first
            }
        }
        self.remove_peer(peer);
    }

    /// Promote a peer to anchor status. Requires proof of eligible reputation.
    /// Returns true if promotion succeeded.
    pub fn promote_to_anchor(&mut self, peer: &NetworkId, _proof: AnchorEligible) -> bool {
        let anchor_count = self.peers.values().filter(|s| s.anchored).count();
        if anchor_count >= self.max_anchors {
            return false;
        }
        if let Some(slot) = self.peers.get_mut(peer) {
            if !slot.anchored {
                slot.anchored = true;
                return true;
            }
        }
        false
    }

    /// Demote a peer from anchor status.
    pub fn demote_anchor(&mut self, peer: &NetworkId) -> bool {
        if let Some(slot) = self.peers.get_mut(peer) {
            if slot.anchored {
                slot.anchored = false;
                return true;
            }
        }
        false
    }

    pub fn is_anchored(&self, peer: &NetworkId) -> bool {
        self.peers.get(peer).is_some_and(|s| s.anchored)
    }

    // ── Private helpers ────────────────────────────────────────────

    fn insert_peer(
        &mut self,
        peer: NetworkId,
        bucket: SubnetBucket,
        transport: TransportClass,
        trust: TrustLevel,
    ) {
        *self.subnet_counts.entry(bucket).or_insert(0) += 1;
        self.peers.insert(
            peer,
            PeerSlot {
                bucket,
                transport,
                trust,
                anchored: false,
            },
        );
    }

    fn remove_peer(&mut self, peer: &NetworkId) {
        if let Some(slot) = self.peers.remove(peer) {
            if let Some(count) = self.subnet_counts.get_mut(&slot.bucket) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    self.subnet_counts.remove(&slot.bucket);
                }
            }
        }
    }

    fn transport_usage_and_limit(
        &self,
        transport: TransportClass,
        balance: TransportBalance,
    ) -> (usize, usize) {
        let count = self
            .peers
            .values()
            .filter(|s| s.transport == transport)
            .count();
        let limit = match transport {
            TransportClass::LocalMesh => balance.max_local_mesh(self.total_capacity),
            TransportClass::Internet => balance.max_internet(self.total_capacity),
            _ => self.total_capacity, // forward compat for non_exhaustive
        };
        (count, limit)
    }

    /// Find the lowest-trust, non-anchored peer in the given transport pool
    /// that has strictly lower trust than `incoming_trust`.
    fn find_evictable(
        &self,
        transport: TransportClass,
        incoming_trust: TrustLevel,
    ) -> Option<NetworkId> {
        self.peers
            .iter()
            .filter(|(_, slot)| slot.transport == transport && !slot.anchored)
            .filter(|(_, slot)| slot.trust < incoming_trust)
            .min_by_key(|(_, slot)| slot.trust)
            .map(|(id, _)| id.clone())
    }
}

// ─── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(capacity: usize) -> TopologyGate {
        TopologyGate::new(capacity, SubnetQuota::DEFAULT, 4)
    }

    fn net_id(n: u8) -> NetworkId {
        NetworkId::from(format!("peer-{n}"))
    }

    #[test]
    fn admit_and_release() {
        let mut g = gate(10);
        let (ticket, evicted) = g
            .try_admit(
                net_id(1),
                TrustLevel::Ignored,
                SubnetBucket::test_bucket(1),
                TransportClass::Internet,
                TransportBalance::DEFAULT,
            )
            .unwrap();
        assert_eq!(ticket.peer(), &net_id(1));
        assert!(evicted.is_none());
        assert_eq!(g.peer_count(), 1);

        g.release(&net_id(1));
        assert_eq!(g.peer_count(), 0);
    }

    #[test]
    fn idempotent_admission() {
        let mut g = gate(10);
        g.try_admit(
            net_id(1),
            TrustLevel::Ignored,
            SubnetBucket::test_bucket(1),
            TransportClass::Internet,
            TransportBalance::DEFAULT,
        )
        .unwrap();
        // Admit same peer again — idempotent
        let (_, evicted) = g
            .try_admit(
                net_id(1),
                TrustLevel::Ignored,
                SubnetBucket::test_bucket(1),
                TransportClass::Internet,
                TransportBalance::DEFAULT,
            )
            .unwrap();
        assert!(evicted.is_none());
        assert_eq!(g.peer_count(), 1);
    }

    #[test]
    fn subnet_quota_enforced() {
        let mut g = TopologyGate::new(100, SubnetQuota::DEFAULT, 4); // quota = 8
        let bucket = SubnetBucket::test_bucket(42);

        // Fill 8 peers in same bucket
        for i in 0..8 {
            g.try_admit(
                net_id(i),
                TrustLevel::Ignored,
                bucket,
                TransportClass::Internet,
                TransportBalance::DEFAULT,
            )
            .unwrap();
        }

        // 9th peer in same bucket → SubnetQuotaExceeded
        let err = g
            .try_admit(
                net_id(9),
                TrustLevel::Ignored,
                bucket,
                TransportClass::Internet,
                TransportBalance::DEFAULT,
            )
            .unwrap_err();
        assert!(matches!(err, AdmissionDenied::SubnetQuotaExceeded { .. }));
    }

    #[test]
    fn local_mesh_skips_subnet_check() {
        let mut g = TopologyGate::new(100, SubnetQuota::DEFAULT, 4);
        let bucket = SubnetBucket::local_mesh();

        // Can add more than 8 local mesh peers with same bucket
        for i in 0..25 {
            g.try_admit(
                net_id(i),
                TrustLevel::Ignored,
                bucket,
                TransportClass::LocalMesh,
                TransportBalance::DEFAULT,
            )
            .unwrap();
        }
        assert_eq!(g.peer_count(), 25);
    }

    #[test]
    fn transport_quota_enforced() {
        // 10 total, 25% local mesh = ceil(2.5) = 3 local mesh slots
        let mut g = gate(10);
        let balance = TransportBalance::DEFAULT;

        for i in 0..3 {
            g.try_admit(
                net_id(i),
                TrustLevel::Ignored,
                SubnetBucket::local_mesh(),
                TransportClass::LocalMesh,
                balance,
            )
            .unwrap();
        }

        // 4th local mesh peer → TransportQuotaExceeded (no one to evict, all same trust)
        let err = g
            .try_admit(
                net_id(99),
                TrustLevel::Ignored,
                SubnetBucket::local_mesh(),
                TransportClass::LocalMesh,
                balance,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AdmissionDenied::TransportQuotaExceeded { .. }
        ));
    }

    #[test]
    fn iwfq_preemption_evicts_lower_trust() {
        let mut g = gate(4); // 4 total, 75% internet = 3 internet slots
        let balance = TransportBalance::DEFAULT;

        g.try_admit(
            net_id(1),
            TrustLevel::Ignored,
            SubnetBucket::test_bucket(1),
            TransportClass::Internet,
            balance,
        )
        .unwrap();
        g.try_admit(
            net_id(2),
            TrustLevel::Ignored,
            SubnetBucket::test_bucket(2),
            TransportClass::Internet,
            balance,
        )
        .unwrap();
        g.try_admit(
            net_id(3),
            TrustLevel::Ignored,
            SubnetBucket::test_bucket(3),
            TransportClass::Internet,
            balance,
        )
        .unwrap();

        // Ally arrives — should evict one Ignored peer
        let (_, evicted) = g
            .try_admit(
                net_id(4),
                TrustLevel::Ally,
                SubnetBucket::test_bucket(4),
                TransportClass::Internet,
                balance,
            )
            .unwrap();
        assert!(evicted.is_some());
        assert_eq!(g.peer_count(), 3);
        assert!(g.is_admitted(&net_id(4)));
    }

    #[test]
    fn anchor_survives_eviction() {
        let mut g = gate(4); // 4 total, 75% internet = 3 internet slots
        let balance = TransportBalance::DEFAULT;

        g.try_admit(
            net_id(1),
            TrustLevel::Ignored,
            SubnetBucket::test_bucket(1),
            TransportClass::Internet,
            balance,
        )
        .unwrap();
        g.try_admit(
            net_id(2),
            TrustLevel::Ignored,
            SubnetBucket::test_bucket(2),
            TransportClass::Internet,
            balance,
        )
        .unwrap();
        g.try_admit(
            net_id(3),
            TrustLevel::Ignored,
            SubnetBucket::test_bucket(3),
            TransportClass::Internet,
            balance,
        )
        .unwrap();

        // Anchor all three peers
        for i in 1..=3 {
            let proof = AnchorEligible::try_from_score(0.8).unwrap();
            g.promote_to_anchor(&net_id(i), proof);
        }

        // Ally arrives — all anchored, no eviction possible
        let err = g
            .try_admit(
                net_id(4),
                TrustLevel::Ally,
                SubnetBucket::test_bucket(4),
                TransportClass::Internet,
                balance,
            )
            .unwrap_err();
        assert!(matches!(
            err,
            AdmissionDenied::TransportQuotaExceeded { .. } | AdmissionDenied::CapacityFull
        ));
    }

    #[test]
    fn release_noop_on_anchored_peer() {
        let mut g = gate(10);
        g.try_admit(
            net_id(1),
            TrustLevel::Verified,
            SubnetBucket::test_bucket(1),
            TransportClass::Internet,
            TransportBalance::DEFAULT,
        )
        .unwrap();

        let proof = AnchorEligible::try_from_score(0.7).unwrap();
        g.promote_to_anchor(&net_id(1), proof);

        g.release(&net_id(1)); // Should be no-op
        assert_eq!(g.peer_count(), 1);
        assert!(g.is_anchored(&net_id(1)));

        // Demote, then release works
        g.demote_anchor(&net_id(1));
        g.release(&net_id(1));
        assert_eq!(g.peer_count(), 0);
    }

    #[test]
    fn anchor_eligible_threshold() {
        assert!(AnchorEligible::try_from_score(0.49).is_none());
        assert!(AnchorEligible::try_from_score(0.5).is_some());
        assert!(AnchorEligible::try_from_score(1.0).is_some());
    }

    #[test]
    fn transport_balance_clamping() {
        let b = TransportBalance::new(0.0);
        assert_eq!(b.max_local_mesh(100), 10); // clamped to 0.1

        let b = TransportBalance::new(1.0);
        assert_eq!(b.max_local_mesh(100), 50); // clamped to 0.5
    }

    #[test]
    fn subnet_counts_decrement_on_release() {
        let mut g = gate(10);
        let bucket = SubnetBucket::test_bucket(5);

        g.try_admit(
            net_id(1),
            TrustLevel::Ignored,
            bucket,
            TransportClass::Internet,
            TransportBalance::DEFAULT,
        )
        .unwrap();
        assert_eq!(g.subnet_counts().get(&bucket), Some(&1));

        g.release(&net_id(1));
        assert_eq!(g.subnet_counts().get(&bucket), None); // cleaned up
    }
}
