// crates/phalanx-forensics/src/eclipse.rs
//
// Passive eclipse detection. Pure logic — no IO, no tokio, no libp2p.
// Complements the Shield Wall (spectral anomaly detection) by detecting
// quiet eclipse attacks where the attacker behaves normally but controls
// all peer slots.

use phalanx_proto::prelude::*;
use std::collections::{HashMap, VecDeque};

/// Lightweight fingerprint of the peer set at a point in time.
/// ~40 bytes per snapshot instead of ~7KB for a full HashSet<NetworkId>.
pub struct MeshFingerprint {
    /// Hash of sorted peer NetworkIds — detects set changes without storing the set.
    pub peer_set_hash: u64,
    /// Number of connected peers.
    pub peer_count: usize,
    /// Subnet distribution — needed for concentration analysis.
    /// Cloned from TopologyGate.subnet_counts (typically <20 entries).
    pub subnet_distribution: HashMap<SubnetBucket, usize>,
    /// Timestamp for ordering and freshness.
    pub timestamp: MonotonicClock,
}

/// Passive eclipse detector. Maintains a ring buffer of mesh fingerprints
/// and evaluates eclipse risk from the pattern of changes.
pub struct EclipseProbe {
    history: VecDeque<MeshFingerprint>,
    max_snapshots: usize,
}

impl EclipseProbe {
    pub fn new(max_snapshots: usize) -> Self {
        Self {
            history: VecDeque::with_capacity(max_snapshots),
            max_snapshots: max_snapshots.max(3), // Need at least 3 for stagnation detection
        }
    }

    /// Ingest a new fingerprint. Pure — no IO.
    pub fn record(&mut self, fingerprint: MeshFingerprint) {
        if self.history.len() >= self.max_snapshots {
            self.history.pop_front();
        }
        self.history.push_back(fingerprint);
    }

    /// Evaluate eclipse risk. Pure function of fingerprint history.
    pub fn evaluate(&self) -> EclipseRisk {
        if self.history.len() < 3 {
            return EclipseRisk::None; // Not enough data
        }

        let stagnant = self.is_stagnant();
        let concentrated = self.is_concentrated();

        match (stagnant, concentrated) {
            (true, true) => EclipseRisk::Critical,
            (true, false) | (false, true) => EclipseRisk::Elevated,
            (false, false) => EclipseRisk::None,
        }
    }

    /// Peer set stagnation: identical peer_set_hash across last 3+ snapshots.
    // Indices governed by take(3) and len() >= 3 guard above.
    #[allow(clippy::indexing_slicing)]
    fn is_stagnant(&self) -> bool {
        if self.history.len() < 3 {
            return false;
        }

        let last_three: Vec<_> = self.history.iter().rev().take(3).collect();
        let hash = last_three[0].peer_set_hash;
        last_three.iter().all(|fp| fp.peer_set_hash == hash) && hash != 0
    }

    /// Subnet concentration: >60% of peers share ≤2 SubnetBucket values.
    #[allow(clippy::cast_possible_truncation)] // f64 threshold — peer count is small enough for usize.
    fn is_concentrated(&self) -> bool {
        let latest = match self.history.back() {
            Some(fp) => fp,
            None => return false,
        };

        if latest.peer_count == 0 {
            return false;
        }

        // Sort buckets by count, descending
        let mut counts: Vec<usize> = latest.subnet_distribution.values().copied().collect();
        counts.sort_unstable_by(|a, b| b.cmp(a));

        // Sum of top 2 buckets
        let top_two_sum: usize = counts.iter().take(2).sum();
        // peer_count is non-negative, product with 0.6 is non-negative.
        #[allow(clippy::cast_sign_loss)]
        let threshold = (latest.peer_count as f64 * 0.6).ceil() as usize;

        top_two_sum >= threshold
    }
}

/// Hash a sorted set of peer IDs into a u64 for fingerprinting.
/// Deterministic — same set always produces the same hash.
pub fn hash_peer_set(peers: &mut Vec<&NetworkId>) -> u64 {
    use std::hash::{Hash, Hasher};
    peers.sort_by_key(|a| a.to_string());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    for peer in peers {
        peer.hash(&mut hasher);
    }
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fingerprint(hash: u64, count: usize, distribution: Vec<(u8, usize)>) -> MeshFingerprint {
        MeshFingerprint {
            peer_set_hash: hash,
            peer_count: count,
            subnet_distribution: distribution
                .into_iter()
                .map(|(id, c)| (SubnetBucket::test_bucket(id), c))
                .collect(),
            timestamp: MonotonicClock(0),
        }
    }

    #[test]
    fn insufficient_history_returns_none() {
        let mut probe = EclipseProbe::new(6);
        probe.record(fingerprint(123, 10, vec![(1, 5), (2, 5)]));
        probe.record(fingerprint(123, 10, vec![(1, 5), (2, 5)]));
        assert_eq!(probe.evaluate(), EclipseRisk::None); // Only 2 snapshots
    }

    #[test]
    fn stagnant_and_concentrated_is_critical() {
        let mut probe = EclipseProbe::new(6);
        // Same hash, concentrated in 1 bucket (>60% in top 2)
        for _ in 0..3 {
            probe.record(fingerprint(42, 10, vec![(1, 8), (2, 2)]));
        }
        assert_eq!(probe.evaluate(), EclipseRisk::Critical);
    }

    #[test]
    fn stagnant_but_diverse_is_elevated() {
        let mut probe = EclipseProbe::new(6);
        // Same hash, but well-distributed across many buckets
        for _ in 0..3 {
            probe.record(fingerprint(
                42,
                10,
                vec![(1, 2), (2, 2), (3, 2), (4, 2), (5, 2)],
            ));
        }
        assert_eq!(probe.evaluate(), EclipseRisk::Elevated);
    }

    #[test]
    fn changing_and_concentrated_is_elevated() {
        let mut probe = EclipseProbe::new(6);
        // Different hashes each time, but concentrated
        probe.record(fingerprint(1, 10, vec![(1, 9), (2, 1)]));
        probe.record(fingerprint(2, 10, vec![(1, 8), (2, 2)]));
        probe.record(fingerprint(3, 10, vec![(1, 7), (2, 3)]));
        assert_eq!(probe.evaluate(), EclipseRisk::Elevated);
    }

    #[test]
    fn changing_and_diverse_is_none() {
        let mut probe = EclipseProbe::new(6);
        probe.record(fingerprint(
            1,
            10,
            vec![(1, 2), (2, 2), (3, 2), (4, 2), (5, 2)],
        ));
        probe.record(fingerprint(
            2,
            12,
            vec![(1, 3), (2, 2), (3, 2), (4, 2), (5, 3)],
        ));
        probe.record(fingerprint(
            3,
            11,
            vec![(1, 2), (2, 3), (3, 2), (4, 2), (5, 2)],
        ));
        assert_eq!(probe.evaluate(), EclipseRisk::None);
    }

    #[test]
    fn ring_buffer_evicts_old_entries() {
        let mut probe = EclipseProbe::new(3);
        // First 3: stagnant
        for _ in 0..3 {
            probe.record(fingerprint(42, 10, vec![(1, 8), (2, 2)]));
        }
        assert_eq!(probe.evaluate(), EclipseRisk::Critical);

        // New different fingerprint pushes out oldest
        probe.record(fingerprint(99, 10, vec![(1, 2), (2, 2), (3, 6)]));
        // Now history is [42, 42, 99] — not all same → not stagnant, but still concentrated
        assert_eq!(probe.evaluate(), EclipseRisk::Elevated);
    }
}
