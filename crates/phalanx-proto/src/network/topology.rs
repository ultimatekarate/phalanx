// crates/phalanx-proto/src/topology.rs
//
// The Topology Nouns: network-origin buckets, transport classes, and eclipse risk.
// Used by the Laboratory (TopologyGate, EclipseProbe) to reason about peer diversity.
// The Hands populate these from Multiaddr / DiscoverySource.

use serde::{Deserialize, Serialize};

/// Coarse network-origin bucket: first two octets of an IPv4 address,
/// or the first two bytes of a SHA-256 over an IPv6 /48 prefix.
/// The Laboratory reasons about these; the Hands populate them from Multiaddr.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SubnetBucket([u8; 2]);

impl SubnetBucket {
    /// Construct from IPv4 first two octets (/16 prefix).
    /// Panics are impossible — any two bytes are valid.
    pub fn from_ipv4_prefix(a: u8, b: u8) -> Self {
        Self([a, b])
    }

    /// Construct from an IPv6 /48 by hashing to two bytes.
    #[allow(clippy::indexing_slicing)] // BLAKE3 always produces 32 bytes — [0] and [1] are always valid.
    pub fn from_ipv6_prefix(prefix_bytes: &[u8]) -> Self {
        let hash: [u8; 32] = blake3::hash(prefix_bytes).into();
        Self([hash[0], hash[1]])
    }

    /// Deterministic bucket from a single byte. Useful for testing.
    pub fn test_bucket(id: u8) -> Self {
        Self([id, 0])
    }

    pub fn octets(&self) -> [u8; 2] {
        self.0
    }
}

impl std::fmt::Display for SubnetBucket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.x.x", self.0[0], self.0[1])
    }
}

/// Maximum number of admitted peers sharing the same SubnetBucket.
/// Newtype to prevent confusion with other usize limits (slot counts, etc).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubnetQuota(usize);

impl SubnetQuota {
    pub const DEFAULT: Self = Self(8);

    pub fn new(n: usize) -> Option<Self> {
        if n == 0 { None } else { Some(Self(n)) }
    }

    pub fn limit(&self) -> usize {
        self.0
    }
}

/// Transport class — coarse categorization of how a peer was reached.
/// Derived from `DiscoverySource` in the Hands; consumed by the Laboratory
/// for partitioned slot accounting.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TransportClass {
    Internet,
}

impl TransportClass {
    /// Map the existing `DiscoverySource` to a transport class.
    /// This is the single canonical conversion — no ad-hoc matching elsewhere.
    pub fn from_discovery_source(src: crate::telemetry::DiscoverySource) -> Self {
        use crate::telemetry::DiscoverySource;
        match src {
            DiscoverySource::Bootstrap
            | DiscoverySource::Kademlia
            | DiscoverySource::Mdns
            | DiscoverySource::Identify
            | DiscoverySource::Quic => Self::Internet,
        }
    }
}

/// Eclipse risk assessment. Non-exhaustive for forward compatibility.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum EclipseRisk {
    None,
    Elevated,
    Critical,
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
    fn subnet_bucket_ipv4_deterministic() {
        let a = SubnetBucket::from_ipv4_prefix(10, 0);
        let b = SubnetBucket::from_ipv4_prefix(10, 0);
        assert_eq!(a, b);
        assert_eq!(a.octets(), [10, 0]);
    }

    #[test]
    fn subnet_bucket_ipv4_different_prefixes() {
        let a = SubnetBucket::from_ipv4_prefix(10, 0);
        let b = SubnetBucket::from_ipv4_prefix(192, 168);
        assert_ne!(a, b);
    }

    #[test]
    fn subnet_bucket_ipv6_hashes_to_two_bytes() {
        let prefix = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01]; // 2001:0db8:0001::/48
        let bucket = SubnetBucket::from_ipv6_prefix(&prefix);
        assert_eq!(bucket.octets().len(), 2);
    }

    #[test]
    fn subnet_quota_zero_rejected() {
        assert!(SubnetQuota::new(0).is_none());
    }

    #[test]
    fn subnet_quota_default_is_eight() {
        assert_eq!(SubnetQuota::DEFAULT.limit(), 8);
    }

    #[test]
    fn transport_class_internet_mapping() {
        use crate::telemetry::DiscoverySource;
        for src in [
            DiscoverySource::Bootstrap,
            DiscoverySource::Kademlia,
            DiscoverySource::Mdns,
            DiscoverySource::Identify,
            DiscoverySource::Quic,
        ] {
            assert_eq!(
                TransportClass::from_discovery_source(src),
                TransportClass::Internet
            );
        }
    }

    #[test]
    fn eclipse_risk_ordering() {
        assert!(EclipseRisk::None < EclipseRisk::Elevated);
        assert!(EclipseRisk::Elevated < EclipseRisk::Critical);
    }
}
