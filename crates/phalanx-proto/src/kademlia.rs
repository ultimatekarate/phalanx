// crates/phalanx-proto/src/kademlia.rs

use crate::identity::NetworkId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Hash, Serialize, Deserialize, PartialEq, Eq)]
#[repr(u16)]
pub enum PayloadKind {
    ShardPointer = 0,
    NodeDiscovery = 1,
    SecurityPolicy = 2,
    Unspecified = 65535,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPayload {
    pub version: u16,
    pub variant: PayloadKind,
    pub expires_at_unix: Option<u64>,
    pub data: Vec<u8>,
}

impl DhtPayload {
    pub const CURRENT_VERSION: u16 = 1;
    pub const MAX_PAYLOAD_SIZE: usize = 65536;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProviderEntry {
    pub network_id: NetworkId,
    pub expiration: u64,
    pub reputation_score: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtProviderSet {
    pub providers: Vec<ProviderEntry>,
}

impl DhtProviderSet {
    pub const MAX_PROVIDERS: usize = 20;
}

impl crate::wire::WireBound for DhtProviderSet {
    fn enforce_wire_bounds(&mut self) {
        if self.providers.len() > Self::MAX_PROVIDERS {
            tracing::warn!(
                count = self.providers.len(),
                limit = Self::MAX_PROVIDERS,
                "S5: Wire bound — provider set truncated on decode"
            );
            self.providers.truncate(Self::MAX_PROVIDERS);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::WireBound;

    fn dummy_provider(i: u64) -> ProviderEntry {
        ProviderEntry {
            network_id: NetworkId(format!("peer_{i}")),
            expiration: 1000 + i,
            reputation_score: 1.0,
        }
    }

    #[test]
    fn s5_wire_bound_truncates_oversized_provider_set() {
        let mut set = DhtProviderSet {
            providers: (0..100).map(dummy_provider).collect(),
        };
        assert_eq!(set.providers.len(), 100);

        set.enforce_wire_bounds();
        assert_eq!(set.providers.len(), DhtProviderSet::MAX_PROVIDERS);
        // Preserves the first MAX_PROVIDERS entries (truncation, not sampling).
        assert_eq!(set.providers[0].network_id, NetworkId("peer_0".into()));
    }

    #[test]
    fn s5_wire_bound_noop_when_within_limit() {
        let mut set = DhtProviderSet {
            providers: (0..5).map(dummy_provider).collect(),
        };
        set.enforce_wire_bounds();
        assert_eq!(set.providers.len(), 5);
    }

    #[test]
    fn s5_wire_bound_noop_at_exact_limit() {
        let mut set = DhtProviderSet {
            providers: (0..DhtProviderSet::MAX_PROVIDERS as u64)
                .map(dummy_provider)
                .collect(),
        };
        set.enforce_wire_bounds();
        assert_eq!(set.providers.len(), DhtProviderSet::MAX_PROVIDERS);
    }
}
