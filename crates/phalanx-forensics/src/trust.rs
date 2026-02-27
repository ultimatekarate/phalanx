use phalanx_proto::prelude::*;

/// Boundary: Allows any component to verify peer standing.
pub trait ReputationGate {
    fn is_blacklisted(&self, did: &Did) -> bool;
}

/// Boundary: Used by Kademlia to rank peers during routing.
pub trait PeerEvaluator: Send + Sync {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32;
}

/// Dependency Inversion boundary.
/// Allows any component to verify peer standing without knowing internal registry logic.
pub trait ReputationGate {
    fn is_blacklisted(&self, did: &Did) -> bool;
}

impl ReputationGate for TrustRegistry {
    fn is_blacklisted(&self, did: &Did) -> bool {
        self.contacts
            .get(did)
            .is_some_and(|record| record.reputation.is_blacklisted)
    }
}
