use phalanx_proto::prelude::*;
use phalanx_proto::trust::Offense;

/// The Verb "To Assess": Maps an Offense to its penalty magnitude.
pub fn assess_penalty(offense: &Offense) -> i64 {
    match offense {
        Offense::QuotaExceeded => 25,
        Offense::InvalidSignature | Offense::IdentityTheft => 101,
        Offense::EclipseAttempt => 50,
        Offense::SpectralAnomaly => 15,
        _ => 10,
    }
}

/// Boundary: Allows any component to verify peer standing.
pub trait ReputationGate {
    fn is_blacklisted(&self, did: &Did) -> bool;
}

/// Boundary: Used by Kademlia to rank peers during routing.
pub trait PeerEvaluator: Send + Sync {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32;
}
