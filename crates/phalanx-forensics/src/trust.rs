use phalanx_proto::prelude::ShardError;
use phalanx_proto::prelude::*;
use phalanx_proto::trust::TrustRegistry; // <-- FIX: Import the Noun
use tracing::{info, warn};

pub trait TrustAuthority {
    /// The Verb "To Authorize": Determines if a peer is allowed to participate.
    fn authorize_peer(&self, did: &Did) -> Result<(), ShardError>;

    /// The Verb "To Penalize": Drops the reputation of a peer for bad behavior.
    fn penalize_peer(&mut self, did: &Did, penalty: i64);

    fn assess_violation_penalty(err: &ShardError) -> i64;
}

impl TrustAuthority for TrustRegistry {
    fn authorize_peer(&self, did: &Did) -> Result<(), ShardError> {
        if let Some(record) = self.peers.get(did) {
            if record.is_banned || record.reputation < 0 {
                warn!(peer = %did, "Trust Gate Rejected: Peer is banned or untrusted");
                return Err(ShardError::Unauthorized("Peer trust score too low".into()));
            }
        }
        // Zero-Trust Default: If they aren't banned and have valid crypto (checked prior),
        // they are tentatively allowed.
        Ok(())
    }

    fn penalize_peer(&mut self, did: &Did, penalty: i64) {
        let record = self.peers.entry(did.clone()).or_default();
        record.reputation = record.reputation.saturating_sub(penalty);

        if record.reputation < 0 {
            record.is_banned = true;
            info!(peer = %did, "Peer has been banned due to negative trust score");
        }
    }

    fn assess_violation_penalty(err: &ShardError) -> i64 {
        match err {
            // High severity: Cryptographic failures or chain breakage
            ShardError::SigningError(_) => 100,
            ShardError::InvalidConfiguration(msg) if msg.contains("Causality") => 100,

            // Medium severity: Resource abuse
            ShardError::CapacityExceeded(_) => 25,

            // Low severity: Routine network noise or malformed data
            ShardError::SerializationError(_) => 5,
            _ => 10, // Default penalty
        }
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

/// Dependency Inversion boundary.
/// Allows any component to verify peer standing without knowing internal registry logic.
impl ReputationGate for TrustRegistry {
    fn is_blacklisted(&self, did: &Did) -> bool {
        self.peers.get(did).is_some_and(|record| record.is_banned)
    }
}
