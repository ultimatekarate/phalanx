// crates/phalanx-forensics/src/gates.rs

use phalanx_proto::prelude::*;
use phalanx_proto::evidence::{Evidence, WitnessEnvelope, SignatureHash};
use phalanx_proto::storage::ShardError;
use phalanx_proto::time::PhalanxTimestamp;
use std::collections::HashMap;
use tracing::{error, warn};

/// Gate 1: The Witnessing Gate
pub trait WitnessGate {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError>;
}

impl WitnessGate for Evidence {
    fn seal(
        self,
        identity: &PhalanxIdentity,
        peer_id: NetworkId,
        prev_hash: Option<SignatureHash>,
    ) -> Result<WitnessEnvelope, ShardError> {
        WitnessEnvelope::new(self, identity, peer_id, prev_hash).map_err(|e| {
            error!(event = "signing_failure", error = %e, "Witness Gate: Failed to seal unit");
            e
        })
    }
}

/// Gate 2: The Chronos Gate (Timeline Integrity)
pub trait ChronosGate {
    fn verify_continuity(&self, envelopes: &[WitnessEnvelope]) -> Result<(), ShardError>;
}

impl ChronosGate for Vec<WitnessEnvelope> {
    fn verify_continuity(&self, envelopes: &[WitnessEnvelope]) -> Result<(), ShardError> {
        if envelopes.is_empty() { return Ok(()); }

        for window in envelopes.windows(2) {
            let (prev, curr) = (&window[0], &window[1]);

            if curr.prev_hash != Some(prev.signature_hash()) {
                return Err(ShardError::InvalidConfiguration("Causality Break".into()));
            }

            if curr.evidence.timestamp() < prev.evidence.timestamp() {
                return Err(ShardError::InvalidConfiguration("Temporal Paradox".into()));
            }
        }
        Ok(())
    }
}

/// Gate 3: The Integrity Gate (Reception Side)
pub trait IntegrityGate {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        now: PhalanxTimestamp,
        tolerance: u64,
    ) -> Result<Self, ShardError>
    where Self: Sized;
}

impl IntegrityGate for WitnessEnvelope {
    fn check_integrity(
        self,
        node_id: &NetworkId,
        now: PhalanxTimestamp,
        tolerance: u64,
    ) -> Result<Self, ShardError> {
        if !self.verify() {
            error!(event = "integrity_failure", node = %node_id, peer = %self.did, "SIGNATURE_INVALID");
            return Err(ShardError::SigningError("Signature verification failed".into()));
        }
        // Assuming TimeJudge is imported/used in context
        Ok(self)
    }
}

/// Gate 4: The Privacy Gate (Egress)
pub trait PrivacyGate {
    fn safeguard(self, key: &SymmetricKey) -> Result<Self, ShardError> where Self: Sized;
}

impl PrivacyGate for Evidence {
    fn safeguard(mut self, key: &SymmetricKey) -> Result<Self, ShardError> {
        let res = match &mut self {
            Evidence::Video(s) => s.encrypt(key),
            Evidence::Audio(s) => s.encrypt(key),
            _ => Ok(()),
        };

        res.map(|_| self).map_err(|e| {
            error!(event = "privacy_failure", error = %e, "Safeguarding failed");
            ShardError::Encryption(e)
        })
    }
}

/// Gate 5: The Ingress Capacity Gate
pub trait CapacityGate {
    fn check_capacity(self, peer: &NetworkId, pending: usize, limit: usize) -> Result<Self, ShardError>
    where Self: Sized;
}

impl CapacityGate for WitnessEnvelope {
    fn check_capacity(self, peer: &NetworkId, pending: usize, limit: usize) -> Result<Self, ShardError> {
        if pending > limit {
            warn!(event = "capacity_shedding", peer = %peer, "Node saturated");
            return Err(ShardError::CapacityExceeded(pending as u64));
        }
        Ok(self)
    }
}

/// Gate 6: The Memory Buffer Gate
pub trait BufferCapacityGate {
    fn enforce_capacity_limit(
        &mut self,
        incoming_shard: &ShardId,
        capacity_limit: usize,
    ) -> Result<&mut Self, ShardError>;
}

impl BufferCapacityGate for HashMap<ShardId, crate::crucible::WorkContext<Vec<u8>>> {
    fn enforce_capacity_limit(
        &mut self,
        incoming_shard: &ShardId,
        limit: usize,
    ) -> Result<&mut Self, ShardError> {
        if !self.contains_key(incoming_shard) && self.len() >= limit {
            let stale = self.iter()
                .min_by_key(|(_, ctx)| ctx.created_at)
                .map(|(k, _)| k.clone());

            if let Some(id) = stale {
                warn!(event = "buffer_eviction", evicted = %id, "Memory limit reached");
                self.remove(&id);
            } else {
                return Err(ShardError::InvalidConfiguration("Zero capacity".into()));
            }
        }
        Ok(self)
    }
}

/// Monadic Observation Extension
pub trait ForensicGate<T, E> {
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E>;
}

impl<T, E: std::fmt::Display> ForensicGate<T, E> for Result<T, E> {
    fn gate(self, event: &str, node: &NetworkId, msg: &str) -> Result<T, E> {
        if let Err(ref e) = self {
            error!(event = event, node = %node, error = %e, "{msg}");
        }
        self
    }
}