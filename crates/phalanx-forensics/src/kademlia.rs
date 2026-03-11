// crates/phalanx-forensics/src/kademlia.rs

use phalanx_proto::identity::NetworkId;
use phalanx_proto::kademlia::*;
use phalanx_proto::prelude::ShardError;
use std::time::Duration;
use std::time::Instant;
use std::time::{SystemTime, UNIX_EPOCH};

/// THE CHRONOS VERBS: Time math for DHT entries
pub fn is_expired(unix_timestamp: Option<u64>) -> bool {
    unix_timestamp.is_some_and(|t| t <= system_time_now_unix())
}

fn instant_to_unix(instant: Option<Instant>) -> Option<u64> {
    let target_instant = instant?;
    let current_instant = Instant::now();
    let current_unix = system_time_now_unix();

    if target_instant > current_instant {
        Some(current_unix.saturating_add(target_instant.duration_since(current_instant).as_secs()))
    } else {
        Some(current_unix.saturating_sub(current_instant.duration_since(target_instant).as_secs()))
    }
}

fn _unix_to_instant(unix_timestamp: Option<u64>) -> Option<Instant> {
    let target_unix = unix_timestamp?;
    let current_instant = Instant::now();
    let current_unix = system_time_now_unix();

    if target_unix > current_unix {
        current_instant.checked_add(Duration::from_secs(
            target_unix.saturating_sub(current_unix),
        ))
    } else {
        current_instant.checked_sub(Duration::from_secs(
            current_unix.saturating_sub(target_unix),
        ))
    }
}

fn system_time_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub trait DhtPayloadAuthority {
    fn new(data: Vec<u8>, variant: PayloadKind, expires: Option<Instant>) -> Self;
    fn encode(&self) -> Result<Vec<u8>, ShardError>;
    fn decode(bytes: &[u8]) -> Result<Self, ShardError>
    where
        Self: Sized;
    fn validate(&self) -> Result<(), ShardError>;
    fn verify_ownership(&self, expected_owner_prefix: &str) -> bool;
}

impl DhtPayloadAuthority for DhtPayload {
    fn new(data: Vec<u8>, variant: PayloadKind, expires: Option<Instant>) -> Self {
        Self {
            version: 1, // Accessing static consts or hardcoding for the Noun
            variant,
            expires_at_unix: instant_to_unix(expires),
            data,
        }
    }

    fn encode(&self) -> Result<Vec<u8>, ShardError> {
        self.validate()?;
        postcard::to_allocvec(self).map_err(|e| ShardError::SerializationError(e.to_string()))
    }

    fn decode(bytes: &[u8]) -> Result<Self, ShardError> {
        let decoded: Self = crate::gate::unmarshal(bytes, "DhtPayload::decode")?;
        decoded.validate()?;
        Ok(decoded)
    }

    fn validate(&self) -> Result<(), ShardError> {
        if self.data.is_empty() {
            return Err(ShardError::InvalidConfiguration("Empty DHT payload".into()));
        }
        // Use the constant from the Dictionary
        if self.data.len() > 1024 {
            // Replace with DhtPayload::MAX_SIZE if defined in proto
            return Err(ShardError::SerializationError("Payload too large".into()));
        }
        Ok(())
    }

    fn verify_ownership(&self, expected_owner_prefix: &str) -> bool {
        if self.data.is_empty() {
            return false;
        }

        let payload_str = String::from_utf8_lossy(&self.data);
        if !payload_str.contains(expected_owner_prefix) {
            tracing::warn!(expected = %expected_owner_prefix, "DHT: Ownership mismatch");
            return false;
        }
        true
    }
}

pub trait ProviderAuthority {
    fn try_insert_weighted(
        &mut self,
        new_peer: NetworkId,
        expiration: u64,
        reputation: f32,
    ) -> bool;

    fn decode(bytes: &[u8]) -> std::result::Result<Self, ShardError>
    where
        Self: Sized;

    fn encode(&self) -> Vec<u8>;

    /// Remove a provider by its string representation. Returns true if a provider was removed.
    fn remove_by_id(&mut self, provider_id: &str) -> bool;
}

impl ProviderAuthority for DhtProviderSet {
    /// THE WEIGHTED VERB: Reputation-based eviction logic
    fn try_insert_weighted(
        &mut self,
        new_peer: NetworkId,
        expiration: u64,
        reputation: f32,
    ) -> bool {
        // 1. Lazy Cleanup
        self.providers.retain(|p| !is_expired(Some(p.expiration)));

        // 2. Deduplication
        if let Some(existing) = self.providers.iter_mut().find(|p| p.network_id == new_peer) {
            existing.expiration = expiration;
            existing.reputation_score = reputation;
            return true;
        }

        let new_entry = ProviderEntry {
            network_id: new_peer,
            expiration,
            reputation_score: reputation,
        };

        // 3. Simple Capacity Check
        if self.providers.len() < Self::MAX_PROVIDERS {
            self.providers.push(new_entry);
            return true;
        }

        // 4. Weighted Eviction: Find the weak link
        let min_idx = self
            .providers
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.reputation_score.partial_cmp(&b.reputation_score).unwrap())
            .map(|(idx, _)| idx);

        if let Some(idx) = min_idx {
            if reputation > self.providers[idx].reputation_score {
                // Swap out the low reputation peer for the better one
                self.providers[idx] = new_entry;
                return true;
            }
        }
        false
    }

    fn decode(bytes: &[u8]) -> std::result::Result<Self, ShardError> {
        if bytes.is_empty() {
            return Ok(DhtProviderSet {
                providers: Vec::new(),
            });
        }
        crate::gate::unmarshal(bytes, "DhtProviderSet::decode")
    }

    fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).unwrap_or_default()
    }

    fn remove_by_id(&mut self, provider_id: &str) -> bool {
        let initial_len = self.providers.len();
        self.providers
            .retain(|p| p.network_id.to_string() != provider_id);
        self.providers.len() < initial_len
    }
}

pub trait PeerEvaluator: Send + Sync + 'static {
    /// Returns a normalized reputation score (e.g., 0.0 to 1.0).
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32;
}

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_proto::identity::NetworkId;

    #[test]
    fn test_dht_provider_set_weighted_eviction() {
        let mut set = DhtProviderSet {
            providers: Vec::new(),
        };
        let now = system_time_now_unix();
        let future = now + 1000;

        // Fill the set with providers of increasing reputation
        for i in 0..DhtProviderSet::MAX_PROVIDERS {
            let pid = NetworkId::from(format!("peer_{}", i));
            // Reputation 0.0 to 0.19
            set.try_insert_weighted(pid, future, i as f32 / 100.0);
        }

        // Ensure full
        assert_eq!(set.providers.len(), DhtProviderSet::MAX_PROVIDERS);

        // Attempt to insert a high reputation peer (1.0)
        let high_rep = NetworkId::from("high_rep_peer");
        let inserted = set.try_insert_weighted(high_rep.clone(), future, 1.0);

        assert!(
            inserted,
            "High reputation peer should displace low reputation peer"
        );

        // Verify the new peer is present
        assert!(set.providers.iter().any(|p| p.network_id == high_rep));

        // Verify the lowest reputation peer (peer_0 with 0.0) was evicted
        let evicted = NetworkId::from("peer_0");
        assert!(!set.providers.iter().any(|p| p.network_id == evicted));

        // Attempt to insert a low reputation peer (0.0)
        let low_rep = NetworkId::from("low_rep_peer");
        let inserted_low = set.try_insert_weighted(low_rep, future, 0.0);

        assert!(
            !inserted_low,
            "Low reputation peer should not displace existing better peers"
        );
    }

    #[test]
    fn test_dht_payload_validation() {
        let valid = DhtPayload::new(vec![0x01, 0x02], PayloadKind::ShardPointer, None);
        assert!(valid.validate().is_ok());

        let empty = DhtPayload::new(vec![], PayloadKind::ShardPointer, None);
        assert!(matches!(
            empty.validate(),
            Err(ShardError::InvalidConfiguration(_))
        ));
    }
}
