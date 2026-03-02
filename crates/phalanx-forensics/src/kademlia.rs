// crates/phalanx-forensics/src/kademlia.rs
use phalanx_proto::crypto::CryptoError;
use phalanx_proto::identity::NetworkId;
use phalanx_proto::kademlia::*;
use phalanx_proto::kademlia::*;
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

fn unix_to_instant(unix_timestamp: Option<u64>) -> Option<Instant> {
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

impl DhtPayload {
    pub fn new(data: Vec<u8>, variant: PayloadKind, expires: Option<Instant>) -> Self {
        Self {
            version: Self::CURRENT_VERSION,
            variant,
            expires_at_unix: instant_to_unix(expires),
            data,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        postcard::to_stdvec(self).map_err(|_| Error::ValueTooLarge)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let decoded: Self = postcard::from_bytes(bytes).map_err(|_| Error::ValueTooLarge)?;
        decoded.validate()?;
        Ok(decoded)
    }

    pub fn validate(&self) -> Result<()> {
        if self.data.is_empty() {
            return Err(Error::ValueTooLarge);
        }

        if self.data.len() > Self::MAX_PAYLOAD_SIZE {
            return Err(Error::ValueTooLarge);
        }

        Ok(())
    }

    pub fn verify_ownership(&self, expected_owner_prefix: &str) -> bool {
        if self.data.is_empty() {
            return false;
        }

        let payload_str = String::from_utf8_lossy(&self.data);
        if !payload_str.contains(expected_owner_prefix) {
            tracing::warn!(
                expected = %expected_owner_prefix,
                "DHT: Rejected record injection due to ownership prefix mismatch"
            );
            return false;
        }

        true
    }
}

impl DhtProviderSet {
    /// THE WEIGHTED VERB: Reputation-based eviction logic
    pub fn try_insert_weighted(
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
}

pub trait PeerEvaluator: Send + Sync + 'static {
    /// Returns a normalized reputation score (e.g., 0.0 to 1.0).
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32;
}
