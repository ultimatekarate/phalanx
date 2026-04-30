// crates/phalanx-forensics/src/kademlia.rs

use phalanx_proto::identity::MeshAddress;
use phalanx_proto::kademlia::{DhtProviderSet, ProviderEntry};

pub struct KademliaGovernor;

impl KademliaGovernor {
    /// Attempts to insert a provider into a set using reputation-weighted eviction.
    /// Returns true if the set was modified.
    pub fn try_insert_weighted(
        set: &mut DhtProviderSet,
        network_id: MeshAddress,
        expiration: u64,
        reputation: f32,
        current_time: u64,
    ) -> bool {
        // Temporal Decay: Clear expired records
        set.providers.retain(|p| p.expiration > current_time);

        // Deduplication
        if let Some(existing) = set.providers.iter_mut().find(|p| p.address == network_id) {
            existing.expiration = expiration;
            existing.reputation_score = reputation;
            return true;
        }

        let new_entry = ProviderEntry {
            address: network_id,
            expiration,
            reputation_score: reputation,
        };

        // Simple Admission
        if set.providers.len() < DhtProviderSet::MAX_PROVIDERS {
            set.providers.push(new_entry);
            return true;
        }

        // Reputation-Weighted Eviction
        // We find the peer with the lowest reputation to determine eligibility
        if let Some((idx, min_score)) = set
            .providers
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.reputation_score.total_cmp(&b.reputation_score))
            .map(|(i, p)| (i, p.reputation_score))
        {
            if reputation > min_score {
                // Safety: idx comes from enumerate() over set.providers, so it is always in bounds.
                #[allow(clippy::indexing_slicing)]
                {
                    set.providers[idx] = new_entry;
                }
                return true;
            }
        }

        false
    }
}
