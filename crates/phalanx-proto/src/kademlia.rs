// crates/phalanx-proto/src/kademlia.rs
use serde::{Deserialize, Serialize};
use crate::identity::NetworkId;

#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
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

#[derive(Debug, Serialize, Deserialize)]
pub struct DhtProviderSet {
    pub providers: Vec<ProviderEntry>,
}

#[derive(Serialize, Deserialize)]
pub struct PersistentProvider {
    pub network_id: NetworkId,
    pub expires_at_unix: Option<u64>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DhtProviderSet {
    pub providers: Vec<ProviderEntry>,
}

impl DhtProviderSet {
    pub const MAX_PROVIDERS: usize = 20;

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Self {
                providers: Vec::new(),
            });
        }
        postcard::from_bytes(bytes).map_err(|_| Error::MaxProvidedKeys)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }

    /// Attempts to insert a provider using reputation-weighted eviction.
    pub fn try_insert_weighted(
        &mut self,
        new_peer: PeerId,
        expiration: u64,
        reputation: f32,
    ) -> bool {
        let network_id = NetworkId::from(new_peer);

        // Temporal Decay: Lazy cleanup of expired providers before evaluating capacity
        self.providers.retain(|p| !is_expired(Some(p.expiration)));

        // 1. Deduplication: Update existing entry if present
        if let Some(existing) = self
            .providers
            .iter_mut()
            .find(|p| p.network_id.as_ref() == &new_peer)
        {
            existing.expiration = expiration;
            existing.reputation_score = reputation;
            return true;
        }

        let new_entry = ProviderEntry {
            network_id,
            expiration,
            reputation_score: reputation,
        };

        // 2. Capacity Check
        if self.providers.len() < Self::MAX_PROVIDERS {
            self.providers.push(new_entry);
            return true;
        }

        // 3. Eviction Logic: Find the lowest reputation peer
        let (min_index, min_score) = self
            .providers
            .iter()
            .enumerate()
            .min_by(|(_, a), (_, b)| a.reputation_score.partial_cmp(&b.reputation_score).unwrap())
            .map(|(idx, entry)| (idx, entry.reputation_score))
            .unwrap();

        // Only evict if the new provider has a strictly higher reputation
        if reputation > min_score {
            tracing::info!(
                evicted = %self.providers[min_index].network_id,
                replaced_by = %new_peer,
                "DHT: Executing reputation-weighted provider eviction"
            );
            self.providers[min_index] = new_entry;
            return true;
        }

        false
    }

    pub fn remove(&mut self, provider: &PeerId) -> bool {
        let initial_len = self.providers.len();
        self.providers.retain(|p| p.network_id.as_ref() != provider);
        self.providers.len() < initial_len
    }

    pub fn into_records(self, key: RecordKey) -> Vec<ProviderRecord> {
        self.providers
            .into_iter()
            .filter(|p| !is_expired(Some(p.expiration))) // Lazy temporal filter
            .map(|p| ProviderRecord {
                key: key.clone(),
                provider: *p.network_id.as_ref(),
                expires: unix_to_instant(Some(p.expiration)),
                addresses: Vec::new(),
            })
            .collect()
    }
}
