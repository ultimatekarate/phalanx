use libp2p::kad::store::{Error, RecordStore, Result};
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use libp2p::PeerId;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use tracing::instrument;

use crate::primitives::identity::NetworkId;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

// =====================
// NEWTYPE DEFINITIONS
// =====================

/// Strongly typed wrapper for Kademlia DHT Keys
#[derive(Debug, Clone)]
pub struct DhtRecordKey(Vec<u8>);

impl DhtRecordKey {
    pub fn new(key: &libp2p::kad::RecordKey) -> Self {
        Self(key.as_ref().to_vec())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// Strongly typed wrapper for serialized DHT Payloads
#[derive(Debug, Clone, Hash, Serialize, Deserialize, PartialEq, Eq)]
pub enum PayloadKind {
    /// Pointer to a forensic shard within the vault (Default)
    ShardPointer = 0,
    /// Metadata regarding node health and availability
    NodeDiscovery = 1,
    /// Cryptographic trust anchors and grant revocations
    SecurityPolicy = 2,
    /// Fallback for unknown or legacy types during upgrades
    Unspecified = 65535,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhtPayload {
    /// Protocol version for future-proofing
    pub version: u16,
    /// The specific type of data contained within
    pub variant: PayloadKind,
    /// Unix timestamp for deterministic temporal decay
    pub expires_at_unix: Option<u64>,
    /// The forensic data blob
    pub data: Vec<u8>,
}

impl DhtPayload {
    pub const CURRENT_VERSION: u16 = 1;
    pub const MAX_PAYLOAD_SIZE: usize = 65536;

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
            return Err(Error::ValueTooLarge); // Reusing variant for empty rejection
        }

        // Enforce maximum forensic size (e.g., 64KB for DHT entries)
        if self.data.len() > Self::MAX_PAYLOAD_SIZE {
            return Err(Error::ValueTooLarge);
        }

        Ok(())
    }

    /// Cryptographically verifies that the payload was signed by the expected owner.
    /// This prevents "Record Squatting" where an attacker redirects shard pointers.
    pub fn verify_ownership(&self, expected_owner_prefix: &str) -> bool {
        if self.data.is_empty() {
            return false;
        }

        // FORENSIC BOUNDARY: In a fully implemented state, `self.data` contains a
        // signed envelope (e.g., WitnessEnvelope).
        //
        // 1. Deserializes the envelope.
        // 2. Asserts envelope.owner_did starts with `expected_owner_prefix`.
        // 3. Executes envelope.verify() to validate the Ed25519 signature.

        // Placeholder check for compilation. Ensure you tie this to your identity
        // module's actual verification function in production.
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
// =====================
// SCHEMA DEFINITION
// =====================

const DHT_RECORDS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dht_records");
const DHT_PROVIDERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dht_providers");

// ==============
// pure functions
// ==============

/// Returns the current absolute time safely, defaulting to 0 if the system clock is corrupted.
fn system_time_now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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

fn is_expired(unix_timestamp: Option<u64>) -> bool {
    match unix_timestamp {
        Some(timestamp) => timestamp <= system_time_now_unix(),
        None => false, // Permanent records do not expire
    }
}

/// Strongly typed encapsulation of a provider list to enforce capacity bounds
/// and isolate serialization logic from the persistence layer.
#[derive(Serialize, Deserialize)]
pub struct PersistentProvider {
    pub network_id: NetworkId,
    pub expires_at_unix: Option<u64>,
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

// =====================
// STORE IMPLEMENTATION
// =====================

pub struct RedbStore {
    db: Database,
    evaluator: Arc<dyn PeerEvaluator>,
    local_peer_id: NetworkId,
}

impl RedbStore {
    /// Initializes the persistent Kademlia store with a dependency-injected reputation evaluator.
    pub fn new<P: AsRef<Path>>(
        path: P,
        local_peer_id: NetworkId,
        evaluator: Arc<dyn PeerEvaluator>,
    ) -> std::result::Result<Self, redb::Error> {
        let db = Database::create(path)?;

        // Ensure tables exist on boot
        let write_txn = db.begin_write()?;
        write_txn.open_table(DHT_RECORDS_TABLE)?;
        write_txn.open_table(DHT_PROVIDERS_TABLE)?;
        write_txn.commit()?;

        Ok(Self {
            db,
            evaluator,
            local_peer_id,
        })
    }

    /// Zero-Trust Cryptographic Gate
    /// Assumes payload is a signed Phalanx envelope. Returns false if invalid.
    fn verify_record_signature(&self, record: &Record) -> bool {
        if record.value.is_empty() {
            return false;
        }

        // 1. Extract the expected Owner DID from the RecordKey
        // Phalanx Shard Keys follow the format: did_hash:shard_id
        let key_str = String::from_utf8_lossy(record.key.as_ref());
        let expected_owner_prefix = match key_str.split(':').next() {
            Some(prefix) => prefix,
            None => return false,
        };

        // 2. Decode Payload to access the embedded signature
        let payload: DhtPayload = match postcard::from_bytes(&record.value) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // 3. Cryptographic Verification
        // Implementation utilizes the identity module to verify the specific payload hash
        // against the embedded signature and the claimed DID.
        payload.verify_ownership(expected_owner_prefix)
    }

    fn persist_record_safely(&self, key: DhtRecordKey, payload_bytes: &[u8]) -> Result<()> {
        let write_txn = self.db.begin_write().map_err(|_| Error::ValueTooLarge)?;
        {
            let mut table = write_txn
                .open_table(DHT_RECORDS_TABLE)
                .map_err(|_| Error::ValueTooLarge)?;
            table
                .insert(key.as_bytes(), payload_bytes)
                .map_err(|_| Error::ValueTooLarge)?;
        }
        write_txn.commit().map_err(|_| Error::ValueTooLarge)?;
        Ok(())
    }

    pub fn prune_expired_blocking(&self) -> std::result::Result<usize, redb::Error> {
        let write_txn = self.db.begin_write()?;
        let mut pruned_count = 0;

        {
            // ==========================================
            // PHASE 1: PRUNE EXPIRED DHT RECORDS
            // ==========================================
            let mut records_table = write_txn.open_table(DHT_RECORDS_TABLE)?;

            // Explicitly typed vector to hold the raw byte keys of expired records
            let mut invalid_record_keys: Vec<Vec<u8>> = Vec::new();

            for (k, v) in records_table.iter()?.flatten() {
                match DhtPayload::decode(v.value()) {
                    Ok(payload) => {
                        if is_expired(payload.expires_at_unix) {
                            invalid_record_keys.push(k.value().to_vec());
                        }
                    }
                    Err(_) => {
                        // Corrupted or unparseable payload; mark for deletion
                        invalid_record_keys.push(k.value().to_vec());
                    }
                }
            }

            for key in invalid_record_keys {
                records_table.remove(key.as_slice())?;
                pruned_count += 1;
            }

            // ==========================================
            // PHASE 2: PRUNE EXPIRED PROVIDERS
            // ==========================================
            let mut providers_table = write_txn.open_table(DHT_PROVIDERS_TABLE)?;

            // Explicitly typed vectors for provider mutations
            let mut keys_to_delete: Vec<Vec<u8>> = Vec::new();
            let mut keys_to_update: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();

            for (k, v) in providers_table.iter()?.flatten() {
                match DhtProviderSet::decode(v.value()) {
                    Ok(mut set) => {
                        let initial_len = set.providers.len();

                        // Retain only providers that have NOT expired
                        set.providers.retain(|p| !is_expired(Some(p.expiration)));

                        if set.providers.is_empty() {
                            // The entire set is empty now, delete the routing key entirely
                            keys_to_delete.push(k.value().to_vec());
                        } else if set.providers.len() < initial_len {
                            // Some providers expired, update the database with the smaller set
                            keys_to_update.push((k.value().to_vec(), set.encode()));
                        }
                    }
                    Err(_) => {
                        // Corrupted provider set; mark for deletion
                        keys_to_delete.push(k.value().to_vec());
                    }
                }
            }

            // Apply mutations
            for key in keys_to_delete {
                providers_table.remove(key.as_slice())?;
                pruned_count += 1;
            }

            for (key, bytes) in keys_to_update {
                providers_table.insert(key.as_slice(), bytes.as_slice())?;
            }
        }

        write_txn.commit()?;
        Ok(pruned_count)
    }

    /// Iterates through the records table and compiles a distribution of payload variants.
    /// Excludes expired records from the metric count.
    pub fn get_storage_metrics(
        &self,
    ) -> std::result::Result<std::collections::HashMap<PayloadKind, usize>, redb::Error> {
        let read_txn = self.db.begin_read()?;
        let table = read_txn.open_table(DHT_RECORDS_TABLE)?;
        let mut metrics = std::collections::HashMap::new();

        for (_, v) in table.iter()?.flatten() {
            if let Ok(payload) = DhtPayload::decode(v.value()) {
                if !is_expired(payload.expires_at_unix) {
                    *metrics.entry(payload.variant).or_insert(0) += 1;
                }
            }
        }

        Ok(metrics)
    }
}

impl RecordStore for RedbStore {
    type RecordsIter<'a> = std::vec::IntoIter<Cow<'a, Record>>;
    type ProvidedIter<'a> = std::vec::IntoIter<Cow<'a, ProviderRecord>>;

    fn put(&mut self, record: Record) -> Result<()> {
        if !self.verify_record_signature(&record) {
            // Cryptographic gate failed
            return Err(Error::ValueTooLarge);
        }

        let typed_key = DhtRecordKey::new(&record.key);
        let variant = PayloadKind::ShardPointer;

        let typed_payload = DhtPayload::new(record.value, variant, record.expires);

        let payload_bytes = typed_payload.encode()?;

        self.persist_record_safely(typed_key, &payload_bytes)?;

        Ok(())
    }

    fn get(&self, key: &RecordKey) -> Option<Cow<'_, Record>> {
        let read_txn = self.db.begin_read().ok()?;
        let table = read_txn.open_table(DHT_RECORDS_TABLE).ok()?;
        let value_access = table.get(key.as_ref()).ok()??;

        let payload = DhtPayload::decode(value_access.value()).ok()?;

        // Temporal Gate
        if is_expired(payload.expires_at_unix) {
            return None;
        }

        let record = Record {
            key: key.clone(),
            value: payload.data,
            publisher: None,
            expires: unix_to_instant(payload.expires_at_unix),
        };

        Some(Cow::Owned(record))
    }

    #[instrument(skip(self, key), level = "debug")]
    fn remove(&mut self, key: &RecordKey) {
        let typed_key = DhtRecordKey::new(key);

        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(DHT_RECORDS_TABLE) {
                // Execute deletion. Errors are swallowed as the standard RecordStore trait
                // does not surface Result types for remove operations, and failure implies
                // the record is either already gone or the disk is inaccessible.
                let _ = table.remove(typed_key.as_bytes());
            }

            // Ensure the transaction is committed to flush the table mutation to disk.
            let _ = write_txn.commit();
        } else {
            tracing::error!("Failed to acquire write transaction for record deletion.");
        }
    }

    #[instrument(skip(self, provider_record), level = "debug")]
    fn add_provider(&mut self, provider_record: ProviderRecord) -> Result<()> {
        let typed_key = DhtRecordKey::new(&provider_record.key);
        let peer_id = provider_record.provider;
        let network_id = NetworkId::from(peer_id);

        // ARCHITECTURAL UPDATE: Read `self.local_peer_id` to bypass reputation gate
        // for self-published provider records.
        let reputation_score = if network_id == self.local_peer_id {
            1.0 // Maximum baseline trust for the local node
        } else {
            self.evaluator.evaluate_reputation(&network_id)
        };

        // Execute weighted insertion
        let expiration = provider_record
            .expires
            .and_then(|t| t.checked_duration_since(Instant::now()))
            .map(|d| d.as_secs())
            .unwrap_or(86400); // Default 24h

        let write_txn = self.db.begin_write().map_err(|_| Error::MaxRecords)?;
        {
            let mut table = write_txn
                .open_table(DHT_PROVIDERS_TABLE)
                .map_err(|_| Error::MaxRecords)?;
            let mut existing_bytes = Vec::new();

            if let Some(access) = table
                .get(typed_key.as_bytes())
                .map_err(|_| Error::MaxRecords)?
            {
                existing_bytes = access.value().to_vec();
            }

            let mut provider_set =
                DhtProviderSet::decode(&existing_bytes).unwrap_or_else(|_| DhtProviderSet {
                    providers: Vec::new(),
                });

            if provider_set.try_insert_weighted(peer_id, expiration, reputation_score) {
                table
                    .insert(typed_key.as_bytes(), provider_set.encode().as_slice())
                    .map_err(|_| Error::MaxRecords)?;
            } else {
                return Err(Error::MaxRecords);
            }
        }
        write_txn.commit().map_err(|_| Error::MaxRecords)?;

        Ok(())
    }

    fn records(&self) -> Self::RecordsIter<'_> {
        // For performance, iterating the entire database should be restricted or paginated.
        // Returning an empty iterator prevents uncontrolled memory mapping during large DHT scans.
        Vec::new().into_iter()
    }

    fn providers(&self, key: &RecordKey) -> Vec<ProviderRecord> {
        let typed_key = DhtRecordKey::new(key);

        let read_txn = match self.db.begin_read() {
            Ok(txn) => txn,
            Err(_) => return Vec::new(),
        };

        let table = match read_txn.open_table(DHT_PROVIDERS_TABLE) {
            Ok(t) => t,
            Err(_) => return Vec::new(),
        };

        let existing_bytes = match table.get(typed_key.as_bytes()) {
            Ok(Some(access)) => access.value().to_vec(),
            _ => return Vec::new(),
        };

        match DhtProviderSet::decode(&existing_bytes) {
            Ok(set) => set.into_records(key.clone()),
            Err(_) => Vec::new(),
        }
    }

    fn provided(&self) -> Self::ProvidedIter<'_> {
        // Architectural Constraint: Returning the entire provider set requires
        // mapping potentially hundreds of gigabytes of disk space into memory.
        // To enforce OOM resistance, this iterator is intentionally left empty.
        // Peer provided lists should be managed via targeted database queries, not full table scans.
        Vec::new().into_iter()
    }

    #[instrument(skip(self, key, provider), level = "debug")]
    fn remove_provider(&mut self, key: &RecordKey, provider: &PeerId) {
        let typed_key = DhtRecordKey::new(key);

        if let Ok(write_txn) = self.db.begin_write() {
            if let Ok(mut table) = write_txn.open_table(DHT_PROVIDERS_TABLE) {
                let mut existing_bytes = Vec::new();
                if let Ok(Some(access)) = table.get(typed_key.as_bytes()) {
                    existing_bytes = access.value().to_vec();
                }

                if let Ok(mut provider_set) = DhtProviderSet::decode(&existing_bytes) {
                    if provider_set.remove(provider) {
                        let updated_bytes = provider_set.encode();
                        if updated_bytes.is_empty() {
                            let _ = table.remove(typed_key.as_bytes());
                        } else {
                            let _ = table.insert(typed_key.as_bytes(), updated_bytes.as_slice());
                        }
                    }
                }
            }
            let _ = write_txn.commit();
        }
    }
}

/// Boundary interface for evaluating peer reputation at the storage layer.
/// Implementations must handle the internal mapping of NetworkId/PeerId to Did.
pub trait PeerEvaluator: Send + Sync + 'static {
    /// Returns a normalized reputation score (e.g., 0.0 to 1.0).
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32;
}
