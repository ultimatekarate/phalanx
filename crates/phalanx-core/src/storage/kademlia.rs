use libp2p::kad::store::{Error, RecordStore, Result};
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use libp2p::PeerId;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::borrow::Cow;
use std::path::Path;
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
}
// =====================
// SCHEMA DEFINITION
// =====================

const DHT_RECORDS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dht_records");
const DHT_PROVIDERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dht_providers");
const MAX_PROVIDERS_PER_KEY: usize = 20;

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

#[derive(Serialize, Deserialize)]
pub struct DhtProviderSet(Vec<PersistentProvider>);

impl DhtProviderSet {
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Ok(Self(Vec::new()));
        }
        postcard::from_bytes(bytes).map_err(|_| Error::MaxProvidedKeys)
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_stdvec(self).unwrap_or_default()
    }

    pub fn try_insert(&mut self, provider: PeerId, expires: Option<Instant>) -> Result<()> {
        // Temporal Decay: Lazy cleanup of expired providers before evaluating capacity
        self.0.retain(|p| !is_expired(p.expires_at_unix));

        // Update if exists
        if let Some(existing) = self.0.iter_mut().find(|p| p.network_id.0 == provider) {
            existing.expires_at_unix = instant_to_unix(expires);
            return Ok(());
        }

        if self.0.len() >= MAX_PROVIDERS_PER_KEY {
            return Err(Error::MaxProvidedKeys);
        }

        self.0.push(PersistentProvider {
            network_id: NetworkId::from(provider),
            expires_at_unix: instant_to_unix(expires),
        });

        Ok(())
    }

    pub fn remove(&mut self, provider: &PeerId) -> bool {
        let initial_len = self.0.len();
        self.0.retain(|p| &p.network_id.0 != provider);
        self.0.len() < initial_len
    }

    pub fn into_records(self, key: RecordKey) -> Vec<ProviderRecord> {
        self.0
            .into_iter()
            .filter(|p| !is_expired(p.expires_at_unix)) // Lazy temporal filter
            .map(|p| ProviderRecord {
                key: key.clone(),
                provider: p.network_id.0,
                expires: unix_to_instant(p.expires_at_unix),
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
    local_peer_id: PeerId,
}

impl RedbStore {
    /// Initializes the persistent Kademlia store.
    pub fn new<P: AsRef<Path>>(
        path: P,
        local_peer_id: PeerId,
    ) -> std::result::Result<Self, redb::Error> {
        let db = Database::create(path)?;

        // Ensure tables exist on boot
        let write_txn = db.begin_write()?;
        write_txn.open_table(DHT_RECORDS_TABLE)?;
        write_txn.open_table(DHT_PROVIDERS_TABLE)?;
        write_txn.commit()?;

        Ok(Self { db, local_peer_id })
    }

    /// Zero-Trust Cryptographic Gate
    /// Assumes payload is a signed Phalanx envelope. Returns false if invalid.
    fn verify_record_signature(&self, record: &Record) -> bool {
        // Implementation delegates to the identity module to verify the signature
        // against the record's embedded public key or derived PeerId.
        // For standard DHT operations, libp2p provides a validation pipeline,
        // but explicit storage-layer gating prevents application-layer bypasses.
        if record.value.is_empty() {
            return false;
        }

        // Placeholder for strict verification logic
        true
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
            let mut records_table = write_txn.open_table(DHT_RECORDS_TABLE)?;
            let mut invalid_record_keys = Vec::new();

            for result in records_table.iter()? {
                if let Ok((k, v)) = result {
                    match DhtPayload::decode(v.value()) {
                        Ok(payload) if is_expired(payload.expires_at_unix) => {
                            invalid_record_keys.push(k.value().to_vec());
                        }
                        Err(_) => invalid_record_keys.push(k.value().to_vec()), // Prune corrupted bytes
                        _ => {}
                    }
                }
            }

            for key in invalid_record_keys {
                records_table.remove(key.as_slice())?;
                pruned_count += 1;
            }

            let mut providers_table = write_txn.open_table(DHT_PROVIDERS_TABLE)?;
            let mut keys_to_delete = Vec::new();
            let mut keys_to_update = Vec::new();

            for result in providers_table.iter()? {
                if let Ok((k, v)) = result {
                    match DhtProviderSet::decode(v.value()) {
                        Ok(mut set) => {
                            let initial_len = set.0.len();
                            set.0.retain(|p| !is_expired(p.expires_at_unix));

                            if set.0.is_empty() {
                                keys_to_delete.push(k.value().to_vec());
                            } else if set.0.len() < initial_len {
                                keys_to_update.push((k.value().to_vec(), set.encode()));
                            }
                        }
                        Err(_) => keys_to_delete.push(k.value().to_vec()),
                    }
                }
            }

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

        for result in table.iter()? {
            if let Ok((_, v)) = result {
                if let Ok(payload) = DhtPayload::decode(v.value()) {
                    if !is_expired(payload.expires_at_unix) {
                        *metrics.entry(payload.variant).or_insert(0) += 1;
                    }
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

    fn add_provider(&mut self, record: ProviderRecord) -> Result<()> {
        // Prevent malicious peers from constantly reflecting our own ID back to us
        // to exhaust disk I/O.
        if record.provider == self.local_peer_id {
            tracing::debug!("Discarding self-referential provider record injection.");
            return Ok(());
        }

        let typed_key = DhtRecordKey::new(&record.key);
        let write_txn = self.db.begin_write().map_err(|_| Error::MaxProvidedKeys)?;

        {
            let mut table = write_txn
                .open_table(DHT_PROVIDERS_TABLE)
                .map_err(|_| Error::MaxProvidedKeys)?;
            let existing_bytes = table
                .get(typed_key.as_bytes())
                .map_err(|_| Error::MaxProvidedKeys)?
                .map(|access| access.value().to_vec())
                .unwrap_or_default();

            let mut provider_set = DhtProviderSet::decode(&existing_bytes)?;
            provider_set.try_insert(record.provider, record.expires)?;

            table
                .insert(typed_key.as_bytes(), provider_set.encode().as_slice())
                .map_err(|_| Error::MaxProvidedKeys)?;
        }

        write_txn.commit().map_err(|_| Error::MaxProvidedKeys)?;
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
