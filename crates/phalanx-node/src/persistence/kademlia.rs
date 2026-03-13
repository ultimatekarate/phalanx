use libp2p::kad::store::{Error, RecordStore, Result};
use libp2p::kad::{ProviderRecord, Record, RecordKey};
use libp2p::PeerId;
use phalanx_forensics::kademlia::*;
use phalanx_forensics::trust::PeerEvaluator;
use phalanx_proto::kademlia::DhtProviderSet;
use phalanx_proto::prelude::*;
use redb::{Database, ReadableDatabase, ReadableTable, TableDefinition};
use std::borrow::Cow;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::instrument;
pub type PhalanxKadStore = RedbStore;
const _DHT_RECORDS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dht_records");
const DHT_RECORDS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dht_records");
const DHT_PROVIDERS_TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("dht_providers");

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

        // Extract the expected Owner DID from the RecordKey
        // Phalanx Shard Keys follow the format: did_hash:shard_id
        let key_str = String::from_utf8_lossy(record.key.as_ref());
        let expected_owner_prefix = match key_str.split(':').next() {
            Some(prefix) => prefix,
            None => return false,
        };

        // Decode Payload to access the embedded signature
        let payload: DhtPayload = match postcard::from_bytes(&record.value) {
            Ok(p) => p,
            Err(_) => return false,
        };

        // Cryptographic Verification
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

        let payload_bytes = typed_payload.encode().map_err(|_| Error::ValueTooLarge)?;

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
        let network_id = NetworkId::from(peer_id.to_string());

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

        let write_txn = self.db.begin_write().map_err(|_| Error::ValueTooLarge)?;
        {
            let mut table = write_txn
                .open_table(DHT_PROVIDERS_TABLE)
                .map_err(|_| Error::ValueTooLarge)?;
            let mut existing_bytes = Vec::new();

            if let Some(access) = table
                .get(typed_key.as_bytes())
                .map_err(|_| Error::ValueTooLarge)?
            {
                existing_bytes = access.value().to_vec();
            }

            let mut provider_set =
                DhtProviderSet::decode(&existing_bytes).unwrap_or_else(|_| DhtProviderSet {
                    providers: Vec::new(),
                });

            if provider_set.try_insert_weighted(network_id.clone(), expiration, reputation_score) {
                table
                    .insert(typed_key.as_bytes(), provider_set.encode().as_slice())
                    .map_err(|_| Error::ValueTooLarge)?;
            } else {
                return Err(Error::MaxProvidedKeys);
            }
        }
        write_txn.commit().map_err(|_| Error::ValueTooLarge)?;

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
            Ok(set) => provider_set_to_records(set, key.clone()),
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
                    if provider_set.remove_by_id(&provider.to_string()) {
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

fn provider_set_to_records(set: DhtProviderSet, key: RecordKey) -> Vec<ProviderRecord> {
    set.providers
        .into_iter()
        .filter_map(|entry| {
            let peer_id: PeerId = entry.network_id.to_string().parse().ok()?;
            let expiration_instant = {
                let now_unix = system_time_now_unix();
                let now_instant = Instant::now();
                if entry.expiration > now_unix {
                    now_instant.checked_add(Duration::from_secs(
                        entry.expiration.saturating_sub(now_unix),
                    ))
                } else {
                    now_instant.checked_sub(Duration::from_secs(
                        now_unix.saturating_sub(entry.expiration),
                    ))
                }
            };
            Some(ProviderRecord {
                key: key.clone(),
                provider: peer_id,
                expires: expiration_instant,
                addresses: Vec::new(),
            })
        })
        .collect()
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
