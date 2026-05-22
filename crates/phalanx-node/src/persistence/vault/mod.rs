// crates/phalanx-node/src/persistence/vault/mod.rs
//
// Guardian: the node's encrypted vault for forensic evidence.
// Owns the Crucible (in-memory reassembly), recording logs (disk),
// content keyring (per-recording DEKs), and storage accounting.

mod crypto;
mod metadata;
mod recording_log;
mod wal;

// Re-export public API from submodules
pub(crate) use crypto::atomic_encrypted_write;
pub use crypto::{derive_vault_key, load_or_create_vault_salt, read_encrypted_file};
pub(crate) use metadata::RecordingMetadataStore;

use crate::NodeConfig;
use phalanx_forensics::crucible::Crucible;
use phalanx_forensics::crucible::RecordingAmalgam;
use phalanx_forensics::crucible::{EnvelopeHashExt, EvidenceExt};
use phalanx_forensics::gate::PromotionGate;
use phalanx_forensics::unit::ForensicUnit;
use phalanx_proto::crypto::{DekMaster, SymmetricKey};
use phalanx_proto::evidence::PrnuPosterior;
use phalanx_proto::evidence::Recording;
use phalanx_proto::evidence::RecordingMetadata;
use phalanx_proto::evidence::SignatureHash;
use phalanx_proto::evidence::StorageSequence;
use phalanx_proto::evidence::WitnessEnvelope;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::prelude::*;
use phalanx_proto::storage::GuardianError;
use phalanx_proto::time::TrustedClock;
use phalanx_proto::types::ByteCapacity;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::fs;
use tracing::info;
use zeroize::Zeroize;

use recording_log::RecordingLog;

// ── Storage Ledger ──────────────────────────────────────────────────

/// Per-node storage accounting. Distinguishes own evidence from foreign
/// (relay/replica) data to support fair contribution tracking and eviction policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StorageLedger {
    /// Bytes of MY evidence stored in the local vault.
    pub own_bytes: ByteCapacity,
    /// Foreign shards I'm a K-replica for (long-term committed storage).
    pub foreign_committed_bytes: ByteCapacity,
    /// Foreign shards in the relay buffer (transient, evictable).
    pub foreign_transient_bytes: ByteCapacity,
    /// Per-owner foreign byte counts (committed + transient combined).
    /// Used for per-DID quota enforcement to prevent a single owner from
    /// monopolizing all foreign storage capacity.
    #[serde(default)]
    pub foreign_bytes_by_owner: HashMap<Did, u64>,
    /// Cumulative bytes of my evidence pushed to the mesh.
    pub own_bytes_pushed: ByteCapacity,
}

#[allow(clippy::arithmetic_side_effects)] // Ledger arithmetic — byte accounting with bounded values.
impl StorageLedger {
    /// Total foreign bytes (committed + transient).
    pub fn total_foreign_bytes(&self) -> u64 {
        self.foreign_committed_bytes.as_u64() + self.foreign_transient_bytes.as_u64()
    }

    /// Total bytes held locally (own + all foreign).
    pub fn total_local_bytes(&self) -> u64 {
        self.own_bytes.as_u64() + self.total_foreign_bytes()
    }

    /// Record ingestion of own evidence.
    pub fn record_own_ingestion(&mut self, bytes: u64) {
        self.own_bytes = ByteCapacity(self.own_bytes.as_u64() + bytes);
    }

    /// Record ingestion of foreign evidence (transient until promoted to committed).
    /// Tracks both the global transient total and per-owner accounting.
    pub fn record_foreign_ingestion(&mut self, bytes: u64, owner_did: &Did) {
        self.foreign_transient_bytes = ByteCapacity(self.foreign_transient_bytes.as_u64() + bytes);
        let entry = self
            .foreign_bytes_by_owner
            .entry(owner_did.clone())
            .or_insert(0);
        *entry = entry.saturating_add(bytes);
    }

    /// Returns the total foreign bytes tracked for a specific owner DID.
    pub fn foreign_bytes_for_owner(&self, owner_did: &Did) -> u64 {
        self.foreign_bytes_by_owner
            .get(owner_did)
            .copied()
            .unwrap_or(0)
    }

    /// Promote transient foreign storage to committed (K-replica confirmed).
    pub fn promote_to_committed(&mut self, bytes: u64) {
        let moved = bytes.min(self.foreign_transient_bytes.as_u64());
        self.foreign_transient_bytes =
            ByteCapacity(self.foreign_transient_bytes.as_u64().saturating_sub(moved));
        self.foreign_committed_bytes = ByteCapacity(self.foreign_committed_bytes.as_u64() + moved);
    }

    /// Record bytes of own evidence successfully pushed to the mesh.
    pub fn record_own_push(&mut self, bytes: u64) {
        self.own_bytes_pushed = ByteCapacity(self.own_bytes_pushed.as_u64() + bytes);
    }

    /// Evict foreign transient bytes (e.g., relay buffer cleanup).
    pub fn evict_transient(&mut self, bytes: u64) {
        self.foreign_transient_bytes =
            ByteCapacity(self.foreign_transient_bytes.as_u64().saturating_sub(bytes));
    }
}

// ── Guardian ────────────────────────────────────────────────────────

pub struct Guardian {
    pub crucible: Crucible<RecordingAmalgam>,
    pub vault_path: String,
    pub local_did: Did,
    pub clock: Arc<dyn TrustedClock>,
    pub vault_key: SymmetricKey,
    /// HKDF master used to derive per-recording DEKs deterministically. This
    /// is what makes recordings phrase-recoverable: a fresh-restored sentinel
    /// rebuilds `dek_master` from the BIP39 phrase and decrypts every own
    /// recording without needing the local keyring file.
    pub dek_master: DekMaster,
    /// Per-node storage accounting for fairness and eviction policy.
    pub ledger: StorageLedger,
    /// Append-only recording logs, one per recording. Keyed by RecordingId.
    recording_logs: BTreeMap<RecordingId, RecordingLog>,
    /// Revoked recordings: future shards for these recordings are rejected.
    /// Public for StorageActor bootstrap (recovering revocations from journal).
    pub revoked_recordings: HashSet<RecordingId>,
    /// Per-recording content encryption keys (DEKs) for FOREIGN recordings
    /// (and legacy own recordings made before the deterministic-DEK regime).
    /// Own derived recordings are absent from this map — their DEKs are
    /// recomputed via `content_key_for(recording_id)` on every read.
    /// Uses `[u8; 32]` instead of `SymmetricKey` to allow Serialize/Deserialize
    /// (respects M5 no-Serialize invariant on SymmetricKey).
    pub content_keyring: BTreeMap<RecordingId, [u8; 32]>,
    /// Per-recording policy state (e.g. `publishable`). Local-only; gone
    /// after a fresh-restore. Persisted to `recording_metadata.bin`.
    pub(crate) recording_metadata: RecordingMetadataStore,
}

impl Guardian {
    pub fn new(
        vault_path: &str,
        _config: &NodeConfig,
        local_did: Did,
        clock: Arc<dyn TrustedClock>,
        vault_key: SymmetricKey,
        dek_master: DekMaster,
    ) -> Self {
        Self {
            crucible: Crucible::new(RecordingAmalgam, Duration::from_secs(5), 1000),
            vault_path: vault_path.to_string(),
            local_did,
            clock,
            vault_key,
            dek_master,
            ledger: StorageLedger::default(),
            recording_logs: BTreeMap::new(),
            revoked_recordings: HashSet::new(),
            content_keyring: BTreeMap::new(),
            recording_metadata: RecordingMetadataStore::default(),
        }
    }

    /// Returns `true` if the recording exists locally — either committed to
    /// disk (recording_logs) or in-progress reassembly (Crucible contexts).
    pub fn has_recording(&self, recording_id: &RecordingId) -> bool {
        self.recording_logs.contains_key(recording_id)
            || self.crucible.contexts.contains_key(recording_id)
    }

    /// Returns all recording IDs known to this node — completed (on disk),
    /// in-progress reassembly (Crucible contexts), and locally-initiated
    /// recordings (content_keyring entries from StartRecording).
    /// Excludes revoked recordings.
    pub fn list_all_recordings(&self) -> Vec<RecordingId> {
        let mut ids: Vec<RecordingId> = self
            .recording_logs
            .keys()
            .chain(self.crucible.contexts.keys())
            .chain(self.content_keyring.keys())
            .filter(|id| !self.revoked_recordings.contains(id))
            .cloned()
            .collect();
        ids.sort();
        ids.dedup();
        ids
    }

    /// Debug: return shard count + has_key for a recording.
    pub fn debug_recording_info(&self, recording_id: &RecordingId) -> (usize, bool) {
        let shard_count = self
            .recording_logs
            .get(recording_id)
            .map(|log| log.index.len())
            .unwrap_or(0);
        let has_key = self.content_keyring.contains_key(recording_id);
        (shard_count, has_key)
    }

    /// Debug-only: delete a recording's data without cryptographic revocation.
    /// Removes the recording log file, crucible context, and keyring entry.
    /// NOT forensically sound — skips revocation token generation/verification.
    pub async fn debug_delete_recording(
        &mut self,
        recording_id: &RecordingId,
    ) -> Result<(), GuardianError> {
        // Remove recording log (in-memory + disk file)
        if let Some(log) = self.recording_logs.remove(recording_id) {
            if let Err(e) = tokio::fs::remove_file(&log.path).await {
                tracing::warn!(error = %e, "debug_delete: failed to remove recording file");
            }
        }
        // Remove crucible context
        self.crucible.contexts.remove(recording_id);
        // Remove content key
        self.content_keyring.remove(recording_id);
        // Persist updated keyring
        self.persist_keyring().await?;
        tracing::info!(recording = %recording_id, "debug_delete: recording deleted");
        Ok(())
    }

    // ── Content keyring (per-recording DEKs) ──────────────────────────

    /// Derive the deterministic DEK for an OWN recording.
    ///
    /// Pure function of `dek_master` + `recording_id`; no randomness is
    /// consumed and nothing is written to the keyring. Identical inputs
    /// always yield the identical key — that's the property a fresh-
    /// restored device relies on.
    pub fn content_key_for(&self, recording_id: &RecordingId) -> SymmetricKey {
        phalanx_forensics::derive_recording_dek(&self.dek_master, recording_id)
    }

    /// Mint a random DEK for a FOREIGN recording's relay storage and
    /// register it in the keyring.
    ///
    /// We are not the owner of this recording, so we cannot derive its DEK
    /// from our own `dek_master` — the foreign owner's master is unknown to
    /// us. Instead we mint a per-relay random key, persist it locally, and
    /// use it whenever we read or rewrite the recording on this device.
    pub fn mint_foreign_content_key(&mut self, recording_id: &RecordingId) -> SymmetricKey {
        let mut key_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut key_bytes);
        self.content_keyring.insert(recording_id.clone(), key_bytes);
        SymmetricKey::from_bytes(key_bytes)
    }

    /// Retrieve the keyring-resident content key for a recording, if any.
    ///
    /// Hits only legacy own recordings and foreign recordings — own derived
    /// recordings are intentionally absent here.
    pub fn get_content_key(&self, recording_id: &RecordingId) -> Option<SymmetricKey> {
        self.content_keyring
            .get(recording_id)
            .map(|b| SymmetricKey::from_bytes(*b))
    }

    /// Destroy the content key for a recording (crypto-shredding moment).
    /// Zeroizes the keyring entry if present. Returns `true` if a keyring
    /// entry existed; for own derived recordings this returns `false` —
    /// crypto-shredding for those is achieved by deleting the encrypted
    /// blobs (the DEK itself remains derivable until the BIP39 phrase is
    /// destroyed, which is the user's responsibility).
    pub fn destroy_content_key(&mut self, recording_id: &RecordingId) -> bool {
        if let Some(key_bytes) = self.content_keyring.get_mut(recording_id) {
            key_bytes.zeroize();
            self.content_keyring.remove(recording_id);
            true
        } else {
            false
        }
    }

    /// Resolve the encryption key for a recording.
    ///
    /// Lookup chain (in order):
    /// 1. **Keyring hit** — foreign recordings always live here; legacy own
    ///    recordings (made under the random-DEK regime) also live here.
    /// 2. **Derive from dek_master** — own recordings under the deterministic
    ///    regime have no keyring entry; they derive on demand. The invariant
    ///    "own derived recordings are absent from the keyring" makes this
    ///    branch safe to take without an explicit own-vs-foreign signal: if
    ///    we somehow derive for a foreign recording (caller bug), AEAD
    ///    authentication on the wrong key fails cleanly downstream.
    pub fn resolve_encryption_key(&self, recording_id: &RecordingId) -> SymmetricKey {
        if let Some(k) = self.get_content_key(recording_id) {
            return k;
        }
        self.content_key_for(recording_id)
    }

    /// Persist the entire keyring to disk, encrypted with vault_key (KEK).
    pub async fn persist_keyring(&self) -> Result<(), GuardianError> {
        let path = Path::new(&self.vault_path).join("content_keyring.bin");
        let plaintext = postcard::to_allocvec(&self.content_keyring)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;
        atomic_encrypted_write(&path, &plaintext, &self.vault_key).await
    }

    /// Load keyring from disk. Called during bootstrap.
    pub async fn load_keyring(&mut self) -> Result<(), GuardianError> {
        let path = Path::new(&self.vault_path).join("content_keyring.bin");
        if !path.exists() {
            return Ok(());
        }
        let plaintext = read_encrypted_file(&path, &self.vault_key).await?;
        self.content_keyring = postcard::from_bytes(&plaintext)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;
        Ok(())
    }

    // ── Recording metadata (per-recording policy) ──────────────────────

    /// Whether the recording is publishable.
    ///
    /// Recordings without a metadata entry default to `true` — preserving
    /// implicit-publish behaviour for legacy data and for the no-options
    /// `start_recording` path.
    pub fn is_recording_publishable(&self, recording_id: &RecordingId) -> bool {
        self.recording_metadata.is_publishable(recording_id)
    }

    /// Insert (or replace) the policy entry for a recording.
    pub fn set_recording_metadata(
        &mut self,
        recording_id: RecordingId,
        metadata: RecordingMetadata,
    ) {
        self.recording_metadata.insert(recording_id, metadata);
    }

    /// Persist the metadata map to disk, encrypted with vault_key.
    pub async fn persist_recording_metadata(&self) -> Result<(), GuardianError> {
        self.recording_metadata
            .persist(&self.vault_path, &self.vault_key)
            .await
    }

    /// Load the metadata map from disk. Called during bootstrap.
    pub async fn load_recording_metadata(&mut self) -> Result<(), GuardianError> {
        self.recording_metadata
            .load(&self.vault_path, &self.vault_key)
            .await
    }

    // ── Manifest recording ───────────────────────────

    /// The deterministic `RecordingId` of this identity's manifest
    /// recording. Pure function of the held `dek_master`; computed on
    /// demand. A fresh-restored sentinel can derive the same id from the
    /// BIP39 phrase alone.
    pub fn manifest_recording_id(&self) -> RecordingId {
        phalanx_forensics::derive_manifest_recording_id(&self.dek_master)
    }

    /// The `(next_sequence_id, prev_hash)` for an in-progress chain on
    /// the manifest's recording_log.
    ///
    /// Returns `(StorageSequence(1), None)` when the manifest log doesn't
    /// exist yet (first-ever publishable recording). Otherwise reads the
    /// latest shard, decrypts it, and recovers its `signature_hash` so
    /// the next manifest envelope can chain via `prev_hash`. Cheap (~ms)
    /// and avoids any in-memory state-coherence concerns; the storage
    /// actor's single-threaded handler loop guarantees no interleaved
    /// writes.
    ///
    /// Takes `&mut self` because `read_shard` does.
    pub async fn manifest_chain_state(
        &mut self,
    ) -> Result<(StorageSequence, Option<SignatureHash>), GuardianError> {
        use phalanx_forensics::crucible::EnvelopeHashExt;

        let manifest_id = self.manifest_recording_id();
        let last_seq = self
            .recording_logs
            .get(&manifest_id)
            .and_then(|log| log.index.keys().next_back().copied());

        match last_seq {
            None => Ok((StorageSequence(1), None)),
            Some(seq) => {
                let last_envelope = self.read_shard(&manifest_id, seq, None).await?;
                let prev_hash = last_envelope.signature_hash();
                #[allow(clippy::arithmetic_side_effects)]
                // seq.0 is bounded by u32 and we only call this after at
                // least one successful append; overflow at u32::MAX is
                // a non-issue at any realistic capture rate.
                let next_seq = StorageSequence(seq.0 + 1);
                Ok((next_seq, Some(prev_hash)))
            }
        }
    }

    /// Persist the Bayesian PRNU posterior to disk, encrypted with vault_key.
    /// Called periodically from the capture path (every 100 frames) and on
    /// calibration finish. 44 bytes of payload — negligible IO.
    pub async fn persist_prnu_posterior(
        &self,
        posterior: &PrnuPosterior,
    ) -> Result<(), GuardianError> {
        let path = Path::new(&self.vault_path).join("prnu_posterior.bin");
        let plaintext = postcard::to_allocvec(posterior)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;
        atomic_encrypted_write(&path, &plaintext, &self.vault_key).await
    }

    /// Load the Bayesian PRNU posterior from disk. Returns `None` if no
    /// posterior has been persisted yet (cold start → use uninformed prior).
    pub async fn load_prnu_posterior(&self) -> Option<PrnuPosterior> {
        let path = Path::new(&self.vault_path).join("prnu_posterior.bin");
        if !path.exists() {
            return None;
        }
        let plaintext = read_encrypted_file(&path, &self.vault_key).await.ok()?;
        postcard::from_bytes(&plaintext).ok()
    }

    // ── Data promotion ──────────────────────────────────────────────────

    /// The sole entry point for data promotion into the permanent archive.
    pub async fn ingest_envelope(
        &mut self,
        state: EnvelopeState,
        current_tolerance: Duration,
    ) -> Result<(), GuardianError> {
        tracing::debug!("Guardian: Received envelope for ingestion. Verifying...");

        let EnvelopeState::Intact(envelope) = state;
        let vid = envelope.evidence.recording_id().clone();

        // Cryptographic Forgetting: reject shards for revoked recordings.
        if self.revoked_recordings.contains(&vid) {
            return Err(GuardianError::RecordingRevoked(vid.to_string()));
        }
        let seq = envelope.evidence.sequence_id();
        let sender_did = envelope.witness_peer_id.clone();

        // Log the attempt
        tracing::info!(recording = %vid, seq = %seq.0, from = %sender_did, "Guardian: Processing frame");

        let seq = envelope.evidence.sequence_id();
        let recording_id = envelope.evidence.recording_id().clone();
        let mut anchor = None;

        if seq.0 > 1 {
            // Subtraction guarded by seq.0 > 1 check above.
            #[allow(clippy::arithmetic_side_effects)]
            let prev_seq = StorageSequence(seq.0 - 1);

            // Look up the previous anchor in the vault
            if let Some(prev_envelope) = self.get_shard(&recording_id, prev_seq) {
                anchor = Some(prev_envelope.signature_hash());
            }
        }

        // Promotion Gate (Integrity + Continuity + Time)
        let node_id = envelope.witness_peer_id.clone();

        let unit = ForensicUnit::new(envelope);
        // T4 FIX: Pass Duration directly instead of raw u64.
        // Clamp dynamic tolerance to an absolute max of 30 seconds.
        let max_tolerance = Duration::from_secs(30);
        let clamped_tolerance = current_tolerance.min(max_tolerance);

        let verified_unit = unit
            .promote(&node_id, &*self.clock, clamped_tolerance, anchor)
            .map_err(|e| match e {
                ShardError::InvalidConfiguration(ref msg) if msg.contains("Causality Break") => {
                    GuardianError::ChainIntegrityViolation(msg.clone())
                }
                _ => GuardianError::VerificationFailed(e.to_string()),
            })?;

        // Recording Aggregation
        // The Crucible now accepts only Verified units
        let maybe_recording = self.crucible.process(verified_unit)?;

        if let Some(recording) = maybe_recording {
            self.commit_recording_to_disk(&recording).await?;
        }

        // Trigger TTL checks, stale recording flushing, and workbench cleanup
        self.check_and_finalize_recording(current_tolerance).await?;

        Ok(())
    }

    /// Evaluates active working contexts for TTL expiration.
    pub async fn check_and_finalize_recording(
        &mut self,
        current_tolerance: Duration,
    ) -> Result<(), GuardianError> {
        let stale_recordings = self.crucible.flush_stale(current_tolerance);
        for recording in stale_recordings {
            self.commit_recording_to_disk(&recording).await?;
        }
        Ok(())
    }

    pub fn get_shard(
        &self,
        recording_id: &RecordingId,
        sequence_id: StorageSequence,
    ) -> Option<WitnessEnvelope> {
        // We leverage the Crucible's active contexts directly
        self.get_active_recording_shards(recording_id)
            .and_then(|shards| shards.get(&sequence_id))
            .cloned()
    }

    /// Cryptographic Forgetting: destroy all evidence for a recording.
    ///
    /// Crash-safe ordering: persist key destruction to disk FIRST, then delete
    /// data files. If we crash after keyring persist but before data deletion,
    /// the key is gone → ciphertext permanently unreadable (crypto-shredded).
    pub async fn revoke_recording(
        &mut self,
        recording_id: &RecordingId,
    ) -> Result<(), GuardianError> {
        // 1. Crypto-shred: destroy content key and persist to disk FIRST.
        //    After persist_keyring() completes, key is gone from disk atomically.
        let key_destroyed = self.destroy_content_key(recording_id);
        if key_destroyed {
            self.persist_keyring().await?;
            tracing::info!(
                target: "phalanx::vault",
                recording = %recording_id,
                "Content key destroyed (crypto-shredded)"
            );
        }

        // 2. Remove from Crucible (in-memory state)
        self.crucible.contexts.remove(recording_id);

        // 3. Close and delete recording log (defense-in-depth — data already unreadable)
        if let Some(log) = self.recording_logs.remove(recording_id) {
            let path = log.path.clone();
            drop(log);
            // Overwrite with zeros before delete (defense-in-depth)
            if let Ok(metadata) = fs::metadata(&path).await {
                let zeros = vec![0u8; usize::try_from(metadata.len()).unwrap_or(0)];
                let _ = fs::write(&path, &zeros).await;
            }
            let _ = fs::remove_file(&path).await;
            tracing::info!(recording = %recording_id, path = ?path, "Recording log zeroed and deleted");
        }

        // 4. Mark as revoked (blocks future ingestion)
        self.revoked_recordings.insert(recording_id.clone());

        // 5. Drop the policy metadata entry. It's local-only state and no
        //    longer meaningful once the recording is revoked.
        if self.recording_metadata.remove(recording_id).is_some() {
            // Best-effort persist — failure here is non-fatal because the
            // entry only governs local publish behaviour for a recording
            // that has already been crypto-shredded.
            if let Err(e) = self.persist_recording_metadata().await {
                tracing::warn!(
                    target: "phalanx::vault",
                    error = %e,
                    "Failed to persist recording metadata after revocation"
                );
            }
        }

        Ok(())
    }

    /// Explicit salvage command for node termination sequences.
    pub async fn salvage(&mut self) -> Result<Vec<Recording>, GuardianError> {
        // Flush the Crucible to extract all pending reassemblies from memory
        let active_recordings = self.crucible.flush_all();

        // Early return if there's nothing to save (returns an empty Vec)
        if active_recordings.is_empty() {
            return Ok(vec![]);
        }

        // Commit each recording to the permanent silo (The 'Hands' layer)
        // We iterate by reference so we can return the collection at the end
        for recording in &active_recordings {
            self.commit_recording_to_disk(recording).await?;
        }

        // Return the collection to satisfy the return type Result<Vec<Recording>, ...>
        Ok(active_recordings)
    }

    /// Non-blocking Disk Persistence
    pub async fn commit_recording_to_disk(
        &self,
        recording: &Recording,
    ) -> Result<(), GuardianError> {
        // Use `.sealed` extension to avoid overwriting the append-only `.recording`
        // log created by `append_shard()`. The `.recording` file uses frame-based
        // format (plaintext seq_id + payload_len headers) for O(1) random access
        // during playback. This `.sealed` file is a Crucible-finalized snapshot
        // for archival/export — a completely different format (full Recording struct
        // encrypted as a single blob).
        let file_name = format!("{}.sealed", recording.id.to_safe_name());
        let path = std::path::PathBuf::from(&self.vault_path)
            .join(recording.owner_did.to_safe_name())
            .join(file_name);

        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| GuardianError::StorageFailure(e.to_string()))?;
        }

        let data = postcard::to_allocvec(&recording)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;

        atomic_encrypted_write(&path, &data, &self.vault_key).await?;

        info!(path = ?path, "DISK_WRITE_SUCCESS: Recording committed (sealed)");
        Ok(())
    }

    /// Estimates the total bytes held across all active recording contexts in the crucible.
    /// Used by the StorageActor to feed WAL/storage pressure into the integral loop.
    #[allow(clippy::arithmetic_side_effects)] // Byte estimate — multiplication of counts by small constant.
    pub fn wal_bytes_estimate(&self) -> u64 {
        // Conservative per-envelope estimate: signature (64) + evidence (~4KB avg) + metadata
        const AVG_ENVELOPE_BYTES: u64 = 4096;
        self.crucible
            .contexts
            .values()
            .map(|ctx| ctx.accumulator.artifacts.len() as u64 * AVG_ENVELOPE_BYTES)
            .sum()
    }

    pub fn get_active_recording_shards(
        &self,
        recording_id: &RecordingId,
    ) -> Option<&BTreeMap<StorageSequence, WitnessEnvelope>> {
        self.crucible
            .contexts // FIX: Crucible doesn't have .get(), its BTreeMap is 'contexts'
            .get(recording_id) // FIX: No more .to_string()!
            .map(|ctx| &ctx.accumulator.artifacts) // FIX: Access through WorkContext wrapper
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use phalanx_forensics::witness::WitnessAuthority;
    use phalanx_proto::evidence::Evidence;
    use phalanx_proto::evidence::ForensicMetrics;
    use phalanx_proto::evidence::VideoShard;
    use phalanx_proto::time::{SystemClock, TrustedClock};
    use phalanx_proto::types::Fps;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_ingest_envelope_valid() {
        // 1. Setup ephemeral test environment
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let vault_path = temp_dir.path().to_string_lossy().to_string();

        let identity = PhalanxIdentity::new_ephemeral();
        let vault_key = derive_vault_key(&identity, &[0u8; 32]);
        let config = NodeConfig::default();
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key,
            identity.dek_master.clone(),
        );

        // Define a specific RecordingId for this stream
        let vid = RecordingId::new("v1");

        let shard = VideoShard {
            timestamp: SystemClock.now(),
            sequence_id: StorageSequence(1),
            fps: Fps::new(30),
            recording_id: vid.clone(), // Use the RecordingId here
            payload: DataPayload::Clear(vec![1, 2, 3]),
            lens_metrics: ForensicMetrics::default(),
        };

        // Seal the unit (The 4th argument is None for the start of the chain)
        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(shard),
            &identity,
            WitnessId::random(),
            None,
        )
        .expect("WitnessEnvelope construction failed");

        let result = guardian
            .ingest_envelope(EnvelopeState::Intact(envelope), Duration::from_secs(1))
            .await;
        assert!(result.is_ok(), "Ingestion failed: {:?}", result.err());

        // FIX: Verify Crucible state mutation using the RecordingId, NOT the Did
        let active_shards = guardian.get_active_recording_shards(&vid);

        assert!(
            active_shards.is_some(),
            "Crucible should contain an active recording buffer for this RecordingId"
        );

        let shards_map = active_shards.unwrap();
        assert!(
            shards_map.contains_key(&StorageSequence(1)),
            "Recording buffer should contain the ingested sequence ID"
        );
    }

    #[tokio::test]
    async fn test_guardian_ingestion_cycle() {
        let temp_dir = tempdir().expect("Failed to create temporary directory");
        let vault_path = temp_dir.path().to_string_lossy().to_string();

        let identity = PhalanxIdentity::new_ephemeral();
        let vault_key = derive_vault_key(&identity, &[0u8; 32]);
        let config = NodeConfig::default();
        let mut guardian = Guardian::new(
            &vault_path,
            &config,
            identity.did.clone(),
            Arc::new(SystemClock),
            vault_key,
            identity.dek_master.clone(),
        );

        let shard = VideoShard {
            timestamp: SystemClock.now(),
            sequence_id: StorageSequence(1),
            fps: Fps::new(30),
            recording_id: RecordingId::new("v1"),
            payload: DataPayload::Clear(vec![1, 2, 3]),
            lens_metrics: ForensicMetrics::default(),
        };

        // FIX: Add 'None' as the 4th argument (the causality link)
        let envelope = WitnessEnvelope::sign_envelope(
            Evidence::Video(shard),
            &identity,
            WitnessId::random(),
            None,
        )
        .expect("WitnessEnvelope construction failed");

        let result = guardian
            .ingest_envelope(EnvelopeState::Intact(envelope), Duration::from_secs(1))
            .await;

        assert!(result.is_ok());
    }

    // ── StorageLedger Tests ──

    fn test_foreign_did() -> Did {
        Did::new("did:key:z6MkTestForeign")
    }

    #[test]
    fn test_storage_ledger_defaults_to_zero() {
        let ledger = StorageLedger::default();
        assert_eq!(ledger.own_bytes.as_u64(), 0);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 0);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 0);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 0);
        assert_eq!(ledger.total_foreign_bytes(), 0);
        assert_eq!(ledger.total_local_bytes(), 0);
    }

    #[test]
    fn test_storage_ledger_own_ingestion_tracking() {
        let mut ledger = StorageLedger::default();
        ledger.record_own_ingestion(1000);
        assert_eq!(ledger.own_bytes.as_u64(), 1000);
        assert_eq!(ledger.total_local_bytes(), 1000);

        ledger.record_own_ingestion(500);
        assert_eq!(ledger.own_bytes.as_u64(), 1500);
        assert_eq!(
            ledger.total_foreign_bytes(),
            0,
            "Foreign should be unaffected"
        );
    }

    #[test]
    fn test_storage_ledger_foreign_ingestion_is_transient() {
        let mut ledger = StorageLedger::default();
        ledger.record_foreign_ingestion(2000, &test_foreign_did());

        // Foreign ingestion lands in transient first
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 2000);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 0);
        assert_eq!(ledger.total_foreign_bytes(), 2000);
        assert_eq!(ledger.total_local_bytes(), 2000);
    }

    #[test]
    fn test_storage_ledger_promote_transient_to_committed() {
        let mut ledger = StorageLedger::default();
        ledger.record_foreign_ingestion(3000, &test_foreign_did());

        // Promote 1000 bytes to committed (K-replica confirmed)
        ledger.promote_to_committed(1000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 2000);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 1000);
        assert_eq!(
            ledger.total_foreign_bytes(),
            3000,
            "Total foreign unchanged"
        );

        // Promote more than available transient — clamped to available
        ledger.promote_to_committed(5000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 0);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 3000);
    }

    #[test]
    fn test_storage_ledger_own_push_tracking() {
        let mut ledger = StorageLedger::default();
        ledger.record_own_push(500);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 500);
        ledger.record_own_push(300);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 800);
    }

    #[test]
    fn test_storage_ledger_evict_transient() {
        let mut ledger = StorageLedger::default();
        ledger.record_foreign_ingestion(5000, &test_foreign_did());

        ledger.evict_transient(2000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 3000);

        // Evict more than available — saturating subtraction, no underflow
        ledger.evict_transient(10000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 0);
    }

    #[test]
    fn test_storage_ledger_combined_accounting() {
        let mut ledger = StorageLedger::default();

        // Simulate a node that stores own evidence and hosts foreign replicas
        ledger.record_own_ingestion(10_000);
        ledger.record_foreign_ingestion(8_000, &test_foreign_did());
        ledger.promote_to_committed(3_000); // 3K committed, 5K transient
        ledger.record_own_push(6_000);

        assert_eq!(ledger.own_bytes.as_u64(), 10_000);
        assert_eq!(ledger.foreign_committed_bytes.as_u64(), 3_000);
        assert_eq!(ledger.foreign_transient_bytes.as_u64(), 5_000);
        assert_eq!(ledger.own_bytes_pushed.as_u64(), 6_000);
        assert_eq!(ledger.total_foreign_bytes(), 8_000);
        assert_eq!(ledger.total_local_bytes(), 18_000);

        // Evict transient relay buffer
        ledger.evict_transient(5_000);
        assert_eq!(ledger.total_foreign_bytes(), 3_000);
        assert_eq!(ledger.total_local_bytes(), 13_000);
    }

    #[test]
    fn test_storage_ledger_per_owner_tracking() {
        let mut ledger = StorageLedger::default();
        let owner_a = Did::new("did:key:z6MkOwnerA");
        let owner_b = Did::new("did:key:z6MkOwnerB");

        ledger.record_foreign_ingestion(1000, &owner_a);
        ledger.record_foreign_ingestion(2000, &owner_b);
        ledger.record_foreign_ingestion(500, &owner_a);

        assert_eq!(ledger.foreign_bytes_for_owner(&owner_a), 1500);
        assert_eq!(ledger.foreign_bytes_for_owner(&owner_b), 2000);
        assert_eq!(ledger.total_foreign_bytes(), 3500);

        // Unknown owner returns 0
        let owner_c = Did::new("did:key:z6MkOwnerC");
        assert_eq!(ledger.foreign_bytes_for_owner(&owner_c), 0);
    }
}
