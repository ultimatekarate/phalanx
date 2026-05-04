// crates/phalanx-node/src/persistence/vault/metadata.rs
//
// RecordingMetadataStore: per-recording policy state, persisted alongside
// the content keyring. Distinct file from `content_keyring.bin` so that
// policy and key material have independent lifecycles (revocation can
// delete the key but might want to retain a tombstone metadata entry,
// etc.).
//
// On-disk format mirrors the keyring: [24-byte nonce][postcard map],
// encrypted under `vault_key`.
//
// Threat model note: this file lives only on the local device. After a
// fresh-restore (BIP39 phrase only), the metadata file is gone — every
// recovered recording reverts to default policy (`publishable: true`).

use phalanx_proto::crypto::SymmetricKey;
use phalanx_proto::evidence::RecordingMetadata;
use phalanx_proto::identity::RecordingId;
use phalanx_proto::storage::GuardianError;
use std::collections::BTreeMap;
use std::path::Path;

use super::crypto::{atomic_encrypted_write, read_encrypted_file};

const METADATA_FILE_NAME: &str = "recording_metadata.bin";

/// Per-recording policy map. Persisted as `recording_metadata.bin` in the
/// vault dir, encrypted with `vault_key`.
#[derive(Debug, Default)]
pub(crate) struct RecordingMetadataStore {
    map: BTreeMap<RecordingId, RecordingMetadata>,
}

impl RecordingMetadataStore {
    /// Insert or replace the metadata entry for a recording.
    pub fn insert(&mut self, recording_id: RecordingId, metadata: RecordingMetadata) {
        self.map.insert(recording_id, metadata);
    }

    /// Remove the metadata entry for a recording, returning the previous
    /// value if any. Used by `revoke_recording` for cleanup.
    pub fn remove(&mut self, recording_id: &RecordingId) -> Option<RecordingMetadata> {
        self.map.remove(recording_id)
    }

    /// Returns whether the recording is publishable. Recordings without a
    /// metadata entry default to publishable — preserving the historical
    /// implicit-publish behaviour for legacy recordings and for recordings
    /// captured via the no-options API.
    pub fn is_publishable(&self, recording_id: &RecordingId) -> bool {
        self.map
            .get(recording_id)
            .map(|m| m.publishable)
            .unwrap_or(true)
    }

    /// Persist the entire map to disk, encrypted with `vault_key`.
    pub async fn persist(
        &self,
        vault_path: &str,
        vault_key: &SymmetricKey,
    ) -> Result<(), GuardianError> {
        let path = Path::new(vault_path).join(METADATA_FILE_NAME);
        let plaintext = postcard::to_allocvec(&self.map)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;
        atomic_encrypted_write(&path, &plaintext, vault_key).await
    }

    /// Load the map from disk. Absent file → empty map (legacy vaults that
    /// pre-date the metadata file). Decryption / deserialization failures
    /// propagate so the caller can decide: today they log and continue
    /// with the empty map, matching the keyring loader's behaviour.
    pub async fn load(
        &mut self,
        vault_path: &str,
        vault_key: &SymmetricKey,
    ) -> Result<(), GuardianError> {
        let path = Path::new(vault_path).join(METADATA_FILE_NAME);
        if !path.exists() {
            return Ok(());
        }
        let plaintext = read_encrypted_file(&path, vault_key).await?;
        self.map = postcard::from_bytes(&plaintext)
            .map_err(|e| GuardianError::SerializationError(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use phalanx_proto::evidence::{RecordingOptions, RECORDING_METADATA_VERSION};
    use phalanx_proto::identity::PhalanxIdentity;
    use tempfile::tempdir;

    fn dummy_vault_key() -> SymmetricKey {
        let identity = PhalanxIdentity::new_ephemeral();
        super::super::crypto::derive_vault_key(&identity, &[0u8; 32])
    }

    #[test]
    fn defaults_to_publishable_when_absent() {
        let store = RecordingMetadataStore::default();
        let rid = RecordingId::new("ghost");
        assert!(store.is_publishable(&rid));
    }

    #[test]
    fn explicit_unpublishable_is_observed() {
        let mut store = RecordingMetadataStore::default();
        let rid = RecordingId::new("private");
        store.insert(
            rid.clone(),
            RecordingOptions { publishable: false }.into_metadata(),
        );
        assert!(!store.is_publishable(&rid));
    }

    #[tokio::test]
    async fn persist_round_trips_through_disk() {
        let temp = tempdir().unwrap();
        let vault_path = temp.path().to_string_lossy().into_owned();
        let key = dummy_vault_key();

        let mut store = RecordingMetadataStore::default();
        store.insert(
            RecordingId::new("public"),
            RecordingOptions::default().into_metadata(),
        );
        store.insert(
            RecordingId::new("private"),
            RecordingOptions { publishable: false }.into_metadata(),
        );
        store.persist(&vault_path, &key).await.unwrap();

        let mut loaded = RecordingMetadataStore::default();
        loaded.load(&vault_path, &key).await.unwrap();
        assert!(loaded.is_publishable(&RecordingId::new("public")));
        assert!(!loaded.is_publishable(&RecordingId::new("private")));

        // Schema version is pinned by RecordingOptions::into_metadata.
        let pinned = RecordingOptions::default().into_metadata();
        assert_eq!(pinned.schema_version, RECORDING_METADATA_VERSION);
    }

    #[tokio::test]
    async fn missing_file_loads_as_empty_map() {
        let temp = tempdir().unwrap();
        let vault_path = temp.path().to_string_lossy().into_owned();
        let key = dummy_vault_key();
        let mut store = RecordingMetadataStore::default();
        // No persist call — file doesn't exist.
        store.load(&vault_path, &key).await.unwrap();
        assert!(store.is_publishable(&RecordingId::new("anything")));
    }
}
