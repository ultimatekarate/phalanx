use crate::base::config::PhalanxConfig;
use crate::primitives::identity::Did;
use crate::primitives::time::{PhalanxTimestamp, TimeError, TrustedClock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{info, warn};

/// Tracks the real-time behavior and security metrics of remote peers.
/// Centralized to prevent split-brain logic between transient and persistent layers.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PeerReputation {
    pub invalid_sigs: u32,
    pub total_shards_sent: u64,
    pub active_buffers: usize,
    pub last_seen_load: f32,
    pub is_blacklisted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offense {
    InvalidSignature,
    ReplayAttack,
    QuotaExceeded,
    MalformedPacket,
}

/// A user-defined local identifier for a DID (Pet name).
///
/// Constraints:
/// - Max length: 64 chars
/// - No control characters
/// - Cannot be empty
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PetName(String);

impl PetName {
    #[allow(clippy::missing_errors_doc)]
    pub fn new(s: impl Into<String>) -> Result<Self, TrustError> {
        let s = s.into();
        if s.trim().is_empty() {
            return Err(TrustError::InvalidPetName(
                "Pet name cannot be empty".into(),
            ));
        }
        if s.len() > 64 {
            return Err(TrustError::InvalidPetName(
                "Pet name too long (max 64)".into(),
            ));
        }
        if s.chars().any(|c| c.is_control()) {
            return Err(TrustError::InvalidPetName(
                "Pet name contains control characters".into(),
            ));
        }
        Ok(Self(s))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Defines the explicit relationship between the local user and a remote peer.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Explicitly Banned. All traffic from this peer is dropped immediately.
    Blocked,
    /// Default state. We see them, but treat data with maximum scrutiny.
    #[default]
    Ignored,
    /// Known contact. We accept direct connections and storage requests.
    Verified,
    /// High-trust team member. Prioritized bandwidth and auto-accept grants.
    Ally,
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("The pet name '{0}' is already in use by another DID")]
    PetnameCollision(String),
    #[error("Failed to persist registry: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid Pet name format: {0}")]
    InvalidPetName(String),
    #[error("Trusted clock failure: {0}")]
    TimeSource(#[from] TimeError),
}

/// A single entry in the Trust Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub did: Did,
    /// The local "Pet name" for this user (e.g., "Alice", "HQ-Server").
    /// This is strictly local and never transmitted over the network.
    pub pet_name: PetName,
    pub level: TrustLevel,
    pub added_at: PhalanxTimestamp,
    pub last_interaction: PhalanxTimestamp,
    pub reputation: PeerReputation,
}

/// Manages the "Social Graph" of the node with bi-directional lookup.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustRegistry {
    /// Primary storage: DID -> Record
    contacts: HashMap<Did, PeerRecord>,
    /// Lookup index: Alias -> DID (Ephemeral, rebuilt on load)
    #[serde(skip)]
    pet_name_index: HashMap<PetName, Did>,

    storage_path: PathBuf,
}

impl TrustRegistry {
    /// Asynchronous initialization to prevent blocking the executor on node startup.
    pub async fn build(config: &PhalanxConfig) -> Self {
        let vault = PathBuf::from(&config.storage.vault_path);

        // Non-blocking directory verification
        if !fs::try_exists(&vault).await.unwrap_or(false) {
            let _ = fs::create_dir_all(&vault).await;
        }

        let storage_path = vault.join("trust_registry.bin");

        let mut registry = Self {
            contacts: HashMap::new(),
            pet_name_index: HashMap::new(),
            storage_path,
        };

        if let Err(e) = registry.load().await {
            warn!(target: "trust", "Failed to load trust registry (starting fresh): {}", e);
        }

        registry
    }

    #[allow(clippy::missing_errors_doc)]
    pub async fn set_peer(
        &mut self,
        did: &Did,
        pet_name: &PetName,
        level: TrustLevel,
        clock: &TrustedClock,
    ) -> Result<(), TrustError> {
        if let Some(existing_did) = self.pet_name_index.get(pet_name) {
            if *existing_did != *did {
                return Err(TrustError::PetnameCollision(pet_name.to_string()));
            }
        }

        let mut existing_reputation = PeerReputation::default();

        if let Some(old_record) = self.contacts.get(did) {
            existing_reputation = old_record.reputation.clone();
            if old_record.pet_name != *pet_name {
                self.pet_name_index.remove(&old_record.pet_name);
            }
        }

        let timestamp = clock.now()?;

        let original_added_at = self
            .contacts
            .get(did)
            .map_or(timestamp, |record| record.added_at);

        let record = PeerRecord {
            did: did.clone(),
            pet_name: pet_name.clone(),
            level,
            added_at: original_added_at,
            last_interaction: timestamp,
            reputation: existing_reputation,
        };

        self.contacts.insert(did.clone(), record);
        self.pet_name_index.insert(pet_name.clone(), did.clone());

        info!(target: "trust", %did, %pet_name, ?level, "Peer record updated");

        self.save().await?;
        Ok(())
    }

    /// Updates the last interaction timestamp. Must be awaited.
    pub async fn touch(&mut self, did: &Did, clock: &TrustedClock) {
        if let Some(record) = self.contacts.get_mut(did) {
            match clock.now() {
                Ok(now) => {
                    record.last_interaction = now;
                    if let Err(e) = self.save().await {
                        tracing::warn!(
                            target: "trust",
                            did = %did,
                            error = %e,
                            "Failed to persist interaction timestamp asynchronously"
                        );
                    }
                }
                Err(e) => {
                    tracing::error!(
                        target: "trust",
                        did = %did,
                        error = %e,
                        "Touch failed: Trusted Clock is compromised or drifting"
                    );
                }
            }
        }
    }

    pub async fn remove_peer(&mut self, did: &Did) -> Result<(), TrustError> {
        if let Some(record) = self.contacts.remove(did) {
            self.pet_name_index.remove(&record.pet_name);
            self.save().await?;
        }
        Ok(())
    }

    /// Performs a non-blocking write to the WAL/storage path.
    async fn save(&self) -> Result<(), TrustError> {
        let data = postcard::to_stdvec(&self.contacts)
            .map_err(|e| TrustError::SerializationError(e.to_string()))?;

        let temp_path = self.storage_path.with_extension("tmp");

        // Asynchronous file operations
        let mut file = File::create(&temp_path).await?;
        file.write_all(&data).await?;
        file.sync_all().await?; // Ensures OS buffers are flushed to disk
        fs::rename(temp_path, &self.storage_path).await?;

        Ok(())
    }

    /// Performs a non-blocking read from disk on initialization.
    async fn load(&mut self) -> Result<(), TrustError> {
        if !fs::try_exists(&self.storage_path).await.unwrap_or(false) {
            return Ok(());
        }

        let mut file = File::open(&self.storage_path).await?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        let loaded: HashMap<Did, PeerRecord> = postcard::from_bytes(&buffer)
            .map_err(|e| TrustError::SerializationError(e.to_string()))?;

        self.contacts = loaded;

        self.pet_name_index.clear();
        for (did, record) in &self.contacts {
            self.pet_name_index
                .insert(record.pet_name.clone(), did.clone());
        }

        Ok(())
    }

    pub async fn record_offense(&mut self, did: &Did, offense: Offense, clock: &TrustedClock) {
        // Ensure the peer is tracked in the registry. If unknown, register as Ignored.
        if !self.contacts.contains_key(did) {
            let base_name = format!(
                "Unknown-{}",
                did.as_str().chars().take(8).collect::<String>()
            );
            let mut fallback_name = base_name.clone();
            let mut counter = 1;

            let mut pet_name =
                PetName::new(&fallback_name).unwrap_or_else(|_| PetName::new("Unknown").unwrap());

            // Deterministic collision resolution: Append suffix until unique
            while self.pet_name_index.contains_key(&pet_name) {
                fallback_name = format!("{}-{}", base_name, counter);
                pet_name = PetName::new(&fallback_name)
                    .unwrap_or_else(|_| PetName::new("Unknown").unwrap());
                counter += 1;
            }

            if let Err(e) = self
                .set_peer(did, &pet_name, TrustLevel::Ignored, clock)
                .await
            {
                tracing::error!(%did, error = %e, "Failed to register unknown offender");
                return;
            }
        }

        let mut needs_save = false;

        if let Some(record) = self.contacts.get_mut(did) {
            if record.reputation.is_blacklisted {
                return; // Already penalized
            }

            match offense {
                Offense::InvalidSignature => {
                    record.reputation.invalid_sigs =
                        record.reputation.invalid_sigs.saturating_add(1);

                    if record.reputation.invalid_sigs >= 5 {
                        record.reputation.is_blacklisted = true;
                        needs_save = true;
                        tracing::warn!(%did, "PEER BLACKLISTED: Cryptographic failure threshold exceeded.");
                    }
                }
                Offense::ReplayAttack => {
                    record.reputation.is_blacklisted = true;
                    needs_save = true;
                    tracing::warn!(%did, "PEER BLACKLISTED: Replay attack detected.");
                }
                Offense::QuotaExceeded | Offense::MalformedPacket => {
                    tracing::debug!(%did, ?offense, "Minor peer offense recorded.");
                }
            }
        }

        // Immediately persist critical state changes to disk
        if needs_save {
            if let Err(e) = self.save().await {
                tracing::error!(%did, error = %e, "Failed to persist blacklist status to disk");
            }
        }
    }

    #[must_use]
    pub fn resolve_pet_name(&self, pet_name: &PetName) -> Option<&Did> {
        self.pet_name_index.get(pet_name)
    }

    #[must_use]
    pub fn get_alias(&self, did: &Did) -> Option<&str> {
        self.contacts.get(did).map(|r| r.pet_name.as_str())
    }

    #[must_use]
    pub fn check_trust(&self, did: &Did) -> TrustLevel {
        self.contacts
            .get(did)
            .map_or(TrustLevel::Ignored, |r| r.level)
    }

    /// Retrieves a mutable reference to a peer's reputation state.
    pub fn get_reputation_mut(&mut self, did: &Did) -> Option<&mut PeerReputation> {
        self.contacts
            .get_mut(did)
            .map(|record| &mut record.reputation)
    }
}

/// Dependency Inversion boundary.
/// Allows any component to verify peer standing without knowing internal registry logic.
pub trait ReputationGate {
    fn is_blacklisted(&self, did: &Did) -> bool;
}

impl ReputationGate for TrustRegistry {
    fn is_blacklisted(&self, did: &Did) -> bool {
        self.contacts
            .get(did)
            .is_some_and(|record| record.reputation.is_blacklisted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::PhalanxConfig;
    use crate::primitives::time::TrustedClock;

    #[tokio::test]
    async fn test_aliasing() {
        let config = PhalanxConfig::test_defaults();
        let mut registry = TrustRegistry::build(&config).await;

        let did1 = Did::from("did:phx:user_one");
        let did2 = Did::from("did:phx:user_two");

        let pet_name: PetName = PetName::new("Alice").expect("Static string should be valid");
        let big_pet_name: PetName =
            PetName::new("BigAlice").expect("Static string should be valid");
        let clock = TrustedClock::new();

        registry
            .set_peer(&did1.clone(), &pet_name.clone(), TrustLevel::Ally, &clock)
            .await
            .unwrap();

        assert_eq!(registry.resolve_pet_name(&pet_name.clone()), Some(&did1));
        assert_eq!(registry.get_alias(&did1), Some("Alice"));

        let err = registry
            .set_peer(
                &did2.clone(),
                &pet_name.clone(),
                TrustLevel::Ignored,
                &clock,
            )
            .await;

        assert!(matches!(err, Err(TrustError::PetnameCollision(_))));

        registry
            .set_peer(
                &did1.clone(),
                &big_pet_name.clone(),
                TrustLevel::Ally,
                &clock,
            )
            .await
            .unwrap();

        assert_eq!(
            registry.resolve_pet_name(&big_pet_name.clone()),
            Some(&did1)
        );
        assert_eq!(registry.resolve_pet_name(&pet_name.clone()), None);
    }
}
