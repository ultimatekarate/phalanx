use crate::base::config::PhalanxConfig;
use crate::primitives::identity::Did;
use crate::primitives::time::{TimeError, TrustedClock};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::PathBuf;
use thiserror::Error;
use tracing::{info, warn};

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
    pub added_at: u64,
    pub last_interaction: u64,
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
    /// Initialize the registry, loading from disk if available.
    pub fn new(config: &PhalanxConfig) -> Self {
        let vault = PathBuf::from(&config.storage.vault_path);

        // Ensure the directory exists before trying to access the file
        if !vault.exists() {
            let _ = fs::create_dir_all(&vault);
        }

        let storage_path = vault.join("trust_registry.bin");

        let mut registry = Self {
            contacts: HashMap::new(),
            pet_name_index: HashMap::new(),
            storage_path,
        };

        if let Err(e) = registry.load() {
            warn!(target: "trust", "Failed to load trust registry (starting fresh): {}", e);
        }

        registry
    }

    /// Registers or updates a peer with a specific Trust Level and Alias.
    ///
    /// # Consistency Check
    /// If the alias is already used by *another* DID, this returns an error.
    /// If the alias is used by the *same* DID, it updates the record.
    pub fn set_peer(
        &mut self,
        did: Did,
        pet_name: PetName,
        level: TrustLevel,
        clock: &TrustedClock,
    ) -> Result<(), TrustError> {
        // 1. Check Alias Uniqueness
        if let Some(existing_did) = self.pet_name_index.get(&pet_name) {
            if *existing_did != did {
                return Err(TrustError::PetnameCollision(pet_name.to_string()));
            }
        }

        // 2. Remove old pet name if the user is renaming this DID
        if let Some(old_record) = self.contacts.get(&did) {
            if old_record.pet_name != pet_name {
                self.pet_name_index.remove(&old_record.pet_name);
            }
        }

        // 3. Update Indices - no need to use trusted time here, this is local
        // to the device.
        let timestamp = clock.now()?;

        let original_added_at = self
            .contacts
            .get(&did)
            .map(|record| record.added_at) // Extract existing timestamp
            .unwrap_or(timestamp);

        let record = PeerRecord {
            did: did.clone(),
            pet_name: pet_name.clone(),
            level,
            added_at: original_added_at,
            last_interaction: timestamp,
        };

        self.contacts.insert(did.clone(), record);
        self.pet_name_index.insert(pet_name.clone(), did.clone());

        info!(target: "trust", %did, %pet_name, ?level, "Peer record updated");

        self.save()?;
        Ok(())
    }

    /// Updates the last interaction timestamp.
    ///
    /// # Forensic Safety
    /// This method absorbs clock errors rather than propagating them,
    /// preventing telemetry glitches from crashing the main loop.
    /// Failures are logged as warnings.
    pub fn touch(&mut self, did: &Did, clock: &TrustedClock) {
        // We only proceed if the peer exists
        if let Some(record) = self.contacts.get_mut(did) {
            // Sentinel: Attempt to get time, handle failure gracefully
            match clock.now() {
                Ok(now) => {
                    record.last_interaction = now;

                    // Best-effort save. We log errors but don't panic.
                    if let Err(e) = self.save() {
                        tracing::warn!(
                            target: "trust",
                            did = %did,
                            error = %e,
                            "Failed to persist interaction timestamp"
                        );
                    }
                }
                Err(e) => {
                    // Log the forensic failure (Clock Skew / Poison)
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

    /// Resolves a local pet name (e.g., "Alice") to a global DID.
    /// Returns None if the alias is unknown.
    pub fn resolve_pet_name(&self, pet_name: &PetName) -> Option<&Did> {
        self.pet_name_index.get(pet_name)
    }

    /// Reverse lookup: Get the local alias for a given DID.
    /// Useful for logging: `info!("Message from {}", registry.get_pet_name(did))`
    pub fn get_alias(&self, did: &Did) -> Option<&str> {
        self.contacts.get(did).map(|r| r.pet_name.as_str())
    }

    /// Gets the trust level. Returns `Ignored` (Neutral) for unknown DIDs.
    pub fn check_trust(&self, did: &Did) -> TrustLevel {
        self.contacts
            .get(did)
            .map(|r| r.level)
            .unwrap_or(TrustLevel::Ignored)
    }

    /// Removes a peer from the registry entirely.
    pub fn remove_peer(&mut self, did: &Did) -> Result<(), TrustError> {
        if let Some(record) = self.contacts.remove(did) {
            self.pet_name_index.remove(&record.pet_name);
            self.save()?;
        }
        Ok(())
    }

    // --- Persistence Logic ---

    fn save(&self) -> Result<(), TrustError> {
        // We only serialize `contacts`. `pet_name_index` is rebuilt on load.
        let data = postcard::to_stdvec(&self.contacts)
            .map_err(|e| TrustError::SerializationError(e.to_string()))?;

        // Atomic Write
        let temp_path = self.storage_path.with_extension("tmp");
        let mut file = File::create(&temp_path)?;
        file.write_all(&data)?;
        file.sync_all()?;
        fs::rename(temp_path, &self.storage_path)?;

        Ok(())
    }

    fn load(&mut self) -> Result<(), TrustError> {
        if !self.storage_path.exists() {
            return Ok(());
        }

        let mut file = File::open(&self.storage_path)?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)?;

        let loaded: HashMap<Did, PeerRecord> = postcard::from_bytes(&buffer)
            .map_err(|e| TrustError::SerializationError(e.to_string()))?;

        self.contacts = loaded;

        // Rebuild the Alias Index
        self.pet_name_index.clear();
        for (did, record) in &self.contacts {
            self.pet_name_index
                .insert(record.pet_name.clone(), did.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::PhalanxConfig;
    use crate::primitives::time::TrustedClock;

    #[test]
    fn test_aliasing() {
        let config = PhalanxConfig::test_defaults();
        let mut registry = TrustRegistry::new(&config);

        let did1 = Did::from("did:phx:user_one");
        let did2 = Did::from("did:phx:user_two");

        let pet_name: PetName = PetName::new("Alice").expect("Static string should be valid");
        let big_pet_name: PetName =
            PetName::new("BigAlice").expect("Static string should be valid");
        let clock = TrustedClock::new();
        // Set Alice
        registry
            .set_peer(did1.clone(), pet_name.clone(), TrustLevel::Ally, &clock)
            .unwrap();

        // Resolve Alice
        assert_eq!(registry.resolve_pet_name(&pet_name.clone()), Some(&did1));
        assert_eq!(registry.get_alias(&did1), Some("Alice"));

        // Attempt Collision
        let err = registry.set_peer(did2.clone(), pet_name.clone(), TrustLevel::Ignored, &clock);
        assert!(matches!(err, Err(TrustError::PetnameCollision(_))));

        // Rename Alice -> BigAlice
        registry
            .set_peer(did1.clone(), big_pet_name.clone(), TrustLevel::Ally, &clock)
            .unwrap();
        assert_eq!(
            registry.resolve_pet_name(&big_pet_name.clone()),
            Some(&did1)
        );
        assert_eq!(registry.resolve_pet_name(&pet_name.clone()), None); // Old alias freed
    }
}
