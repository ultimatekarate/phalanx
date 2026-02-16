use crate::primitives::identity::Did;
use crate::base::config::PhalanxConfig;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use tracing::{info, warn, error};
use thiserror::Error;

/// Defines the explicit relationship between the local user and a remote peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustLevel {
    /// Explicitly Banned. All traffic from this peer is dropped immediately.
    Blocked,
    /// Default state. We see them, but treat data with maximum scrutiny.
    Ignored,
    /// Known contact. We accept direct connections and storage requests.
    Verified,
    /// High-trust team member. Prioritized bandwidth and auto-accept grants.
    Ally,
}

impl Default for TrustLevel {
    fn default() -> Self {
        Self::Ignored
    }
}

#[derive(Debug, Error)]
pub enum TrustError {
    #[error("The alias '{0}' is already in use by another DID")]
    AliasCollision(String),
    #[error("Failed to persist registry: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// A single entry in the Trust Registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerRecord {
    pub did: Did,
    /// The local "Pet name" for this user (e.g., "Alice", "HQ-Server").
    /// This is strictly local and never transmitted over the network.
    pub alias: String,
    pub level: TrustLevel,
    pub added_at: u64,
    pub last_interaction: u64,
}

/// Manages the "Social Graph" of the node with bi-directional lookup.
#[derive(Debug)]
pub struct TrustRegistry {
    /// Primary storage: DID -> Record
    contacts: HashMap<Did, PeerRecord>,
    /// Lookup index: Alias -> DID (Ephemeral, rebuilt on load)
    #[serde(skip)]
    alias_index: HashMap<String, Did>,
    
    storage_path: PathBuf,
}

impl TrustRegistry {
    /// Initialize the registry, loading from disk if available.
    pub fn new(config: &PhalanxConfig) -> Self {
        let storage_path = config.data_dir.join("trust_registry.bin");
        
        let mut registry = Self {
            contacts: HashMap::new(),
            alias_index: HashMap::new(),
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
        alias: String, 
        level: TrustLevel
    ) -> Result<(), TrustError> {
        // 1. Check Alias Uniqueness
        if let Some(existing_did) = self.alias_index.get(&alias) {
            if *existing_did != did {
                return Err(TrustError::AliasCollision(alias));
            }
        }

        // 2. Remove old alias if the user is renaming this DID
        if let Some(old_record) = self.contacts.get(&did) {
            if old_record.alias != alias {
                self.alias_index.remove(&old_record.alias);
            }
        }

        // 3. Update Indices
        let timestamp = crate::security::time::TrustedClock::now();
        let record = PeerRecord {
            did: did.clone(),
            alias: alias.clone(),
            level,
            added_at: timestamp,
            last_interaction: timestamp, // Reset interaction on update? Or preserve?
        };

        self.contacts.insert(did.clone(), record);
        self.alias_index.insert(alias.clone(), did.clone());

        info!(target: "trust", %did, %alias, ?level, "Peer record updated");
        
        self.save()?;
        Ok(())
    }

    /// Resolves a local Alias (e.g., "Alice") to a global DID.
    /// Returns None if the alias is unknown.
    pub fn resolve_alias(&self, alias: &str) -> Option<&Did> {
        self.alias_index.get(alias)
    }

    /// Reverse lookup: Get the local alias for a given DID.
    /// Useful for logging: `info!("Message from {}", registry.get_alias(did))`
    pub fn get_alias(&self, did: &Did) -> Option<&str> {
        self.contacts.get(did).map(|r| r.alias.as_str())
    }

    /// Gets the trust level. Returns `Ignored` (Neutral) for unknown DIDs.
    pub fn check_trust(&self, did: &Did) -> TrustLevel {
        self.contacts.get(did).map(|r| r.level).unwrap_or(TrustLevel::Ignored)
    }

    /// Removes a peer from the registry entirely.
    pub fn remove_peer(&mut self, did: &Did) -> Result<(), TrustError> {
        if let Some(record) = self.contacts.remove(did) {
            self.alias_index.remove(&record.alias);
            self.save()?;
        }
        Ok(())
    }

    // --- Persistence Logic ---

    fn save(&self) -> Result<(), TrustError> {
        // We only serialize `contacts`. `alias_index` is rebuilt on load.
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
        self.alias_index.clear();
        for (did, record) in &self.contacts {
            self.alias_index.insert(record.alias.clone(), did.clone());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base::config::PhalanxConfig;

    #[test]
    fn test_aliasing() {
        let config = PhalanxConfig::test_defaults();
        let mut registry = TrustRegistry::new(&config);
        
        let did1 = Did::from("did:phx:user_one");
        let did2 = Did::from("did:phx:user_two");

        // Set Alice
        registry.set_peer(did1.clone(), "Alice".into(), TrustLevel::Ally).unwrap();
        
        // Resolve Alice
        assert_eq!(registry.resolve_alias("Alice"), Some(&did1));
        assert_eq!(registry.get_alias(&did1), Some("Alice"));

        // Attempt Collision
        let err = registry.set_peer(did2.clone(), "Alice".into(), TrustLevel::Ignored);
        assert!(matches!(err, Err(TrustError::AliasCollision(_))));

        // Rename Alice -> BigAlice
        registry.set_peer(did1.clone(), "BigAlice".into(), TrustLevel::Ally).unwrap();
        assert_eq!(registry.resolve_alias("BigAlice"), Some(&did1));
        assert_eq!(registry.resolve_alias("Alice"), None); // Old alias freed
    }
}