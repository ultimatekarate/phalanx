use crate::clock::TrustedClock;
use crate::NodeConfig;
use phalanx_forensics::trust::{PeerEvaluator, ReputationGate};
use phalanx_proto::prelude::*;
use phalanx_proto::trust::MonotonicClock;
use phalanx_proto::trust::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub trait ClockProvider {
    fn current_monotonic(&self) -> MonotonicClock;
}

/// Real-world implementation for the node.
pub struct SystemClock;

impl ClockProvider for SystemClock {
    fn current_monotonic(&self) -> MonotonicClock {
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time moved backwards")
            .as_secs();
        MonotonicClock(start)
    }
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
    pub async fn build(config: &NodeConfig) -> Self {
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
        let data = postcard::to_allocvec(&self.contacts)
            .map_err(|e| TrustError::SerializationError(e.to_string()))?;

        let temp_path = self.storage_path.with_extension("tmp");

        // Asynchronous file operations
        let mut file = File::create(&temp_path)
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))?;
        file.write_all(&data)
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))?;
        file.sync_all()
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))?; // Ensures OS buffers are flushed to disk
        fs::rename(temp_path, &self.storage_path)
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))?;

        Ok(())
    }

    /// Performs a non-blocking read from disk on initialization.
    async fn load(&mut self) -> Result<(), TrustError> {
        if !fs::try_exists(&self.storage_path).await.unwrap_or(false) {
            return Ok(());
        }

        let mut file = File::open(&self.storage_path)
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))?;
        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer)
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))?;

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
                Offense::QuotaExceeded => {
                    record.reputation.quota_violations =
                        record.reputation.quota_violations.saturating_add(1);

                    if record.reputation.quota_violations >= 5 {
                        record.reputation.is_blacklisted = true;
                        needs_save = true;
                        tracing::warn!(%did, "PEER BLACKLISTED: Quota failure threshold exceeded (Vampire Attack).");
                    } else {
                        tracing::debug!(%did, ?offense, "Peer quota offense recorded.");
                    }
                }
                Offense::MalformedPacket => {
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

    /// Inserts a new peer into the registry, failing if the peer already exists.
    ///
    /// # Errors
    ///
    /// Returns `TrustError::PeerAlreadyExists` if the `did` is already tracked,
    /// or `TrustError::PetnameCollision` if the `pet_name` is in use by another peer.
    pub async fn insert_peer(
        &mut self,
        did: &Did,
        pet_name: &PetName,
        level: TrustLevel,
        clock: &TrustedClock,
    ) -> Result<(), TrustError> {
        if self.contacts.contains_key(did) {
            return Err(TrustError::PeerAlreadyExists(did.clone()));
        }

        if self.pet_name_index.contains_key(pet_name) {
            return Err(TrustError::PetnameCollision(pet_name.to_string()));
        }

        let timestamp = clock.now()?;
        let record = PeerRecord {
            did: did.clone(),
            pet_name: pet_name.clone(),
            level,
            added_at: timestamp,
            last_interaction: timestamp,
            reputation: PeerReputation::default(),
        };

        self.contacts.insert(did.clone(), record);
        self.pet_name_index.insert(pet_name.clone(), did.clone());

        self.save().await
    }
}

impl PeerEvaluator for TrustRegistry {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32 {
        // Deterministic Identity Resolution
        // Converts the base58 PeerId string into a standard did:key format
        let deterministic_did_str = format!("did:key:{}", peer_id);
        let target_did = Did::from(deterministic_did_str);

        let record = match self.contacts.get(&target_did) {
            Some(r) => r,
            None => return 1.0, // Baseline neutral reputation for untracked peers
        };

        if record.reputation.is_blacklisted {
            return 0.0; // Guaranteed eviction/rejection
        }

        // Heuristic Scoring Algorithm
        let mut score: f32 = 1.0;

        // Severe penalty for cryptographic failures (20% reduction per offense)
        score -= (record.reputation.invalid_sigs as f32) * 0.20;

        // Moderate penalty for resource exhaustion attempts (10% reduction per offense)
        score -= (record.reputation.quota_violations as f32) * 0.10;

        // Ensure score remains within mathematical bounds.
        // A minimum of 0.1 distinguishes severely degraded peers from fully blacklisted (0.0) peers.
        score.clamp(0.1, 1.0)
    }
}

impl ReputationGate for TrustRegistry {
    fn is_blacklisted(&self, did: &Did) -> bool {
        self.contacts
            .get(did)
            .is_some_and(|r| r.reputation.is_blacklisted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_aliasing() {
        let config = NodeConfig::test_defaults();
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
