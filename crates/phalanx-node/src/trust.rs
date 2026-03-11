use crate::clock::TrustedClock;
use crate::NodeConfig;
use phalanx_forensics::trust::{PeerEvaluator, ReputationGate};
use phalanx_proto::prelude::*;
use phalanx_proto::trust::MonotonicClock;
use phalanx_proto::trust::TrustRegistry as ProtoTrustRegistry;
use phalanx_proto::trust::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use phalanx_proto::prelude::NetworkId;
use std::sync::{Arc, RwLock as StdRwLock};

#[derive(Clone, Default, Debug)]
pub struct PeerReputationInfo {
    pub score: f32,
    pub is_blacklisted: bool,
    pub trust_level: TrustLevel,
}

#[derive(Clone, Default, Debug)]
pub struct ReputationProjection {
    scores: Arc<StdRwLock<HashMap<NetworkId, PeerReputationInfo>>>,
    did_to_network_id: Arc<StdRwLock<HashMap<Did, NetworkId>>>,
}

pub trait TrustOracle: Send + Sync {
    fn is_blacklisted_by_did(&self, did: &Did) -> bool;
    fn check_trust_by_did(&self, did: &Did) -> TrustLevel;
}

impl TrustOracle for ReputationProjection {
    fn is_blacklisted_by_did(&self, did: &Did) -> bool {
        let did_map = self.did_to_network_id.read().unwrap();
        if let Some(network_id) = did_map.get(did) {
            let scores_map = self.scores.read().unwrap();
            if let Some(info) = scores_map.get(network_id) {
                return info.is_blacklisted;
            }
        }
        false
    }

    fn check_trust_by_did(&self, did: &Did) -> TrustLevel {
        let did_map = self.did_to_network_id.read().unwrap();
        if let Some(network_id) = did_map.get(did) {
            let scores_map = self.scores.read().unwrap();
            scores_map
                .get(network_id)
                .map_or(TrustLevel::Ignored, |info| info.trust_level)
        } else {
            TrustLevel::Ignored
        }
    }
}

impl PeerEvaluator for ReputationProjection {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32 {
        self.scores
            .read()
            .unwrap()
            .get(peer_id)
            .map_or(1.0, |info| info.score)
    }
}

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

impl ClockProvider for TrustedClock {
    fn current_monotonic(&self) -> MonotonicClock {
        let millis = self.now().unwrap_or_default().0;
        MonotonicClock(millis / 1000)
    }
}

/// Manages the "Social Graph" of the node with bi-directional lookup.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustRegistry {
    #[serde(flatten)]
    pub core: ProtoTrustRegistry,
    /// Lookup index: Alias -> DID (Ephemeral, rebuilt on load)
    #[serde(skip)]
    pet_name_index: HashMap<PetName, Did>,
    #[serde(skip)]
    pub live_projection: ReputationProjection,
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
            core: ProtoTrustRegistry::default(),
            pet_name_index: HashMap::new(),
            live_projection: ReputationProjection::default(),
            storage_path,
        };

        if let Err(e) = registry.load().await {
            tracing::warn!(target: "trust", "Failed to load trust registry (starting fresh): {}", e);
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

        if let Some(old_record) = self.core.peers.get(did) {
            existing_reputation = old_record.reputation.clone();
            if let Some(old_name) = &old_record.pet_name {
                if old_name != pet_name {
                    self.pet_name_index.remove(old_name);
                }
            }
        }

        if level == TrustLevel::Blocked {
            existing_reputation.is_blacklisted = true;
        }

        let timestamp = clock.now()?;

        let original_added_at = self
            .core
            .peers
            .get(did)
            .map_or(timestamp, |record| record.added_at);

        let record = PeerRecord {
            did: did.clone(),
            pet_name: Some(pet_name.clone()),
            level,
            added_at: original_added_at,
            last_interaction: timestamp,
            reputation: existing_reputation,
        };

        self.core.peers.insert(did.clone(), record);
        self.pet_name_index.insert(pet_name.clone(), did.clone());

        tracing::info!(target: "trust", %did, %pet_name, ?level, "Peer record updated");

        self.save()
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))?;
        Ok(())
    }

    pub fn projection_handle(&self) -> ReputationProjection {
        self.live_projection.clone()
    }

    fn sync_projection_for(projection: &ReputationProjection, did: &Did, record: &PeerRecord) {
        let network_id_str = did.as_str().replace("did:key:", "");
        let network_id = NetworkId::from(network_id_str);

        let score_normalized = if record.reputation.is_blacklisted {
            0.0
        } else {
            ((record.reputation.score as f32) / 100.0).clamp(0.1, 1.0)
        };

        let info = PeerReputationInfo {
            score: score_normalized,
            is_blacklisted: record.reputation.is_blacklisted,
            trust_level: record.level,
        };

        projection
            .scores
            .write()
            .unwrap()
            .insert(network_id.clone(), info);

        projection
            .did_to_network_id
            .write()
            .unwrap()
            .insert(did.clone(), network_id);
    }

    /// Updates the last interaction timestamp. Must be awaited.
    pub async fn touch(&mut self, did: &Did, clock: &TrustedClock) {
        if let Some(record) = self.core.peers.get_mut(did) {
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
        if let Some(record) = self.core.peers.remove(did) {
            if let Some(ref pet_name) = record.pet_name {
                self.pet_name_index.remove(pet_name);
            }
            self.save()
                .await
                .map_err(|e| TrustError::IoError(e.to_string()))?;
        }
        Ok(())
    }

    pub async fn record_offense<C: ClockProvider>(
        &mut self,
        did: &Did,
        offense: Offense,
        clock: &C,
    ) {
        let mut requires_save = false;
        tracing::debug!(
            target: "phalanx::trust",
            offender_did = %did,
            offense_type = ?offense,
            "PENALTY_ATTEMPTED"
        );
        // LAZY REGISTRATION: Never ignore a forensic offense, even from unknown peers
        if !self.core.peers.contains_key(did) {
            tracing::info!(
                target: "phalanx::trust",
                offender_did = %did,
                "LAZY_REGISTRATION_TRIGGERED"
            );

            let pet_name = self.generate_unique_pet_name(did);
            let timestamp = PhalanxTimestamp(clock.current_monotonic().0 * 1000);

            let record = PeerRecord {
                did: did.clone(),
                pet_name: Some(pet_name.clone()),
                level: TrustLevel::Ignored, // Untrusted baseline
                added_at: timestamp,
                last_interaction: timestamp,
                reputation: PeerReputation::default(),
            };
            self.core.peers.insert(did.clone(), record);
            self.pet_name_index.insert(pet_name, did.clone());
        }

        if let Some(record) = self.core.peers.get_mut(did) {
            let old_score = record.reputation.score;
            let penalty = match offense {
                Offense::QuotaExceeded => 25,
                // Assuming forensic violations trigger fatal penalties
                Offense::InvalidSignature | Offense::IdentityTheft => 101,
                _ => 10,
            };

            record.reputation.score = record.reputation.score.saturating_sub(penalty);

            tracing::info!(
                target: "phalanx::trust",
                offender_did = %did,
                from_score = old_score,
                to_score = record.reputation.score,
                penalty_applied = penalty,
                "REPUTATION_DEGRADED"
            );

            if record.reputation.score <= 0 || penalty > 100 {
                record.reputation.is_blacklisted = true;
                tracing::warn!(
                    target: "phalanx::trust",
                    offender_did = %did,
                    "PEER_BLACKLISTED"
                );
            }

            let now = clock.current_monotonic();
            record.last_interaction = PhalanxTimestamp(now.0 * 1000);

            // SYNC STATE: Update the read-only projection synchronously
            Self::sync_projection_for(&self.live_projection, did, record);

            requires_save = true;
        }

        if requires_save {
            if let Err(e) = self.save().await {
                tracing::error!(target: "trust", "Failed to persist trust registry after offense: {}", e);
            }
        }
    }

    /// Helper to flush the current state to NVMe/Disk.
    pub async fn save(&self) -> Result<(), std::io::Error> {
        let bytes = postcard::to_allocvec(&self.core)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut file = File::create(&self.storage_path).await?;
        file.write_all(&bytes).await?;
        file.flush().await?;

        Ok(())
    }

    /// Performs a non-blocking read from disk on initialization.
    pub async fn load(&mut self) -> Result<(), std::io::Error> {
        let mut file = match File::open(&self.storage_path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };

        let mut buffer = Vec::new();
        file.read_to_end(&mut buffer).await?;

        if buffer.is_empty() {
            return Ok(());
        }

        // Deserialize using postcard (as per standard project stack)
        let loaded_core: ProtoTrustRegistry = postcard::from_bytes(&buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        self.core = loaded_core;

        // Clear and rebuild ephemeral state
        self.pet_name_index.clear();

        for (did, record) in &self.core.peers {
            if let Some(alias) = &record.pet_name {
                self.pet_name_index.insert(alias.clone(), did.clone());
            }

            // WARM THE CACHE: Synchronous lock acquired and released here.
            // No .await points exist inside this loop.
            Self::sync_projection_for(&self.live_projection, did, record);
        }

        Ok(())
    }

    #[must_use]
    pub fn resolve_pet_name(&self, pet_name: &PetName) -> Option<&Did> {
        self.pet_name_index.get(pet_name)
    }

    #[must_use]
    pub fn get_alias(&self, did: &Did) -> Option<&str> {
        self.core
            .peers
            .get(did)
            .and_then(|r| r.pet_name.as_ref().map(|n| n.as_str()))
    }

    #[must_use]
    pub fn check_trust(&self, did: &Did) -> TrustLevel {
        self.core
            .peers
            .get(did)
            .map_or(TrustLevel::Ignored, |r| r.level)
    }

    /// Retrieves a mutable reference to a peer's reputation state.
    pub fn get_reputation_mut(&mut self, did: &Did) -> Option<&mut PeerReputation> {
        self.core
            .peers
            .get_mut(did)
            .map(|record| &mut record.reputation)
    }

    fn generate_unique_pet_name(&self, did: &Did) -> PetName {
        let base_name = format!(
            "Unknown-{}",
            did.as_str().chars().take(8).collect::<String>()
        );
        let mut fallback_name = base_name.clone();
        let mut counter = 1;

        let mut pet_name =
            PetName::new(&fallback_name).unwrap_or_else(|_| PetName::new("Unknown").unwrap());

        while self.pet_name_index.contains_key(&pet_name) {
            fallback_name = format!("{}-{}", base_name, counter);
            pet_name =
                PetName::new(&fallback_name).unwrap_or_else(|_| PetName::new("Unknown").unwrap());
            counter += 1;
        }
        pet_name
    }

    pub async fn register_peer(
        &mut self,
        did: &Did,
        level: TrustLevel,
        clock: &TrustedClock,
    ) -> Result<(), TrustError> {
        let pet_name = self.generate_unique_pet_name(did);
        self.insert_peer(did, &pet_name, level, clock).await
    }

    pub async fn assign_pet_name(
        &mut self,
        did: &Did,
        pet_name: PetName,
    ) -> Result<(), TrustError> {
        if let Some(existing_did) = self.pet_name_index.get(&pet_name) {
            if existing_did != did {
                return Err(TrustError::PetnameCollision(pet_name.to_string()));
            }
        }

        let record = self
            .core
            .peers
            .get_mut(did)
            .ok_or_else(|| TrustError::PeerNotFound(did.clone()))?;

        if let Some(old_name) = &record.pet_name {
            self.pet_name_index.remove(old_name);
        }
        record.pet_name = Some(pet_name.clone());
        self.pet_name_index.insert(pet_name, did.clone());

        self.save()
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))
    }

    pub fn is_blacklisted(&self, did: &Did) -> bool {
        self.core
            .peers
            .get(did)
            .map_or(false, |record| record.reputation.is_blacklisted)
    }

    /// Checks if a network-level ID is blacklisted by resolving it to a DID.
    #[must_use]
    pub fn is_network_id_blacklisted(&self, network_id: &NetworkId) -> bool {
        // Resolve PeerId string into standard did:key format for lookup
        let deterministic_did_str = format!("did:key:{}", network_id);
        let target_did = Did::from(deterministic_did_str);

        self.is_blacklisted(&target_did)
    }

    pub async fn insert_peer(
        &mut self,
        did: &Did,
        pet_name: &PetName,
        level: TrustLevel,
        clock: &TrustedClock,
    ) -> Result<(), TrustError> {
        if self.core.peers.contains_key(did) {
            return Err(TrustError::PeerAlreadyExists(did.clone()));
        }

        if self.pet_name_index.contains_key(pet_name) {
            return Err(TrustError::PetnameCollision(pet_name.to_string()));
        }

        let timestamp = clock.now()?;
        let record = PeerRecord {
            did: did.clone(),
            pet_name: Some(pet_name.clone()),
            level,
            added_at: timestamp,
            last_interaction: timestamp,
            reputation: PeerReputation::default(),
        };

        self.core.peers.insert(did.clone(), record);
        self.pet_name_index.insert(pet_name.clone(), did.clone());

        self.save()
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))
    }
}

impl PeerEvaluator for TrustRegistry {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32 {
        // Deterministic Identity Resolution
        // Converts the base58 PeerId string into a standard did:key format
        let deterministic_did_str = format!("did:key:{}", peer_id);
        let target_did = Did::from(deterministic_did_str);

        let record = match self.core.peers.get(&target_did) {
            Some(r) => r,
            None => return 1.0, // Baseline neutral reputation for untracked peers
        };

        if record.reputation.is_blacklisted {
            return 0.0; // Guaranteed eviction/rejection
        }

        // Defragmented Evaluation: Directly map the unified integer score to a float
        // representing percentage of trust (Assuming 100 is the max/starting score)
        let score_normalized = (record.reputation.score as f32) / 100.0;

        score_normalized.clamp(0.1, 1.0)
    }
}

impl ReputationGate for TrustRegistry {
    fn is_blacklisted(&self, did: &Did) -> bool {
        self.core
            .peers
            .get(did)
            .is_some_and(|r| r.reputation.is_blacklisted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vitals::init_observability;

    #[tokio::test]
    async fn test_aliasing() {
        let temp = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::test_defaults();
        config.storage.vault_path = temp.path().to_string_lossy().to_string();
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

    #[tokio::test]
    async fn test_record_offense_deterministic_blacklisting() {
        init_observability();
        let temp = tempfile::tempdir().unwrap();
        let mut config = NodeConfig::test_defaults();
        config.storage.vault_path = temp.path().to_string_lossy().to_string();

        let mut registry = TrustRegistry::build(&config).await;
        let clock = SystemClock; // Using SystemClock for the trait impl
        let did = Did::from("did:phx:offender");

        // 1. Record a minor offense (Implicitly registers the peer)
        registry
            .record_offense(&did, Offense::QuotaExceeded, &clock)
            .await;

        let record = registry
            .core
            .peers
            .get(&did)
            .expect("Peer should be lazily registered");
        assert_eq!(record.reputation.score, 75);
        assert!(!record.reputation.is_blacklisted);

        // 2. Record a fatal offense
        registry
            .record_offense(&did, Offense::InvalidSignature, &clock)
            .await;

        let record = registry.core.peers.get(&did).unwrap();
        // If score is i32: 75 - 101 = -26. If u32 saturating: 0.
        assert!(record.reputation.score <= 0);
        assert!(record.reputation.is_blacklisted);
    }
}
