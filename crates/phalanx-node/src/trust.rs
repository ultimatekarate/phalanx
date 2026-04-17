use crate::clock::TrustedClock;
use crate::NodeConfig;
use phalanx_forensics::trust::{PeerEvaluator, ReputationGate};
use phalanx_proto::prelude::*;
use phalanx_proto::trust::MonotonicClock;
use phalanx_proto::trust::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs::{self, File};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use phalanx_proto::prelude::NetworkId;
use std::sync::{Arc, RwLock as StdRwLock};

/// Community trust data: pairs of (baseline_trust, member_dids) for each community.
type CommunityTrustData = Vec<(TrustLevel, HashSet<Did>)>;

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
    /// Community data for effective_trust calculation.
    communities: Arc<StdRwLock<CommunityTrustData>>,
}

pub trait TrustOracle: Send + Sync {
    fn is_blacklisted_by_did(&self, did: &Did) -> bool;
    fn check_trust_by_did(&self, did: &Did) -> TrustLevel;

    /// Community-aware trust: returns the effective trust level considering
    /// community membership elevation. Blacklisting is absolute — community
    /// membership cannot rehabilitate a Blocked peer.
    fn effective_trust(&self, did: &Did) -> TrustLevel {
        // Default: no community awareness, just return individual trust
        self.check_trust_by_did(did)
    }
}

impl TrustOracle for ReputationProjection {
    fn is_blacklisted_by_did(&self, did: &Did) -> bool {
        // Poisoned lock → treat as blacklisted (fail-secure).
        let Ok(did_map) = self.did_to_network_id.read() else {
            tracing::error!("did_to_network_id lock poisoned — failing secure");
            return true;
        };
        if let Some(network_id) = did_map.get(did) {
            let Ok(scores_map) = self.scores.read() else {
                tracing::error!("scores lock poisoned — failing secure");
                return true;
            };
            if let Some(info) = scores_map.get(network_id) {
                return info.is_blacklisted;
            }
        }
        false
    }

    fn check_trust_by_did(&self, did: &Did) -> TrustLevel {
        // Poisoned lock → Blocked (fail-secure).
        let Ok(did_map) = self.did_to_network_id.read() else {
            tracing::error!("did_to_network_id lock poisoned — failing secure");
            return TrustLevel::Blocked;
        };
        if let Some(network_id) = did_map.get(did) {
            let Ok(scores_map) = self.scores.read() else {
                tracing::error!("scores lock poisoned — failing secure");
                return TrustLevel::Blocked;
            };
            scores_map
                .get(network_id)
                .map_or(TrustLevel::Ignored, |info| info.trust_level)
        } else {
            TrustLevel::Ignored
        }
    }

    fn effective_trust(&self, did: &Did) -> TrustLevel {
        let individual = self.check_trust_by_did(did);

        // Blacklisting is absolute — community membership cannot rehabilitate.
        if individual == TrustLevel::Blocked {
            return TrustLevel::Blocked;
        }

        // Poisoned lock → Blocked (fail-secure).
        let Ok(communities) = self.communities.read() else {
            tracing::error!("communities lock poisoned — failing secure");
            return TrustLevel::Blocked;
        };
        let mut best = individual;
        for (baseline_trust, member_dids) in communities.iter() {
            if member_dids.contains(did) && *baseline_trust > best {
                best = *baseline_trust;
            }
        }
        best
    }
}

impl ReputationProjection {
    /// Sync community data for effective_trust lookups.
    /// Called by TrustRegistry when communities are loaded or updated.
    pub fn sync_communities(&self, community_data: CommunityTrustData) {
        let Ok(mut communities) = self.communities.write() else {
            tracing::error!("communities lock poisoned — cannot sync");
            return;
        };
        *communities = community_data;
    }
}

impl PeerEvaluator for ReputationProjection {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32 {
        // Poisoned lock → minimum trust score (fail-secure).
        let Ok(scores) = self.scores.read() else {
            tracing::error!("scores lock poisoned — failing secure");
            return 0.0;
        };
        scores
            .get(peer_id)
            // E4 FIX: Unknown peers start at 0.1 (minimum trust), not 1.0 (maximum).
            // This prevents Sybil attackers from receiving full trust on first contact.
            .map_or(0.1, |info| info.score)
    }
}

impl ReputationGate for ReputationProjection {
    fn is_blacklisted(&self, did: &Did) -> bool {
        self.is_blacklisted_by_did(did)
    }
}

pub trait ClockProvider {
    fn current_monotonic(&self) -> MonotonicClock;
}

/// Real-world implementation for the node.
pub struct SystemClock;

impl ClockProvider for SystemClock {
    fn current_monotonic(&self) -> MonotonicClock {
        // Safety: SystemTime::now() is always >= UNIX_EPOCH on supported platforms.
        // If the clock is before UNIX_EPOCH, fall back to 0.
        let start = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(std::time::Duration::from_secs(0))
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

/// E6 FIX: Maximum number of lazily-registered peers.
/// Prevents Sybil attackers from filling the peer registry with millions of fake DIDs
/// by triggering offenses from unique identities.
const MAX_LAZY_REGISTRATIONS: usize = 10_000;

/// Manages the "Social Graph" of the node with bi-directional lookup.
#[derive(Debug, Serialize, Deserialize)]
pub struct TrustRegistry {
    #[serde(flatten)]
    pub peers: HashMap<Did, PeerRecord>,
    /// Lookup index: Alias -> DID (Ephemeral, rebuilt on load)
    #[serde(skip)]
    pet_name_index: HashMap<PetName, Did>,
    #[serde(skip)]
    pub live_projection: ReputationProjection,
    storage_path: PathBuf,
    /// Trusted communities. Loaded from disk, updated via FFI (deep link import).
    /// NOT gossiped — membership is private. Keyed by CommunityId.
    #[serde(skip)]
    pub communities:
        HashMap<phalanx_proto::community::CommunityId, phalanx_proto::community::Community>,
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
            peers: HashMap::new(),
            pet_name_index: HashMap::new(),
            live_projection: ReputationProjection::default(),
            storage_path,
            communities: HashMap::new(),
        };

        if let Err(e) = registry.load().await {
            tracing::warn!(target: "trust", "Failed to load trust registry (starting fresh): {}", e);
        }

        // Belt-and-suspenders: dissolve expired communities on boot before any operations.
        let boot_clock = TrustedClock::new();
        let boot_now = boot_clock.now().unwrap_or_default();
        registry.dissolve_expired_communities(boot_now);

        registry
    }

    /// Dissolve all expired communities. Zeroes membership data and removes from HashMap.
    /// Called on boot, on maintenance tick, and checked on every effective_trust() access.
    pub fn dissolve_expired_communities(&mut self, now: phalanx_proto::time::PhalanxTimestamp) {
        let expired_ids: Vec<_> = self
            .communities
            .iter()
            .filter(|(_, c)| c.is_expired(now))
            .map(|(id, _)| *id)
            .collect();

        for id in expired_ids {
            if let Some(community) = self.communities.remove(&id) {
                tracing::info!(
                    target: "trust",
                    community = %community.name,
                    "Community expired — dissolving and zeroizing"
                );
                community.dissolve(); // Consumes and zeroizes
            }
        }
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

        if let Some(old_record) = self.peers.get(did) {
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

        self.peers.insert(did.clone(), record);
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
        let network_id = did.to_network_id();

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

        if let Ok(mut scores) = projection.scores.write() {
            scores.insert(network_id.clone(), info);
        } else {
            tracing::error!("scores lock poisoned — cannot sync projection");
        }

        if let Ok(mut did_map) = projection.did_to_network_id.write() {
            did_map.insert(did.clone(), network_id);
        } else {
            tracing::error!("did_to_network_id lock poisoned — cannot sync projection");
        }
    }

    /// Updates the last interaction timestamp. Must be awaited.
    pub async fn touch(&mut self, did: &Did, clock: &TrustedClock) {
        if let Some(record) = self.peers.get_mut(did) {
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
        if let Some(record) = self.peers.remove(did) {
            if let Some(ref pet_name) = record.pet_name {
                self.pet_name_index.remove(pet_name);
            }
            self.save()
                .await
                .map_err(|e| TrustError::IoError(e.to_string()))?;
        }
        Ok(())
    }

    #[allow(clippy::arithmetic_side_effects)] // Timestamp multiplication and reputation arithmetic.
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
        if !self.peers.contains_key(did) {
            // E6 FIX: Rate-limit lazy registrations to prevent Sybil registry flooding.
            // An attacker sending offenses from millions of unique DIDs would fill
            // the HashMap unboundedly. Cap at MAX_LAZY_REGISTRATIONS.
            if self.peers.len() >= MAX_LAZY_REGISTRATIONS {
                tracing::warn!(
                    target: "phalanx::trust",
                    offender_did = %did,
                    registry_size = self.peers.len(),
                    "E6: Lazy registration rejected — registry at capacity"
                );
                return;
            }

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
            self.peers.insert(did.clone(), record);
            self.pet_name_index.insert(pet_name, did.clone());
        }

        if let Some(record) = self.peers.get_mut(did) {
            let old_score = record.reputation.score;
            let penalty = phalanx_forensics::trust::assess_penalty(&offense);

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
        let bytes = postcard::to_allocvec(&self.peers)
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

        self.peers = postcard::from_bytes(&buffer)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Clear and rebuild ephemeral state
        self.pet_name_index.clear();

        for (did, record) in &self.peers {
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
        self.peers
            .get(did)
            .and_then(|r| r.pet_name.as_ref().map(|n| n.as_str()))
    }

    #[must_use]
    pub fn check_trust(&self, did: &Did) -> TrustLevel {
        self.peers.get(did).map_or(TrustLevel::Ignored, |r| r.level)
    }

    /// Retrieves a mutable reference to a peer's reputation state.
    pub fn get_reputation_mut(&mut self, did: &Did) -> Option<&mut PeerReputation> {
        self.peers.get_mut(did).map(|record| &mut record.reputation)
    }

    #[allow(clippy::arithmetic_side_effects)] // Counter increment — overflow not reachable in practice.
    fn generate_unique_pet_name(&self, did: &Did) -> PetName {
        let base_name = format!(
            "Unknown-{}",
            did.as_str().chars().take(8).collect::<String>()
        );
        let mut fallback_name = base_name.clone();
        let mut counter = 1;

        let mut pet_name = PetName::new(&fallback_name).unwrap_or_else(|_| PetName::unknown());

        while self.pet_name_index.contains_key(&pet_name) {
            fallback_name = format!("{}-{}", base_name, counter);
            pet_name = PetName::new(&fallback_name).unwrap_or_else(|_| PetName::unknown());
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
        self.peers
            .get(did)
            .is_some_and(|record| record.reputation.is_blacklisted)
    }

    /// Checks if a network-level ID is blacklisted by resolving it to a DID.
    #[must_use]
    pub fn is_network_id_blacklisted(&self, network_id: &NetworkId) -> bool {
        let target_did = Did::from_network_id(network_id);
        self.is_blacklisted(&target_did)
    }

    pub async fn insert_peer(
        &mut self,
        did: &Did,
        pet_name: &PetName,
        level: TrustLevel,
        clock: &TrustedClock,
    ) -> Result<(), TrustError> {
        if self.peers.contains_key(did) {
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

        self.peers.insert(did.clone(), record);
        self.pet_name_index.insert(pet_name.clone(), did.clone());

        self.save()
            .await
            .map_err(|e| TrustError::IoError(e.to_string()))
    }
}

impl PeerEvaluator for TrustRegistry {
    fn evaluate_reputation(&self, peer_id: &NetworkId) -> f32 {
        let target_did = Did::from_network_id(peer_id);

        let record = match self.peers.get(&target_did) {
            Some(r) => r,
            // E4 FIX: Unknown peers start at minimum trust (0.1), not maximum (1.0).
            // This forces new peers to earn reputation before receiving preferential treatment.
            None => return 0.1,
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
        self.peers
            .get(did)
            .is_some_and(|r| r.reputation.is_blacklisted)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
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

        // Record a minor offense (Implicitly registers the peer)
        registry
            .record_offense(&did, Offense::QuotaExceeded, &clock)
            .await;

        let record = registry
            .peers
            .get(&did)
            .expect("Peer should be lazily registered");
        assert_eq!(record.reputation.score, 75);
        assert!(!record.reputation.is_blacklisted);

        // Record a fatal offense
        registry
            .record_offense(&did, Offense::InvalidSignature, &clock)
            .await;

        let record = registry.peers.get(&did).unwrap();
        // If score is i32: 75 - 101 = -26. If u32 saturating: 0.
        assert!(record.reputation.score <= 0);
        assert!(record.reputation.is_blacklisted);

        let _ = std::fs::remove_dir_all("logs");
    }

    // ── ReputationProjection pure-logic tests ───────────────────────────

    #[test]
    fn is_blacklisted_by_did_returns_false_for_unknown_did() {
        // Fail-open for unknown DIDs is deliberate: the blacklist is only
        // authoritative for peers we've actually seen. An attacker naming a
        // random DID must not inherit a blacklist status. (Fail-secure for
        // poisoned lock is covered separately in the source code — the
        // early-return on `.read()` Err.)
        let projection = ReputationProjection::default();
        let unknown = Did::from("did:phx:stranger");
        assert!(!projection.is_blacklisted_by_did(&unknown));
    }

    #[test]
    fn check_trust_by_did_unknown_did_returns_ignored() {
        // Default trust for unseen peers is Ignored — neither blocked nor
        // verified. This is the baseline the E4 Sybil-resistance fix depends on.
        let projection = ReputationProjection::default();
        let unknown = Did::from("did:phx:stranger");
        assert_eq!(projection.check_trust_by_did(&unknown), TrustLevel::Ignored);
    }

    #[test]
    fn evaluate_reputation_unknown_peer_returns_e4_minimum_trust() {
        // E4 FIX regression guard: unknown peers must start at 0.1 (minimum
        // trust), not 1.0. Without this, a Sybil attacker gets full trust on
        // first contact and can use it to pre-empt verified peers.
        let projection = ReputationProjection::default();
        let stranger = NetworkId::from("fresh-sybil".to_string());
        let score = projection.evaluate_reputation(&stranger);
        assert!(
            (score - 0.1).abs() < f32::EPSILON,
            "E4 FIX: unknown peers must start at 0.1 (got {score})"
        );
    }

    #[test]
    fn effective_trust_blacklisted_cannot_be_rehabilitated_by_community() {
        // Blacklisting is absolute — community membership must not uplift a
        // Blocked peer to Verified or Ally. Without this guard, the
        // community-elevation path would whitelist banned members.
        let projection = ReputationProjection::default();
        let banned_did = Did::from("did:phx:banned");
        let banned_nid = NetworkId::from("nid-banned".to_string());

        // Seed: banned DID maps to a blocked PeerReputationInfo.
        {
            let mut did_map = projection.did_to_network_id.write().unwrap();
            did_map.insert(banned_did.clone(), banned_nid.clone());
        }
        {
            let mut scores = projection.scores.write().unwrap();
            scores.insert(
                banned_nid,
                PeerReputationInfo {
                    score: -10.0,
                    is_blacklisted: true,
                    trust_level: TrustLevel::Blocked,
                },
            );
        }

        // Add the banned DID to a "high trust" community — should NOT elevate.
        let mut members = HashSet::new();
        members.insert(banned_did.clone());
        projection.sync_communities(vec![(TrustLevel::Ally, members)]);

        let effective = projection.effective_trust(&banned_did);
        assert_eq!(
            effective,
            TrustLevel::Blocked,
            "Blocked peers must stay Blocked even in an Ally community"
        );
    }
}
