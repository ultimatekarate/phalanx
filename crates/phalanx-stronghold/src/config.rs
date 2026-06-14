// crates/phalanx-stronghold/src/config.rs
//
// Stronghold configuration as topology selection. Like the node, a Stronghold
// PROJECTS a `DeploymentProfile`: the profile pins the cross-binary coherence-
// critical values (gossipsub topics, protocol version, PSK posture), and the
// operator supplies only INSTANCE data ([instance] tables). A `stronghold.toml`
// selecting a profile with no Stronghold role (e.g. `solo_device`) is a hard,
// named failure.

use phalanx_proto::network::deployment::{DeploymentProfile, Incoherence};
use phalanx_proto::topic::MeshTopic;
use serde::Deserialize;

/// The profile a Stronghold assumes when none is named. The canonical
/// Stronghold deployment is a community custody node.
fn default_stronghold_profile() -> DeploymentProfile {
    DeploymentProfile::CommunityWithStronghold
}

/// The assembled, runtime Stronghold configuration. Produced by
/// [`StrongholdConfig::assemble`]; never deserialized directly from an operator
/// file (that is a [`StrongholdConfigFile`]). Keeps `Deserialize` only so tests
/// and fixtures that build it by value continue to compile.
#[derive(Debug, Deserialize, Clone)]
pub struct StrongholdConfig {
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub corroboration: CorroborationConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    /// Root directory for all Stronghold data.
    #[serde(default = "default_vault_path")]
    pub vault_path: String,
    /// Maximum total storage bytes for evidence (hard cap).
    #[serde(default = "default_max_storage_bytes")]
    pub max_storage_bytes: u64,
    /// Per-community storage quota (hard cap).
    #[serde(default = "default_max_per_community_bytes")]
    pub max_per_community_bytes: u64,
    /// Per-owner (per-DID) custody quota within a community — the balancing
    /// ratio's absolute ceiling. Prevents one member flooding the buffer.
    #[serde(default = "default_max_bytes_per_owner")]
    pub max_bytes_per_owner: u64,
    /// Fraction of `max_per_community_bytes` any single owner may occupy under
    /// contention. The effective per-owner share is
    /// `min(max_bytes_per_owner, max_per_community_bytes * owner_fair_share_ratio)`.
    #[serde(default = "default_owner_fair_share_ratio")]
    pub owner_fair_share_ratio: f64,
    /// Custody window: how long the Stronghold commits to hold a pushed
    /// recording before it may be reclaimed (transient-by-design). Seconds.
    #[serde(default = "default_custody_ttl_secs")]
    pub custody_ttl_secs: u64,
    /// Quiescence window for autonomous export: a held, grant-bearing recording
    /// is auto-exported once no new push for it has arrived for this many
    /// seconds. `0` disables autonomous export entirely.
    #[serde(default = "default_export_quiescence_secs")]
    pub export_quiescence_secs: u64,
    /// Optional durable sink directory for exported C2PA MP4s + signed
    /// `ExportReceipt`s. `None` ⇒ `{vault}/exports`.
    #[serde(default)]
    pub export_path: Option<String>,
    /// After a successful autonomous export, reclaim the custody copy early
    /// rather than holding to `custody_ttl`. Default off (hold to TTL).
    #[serde(default)]
    pub release_custody_after_export: bool,
}

fn default_vault_path() -> String {
    "./stronghold-data".to_string()
}

fn default_max_storage_bytes() -> u64 {
    100 * 1024 * 1024 * 1024 // 100 GB
}

fn default_max_per_community_bytes() -> u64 {
    20 * 1024 * 1024 * 1024 // 20 GB
}

fn default_max_bytes_per_owner() -> u64 {
    2 * 1024 * 1024 * 1024 // 2 GB
}

fn default_owner_fair_share_ratio() -> f64 {
    0.25
}

fn default_custody_ttl_secs() -> u64 {
    7 * 24 * 60 * 60 // 7 days
}

fn default_export_quiescence_secs() -> u64 {
    120 // 2 minutes of no new shards ⇒ the recording has settled
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            max_storage_bytes: default_max_storage_bytes(),
            max_per_community_bytes: default_max_per_community_bytes(),
            max_bytes_per_owner: default_max_bytes_per_owner(),
            owner_fair_share_ratio: default_owner_fair_share_ratio(),
            custody_ttl_secs: default_custody_ttl_secs(),
            export_quiescence_secs: default_export_quiescence_secs(),
            export_path: None,
            release_custody_after_export: false,
        }
    }
}

/// Minimum enforced custody window. A hand-edited `custody_ttl_secs` of 0 (or a
/// tiny value) would expire pushed recordings before the publisher can act on
/// them — the floor rejects that footgun at config-load time. Programmatic
/// construction (tests) bypasses the floor; only [`StorageConfig::clamp_floors`]
/// applies it (invoked inside [`StrongholdConfig::assemble`]).
pub const MIN_CUSTODY_TTL_SECS: u64 = 60;

impl StorageConfig {
    /// Clamp loaded config values up to safe floors. Returns the names of any
    /// fields that were clamped, so the caller can warn the operator.
    pub fn clamp_floors(&mut self) -> Vec<&'static str> {
        let mut clamped = Vec::new();
        if self.custody_ttl_secs < MIN_CUSTODY_TTL_SECS {
            self.custody_ttl_secs = MIN_CUSTODY_TTL_SECS;
            clamped.push("custody_ttl_secs");
        }
        clamped
    }
}

/// The full network configuration consumed by the swarm. Profile-pinned fields
/// (protocol version, PSK posture, topics) are populated by
/// [`NetworkConfig::from_profile`]; listen/bootstrap are instance data.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    // ── Instance ─────────────────────────────────────────────────────────
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    // ── Profile-pinned ───────────────────────────────────────────────────
    pub protocol_version: String,
    pub require_psk: bool,
    pub video_topic: MeshTopic,
    pub audio_topic: MeshTopic,
    pub revocation_topic: MeshTopic,
}

impl NetworkConfig {
    /// Project a profile (pinned fields) over instance data.
    #[must_use]
    pub fn from_profile(profile: DeploymentProfile, instance: &NetworkInstance) -> Self {
        let topics = profile.topics();
        Self {
            listen_addresses: instance.listen_addresses.clone(),
            bootstrap_peers: instance.bootstrap_peers.clone(),
            protocol_version: profile.protocol_version().to_string(),
            require_psk: profile.psk_posture().require_psk(),
            video_topic: topics.video,
            audio_topic: topics.audio,
            revocation_topic: topics.revocation,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CorroborationConfig {
    /// Minimum temporal overlap for corroboration (milliseconds).
    #[serde(default = "default_min_overlap_ms")]
    pub min_overlap_ms: u64,
    /// KS-test divergence alpha threshold.
    #[serde(default = "default_divergence_alpha")]
    pub divergence_alpha: f64,
    /// C2PA certificate path for signing exports.
    #[serde(default)]
    pub c2pa_cert_path: Option<String>,
    /// C2PA private key path.
    #[serde(default)]
    pub c2pa_key_path: Option<String>,
}

fn default_min_overlap_ms() -> u64 {
    5000
}

fn default_divergence_alpha() -> f64 {
    0.05
}

impl Default for CorroborationConfig {
    fn default() -> Self {
        Self {
            min_overlap_ms: default_min_overlap_ms(),
            divergence_alpha: default_divergence_alpha(),
            c2pa_cert_path: None,
            c2pa_key_path: None,
        }
    }
}

// ── Operator file schema: profile + instance ────────────────────────────────

fn default_listen_addresses() -> Vec<String> {
    vec!["/ip4/0.0.0.0/tcp/0".to_string()]
}

/// The instance (operator-tunable) subset of the network config. The pinned
/// fields (protocol version, PSK posture, topics) are structurally absent, so
/// an operator cannot set them; `deny_unknown_fields` turns an attempt into a
/// parse error.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkInstance {
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
}

impl Default for NetworkInstance {
    fn default() -> Self {
        Self {
            listen_addresses: default_listen_addresses(),
            bootstrap_peers: vec![],
        }
    }
}

/// All operator-tunable instance data, grouped by subsystem. Storage and
/// corroboration are entirely instance, so the runtime structs are reused.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct StrongholdInstance {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub network: NetworkInstance,
    #[serde(default)]
    pub corroboration: CorroborationConfig,
}

/// The on-disk operator config schema. A bare `profile = "..."` file is valid;
/// everything under `[instance]` is optional and defaulted.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StrongholdConfigFile {
    #[serde(default = "default_stronghold_profile")]
    pub profile: DeploymentProfile,
    #[serde(default)]
    pub instance: StrongholdInstance,
}

impl Default for StrongholdConfigFile {
    fn default() -> Self {
        Self {
            profile: default_stronghold_profile(),
            instance: StrongholdInstance::default(),
        }
    }
}

/// A [`StrongholdConfig`] that has passed the boot coherence gate. The only
/// constructors are [`StrongholdConfig::assemble`] / [`StrongholdConfig::load`]
/// / [`StrongholdConfig::for_profile`]; the boot path calls
/// [`ValidatedStrongholdConfig::into_inner`]. No `Deserialize`: it cannot be
/// conjured from bytes, only minted by the gate.
///
/// The field is private — no struct literal outside this module:
///
/// ```compile_fail
/// use phalanx_stronghold::config::{StrongholdConfig, ValidatedStrongholdConfig};
/// let _forge = ValidatedStrongholdConfig(StrongholdConfig::default());
/// ```
#[derive(Debug, Clone)]
pub struct ValidatedStrongholdConfig(StrongholdConfig);

impl ValidatedStrongholdConfig {
    /// Consume the proof token and yield the plain config for the sentinel.
    #[must_use]
    pub fn into_inner(self) -> StrongholdConfig {
        self.0
    }

    /// Borrow the validated config without consuming the token.
    #[must_use]
    pub fn get(&self) -> &StrongholdConfig {
        &self.0
    }
}

impl StrongholdConfig {
    fn from_parts(profile: DeploymentProfile, instance: &StrongholdInstance) -> Self {
        Self {
            storage: instance.storage.clone(),
            network: NetworkConfig::from_profile(profile, &instance.network),
            corroboration: instance.corroboration.clone(),
        }
    }

    /// Assemble and validate a Stronghold config from a profile + instance data.
    ///
    /// # Errors
    /// [`Incoherence::ProfileHasNoStrongholdRole`] if the profile has no
    /// Stronghold role (e.g. a `stronghold.toml` selecting `solo_device`).
    pub fn assemble(
        profile: DeploymentProfile,
        instance: &StrongholdInstance,
    ) -> Result<ValidatedStrongholdConfig, Incoherence> {
        if !profile.has_stronghold_role() {
            return Err(Incoherence::ProfileHasNoStrongholdRole {
                profile: profile.name(),
            });
        }
        let mut config = Self::from_parts(profile, instance);

        // Clamp hand-edited values up to safe floors (e.g. a custody TTL of 0
        // that would expire recordings before they can be exported).
        for field in config.storage.clamp_floors() {
            tracing::warn!(
                target: "phalanx::config",
                field,
                "config value below its minimum — clamped to the safe floor"
            );
        }

        // WARN: a custody-target Stronghold that bound only an ephemeral port
        // cannot receive directed pushes reliably.
        if matches!(
            profile.listen_shape(),
            phalanx_proto::network::deployment::ListenShape::InboundReachable
        ) && config
            .network
            .listen_addresses
            .iter()
            .all(|a| a.contains("/tcp/0") || a.contains("/udp/0"))
        {
            tracing::warn!(
                target: "phalanx::config",
                profile = profile.name(),
                "profile expects an inbound-reachable Stronghold but only an ephemeral listen port is configured"
            );
        }

        Ok(ValidatedStrongholdConfig(config))
    }

    /// Assemble from a profile with default instance data.
    ///
    /// # Errors
    /// Propagates [`Incoherence`] from [`StrongholdConfig::assemble`].
    pub fn for_profile(
        profile: DeploymentProfile,
    ) -> Result<ValidatedStrongholdConfig, Incoherence> {
        Self::assemble(profile, &StrongholdInstance::default())
    }

    /// Load a validated config from a TOML file (`profile = "..."` + optional
    /// `[instance]` tables). The file-absent path is handled by the caller.
    ///
    /// # Errors
    /// Returns a string describing an IO/TOML/coherence failure.
    pub fn load(path: &str) -> Result<ValidatedStrongholdConfig, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("Failed to read config {path}: {e}"))?;
        let file: StrongholdConfigFile =
            toml::from_str(&text).map_err(|e| format!("Failed to parse config {path}: {e}"))?;
        Self::assemble(file.profile, &file.instance).map_err(|e| e.to_string())
    }
}

impl Default for StrongholdConfig {
    fn default() -> Self {
        Self::from_parts(default_stronghold_profile(), &StrongholdInstance::default())
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    #[test]
    fn default_pins_canonical_topics_and_protocol() {
        let cfg = StrongholdConfig::default();
        assert_eq!(cfg.network.video_topic, MeshTopic::video());
        assert_eq!(cfg.network.audio_topic, MeshTopic::audio());
        assert_eq!(cfg.network.revocation_topic, MeshTopic::revocation());
        assert_eq!(
            cfg.network.protocol_version,
            phalanx_proto::network::deployment::DEFAULT_PROTOCOL_VERSION
        );
    }

    #[test]
    fn bare_profile_file_assembles_for_a_stronghold_bearing_profile() {
        let file: StrongholdConfigFile =
            toml::from_str("profile = \"high_risk_cross_border\"").expect("TOML parses");
        let cfg = StrongholdConfig::assemble(file.profile, &file.instance)
            .expect("high-risk has a Stronghold role")
            .into_inner();
        assert!(cfg.network.require_psk, "high-risk pins PSK required");
    }

    #[test]
    fn a_profile_without_a_stronghold_role_is_rejected() {
        let result = StrongholdConfig::assemble(
            DeploymentProfile::SoloDevice,
            &StrongholdInstance::default(),
        );
        assert!(matches!(
            result,
            Err(Incoherence::ProfileHasNoStrongholdRole { .. })
        ));
    }

    #[test]
    fn a_pinned_field_in_the_instance_table_is_a_parse_error() {
        // `protocol_version` is profile-pinned and absent from NetworkInstance.
        let parsed: Result<StrongholdConfigFile, _> = toml::from_str(
            r#"
            profile = "community_with_stronghold"
            [instance.network]
            protocol_version = "/phalanx/9.9.9"
            "#,
        );
        assert!(parsed.is_err());
    }

    #[test]
    fn custody_ttl_is_clamped_to_the_floor_on_assemble() {
        let mut instance = StrongholdInstance::default();
        instance.storage.custody_ttl_secs = 0;
        let cfg = StrongholdConfig::assemble(DeploymentProfile::CommunityWithStronghold, &instance)
            .expect("assembles")
            .into_inner();
        assert_eq!(cfg.storage.custody_ttl_secs, MIN_CUSTODY_TTL_SECS);
    }
}
