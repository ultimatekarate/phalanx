// crates/phalanx-stronghold/src/config.rs

use phalanx_proto::topic::MeshTopic;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct StrongholdConfig {
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub corroboration: CorroborationConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    /// Root directory for all Stronghold data.
    pub vault_path: String,
    /// Maximum total storage bytes for evidence (hard cap).
    pub max_storage_bytes: u64,
    /// Per-community storage quota (hard cap).
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

/// Minimum enforced custody window. A hand-edited `custody_ttl_secs` of 0 (or a
/// tiny value) would expire pushed recordings before the publisher can act on
/// them — the floor rejects that footgun at config-load time. Programmatic
/// construction (tests) bypasses the floor; only [`StorageConfig::clamp_floors`]
/// applies it.
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

#[derive(Debug, Deserialize, Clone)]
pub struct NetworkConfig {
    pub listen_addresses: Vec<String>,
    pub bootstrap_peers: Vec<String>,
    #[serde(skip)]
    pub video_topic: MeshTopic,
    #[serde(skip)]
    pub audio_topic: MeshTopic,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CorroborationConfig {
    /// Minimum temporal overlap for corroboration (milliseconds).
    pub min_overlap_ms: u64,
    /// KS-test divergence alpha threshold.
    pub divergence_alpha: f64,
    /// C2PA certificate path for signing exports.
    pub c2pa_cert_path: Option<String>,
    /// C2PA private key path.
    pub c2pa_key_path: Option<String>,
}

impl Default for StrongholdConfig {
    fn default() -> Self {
        Self {
            storage: StorageConfig {
                vault_path: "./stronghold-data".to_string(),
                max_storage_bytes: 100 * 1024 * 1024 * 1024, // 100 GB
                max_per_community_bytes: 20 * 1024 * 1024 * 1024, // 20 GB
                max_bytes_per_owner: default_max_bytes_per_owner(),
                owner_fair_share_ratio: default_owner_fair_share_ratio(),
                custody_ttl_secs: default_custody_ttl_secs(),
            },
            network: NetworkConfig {
                listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
                bootstrap_peers: vec![],
                video_topic: MeshTopic::video(),
                audio_topic: MeshTopic::new("audio/1.0.0"),
            },
            corroboration: CorroborationConfig {
                min_overlap_ms: 5000,
                divergence_alpha: 0.05,
                c2pa_cert_path: None,
                c2pa_key_path: None,
            },
        }
    }
}
