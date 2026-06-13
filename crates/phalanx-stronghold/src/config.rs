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
    /// Quiescence window for autonomous export: a held, grant-bearing recording
    /// is auto-exported once no new push for it has arrived for this many
    /// seconds (so the Stronghold exports a settled recording, not a mid-flight
    /// one). `0` disables autonomous export entirely.
    #[serde(default = "default_export_quiescence_secs")]
    pub export_quiescence_secs: u64,
    /// Optional durable sink directory for exported C2PA MP4s + signed
    /// `ExportReceipt`s. `None` ⇒ `{vault}/exports`. Set to an external,
    /// operator-managed path (e.g. a cloud-synced or archival mount) in prod.
    #[serde(default)]
    pub export_path: Option<String>,
    /// After a successful autonomous export, reclaim the custody copy early
    /// (free its shards + fairness bytes) rather than holding to `custody_ttl`.
    /// The exported artifact is the deliverable, so the encrypted custody copy
    /// is redundant once it lands. Default off (hold to TTL for redundancy).
    #[serde(default)]
    pub release_custody_after_export: bool,
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
    /// Gossipsub media topics. Not operator-settable (`serde(skip)`): the mesh
    /// runs a small fixed set of well-known topics by design, so retargeting
    /// them per deployment is the wrong knob. The explicit `default = …` is
    /// load-bearing — serde fills skipped fields from the *field type's*
    /// default, and `MeshTopic::default()` is "/phalanx/default", so without
    /// it the mere presence of a config file silently disconnected the
    /// Stronghold from the media mesh.
    #[serde(skip, default = "default_video_topic")]
    pub video_topic: MeshTopic,
    #[serde(skip, default = "default_audio_topic")]
    pub audio_topic: MeshTopic,
}

fn default_video_topic() -> MeshTopic {
    MeshTopic::video()
}

fn default_audio_topic() -> MeshTopic {
    MeshTopic::audio()
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
                export_quiescence_secs: default_export_quiescence_secs(),
                export_path: None,
                release_custody_after_export: false,
            },
            network: NetworkConfig {
                listen_addresses: vec!["/ip4/0.0.0.0/tcp/0".to_string()],
                bootstrap_peers: vec![],
                video_topic: default_video_topic(),
                audio_topic: default_audio_topic(),
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

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]
mod tests {
    use super::*;

    /// Regression: with bare `#[serde(skip)]`, parsing any config file filled
    /// the topic fields from `MeshTopic::default()` ("/phalanx/default") —
    /// the mere presence of a stronghold.toml silently changed what the
    /// Stronghold subscribed to.
    #[test]
    fn config_file_presence_does_not_change_topics() {
        let parsed: StrongholdConfig = toml::from_str(
            r#"
            [storage]
            vault_path = "./stronghold-data"
            max_storage_bytes = 1000000
            max_per_community_bytes = 1000000

            [network]
            listen_addresses = ["/ip4/0.0.0.0/tcp/4001"]
            bootstrap_peers = []

            [corroboration]
            min_overlap_ms = 5000
            divergence_alpha = 0.05
            "#,
        )
        .expect("TOML parses");

        let compiled = StrongholdConfig::default();
        assert_eq!(parsed.network.video_topic, compiled.network.video_topic);
        assert_eq!(parsed.network.audio_topic, compiled.network.audio_topic);
        assert_eq!(parsed.network.video_topic, MeshTopic::video());
        assert_eq!(parsed.network.audio_topic, MeshTopic::audio());
    }
}
