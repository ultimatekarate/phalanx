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
    /// Maximum total storage bytes for evidence.
    pub max_storage_bytes: u64,
    /// Per-community storage quota.
    pub max_per_community_bytes: u64,
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
