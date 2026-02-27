use phalanx_proto::{Did, MeshTopic, NetworkId};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
pub struct NodeConfig {
    pub identity: IdentityConfig,
    pub storage: StorageConfig,
    pub network: NetworkConfig,
}

#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
    pub did: Did,
    pub key_path: PathBuf,
}

#[derive(Debug, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: String,
    pub public_addr: Option<String>,
    pub topics: Vec<MeshTopic>, // Using the Noun from proto!
}

impl NodeConfig {
    pub fn load(path: PathBuf) -> Result<Self, config::ConfigError> {
        let s = config::Config::builder()
            .add_source(config::File::from(path))
            .add_source(config::Environment::with_prefix("PHALANX"))
            .build()?;
        s.try_deserialize()
    }
}

use crate::base::types::UnitInterval;
use crate::base::types::{ByteCapacity, MeshTopic};
use serde::{Deserialize, Serialize};
use std::env;
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug)]
pub enum ConfigError {
    NotFound(String),
    ParseError(String),
    PermissionDenied(String),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "Configuration not found: {msg}"),
            Self::ParseError(msg) => write!(f, "Failed to parse configuration: {msg}"),
            Self::PermissionDenied(msg) => write!(f, "Permission denied reading config: {msg}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The Root Configuration for the Phalanx Engine.
#[derive(Debug, Deserialize, Clone)]
pub struct PhalanxConfig {
    pub network: NetworkConfig,
    pub storage: StorageConfig,
    pub hardware: HardwareConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct StorageConfig {
    pub vault_path: String,
    pub max_video_buffer: usize,
    pub max_audio_buffer: usize,
    pub max_peers: usize,
    pub stale_session_threshold: u64,
    pub shards_needed_to_archive: usize,
    #[serde(default = "default_max_storage")]
    pub max_storage_bytes: ByteCapacity,
    #[serde(default = "default_max_foreign")]
    pub max_foreign_storage_bytes: ByteCapacity,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HardwareConfig {
    pub camera_fps: u32,
    pub audio_sample_rate: u32,
    pub audio_channels: u8,
}

// --- Helper Functions and Initializers ---

fn default_service_key() -> String {
    "phalanx/service/storage/v1".to_string()
}
fn default_protocol_version() -> String {
    "/phalanx/1.0.0".to_string()
}
fn default_max_storage() -> ByteCapacity {
    ByteCapacity(1_000_000_000)
}
fn default_max_foreign() -> ByteCapacity {
    ByteCapacity(500_000_000)
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            protocol_version: default_protocol_version(),
            max_chunk_size_bytes: 8192,
            video_topic: "/phalanx/video".into(),
            audio_topic: "/phalanx/audio".into(),
            control_topic: "/phalanx/control".into(),
            cleanup_interval_secs: 60,
            bootstrap_peers: vec![],
            guardian_service_key: default_service_key(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            vault_path: "./sim_vault".to_string(),
            max_video_buffer: 100,
            max_audio_buffer: 100,
            max_peers: 10,
            stale_session_threshold: 3600,
            shards_needed_to_archive: 10,
            max_storage_bytes: default_max_storage(),
            max_foreign_storage_bytes: default_max_foreign(),
        }
    }
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            camera_fps: 10,
            audio_sample_rate: 16000,
            audio_channels: 1,
        }
    }
}

impl PhalanxConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let config: PhalanxConfig = toml::from_str(&content)?;
        Ok(config)
    }

    /// Loads the configuration.
    /// REFACTOR: Removed .expect() to satisfy Forensic Integrity standards.
    #[allow(clippy::missing_errors_doc)]
    pub fn load_default() -> Result<Self, ConfigError> {
        // 1. Attempt to load the file
        // 2. Return the Result directly instead of unwrapping/expecting
        Self::load("phalanx.toml")
            .map_err(|e| ConfigError::NotFound(format!("Critical: Missing phalanx.toml - {e}")))
    }

    #[must_use]
    pub fn load_from_env() -> Self {
        let path = env::var("PHALANX_CONFIG").unwrap_or_else(|_| "phalanx.toml".to_string());
        Self::load(path).unwrap_or_else(|_| Self::default())
    }

    /// Restored: Specifically for simulation environments (src/sim.rs).
    #[must_use]
    pub fn test_defaults() -> Self {
        let mut cfg = Self::default();
        cfg.network.cleanup_interval_secs = 5; // Aggressive cleanup for tests
        cfg
    }

    #[must_use]
    pub fn test_salvage_on_node_death() -> Self {
        let mut cfg = Self::default();
        cfg.storage.vault_path = "sim_vault".to_string();
        // Aggressive cleanup to trigger salvage within the test's sleep window
        cfg.network.cleanup_interval_secs = 1;
        cfg
    }
}

impl Default for PhalanxConfig {
    /// Provides the standard clinical default configuration.
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            storage: StorageConfig::default(),
            hardware: HardwareConfig::default(),
        }
    }
}
