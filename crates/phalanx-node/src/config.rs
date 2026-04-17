// crates/phalanx-node/src/config.rs

use phalanx_proto::evidence::SensorCalibration;
use phalanx_proto::prelude::{Did, MeshTopic};
use phalanx_proto::types::{ByteCapacity, ChannelCount, Fps, RepairRatio, SampleRate, SymbolSize};
use serde::Deserialize;
use std::path::PathBuf;

use std::env;
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub hardware: HardwareConfig,
}

#[derive(Debug, Deserialize)]
pub struct IdentityConfig {
    pub did: Did,
    pub key_path: PathBuf,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    #[serde(default = "default_protocol_version")]
    pub protocol_version: String,
    pub max_chunk_size_bytes: usize,
    pub video_topic: MeshTopic,
    pub audio_topic: MeshTopic,
    pub control_topic: MeshTopic,
    pub cleanup_interval_secs: u64,
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    #[serde(default = "default_service_key")]
    pub guardian_service_key: String,
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,
    /// N3 FIX: When true, the node will refuse to start without a valid PSK.
    /// This prevents silent fallback to unencrypted transport when the swarm key
    /// is missing or corrupt.
    #[serde(default)]
    pub require_psk: bool,
    /// RaptorQ fountain code repair ratio. 1.0 = source symbols only, 1.5 = 50% extra.
    /// Higher ratios increase resilience to packet loss at the cost of bandwidth.
    #[serde(default)]
    pub repair_ratio: RepairRatio,
    /// RaptorQ symbol payload size in bytes. Must fit within a single UDP datagram.
    #[serde(default)]
    pub symbol_size: SymbolSize,
    /// Multiaddr strings the swarm will listen on.
    /// Default: `["/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"]`.
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,
    /// Topic for revocation token propagation (Cryptographic Forgetting).
    #[serde(default = "default_revocation_topic")]
    pub revocation_topic: MeshTopic,
}

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
#[serde(deny_unknown_fields)]
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
    #[serde(default = "default_max_foreign_per_owner")]
    pub max_foreign_per_owner_bytes: ByteCapacity,
    /// Fixed TTL for stored evidence, independent of dynamic temporal tolerance.
    #[serde(default = "default_evidence_ttl")]
    pub evidence_ttl_secs: u64,
    /// Path to the PEM certificate for C2PA manifest signing.
    /// When `None`, ArtifactSink writes unsigned raw bytes.
    #[serde(default)]
    pub c2pa_cert_path: Option<String>,
    /// Path to the PEM private key for C2PA manifest signing.
    #[serde(default)]
    pub c2pa_key_path: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HardwareConfig {
    pub camera_fps: Fps,
    pub audio_sample_rate: SampleRate,
    pub audio_channels: ChannelCount,
    /// Per-device PRNU calibration result from the sensor setup pipeline.
    /// When `None`, LensGate uses conservative default thresholds.
    /// When `Some`, the calibrated `prnu_floor` is bound to the physical sensor.
    #[serde(default)]
    pub sensor_calibration: Option<SensorCalibration>,
}

impl HardwareConfig {
    /// Re-wraps deserialized values through validating constructors.
    /// Call after TOML/env deserialization to enforce invariants that
    /// `#[serde(transparent)]` alone cannot guarantee (e.g. zero FPS).
    #[must_use]
    pub fn validated(self) -> Self {
        Self {
            camera_fps: Fps::new(self.camera_fps.get()),
            audio_sample_rate: SampleRate::new(self.audio_sample_rate.get()),
            audio_channels: ChannelCount::new(self.audio_channels.get()),
            sensor_calibration: self.sensor_calibration,
        }
    }
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
fn default_max_foreign_per_owner() -> ByteCapacity {
    ByteCapacity(50_000_000) // 50 MB per foreign owner
}
fn default_evidence_ttl() -> u64 {
    300
}
fn default_max_connections() -> usize {
    192
}
fn default_listen_addresses() -> Vec<String> {
    vec![
        "/ip4/0.0.0.0/udp/0/quic-v1".to_string(),
        "/ip4/0.0.0.0/tcp/0".to_string(),
    ]
}
fn default_revocation_topic() -> MeshTopic {
    MeshTopic::revocation()
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
            max_connections: default_max_connections(),
            require_psk: false,
            repair_ratio: RepairRatio::default(),
            symbol_size: SymbolSize::default(),
            listen_addresses: default_listen_addresses(),
            revocation_topic: default_revocation_topic(),
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
            max_foreign_per_owner_bytes: default_max_foreign_per_owner(),
            evidence_ttl_secs: default_evidence_ttl(),
            c2pa_cert_path: None,
            c2pa_key_path: None,
        }
    }
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            camera_fps: Fps::new(10),
            audio_sample_rate: SampleRate::new(16_000),
            audio_channels: ChannelCount::new(1),
            sensor_calibration: None,
        }
    }
}

impl NodeConfig {
    #[allow(clippy::missing_errors_doc)]
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self, Box<dyn std::error::Error>> {
        let content = fs::read_to_string(path)?;
        let mut config: NodeConfig = toml::from_str(&content)?;
        config.hardware = config.hardware.validated();
        Ok(config)
    }

    /// Load configuration from the `PHALANX_CONFIG` environment variable.
    ///
    /// - If `PHALANX_CONFIG` is set, the file **must** parse successfully —
    ///   a warning is emitted and compiled defaults are used on failure.
    /// - If `PHALANX_CONFIG` is not set, compiled defaults are used directly.
    ///   This is the normal path on mobile (Flutter provides config via FFI).
    #[must_use]
    pub fn load_from_env() -> Self {
        match env::var("PHALANX_CONFIG") {
            Ok(path) => Self::load(&path).unwrap_or_else(|e| {
                tracing::warn!(
                    target: "phalanx::config",
                    path = %path,
                    error = %e,
                    "PHALANX_CONFIG set but failed to load — falling back to compiled defaults"
                );
                Self::default()
            }),
            Err(_) => Self::default(),
        }
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

impl Default for NodeConfig {
    /// Provides the standard clinical default configuration.
    fn default() -> Self {
        Self {
            network: NetworkConfig::default(),
            storage: StorageConfig::default(),
            hardware: HardwareConfig::default(),
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
mod validation_tests {
    use super::*;

    // The purpose of `HardwareConfig::validated()` is to repair values that
    // slipped through `#[serde(transparent)]` deserialization (which bypasses
    // `Fps::new`, `SampleRate::new`, `ChannelCount::new`). We test that
    // out-of-range TOML values are clamped to safe bounds.

    #[test]
    fn validated_clamps_zero_fps_to_one() {
        // `Fps` has a floor of 1 — zero would divide-by-zero downstream.
        let cfg: HardwareConfig = toml::from_str(
            r#"
            camera_fps = 0
            audio_sample_rate = 16000
            audio_channels = 1
            "#,
        )
        .expect("TOML parses");
        assert_eq!(cfg.camera_fps.get(), 0, "serde accepts raw zero");

        let v = cfg.validated();
        assert_eq!(
            v.camera_fps.get(),
            1,
            "validated() must clamp zero FPS up to the 1-FPS floor"
        );
    }

    #[test]
    fn validated_clamps_sample_rate_above_maximum() {
        // SampleRate::new clamps to [1, 192_000]. A malicious or wrong TOML
        // must not leak an out-of-range audio sample rate into capture pipelines.
        let cfg: HardwareConfig = toml::from_str(
            r#"
            camera_fps = 30
            audio_sample_rate = 5000000
            audio_channels = 2
            "#,
        )
        .expect("TOML parses");
        let v = cfg.validated();
        assert!(
            v.audio_sample_rate.get() <= 192_000,
            "sample rate must be clamped to MAX, got {}",
            v.audio_sample_rate.get()
        );
    }

    #[test]
    fn validated_clamps_excessive_channel_count_to_maximum() {
        // ChannelCount::new clamps to [1, 8].
        let cfg: HardwareConfig = toml::from_str(
            r#"
            camera_fps = 30
            audio_sample_rate = 48000
            audio_channels = 64
            "#,
        )
        .expect("TOML parses");
        let v = cfg.validated();
        assert_eq!(
            v.audio_channels.get(),
            8,
            "channel count must clamp to 8, got {}",
            v.audio_channels.get()
        );
    }

    #[test]
    fn validated_preserves_valid_values_unchanged() {
        // Regression guard: values already within bounds must pass through
        // untouched — validated() must not be a silent rescaler.
        let cfg: HardwareConfig = toml::from_str(
            r#"
            camera_fps = 30
            audio_sample_rate = 48000
            audio_channels = 2
            "#,
        )
        .expect("TOML parses");
        let v = cfg.validated();
        assert_eq!(v.camera_fps.get(), 30);
        assert_eq!(v.audio_sample_rate.get(), 48_000);
        assert_eq!(v.audio_channels.get(), 2);
    }
}
