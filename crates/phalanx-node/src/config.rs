// crates/phalanx-node/src/config.rs

use phalanx_proto::prelude::{Did, MeshTopic};
use phalanx_proto::types::{
    ByteCapacity, ChannelCount, Fps, RepairRatio, SampleRate, SymbolBundleSize, SymbolSize,
};
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
    /// Number of RaptorQ symbols bundled into a single `egress.publish()` call.
    /// Default 1 preserves single-symbol-per-publish behavior. Larger values
    /// reduce the message-rate demand on the per-peer outbound queue at the
    /// cost of larger individual messages and coarser-grained loss.
    #[serde(default)]
    pub symbol_bundle_size: SymbolBundleSize,
    /// Multiaddr strings the swarm will listen on.
    /// Default: `["/ip4/0.0.0.0/udp/0/quic-v1", "/ip4/0.0.0.0/tcp/0"]`.
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,
    /// Topic for revocation token propagation (Cryptographic Forgetting).
    #[serde(default = "default_revocation_topic")]
    pub revocation_topic: MeshTopic,
    /// Archival custody peers (Strongholds) to push recordings to directly, for
    /// export-staging durability. Empty = the directed-push feature is inert
    /// (mesh broadcast still applies).
    #[serde(default)]
    pub archival_peers: Vec<ArchivalPeer>,
    /// Target number of distinct Stronghold custody replicas (K) before a
    /// recording is considered safely in custody. Policy threshold.
    #[serde(default = "default_target_replica_count")]
    pub target_replica_count: usize,
}

fn default_target_replica_count() -> usize {
    2
}

/// A configured archival custody peer (a Stronghold). One block makes the
/// single-Stronghold flow turnkey — the node DIALS it (so directed push has a
/// live connection; the transport rejects pushes to unconnected peers), TARGETS
/// it (the peer id extracted from the multiaddr), and SEALS export grants to it:
///
/// ```toml
/// [[network.archival_peers]]
/// address = "/ip4/10.0.0.5/udp/4001/quic-v1/p2p/12D3KooW...the-stronghold"
/// stronghold_did = "did:key:z...the-stronghold"
/// ```
///
/// `address` is a **dialable multiaddr** whose `/p2p/<peer-id>` tail is also the
/// push target. `stronghold_did`, when set, is the Stronghold's `did:key` used
/// to *seal* an export grant (the publisher re-derives the recording's DEK and
/// seals it with `export` permission, authorizing autonomous export). The DID
/// and the address identify the same Stronghold via different keypairs, so both
/// are given explicitly — sealing is offline (the public key falls out of
/// `did:key`). Absent DID ⇒ custody-only push (the Stronghold holds ciphertext
/// it cannot export).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ArchivalPeer {
    pub address: String,
    #[serde(default)]
    pub stronghold_did: Option<Did>,
}

impl ArchivalPeer {
    /// The push target: the libp2p peer id from the `/p2p/<peer-id>` tail of the
    /// dial multiaddr. `None` if the address carries no peer id (not dialable to
    /// a specific peer, so it cannot be a directed-push target).
    #[must_use]
    pub fn peer_id(&self) -> Option<String> {
        let (_, after) = self.address.rsplit_once("/p2p/")?;
        let id = after.split('/').next().unwrap_or(after);
        (!id.is_empty()).then(|| id.to_string())
    }
}

impl NetworkConfig {
    /// Peers the node dials at startup: the bootstrap set plus every archival
    /// Stronghold's dial address, so directed push has a live connection (custody
    /// peers are otherwise never dialed, and the transport rejects pushes to
    /// unconnected peers). Deduplicated; bootstrap order preserved.
    #[must_use]
    pub fn dial_peers(&self) -> Vec<String> {
        let mut peers = self.bootstrap_peers.clone();
        for p in &self.archival_peers {
            if !peers.contains(&p.address) {
                peers.push(p.address.clone());
            }
        }
        peers
    }
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
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HardwareConfig {
    pub camera_fps: Fps,
    pub audio_sample_rate: SampleRate,
    pub audio_channels: ChannelCount,
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
            symbol_bundle_size: SymbolBundleSize::default(),
            listen_addresses: default_listen_addresses(),
            revocation_topic: default_revocation_topic(),
            archival_peers: vec![],
            target_replica_count: default_target_replica_count(),
        }
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            // Dev-only default. The shipped sentinel binary overrides this with
            // an OS-correct data dir via `crate::paths::NodePaths` (and mobile
            // overrides it with the app sandbox dir); see `paths::DEV_DEFAULT_VAULT_PATH`.
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
        }
    }
}

impl Default for HardwareConfig {
    fn default() -> Self {
        Self {
            camera_fps: Fps::new(10),
            audio_sample_rate: SampleRate::new(16_000),
            audio_channels: ChannelCount::new(1),
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

    // ── Turnkey archival-peer targeting (M2.5) ──────────────────────────

    #[test]
    fn archival_peer_extracts_peer_id_from_multiaddr() {
        let p = ArchivalPeer {
            address: "/ip4/10.0.0.5/udp/4001/quic-v1/p2p/12D3KooWStronghold".to_string(),
            stronghold_did: None,
        };
        assert_eq!(p.peer_id().as_deref(), Some("12D3KooWStronghold"));
    }

    #[test]
    fn archival_peer_peer_id_is_none_without_p2p_component() {
        // A bare transport multiaddr names no specific peer — not a push target.
        let p = ArchivalPeer {
            address: "/ip4/10.0.0.5/udp/4001/quic-v1".to_string(),
            stronghold_did: None,
        };
        assert!(p.peer_id().is_none());
    }

    #[test]
    fn archival_peer_peer_id_ignores_trailing_protocols() {
        // A relay-circuit suffix after /p2p/<id> must not corrupt the peer id.
        let p = ArchivalPeer {
            address: "/ip4/1.2.3.4/tcp/4001/p2p/12D3KooWRelay/p2p-circuit".to_string(),
            stronghold_did: None,
        };
        assert_eq!(p.peer_id().as_deref(), Some("12D3KooWRelay"));
    }

    #[test]
    fn dial_peers_merges_bootstrap_and_archival_deduped() {
        let mut net = NetworkConfig::default();
        net.bootstrap_peers = vec!["/ip4/1.1.1.1/tcp/1".to_string()];
        net.archival_peers = vec![
            ArchivalPeer {
                address: "/ip4/2.2.2.2/tcp/2/p2p/12D3KooWA".to_string(),
                stronghold_did: None,
            },
            // Duplicate of a bootstrap entry — must not be dialed twice.
            ArchivalPeer {
                address: "/ip4/1.1.1.1/tcp/1".to_string(),
                stronghold_did: None,
            },
        ];
        assert_eq!(
            net.dial_peers(),
            vec![
                "/ip4/1.1.1.1/tcp/1".to_string(),
                "/ip4/2.2.2.2/tcp/2/p2p/12D3KooWA".to_string(),
            ]
        );
    }

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
