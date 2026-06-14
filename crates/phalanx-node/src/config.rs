// crates/phalanx-node/src/config.rs
//
// Configuration as topology selection. An operator chooses a `DeploymentProfile`
// (the topology); the profile PINS every cross-binary coherence-critical value
// (gossipsub topics, protocol version, wire chunk ceiling, replica policy, PSK
// posture). Everything else is INSTANCE data — local, defaulted, operator-
// tunable, and incapable of desyncing the mesh. Operator instance data is
// validated when assembled; a hard incoherence fails loudly, a suspicious-but-
// legal value is logged.

use phalanx_proto::network::deployment::{DeploymentProfile, Incoherence};
use phalanx_proto::prelude::{Did, MeshTopic};
use phalanx_proto::types::{
    ByteCapacity, ChannelCount, Fps, RepairRatio, SampleRate, SymbolBundleSize, SymbolSize,
};
use serde::Deserialize;

use std::env;
use std::fmt;
use std::fs;
use std::path::Path;

/// The assembled, runtime node configuration. Produced by [`NodeConfig::assemble`]
/// from a profile plus [`NodeInstance`] data — never deserialized directly from
/// an operator file (the operator file is a [`NodeConfigFile`]). Keeps its
/// `Deserialize` derive only so the ~35 programmatic constructors and tests that
/// build it by value continue to compile.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub storage: StorageConfig,
    pub network: NetworkConfig,
    pub hardware: HardwareConfig,
}

/// The full network configuration consumed by the transport. Profile-pinned
/// fields (protocol version, topics, chunk ceiling, PSK, replica target) are
/// populated by [`NetworkConfig::from_profile`]; the remainder is instance data.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    // ── Profile-pinned (coherence-critical; sourced from DeploymentProfile) ──
    pub protocol_version: String,
    pub max_chunk_size_bytes: usize,
    pub video_topic: MeshTopic,
    pub audio_topic: MeshTopic,
    pub control_topic: MeshTopic,
    pub revocation_topic: MeshTopic,
    /// When true, the node refuses to start without a valid PSK (no silent
    /// fallback to unencrypted transport).
    pub require_psk: bool,
    /// Target number of distinct Stronghold custody replicas (K) before a
    /// recording is considered safely in custody. Policy threshold.
    pub target_replica_count: usize,

    // ── Instance (local, operator-tunable) ──────────────────────────────────
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    /// RaptorQ fountain code repair ratio. Self-describing on the wire (the OTI
    /// is serialized into every chunk), so it is instance data, not pinned.
    #[serde(default)]
    pub repair_ratio: RepairRatio,
    /// RaptorQ symbol payload size in bytes. Self-describing via the OTI.
    #[serde(default)]
    pub symbol_size: SymbolSize,
    /// RaptorQ symbols bundled per `egress.publish()` call. Self-describing.
    #[serde(default)]
    pub symbol_bundle_size: SymbolBundleSize,
    /// Multiaddr strings the swarm will listen on.
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,
    /// Archival custody peers (Strongholds) to push recordings to directly.
    #[serde(default)]
    pub archival_peers: Vec<ArchivalPeer>,
}

/// A configured archival custody peer (a Stronghold). One block makes the
/// single-Stronghold flow turnkey — the node DIALS it (so directed push has a
/// live connection; the transport rejects pushes to unconnected peers), TARGETS
/// it (the peer id extracted from the multiaddr), and SEALS export grants to it:
///
/// ```toml
/// [[instance.network.archival_peers]]
/// address = "/ip4/10.0.0.5/udp/4001/quic-v1/p2p/12D3KooW...the-stronghold"
/// stronghold_did = "did:key:z...the-stronghold"
/// ```
///
/// `address` is a **dialable multiaddr** whose `/p2p/<peer-id>` tail is also the
/// push target. `stronghold_did`, when set, is the Stronghold's `did:key` used
/// to *seal* an export grant. Absent DID ⇒ custody-only push (the Stronghold
/// holds ciphertext it cannot export).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ArchivalPeer {
    pub address: String,
    #[serde(default)]
    pub stronghold_did: Option<Did>,
}

impl ArchivalPeer {
    /// The push target: the libp2p peer id from the `/p2p/<peer-id>` tail of the
    /// dial multiaddr. `None` if the address carries no peer id (so it cannot be
    /// a directed-push target).
    #[must_use]
    pub fn peer_id(&self) -> Option<String> {
        let (_, after) = self.address.rsplit_once("/p2p/")?;
        let id = after.split('/').next().unwrap_or(after);
        (!id.is_empty()).then(|| id.to_string())
    }
}

impl NetworkConfig {
    /// Peers the node dials at startup: the bootstrap set plus every archival
    /// Stronghold's dial address, so directed push has a live connection.
    /// Deduplicated; bootstrap order preserved.
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

    /// Project a profile (pinned fields) over instance data (everything else).
    #[must_use]
    pub fn from_profile(profile: DeploymentProfile, instance: &NetworkInstance) -> Self {
        let topics = profile.topics();
        Self {
            protocol_version: profile.protocol_version().to_string(),
            max_chunk_size_bytes: profile.max_chunk_size_bytes(),
            video_topic: topics.video,
            audio_topic: topics.audio,
            control_topic: topics.control,
            revocation_topic: topics.revocation,
            require_psk: profile.psk_posture().require_psk(),
            target_replica_count: profile.replica_policy().target_replica_count,
            bootstrap_peers: instance.bootstrap_peers.clone(),
            repair_ratio: instance.repair_ratio,
            symbol_size: instance.symbol_size,
            symbol_bundle_size: instance.symbol_bundle_size,
            listen_addresses: instance.listen_addresses.clone(),
            archival_peers: instance.archival_peers.clone(),
        }
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self::from_profile(
            DeploymentProfile::default_profile(),
            &NetworkInstance::default(),
        )
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StorageConfig {
    #[serde(default = "default_vault_path")]
    pub vault_path: String,
    #[serde(default = "default_buffer")]
    pub max_video_buffer: usize,
    #[serde(default = "default_buffer")]
    pub max_audio_buffer: usize,
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
    #[serde(default = "default_camera_fps")]
    pub camera_fps: Fps,
    #[serde(default = "default_audio_sample_rate")]
    pub audio_sample_rate: SampleRate,
    #[serde(default = "default_audio_channels")]
    pub audio_channels: ChannelCount,
}

impl HardwareConfig {
    /// Re-wraps deserialized values through validating constructors, enforcing
    /// invariants that `#[serde(transparent)]` alone cannot (e.g. zero FPS).
    #[must_use]
    pub fn validated(self) -> Self {
        Self {
            camera_fps: Fps::new(self.camera_fps.get()),
            audio_sample_rate: SampleRate::new(self.audio_sample_rate.get()),
            audio_channels: ChannelCount::new(self.audio_channels.get()),
        }
    }
}

// ── Operator file schema: profile + instance ────────────────────────────────

/// The instance (local, operator-tunable) subset of the network config. The
/// profile-pinned fields are *structurally absent* here — there is no field for
/// `protocol_version`, the topics, the chunk ceiling, `require_psk`, or
/// `target_replica_count`, so an operator cannot set (and thereby desync) them.
/// `deny_unknown_fields` turns an attempt into a parse error.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct NetworkInstance {
    #[serde(default)]
    pub bootstrap_peers: Vec<String>,
    #[serde(default)]
    pub repair_ratio: RepairRatio,
    #[serde(default)]
    pub symbol_size: SymbolSize,
    #[serde(default)]
    pub symbol_bundle_size: SymbolBundleSize,
    #[serde(default = "default_listen_addresses")]
    pub listen_addresses: Vec<String>,
    #[serde(default)]
    pub archival_peers: Vec<ArchivalPeer>,
}

impl Default for NetworkInstance {
    fn default() -> Self {
        Self {
            bootstrap_peers: vec![],
            repair_ratio: RepairRatio::default(),
            symbol_size: SymbolSize::default(),
            symbol_bundle_size: SymbolBundleSize::default(),
            listen_addresses: default_listen_addresses(),
            archival_peers: vec![],
        }
    }
}

/// All operator-tunable instance data, grouped by subsystem. Storage and
/// hardware are entirely instance, so the runtime structs are reused directly.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeInstance {
    #[serde(default)]
    pub storage: StorageConfig,
    #[serde(default)]
    pub network: NetworkInstance,
    #[serde(default)]
    pub hardware: HardwareConfig,
}

/// The on-disk operator config schema. A bare `profile = "..."` file is valid;
/// everything under `[instance]` is optional and defaulted.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct NodeConfigFile {
    #[serde(default)]
    pub profile: DeploymentProfile,
    #[serde(default)]
    pub instance: NodeInstance,
}

// ── The validated-config edge newtype ────────────────────────────────────────

/// A [`NodeConfig`] that has passed the boot coherence gate.
///
/// The only constructors are [`NodeConfig::assemble`], [`NodeConfig::for_profile`],
/// and [`NodeConfig::load`] — each runs the gate. The boot path calls
/// [`ValidatedNodeConfig::into_inner`] to hand the plain config to the actors;
/// the typestate is a transient proof token (edge newtype), not threaded inward.
///
/// Forgery resistance is structural: the field is private (no struct literal)
/// and the type has no `Deserialize` impl (it cannot be conjured from bytes).
///
/// The field is private — no struct literal outside this module:
///
/// ```compile_fail
/// use phalanx_node::config::{NodeConfig, ValidatedNodeConfig};
/// let _forge = ValidatedNodeConfig(NodeConfig::default());
/// ```
///
/// It has no `Deserialize` impl — it cannot be conjured from attacker bytes:
///
/// ```compile_fail
/// fn assert_de<T: serde::de::DeserializeOwned>() {}
/// assert_de::<phalanx_node::config::ValidatedNodeConfig>();
/// ```
#[derive(Debug, Clone)]
pub struct ValidatedNodeConfig(NodeConfig);

impl ValidatedNodeConfig {
    /// Consume the proof token and yield the plain config for the actors.
    #[must_use]
    pub fn into_inner(self) -> NodeConfig {
        self.0
    }

    /// Borrow the validated config without consuming the token.
    #[must_use]
    pub fn get(&self) -> &NodeConfig {
        &self.0
    }
}

#[derive(Debug)]
pub enum ConfigError {
    NotFound(String),
    ParseError(String),
    PermissionDenied(String),
    Incoherent(Incoherence),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound(msg) => write!(f, "Configuration not found: {msg}"),
            Self::ParseError(msg) => write!(f, "Failed to parse configuration: {msg}"),
            Self::PermissionDenied(msg) => write!(f, "Permission denied reading config: {msg}"),
            Self::Incoherent(e) => write!(f, "Incoherent configuration: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl From<Incoherence> for ConfigError {
    fn from(e: Incoherence) -> Self {
        Self::Incoherent(e)
    }
}

// --- Helper Functions and Initializers ---

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
fn default_vault_path() -> String {
    // Dev-only default. The shipped sentinel binary overrides this with an
    // OS-correct data dir via `crate::paths::NodePaths` (and mobile overrides
    // it with the app sandbox dir); see `paths::DEV_DEFAULT_VAULT_PATH`.
    "./sim_vault".to_string()
}
fn default_buffer() -> usize {
    100
}
fn default_listen_addresses() -> Vec<String> {
    vec![
        "/ip4/0.0.0.0/udp/0/quic-v1".to_string(),
        "/ip4/0.0.0.0/tcp/0".to_string(),
    ]
}
fn default_camera_fps() -> Fps {
    Fps::new(10)
}
fn default_audio_sample_rate() -> SampleRate {
    SampleRate::new(16_000)
}
fn default_audio_channels() -> ChannelCount {
    ChannelCount::new(1)
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            vault_path: default_vault_path(),
            max_video_buffer: default_buffer(),
            max_audio_buffer: default_buffer(),
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
            camera_fps: default_camera_fps(),
            audio_sample_rate: default_audio_sample_rate(),
            audio_channels: default_audio_channels(),
        }
    }
}

impl NodeConfig {
    /// Build a [`NodeConfig`] from a profile (pinned fields) and instance data.
    fn from_parts(profile: DeploymentProfile, instance: &NodeInstance) -> Self {
        Self {
            storage: instance.storage.clone(),
            network: NetworkConfig::from_profile(profile, &instance.network),
            hardware: instance.hardware.clone().validated(),
        }
    }

    /// Assemble and validate a config from a profile + operator instance data.
    ///
    /// Hard incoherence (a deployment guaranteed broken from this binary's own
    /// viewpoint) returns `Err`. Suspicious-but-legal values are logged via
    /// `tracing::warn!` and do not block boot.
    ///
    /// # Errors
    /// Returns [`Incoherence`] for a hard coherence violation (e.g. an archival
    /// custody peer with no dialable `/p2p/` tail).
    pub fn assemble(
        profile: DeploymentProfile,
        instance: &NodeInstance,
    ) -> Result<ValidatedNodeConfig, Incoherence> {
        let config = Self::from_parts(profile, instance);
        validate_node(&config, profile)?;
        Ok(ValidatedNodeConfig(config))
    }

    /// Assemble from a profile with default instance data. Infallible in
    /// practice (defaults are coherent) but returns `Result` for uniformity.
    ///
    /// # Errors
    /// Propagates [`Incoherence`] from [`NodeConfig::assemble`].
    pub fn for_profile(profile: DeploymentProfile) -> Result<ValidatedNodeConfig, Incoherence> {
        Self::assemble(profile, &NodeInstance::default())
    }

    /// Load a validated config from a TOML file (`profile = "..."` + optional
    /// `[instance]` tables).
    ///
    /// # Errors
    /// [`ConfigError::ParseError`] on IO/TOML failure, [`ConfigError::Incoherent`]
    /// on a hard coherence violation.
    pub fn load<P: AsRef<Path>>(path: P) -> Result<ValidatedNodeConfig, ConfigError> {
        let content =
            fs::read_to_string(path).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        let file: NodeConfigFile =
            toml::from_str(&content).map_err(|e| ConfigError::ParseError(e.to_string()))?;
        Ok(Self::assemble(file.profile, &file.instance)?)
    }

    /// Load configuration from the `PHALANX_CONFIG` environment variable.
    ///
    /// - `PHALANX_CONFIG` set: the file **must** parse and cohere, else `Err`
    ///   (loud failure — no silent fallback to defaults).
    /// - `PHALANX_CONFIG` unset: the default profile is used, logged loudly.
    ///   This is the normal path on mobile (Flutter provides config via FFI).
    ///
    /// # Errors
    /// Propagates [`ConfigError`] from [`NodeConfig::load`].
    pub fn load_from_env() -> Result<ValidatedNodeConfig, ConfigError> {
        match env::var("PHALANX_CONFIG") {
            Ok(path) => Self::load(&path),
            Err(_) => {
                let profile = DeploymentProfile::default_profile();
                tracing::warn!(
                    target: "phalanx::config",
                    profile = profile.name(),
                    "PHALANX_CONFIG not set — starting with the default deployment profile"
                );
                Ok(Self::for_profile(profile)?)
            }
        }
    }

    /// Simulation defaults (the `Simulation` profile, default instance).
    #[must_use]
    pub fn test_defaults() -> Self {
        Self::from_parts(DeploymentProfile::Simulation, &NodeInstance::default())
    }

    #[must_use]
    pub fn test_salvage_on_node_death() -> Self {
        let mut cfg = Self::test_defaults();
        cfg.storage.vault_path = "sim_vault".to_string();
        cfg
    }
}

impl Default for NodeConfig {
    /// The standard default configuration: the default profile, default instance.
    fn default() -> Self {
        Self::from_parts(
            DeploymentProfile::default_profile(),
            &NodeInstance::default(),
        )
    }
}

/// Boot coherence validation over assembled instance data. Hard violations
/// return `Err`; suspicious-but-legal values are logged and tolerated.
fn validate_node(config: &NodeConfig, profile: DeploymentProfile) -> Result<(), Incoherence> {
    let net = &config.network;

    // HARD: a configured archival custody peer that cannot be dialed to a
    // specific peer is a directed-push target that can never receive a push.
    for peer in &net.archival_peers {
        if peer.peer_id().is_none() {
            return Err(Incoherence::UndialableArchivalPeer {
                address: peer.address.clone(),
            });
        }
    }

    // WARN: target replica count the operator cannot meet with the configured
    // Strongholds. `target_replica_count` is a log-only policy field, so this
    // must not block boot.
    if net.target_replica_count > net.archival_peers.len() {
        tracing::warn!(
            target: "phalanx::config",
            target_replica_count = net.target_replica_count,
            archival_peers = net.archival_peers.len(),
            "target_replica_count exceeds configured archival peers — custody quorum cannot be met"
        );
    }

    // WARN: archival peers on a profile with no Stronghold role.
    if !profile.has_stronghold_role() && !net.archival_peers.is_empty() {
        tracing::warn!(
            target: "phalanx::config",
            profile = profile.name(),
            "profile has no Stronghold role but archival peers are configured"
        );
    }

    // WARN: storage caps out of nesting order (silent-incoherence leak).
    let per_owner = config.storage.max_foreign_per_owner_bytes.0;
    let foreign = config.storage.max_foreign_storage_bytes.0;
    let total = config.storage.max_storage_bytes.0;
    if per_owner > foreign || foreign > total {
        tracing::warn!(
            target: "phalanx::config",
            max_foreign_per_owner_bytes = per_owner,
            max_foreign_storage_bytes = foreign,
            max_storage_bytes = total,
            "storage caps out of order: expected per_owner <= foreign <= total"
        );
    }

    // WARN: a single egress bundle that exceeds this node's own chunk ceiling
    // would be rejected by its own inbound gate at peers with the same cap.
    let bundle = usize::try_from(net.symbol_bundle_size.get()).unwrap_or(usize::MAX);
    if let Some(product) = bundle.checked_mul(net.symbol_size.0) {
        if product > net.max_chunk_size_bytes {
            tracing::warn!(
                target: "phalanx::config",
                bundle_bytes = product,
                max_chunk_size_bytes = net.max_chunk_size_bytes,
                "symbol_bundle_size × symbol_size exceeds max_chunk_size_bytes — egress bundles may be rejected"
            );
        }
    }

    Ok(())
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
    use phalanx_proto::network::deployment::{
        DEFAULT_MAX_CHUNK_SIZE_BYTES, DEFAULT_PROTOCOL_VERSION,
    };

    // ── Turnkey archival-peer targeting ─────────────────────────────────────

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
        let p = ArchivalPeer {
            address: "/ip4/10.0.0.5/udp/4001/quic-v1".to_string(),
            stronghold_did: None,
        };
        assert!(p.peer_id().is_none());
    }

    #[test]
    fn archival_peer_peer_id_ignores_trailing_protocols() {
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

    // ── Profile projection ──────────────────────────────────────────────────

    #[test]
    fn default_projects_canonical_topics_and_pinned_wire_values() {
        let net = NetworkConfig::default();
        assert_eq!(net.video_topic, MeshTopic::video());
        assert_eq!(net.audio_topic, MeshTopic::audio());
        assert_eq!(net.control_topic, MeshTopic::control());
        assert_eq!(net.revocation_topic, MeshTopic::revocation());
        assert_eq!(net.protocol_version, DEFAULT_PROTOCOL_VERSION);
        assert_eq!(net.max_chunk_size_bytes, DEFAULT_MAX_CHUNK_SIZE_BYTES);
    }

    #[test]
    fn solo_device_pins_zero_replicas_community_pins_one() {
        let solo = NodeConfig::for_profile(DeploymentProfile::SoloDevice)
            .unwrap()
            .into_inner();
        assert_eq!(solo.network.target_replica_count, 0);
        assert!(!solo.network.require_psk);

        let community = NodeConfig::for_profile(DeploymentProfile::CommunityWithStronghold)
            .unwrap()
            .into_inner();
        assert_eq!(community.network.target_replica_count, 1);
    }

    #[test]
    fn high_risk_pins_psk_required() {
        let cfg = NodeConfig::for_profile(DeploymentProfile::HighRiskCrossBorder)
            .unwrap()
            .into_inner();
        assert!(cfg.network.require_psk);
        assert_eq!(cfg.network.target_replica_count, 2);
    }

    // ── File schema: profile selection + pinned-field absence ───────────────

    #[test]
    fn bare_profile_file_uses_named_profile_and_default_instance() {
        let file: NodeConfigFile =
            toml::from_str("profile = \"community_with_stronghold\"").expect("TOML parses");
        assert_eq!(file.profile, DeploymentProfile::CommunityWithStronghold);
        let cfg = NodeConfig::assemble(file.profile, &file.instance)
            .unwrap()
            .into_inner();
        assert_eq!(cfg.network.video_topic, MeshTopic::video());
        assert_eq!(cfg.network.protocol_version, DEFAULT_PROTOCOL_VERSION);
    }

    #[test]
    fn omitted_profile_defaults_to_solo_device() {
        let file: NodeConfigFile = toml::from_str("").expect("empty TOML parses");
        assert_eq!(file.profile, DeploymentProfile::default_profile());
        assert_eq!(file.profile, DeploymentProfile::SoloDevice);
    }

    #[test]
    fn internal_profile_is_not_selectable_from_a_file() {
        // `#[serde(skip)]` removes Development/Simulation from the deserializer.
        let parsed: Result<NodeConfigFile, _> = toml::from_str("profile = \"simulation\"");
        assert!(parsed.is_err());
    }

    #[test]
    fn a_pinned_field_in_the_instance_table_is_a_parse_error() {
        // `protocol_version` is profile-pinned and structurally absent from
        // NetworkInstance; deny_unknown_fields rejects it.
        let parsed: Result<NodeConfigFile, _> = toml::from_str(
            r#"
            profile = "solo_device"
            [instance.network]
            protocol_version = "/phalanx/9.9.9"
            "#,
        );
        assert!(parsed.is_err());
    }

    #[test]
    fn instance_network_tunables_are_accepted() {
        let file: NodeConfigFile = toml::from_str(
            r#"
            profile = "solo_device"
            [instance.network]
            bootstrap_peers = ["/ip4/1.2.3.4/tcp/4001"]
            "#,
        )
        .expect("TOML parses");
        assert_eq!(
            file.instance.network.bootstrap_peers,
            vec!["/ip4/1.2.3.4/tcp/4001".to_string()]
        );
    }

    // ── Boot validation ─────────────────────────────────────────────────────

    #[test]
    fn undialable_archival_peer_is_a_hard_incoherence() {
        let mut instance = NodeInstance::default();
        instance.network.archival_peers = vec![ArchivalPeer {
            address: "/ip4/10.0.0.5/udp/4001/quic-v1".to_string(), // no /p2p tail
            stronghold_did: None,
        }];
        let result = NodeConfig::assemble(DeploymentProfile::CommunityWithStronghold, &instance);
        assert!(matches!(
            result,
            Err(Incoherence::UndialableArchivalPeer { .. })
        ));
    }

    #[test]
    fn dialable_archival_peer_assembles() {
        let mut instance = NodeInstance::default();
        instance.network.archival_peers = vec![ArchivalPeer {
            address: "/ip4/10.0.0.5/udp/4001/quic-v1/p2p/12D3KooWStronghold".to_string(),
            stronghold_did: None,
        }];
        assert!(
            NodeConfig::assemble(DeploymentProfile::CommunityWithStronghold, &instance).is_ok()
        );
    }

    // ── HardwareConfig::validated() repairs out-of-range deserialized values ─

    #[test]
    fn validated_clamps_zero_fps_to_one() {
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
