//! Deployment profiles — the operator-facing topology selector.
//!
//! A `DeploymentProfile` is a Noun (shared vocabulary, like [`MeshTopic`]).
//! Selecting one fixes *every* cross-binary coherence-critical config value as
//! a single coherent bundle: the libp2p protocol version, the gossipsub topic
//! set, the wire chunk ceiling, the replica-custody target, and the PSK
//! posture. Both `phalanx-node` and `phalanx-stronghold` PROJECT the same
//! profile, so two binaries on the same profile cannot silently disagree on a
//! wire-coupled value (the class of bug that previously split the Kademlia DHT
//! when the node pinned `/phalanx/1.0.0` and the Stronghold inherited
//! `/phalanx/1.1.0`).
//!
//! This module holds only the *vocabulary* (the profile, its projected values,
//! and the [`Incoherence`] error). The per-role projection (`assemble`) and the
//! validated-config newtype live in the role crates, which own the IO-tied
//! instance fields the profile is layered onto.

use crate::network::topic::MeshTopic;
use serde::Deserialize;

/// The libp2p protocol version string.
///
/// Feeds the Kademlia `StreamProtocol` (`/phalanx/kad/{version}`) and the
/// identify agent string in the transport factory. Kademlia only forms a DHT
/// among peers sharing the *exact* protocol string, so this is a single source
/// of truth shared by every node, Stronghold, and the transport default.
pub const DEFAULT_PROTOCOL_VERSION: &str = "/phalanx/1.1.0";

/// Wire chunk ceiling, in bytes. Gossipsub `max_transmit` is derived as 2× this
/// in the transport builder. Sized to fit a 100-symbol RaptorQ bundle
/// (100 × 1200 B) plus postcard framing, with margin.
///
/// Wire-coupled: a peer with a smaller ceiling silently drops a larger peer's
/// frames (the inbound-size gate in `MeshSentinel`), so it is pinned
/// network-wide by the profile, never tuned per deployment.
pub const DEFAULT_MAX_CHUNK_SIZE_BYTES: usize = 131_072;

/// The named, expert-authored deployment topology.
///
/// Operator-facing and `Deserialize` (chosen by name in TOML), but deliberately
/// **not** `Serialize` — a profile is an input selector, never a wire value.
/// `#[non_exhaustive]` so adding or renaming an archetype stays a one-line
/// change here plus one arm in [`DeploymentProfile::knobs`]; downstream crates
/// reach every value through accessors, never an exhaustive `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DeploymentProfile {
    /// One phone, no Stronghold. Self-custody only (durability via peer
    /// replication); outbound-only listen; PSK optional.
    SoloDevice,
    /// Small trusted group on a local mesh, no infrastructure. Closed swarm
    /// (PSK required); inbound-reachable; no Stronghold custody.
    AffinityGroupLan,
    /// Phones plus a wall-powered Stronghold custody node. One custody replica;
    /// Stronghold is inbound-reachable; PSK optional.
    CommunityWithStronghold,
    /// Hardened field posture for state-level adversaries. Two custody
    /// replicas; PSK required; Stronghold inbound-reachable.
    HighRiskCrossBorder,
    /// Internal: permissive dev defaults. Not selectable from a config file.
    #[serde(skip)]
    Development,
    /// Internal: simulation defaults. Not selectable from a config file.
    #[serde(skip)]
    Simulation,
}

/// Whether transport-layer PSK is mandatory. A two-state type, not a bare
/// `bool`, so a projection cannot silently flip the security posture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PskPosture {
    /// Refuse to start without a valid PSK.
    Required,
    /// PSK optional (open swarm).
    Optional,
}

impl PskPosture {
    /// Lower to the `require_psk` flag the transport config consumes.
    #[must_use]
    pub fn require_psk(self) -> bool {
        matches!(self, Self::Required)
    }
}

/// The listen-address shape a profile expects of its Stronghold role. Lets boot
/// validation flag a custody-target Stronghold that bound only an ephemeral or
/// loopback address (pushes to it would never connect).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenShape {
    /// Must bind a routable inbound transport (a custody push target).
    InboundReachable,
    /// Ephemeral / outbound-only acceptable (a mobile leaf).
    OutboundOnly,
}

/// Replica-custody posture projected by a profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReplicaPolicy {
    /// K: distinct Stronghold custody replicas before a recording is considered
    /// safely in custody. `0` for profiles with no Stronghold role.
    pub target_replica_count: usize,
}

/// The fixed gossipsub topic set for a deployment, by message class. Built only
/// from [`MeshTopic`] constructors — the single source of truth for topic
/// strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TopicSet {
    pub video: MeshTopic,
    pub audio: MeshTopic,
    pub control: MeshTopic,
    pub revocation: MeshTopic,
    /// Generic mesh/canary control topic. Published to by the Silent Canary;
    /// not subscribed by default (no inbound alert handler yet).
    pub mesh: MeshTopic,
}

impl TopicSet {
    /// The well-known topic set every profile pins today.
    #[must_use]
    pub fn well_known() -> Self {
        Self {
            video: MeshTopic::video(),
            audio: MeshTopic::audio(),
            control: MeshTopic::control(),
            revocation: MeshTopic::revocation(),
            mesh: MeshTopic::mesh(),
        }
    }
}

/// The full coherent value bundle an archetype expands to. Private: operators
/// choose an archetype, never these fields directly.
#[derive(Debug, Clone, Copy)]
struct CoherenceKnobs {
    protocol_version: &'static str,
    max_chunk_size_bytes: usize,
    replica_policy: ReplicaPolicy,
    psk_posture: PskPosture,
    listen_shape: ListenShape,
    has_stronghold_role: bool,
}

impl DeploymentProfile {
    /// The single place a new archetype is wired. Every accessor delegates here.
    fn knobs(self) -> CoherenceKnobs {
        let base = CoherenceKnobs {
            protocol_version: DEFAULT_PROTOCOL_VERSION,
            max_chunk_size_bytes: DEFAULT_MAX_CHUNK_SIZE_BYTES,
            replica_policy: ReplicaPolicy {
                target_replica_count: 0,
            },
            psk_posture: PskPosture::Optional,
            listen_shape: ListenShape::OutboundOnly,
            has_stronghold_role: false,
        };
        match self {
            Self::SoloDevice | Self::Development | Self::Simulation => base,
            Self::AffinityGroupLan => CoherenceKnobs {
                psk_posture: PskPosture::Required,
                listen_shape: ListenShape::InboundReachable,
                ..base
            },
            Self::CommunityWithStronghold => CoherenceKnobs {
                replica_policy: ReplicaPolicy {
                    target_replica_count: 1,
                },
                listen_shape: ListenShape::InboundReachable,
                has_stronghold_role: true,
                ..base
            },
            Self::HighRiskCrossBorder => CoherenceKnobs {
                replica_policy: ReplicaPolicy {
                    target_replica_count: 2,
                },
                psk_posture: PskPosture::Required,
                listen_shape: ListenShape::InboundReachable,
                has_stronghold_role: true,
                ..base
            },
        }
    }

    /// The pinned libp2p protocol version (same for every profile today).
    #[must_use]
    pub fn protocol_version(self) -> &'static str {
        self.knobs().protocol_version
    }

    /// The pinned wire chunk ceiling.
    #[must_use]
    pub fn max_chunk_size_bytes(self) -> usize {
        self.knobs().max_chunk_size_bytes
    }

    /// The pinned gossipsub topic set.
    #[must_use]
    pub fn topics(self) -> TopicSet {
        TopicSet::well_known()
    }

    /// The replica-custody posture.
    #[must_use]
    pub fn replica_policy(self) -> ReplicaPolicy {
        self.knobs().replica_policy
    }

    /// The PSK posture.
    #[must_use]
    pub fn psk_posture(self) -> PskPosture {
        self.knobs().psk_posture
    }

    /// The expected Stronghold listen shape.
    #[must_use]
    pub fn listen_shape(self) -> ListenShape {
        self.knobs().listen_shape
    }

    /// Whether this topology includes a Stronghold custody role. A Stronghold
    /// cannot be assembled from a profile for which this is false.
    #[must_use]
    pub fn has_stronghold_role(self) -> bool {
        self.knobs().has_stronghold_role
    }

    /// The profile used when none is named (env-unset, null FFI config). The
    /// most conservative topology: a lone phone.
    #[must_use]
    pub const fn default_profile() -> Self {
        Self::SoloDevice
    }

    /// Whether this is one of the operator-selectable (non-internal) archetypes.
    #[must_use]
    pub fn is_public(self) -> bool {
        Self::public_archetypes().contains(&self)
    }

    /// Stable, lower-case name (matches the TOML representation). For logs and
    /// error messages.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::SoloDevice => "solo_device",
            Self::AffinityGroupLan => "affinity_group_lan",
            Self::CommunityWithStronghold => "community_with_stronghold",
            Self::HighRiskCrossBorder => "high_risk_cross_border",
            Self::Development => "development",
            Self::Simulation => "simulation",
        }
    }

    /// The operator-selectable archetypes, for enumeration in coherence tests.
    #[must_use]
    pub fn public_archetypes() -> [Self; 4] {
        [
            Self::SoloDevice,
            Self::AffinityGroupLan,
            Self::CommunityWithStronghold,
            Self::HighRiskCrossBorder,
        ]
    }
}

impl Default for DeploymentProfile {
    fn default() -> Self {
        Self::default_profile()
    }
}

/// A coherence violation found while assembling a role config from a profile
/// plus operator instance data. Primitive-only variants keep this crate inert.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Incoherence {
    /// An archival-custody peer address carries no `/p2p/<peer-id>` tail, so it
    /// cannot be a directed-push target — the deployment is guaranteed broken.
    #[error(
        "archival peer address {address:?} has no /p2p/<peer-id> tail — it cannot be a directed-push custody target"
    )]
    UndialableArchivalPeer { address: String },

    /// A Stronghold was configured from a profile that has no Stronghold role
    /// (e.g. a `stronghold.toml` selecting `solo_device`).
    #[error(
        "profile {profile} has no Stronghold role — a Stronghold cannot be configured from it"
    )]
    ProfileHasNoStrongholdRole { profile: &'static str },
}

#[cfg(test)]
#[allow(clippy::indexing_slicing, clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_pins_the_same_protocol_and_chunk_ceiling() {
        for p in DeploymentProfile::public_archetypes() {
            assert_eq!(p.protocol_version(), DEFAULT_PROTOCOL_VERSION);
            assert_eq!(p.max_chunk_size_bytes(), DEFAULT_MAX_CHUNK_SIZE_BYTES);
        }
    }

    #[test]
    fn every_profile_pins_the_well_known_topics() {
        for p in DeploymentProfile::public_archetypes() {
            assert_eq!(p.topics(), TopicSet::well_known());
        }
    }

    #[test]
    fn stronghold_role_matches_replica_expectation() {
        // Profiles that expect custody replicas carry a Stronghold role; those
        // that do not, do not.
        assert!(!DeploymentProfile::SoloDevice.has_stronghold_role());
        assert!(!DeploymentProfile::AffinityGroupLan.has_stronghold_role());
        assert!(DeploymentProfile::CommunityWithStronghold.has_stronghold_role());
        assert!(DeploymentProfile::HighRiskCrossBorder.has_stronghold_role());
    }

    #[test]
    fn high_risk_requires_psk_solo_does_not() {
        assert!(DeploymentProfile::HighRiskCrossBorder
            .psk_posture()
            .require_psk());
        assert!(!DeploymentProfile::SoloDevice.psk_posture().require_psk());
    }

    // Deserialization behavior (snake_case names, `#[serde(skip)]` on the
    // internal variants) is exercised in the node config tests, where a
    // human-readable format (`toml`) is a dev-dependency. proto has no
    // text-format dev-dep, so it is not tested here.
}
