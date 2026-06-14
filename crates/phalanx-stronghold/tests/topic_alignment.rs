// Cross-crate profile-coherence guard.
//
// The node and the Stronghold compile their configs independently. They once
// disagreed on the gossipsub `/1.0.0` topic suffix AND on the libp2p
// protocol_version (`/phalanx/1.0.0` vs `/phalanx/1.1.0`, which split the
// Kademlia DHT). Both classes of drift are now impossible by construction:
// every coherence-critical value is projected from a shared `DeploymentProfile`
// in phalanx-proto. This test is the executable proof that the two binaries,
// assembled from the same profile, actually share a mesh.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use phalanx_node::config::NodeConfig;
use phalanx_node::network::orchestrator;
use phalanx_proto::prelude::{DEFAULT_PROTOCOL_VERSION, DeploymentProfile, MeshTopic};
use phalanx_stronghold::config::{StrongholdConfig, StrongholdConfigFile};
use phalanx_stronghold::swarm;

/// For every Stronghold-bearing profile, the node and the Stronghold assembled
/// from that same profile must (a) agree on every media/revocation topic the
/// node publishes toward the Stronghold, and (b) agree on `protocol_version`
/// (or they form different Kademlia DHTs and never discover each other).
#[test]
fn each_stronghold_profile_shares_topics_and_protocol_version() {
    for profile in DeploymentProfile::public_archetypes() {
        if !profile.has_stronghold_role() {
            continue;
        }
        let node = NodeConfig::for_profile(profile)
            .expect("node assembles")
            .into_inner();
        let sh = StrongholdConfig::for_profile(profile)
            .expect("stronghold assembles")
            .into_inner();
        let sh_sub = swarm::subscribe_topics(&sh.network);

        for topic in [
            node.network.video_topic.to_string(),
            node.network.audio_topic.to_string(),
            node.network.revocation_topic.to_string(),
        ] {
            assert!(
                sh_sub.contains(&topic),
                "profile {}: Stronghold does not subscribe node topic {topic}",
                profile.name()
            );
        }

        assert_eq!(
            node.network.protocol_version,
            sh.network.protocol_version,
            "profile {}: node and Stronghold protocol_version differ — split DHT",
            profile.name()
        );
        assert_eq!(
            node.network.protocol_version,
            DEFAULT_PROTOCOL_VERSION,
            "profile {}: protocol_version is not the single-source-of-truth constant",
            profile.name()
        );
    }
}

/// The node must hear every class it has an inbound handler for: peers' media
/// (ingestion), heartbeats (vitals), and broadcast revocations.
#[test]
fn node_subscribes_to_every_class_it_handles() {
    let node = NodeConfig::default().network;
    let sub = orchestrator::subscribe_topics(&node);
    for topic in [
        node.video_topic.to_string(),
        node.audio_topic.to_string(),
        node.control_topic.to_string(),
        node.revocation_topic.to_string(),
    ] {
        assert!(sub.contains(&topic), "node subscribe list missing {topic}");
    }
}

/// Every message class that is *published* on the mesh must have an intended
/// subscriber on either the node or the Stronghold — except classes on an
/// explicit publish-only allow-list. This is the guard that catches a topic
/// that is published to but subscribed by nobody (the original revocation and
/// Silent-Canary gaps).
#[test]
fn every_published_class_has_a_subscriber_or_is_allow_listed() {
    let node = NodeConfig::default().network;
    let sh = StrongholdConfig::default();

    let mut subscribed: Vec<String> = orchestrator::subscribe_topics(&node);
    subscribed.extend(swarm::subscribe_topics(&sh.network));

    // The full set of classes published anywhere on the mesh.
    let published = [
        MeshTopic::video(),
        MeshTopic::audio(),
        MeshTopic::control(),
        MeshTopic::revocation(),
        MeshTopic::mesh(),
    ];
    // Published-but-intentionally-unsubscribed: the generic mesh/canary topic
    // has no inbound handler yet (see orchestrator::subscribe_topics docs).
    let publish_only = [MeshTopic::mesh()];

    for class in &published {
        let is_subscribed = subscribed.contains(&class.to_string());
        let is_allow_listed = publish_only.contains(class);
        assert!(
            is_subscribed || is_allow_listed,
            "published class {class} has no subscriber and is not on the publish-only allow-list"
        );
    }
}

/// A `stronghold.toml` selecting a profile with no Stronghold role is a hard,
/// named failure — not a silent mis-assembly.
#[test]
fn stronghold_file_with_a_non_stronghold_profile_is_rejected() {
    let file: StrongholdConfigFile =
        toml::from_str("profile = \"solo_device\"").expect("TOML parses");
    let result = StrongholdConfig::assemble(file.profile, &file.instance);
    assert!(result.is_err(), "solo_device has no Stronghold role");
}
