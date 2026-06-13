// Cross-crate topic-alignment guard.
//
// Gossipsub topics are exact-match strings, and the node and the Stronghold
// compile their defaults independently — they once disagreed on the `/1.0.0`
// suffix, so a default-configured node and a default-configured Stronghold
// shared no media topic and Stronghold passive gossip collection silently
// received nothing. Both sides now derive their defaults from the canonical
// `MeshTopic` constructors in phalanx-proto; this test is what keeps them
// from drifting apart again.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use phalanx_node::config::NetworkConfig as NodeNetworkConfig;
use phalanx_node::network::orchestrator;
use phalanx_stronghold::config::StrongholdConfig;
use phalanx_stronghold::swarm;

/// Every message class a default node publishes toward Strongholds must be in
/// the default Stronghold's subscribe list: media (passive gossip collection)
/// and revocation (Cryptographic Forgetting honored against custody copies).
#[test]
fn default_node_publish_topics_are_subscribed_by_default_stronghold() {
    let node = NodeNetworkConfig::default();
    let stronghold = StrongholdConfig::default();
    let sub = swarm::subscribe_topics(&stronghold.network);

    for topic in [
        node.video_topic.to_string(),
        node.audio_topic.to_string(),
        node.revocation_topic.to_string(),
    ] {
        assert!(
            sub.contains(&topic),
            "default Stronghold does not subscribe to node topic {topic}; \
             a default node and a default Stronghold would not share a mesh"
        );
    }
}

/// The node must hear every class it has an inbound handler for: peers' media
/// (ingestion), heartbeats (vitals), and broadcast revocations.
#[test]
fn default_node_subscribes_to_every_class_it_handles() {
    let node = NodeNetworkConfig::default();
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

/// The `serde(skip)` regression, asserted cross-crate: parsing a
/// stronghold.toml must not disconnect the Stronghold from the node's media
/// topics. (Bare `skip` fills fields from the *field type's* default —
/// "/phalanx/default" — not the struct's `Default` impl.)
#[test]
fn file_configured_stronghold_still_shares_the_node_mesh() {
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

    let node = NodeNetworkConfig::default();
    let sub = swarm::subscribe_topics(&parsed.network);
    assert!(sub.contains(&node.video_topic.to_string()));
    assert!(sub.contains(&node.audio_topic.to_string()));
}
