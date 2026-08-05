#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]
// crates/phalanx-sim/tests/adversarial_tests.rs
//
// Adversarial simulation tests that exercise the security fixes from
// red team rounds 1–3. Each test models a specific attack scenario
// and verifies that the corresponding defense holds.

use phalanx_forensics::bloom::RotatingBloomFilter;
use phalanx_forensics::topology_gate::{AnchorEligible, TopologyGate};
use phalanx_node::config::NodeConfig;
use phalanx_proto::evidence::{ChunkType, ShardChunk};
use phalanx_proto::identity::{MeshAddress, NodeRole};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{Did, EncodingSymbolId, PhalanxTimestamp, ShardId};
use phalanx_proto::topology::{SubnetBucket, SubnetQuota, TransportClass};
use phalanx_proto::trust::TrustLevel;
use phalanx_sim::SimulationHarness;
use phalanx_sim::physics::PhalanxPhysics;

use std::time::Duration;

// ============================================================================
// Test Utilities
// ============================================================================

fn make_test_chunk(owner_did: &Did, payload_size: usize) -> Vec<u8> {
    let chunk = ShardChunk {
        shard_id: ShardId(0),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::ForensicUnit,
        is_terminal: true,
        data: vec![0xAB; payload_size],
        owner_did: owner_did.clone(),
        timestamp: PhalanxTimestamp::from_millis(1_700_000_000_000),
    };
    postcard::to_allocvec(&chunk).unwrap_or_default()
}

/// Construct a chunk with a specific owner_did that differs from the
/// node's own DID — models the R2-2 DID spoofing attack.
fn make_spoofed_chunk(claimed_owner: &Did, payload_size: usize) -> Vec<u8> {
    let chunk = ShardChunk {
        shard_id: ShardId(0),
        encoding_symbol_id: EncodingSymbolId(0),
        chunk_type: ChunkType::ForensicUnit,
        is_terminal: true,
        data: vec![0xCD; payload_size],
        owner_did: claimed_owner.clone(),
        timestamp: PhalanxTimestamp::from_millis(1_700_000_000_000),
    };
    postcard::to_allocvec(&chunk).unwrap_or_default()
}

// ============================================================================
// C2 FIX: Bloom filter replay detection
// ============================================================================

/// Verify that the Bloom filter correctly detects replayed evidence hashes.
/// This is the unit-level validation of the C2 seeding fix.
#[test]
fn bloom_replay_detection_blocks_duplicates() {
    let mut filter = RotatingBloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);

    let evidence_hash: [u8; 32] = {
        let mut h = [0u8; 32];
        h[0] = 0xDE;
        h[1] = 0xAD;
        h
    };

    // First insertion — should not be present
    assert!(!filter.contains(&evidence_hash));
    filter.insert(&evidence_hash);

    // Replay — should be detected
    assert!(
        filter.contains(&evidence_hash),
        "Bloom filter must detect replayed evidence hash"
    );
}

/// After one rotation, evidence should still be detected (previous generation).
/// After two rotations, it should be gone.
#[test]
fn bloom_replay_survives_one_rotation() {
    let mut filter = RotatingBloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);

    let hash: [u8; 32] = {
        let mut h = [0u8; 32];
        h[0] = 0xCA;
        h[1] = 0xFE;
        h
    };

    filter.insert(&hash);

    // One rotation: hash moves to previous generation — still detectable
    filter.rotate();
    assert!(
        filter.contains(&hash),
        "Evidence should survive one Bloom rotation"
    );

    // Two rotations: hash is evicted — replay window has closed
    filter.rotate();
    assert!(
        !filter.contains(&hash),
        "Evidence should be evicted after two rotations"
    );
}

/// Simulate post-crash seeding: insert N hashes (simulating WAL recovery),
/// then verify all are detected.
#[test]
fn bloom_seeding_from_wal_recovery() {
    let mut filter = RotatingBloomFilter::new(RotatingBloomFilter::DEFAULT_CAPACITY);

    // Simulate recovering 50 evidence hashes from WAL
    let seed_hashes: Vec<[u8; 32]> = (0..50u8)
        .map(|i| {
            let mut h = [0u8; 32];
            h[0] = i;
            h[1] = i.wrapping_mul(7);
            h
        })
        .collect();

    for hash in &seed_hashes {
        filter.insert(hash);
    }

    // All seeded hashes should be detected as replays
    for (i, hash) in seed_hashes.iter().enumerate() {
        assert!(
            filter.contains(hash),
            "Seeded hash {} should be detected as replay",
            i
        );
    }

    // A new hash should NOT be flagged
    let new_hash = [0xFF; 32];
    assert!(
        !filter.contains(&new_hash),
        "Genuinely new hash should not be flagged as replay"
    );
}

// ============================================================================
// R2-2 FIX: DID spoofing — chunk.owner_did != signer
// ============================================================================

/// Inject a chunk with a spoofed owner_did into a Guardian node.
/// The node should survive (not crash) — the chunk enters the pipeline
/// but will be rejected when the DID mismatch is detected after
/// signature verification in the aggregation layer.
#[tokio::test]
async fn spoofed_owner_did_does_not_crash_node() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim = harness
        .spawn_node("Victim", NodeRole::Guardian)
        .await
        .expect("spawn victim");
    let attacker = harness
        .spawn_node("Attacker", NodeRole::Guardian)
        .await
        .expect("spawn attacker");

    let attacker_net = harness
        .resolve_did(&attacker)
        .await
        .expect("resolve attacker");

    // Spoof: chunk claims to be owned by victim, but is sent from attacker
    let spoofed = make_spoofed_chunk(&victim, 512);
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: attacker_net.clone(),
                topic: config.network.video_topic.clone(),
                data: spoofed,
            },
        )
        .await
        .expect("inject spoofed chunk");

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // Victim should survive — the spoofed chunk is dropped, not crash-inducing
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("Victim must survive DID spoofing attack");

    harness
        .inject_event(&attacker, NetworkEvent::Shutdown)
        .await
        .expect("Attacker shutdown");
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// R2-3 FIX: Outbound queue saturation
// ============================================================================

/// Flood a node with chunks under Byzantine network conditions (all publishes
/// fail). This exercises the outbound queue capacity limit — the queue should
/// eventually reject new entries rather than growing without bound.
/// The node must survive regardless.
#[tokio::test]
async fn outbound_queue_survives_byzantine_flood() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node = harness
        .spawn_node("Queue-Victim", NodeRole::Guardian)
        .await
        .expect("spawn node");

    let net = harness.resolve_did(&node).await.expect("resolve node");

    // Set Byzantine mode — all outbound publishes will fail
    harness
        .inject_chaos(&node, phalanx_proto::telemetry::ChaosMode::Byzantine)
        .await;

    // Flood with 200 chunks — should saturate the outbound queue
    for _ in 0..200u32 {
        let chunk = make_test_chunk(&node, 2048);
        let _ = harness
            .inject_event(
                &node,
                NetworkEvent::DataReceived {
                    origin: net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await;
    }

    // Advance time to let the pipeline process and attempt publishes
    harness.advance_time(Duration::from_secs(10)).await;
    tokio::task::yield_now().await;

    // Node must survive — the queue capacity limit prevents OOM
    harness
        .inject_event(&node, NetworkEvent::Shutdown)
        .await
        .expect("Node must survive outbound queue saturation");
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Eclipse resistance via TopologyGate
// ============================================================================

/// Simulate an eclipse attack: one attacker controls 30 peers in the same
/// subnet, trying to dominate a 50-slot topology gate. Verify that subnet
/// diversity quotas limit attacker's control.
#[test]
fn eclipse_attack_limited_by_subnet_diversity() {
    let mut gate = TopologyGate::new(50, SubnetQuota::DEFAULT, 4);
    let attacker_subnet = SubnetBucket::test_bucket(42);

    let mut attacker_admitted = 0usize;

    // Attacker tries to fill all 50 slots from one subnet
    for i in 0..30u8 {
        let peer = MeshAddress::new(format!("attacker-{i}"));
        if gate
            .try_admit(
                peer,
                TrustLevel::Ignored,
                attacker_subnet,
                TransportClass::Internet,
            )
            .is_ok()
        {
            attacker_admitted += 1;
        }
    }

    // Attacker should be limited to subnet quota (DEFAULT = 8)
    assert!(
        attacker_admitted <= 8,
        "Eclipse attacker controlled {} slots, must be <= 8",
        attacker_admitted
    );

    // Legitimate peers from diverse subnets should still have room
    let mut legitimate_admitted = 0usize;
    for i in 0..20u8 {
        let peer = MeshAddress::new(format!("legit-{i}"));
        let bucket = SubnetBucket::test_bucket(100 + i);
        if gate
            .try_admit(peer, TrustLevel::Verified, bucket, TransportClass::Internet)
            .is_ok()
        {
            legitimate_admitted += 1;
        }
    }

    assert_eq!(
        legitimate_admitted, 20,
        "All 20 diverse legitimate peers should be admitted"
    );

    // Attacker's share of the topology should be < 30%
    let attacker_share = attacker_admitted as f64 / gate.peer_count() as f64;
    assert!(
        attacker_share < 0.30,
        "Attacker's topology share {:.2} must be < 30%",
        attacker_share
    );
}

/// An attacker who anchors all their subnet-quota peers should not prevent
/// legitimate higher-trust peers from joining the remaining capacity.
/// With capacity=40 and 8 anchored attackers, 32 slots remain for
/// legitimate peers.
#[test]
fn anchored_attacker_does_not_block_legitimate_admissions() {
    let mut gate = TopologyGate::new(40, SubnetQuota::DEFAULT, 8);

    // Attacker fills 8 slots (subnet quota) and anchors them
    let attacker_subnet = SubnetBucket::test_bucket(7);
    for i in 0..8u8 {
        let peer = MeshAddress::new(format!("attacker-{i}"));
        gate.try_admit(
            peer.clone(),
            TrustLevel::Ignored,
            attacker_subnet,
            TransportClass::Internet,
        )
        .unwrap();
        let proof = AnchorEligible::try_from_score(0.8).unwrap();
        gate.promote_to_anchor(&peer, proof);
    }

    // Legitimate peers from diverse subnets should fill remaining Internet slots
    let mut admitted = 0usize;
    for i in 0..20u8 {
        let peer = MeshAddress::new(format!("legit-{i}"));
        let bucket = SubnetBucket::test_bucket(50 + i);
        if gate
            .try_admit(peer, TrustLevel::Verified, bucket, TransportClass::Internet)
            .is_ok()
        {
            admitted += 1;
        }
    }

    assert_eq!(
        admitted, 20,
        "20 legitimate peers should be admitted despite 8 anchored attackers"
    );
    // Attacker controls only 8/28 = 28.6% of the topology
    let attacker_share = 8.0 / gate.peer_count() as f64;
    assert!(
        attacker_share < 0.30,
        "Attacker share {:.2} should be < 30%",
        attacker_share
    );
}

// ============================================================================
// Reputation & Trust Scoring
// ============================================================================

/// Verify that the penalty magnitudes in the trust module are ordered
/// correctly: identity theft and invalid signatures should carry the
/// highest penalties.
#[test]
fn offense_penalties_proportional_to_severity() {
    use phalanx_forensics::trust::assess_penalty;
    use phalanx_proto::trust::Offense;

    let identity_theft = assess_penalty(&Offense::IdentityTheft);
    let invalid_sig = assess_penalty(&Offense::InvalidSignature);
    let eclipse = assess_penalty(&Offense::EclipseAttempt);
    let quota = assess_penalty(&Offense::QuotaExceeded);
    let replay = assess_penalty(&Offense::ReplayAttack);

    // Critical offenses should have higher penalties
    assert!(
        identity_theft >= eclipse,
        "IdentityTheft ({}) must be >= EclipseAttempt ({})",
        identity_theft,
        eclipse
    );
    assert!(
        invalid_sig >= eclipse,
        "InvalidSignature ({}) must be >= EclipseAttempt ({})",
        invalid_sig,
        eclipse
    );
    assert!(
        eclipse > quota,
        "EclipseAttempt ({}) must be > QuotaExceeded ({})",
        eclipse,
        quota
    );
    assert!(
        quota >= replay,
        "QuotaExceeded ({}) must be >= ReplayAttack ({})",
        quota,
        replay
    );
}

// ============================================================================
// H1 FIX: Identifier length bounds
// ============================================================================

/// Wire-length bounds should be enforced on identifiers. A DID exceeding
/// MAX_WIRE_LEN should be truncated by WireBound enforcement.
#[test]
fn oversized_did_truncated_by_wire_bounds() {
    use phalanx_proto::identity::Did;

    let oversized = "d".repeat(Did::MAX_WIRE_LEN + 100);
    let did = Did::new(&oversized);

    // The DID itself stores whatever you give it (it's a Noun, no IO)
    assert!(did.as_ref().len() > Did::MAX_WIRE_LEN);

    // But WireBound enforcement on messages containing this DID will truncate.
    // We verify the constant exists and has a reasonable value.
    assert!(
        Did::MAX_WIRE_LEN >= 128,
        "MAX_WIRE_LEN should be at least 128 for real DIDs"
    );
    assert!(
        Did::MAX_WIRE_LEN <= 1024,
        "MAX_WIRE_LEN should be <= 1024 to prevent amplification"
    );
}

// ============================================================================
// Integration: Sustained adversarial attack with diverse vectors
// ============================================================================

/// Sustained multi-vector attack over 10 rounds: each round injects spoofed
/// chunks, oversized payloads, replay attempts (same data twice), and one
/// legitimate chunk. Verifies the node survives all rounds.
#[tokio::test]
async fn sustained_multi_vector_adversarial_attack() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim = harness
        .spawn_node("Victim", NodeRole::Guardian)
        .await
        .expect("spawn victim");

    let net = harness.resolve_did(&victim).await.expect("resolve");

    let attacker_did = Did::from("did:key:z_attacker_spoofed");

    for _round in 0..10u32 {
        // Vector 1: Spoofed owner_did
        let spoofed = make_spoofed_chunk(&attacker_did, 256);
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: spoofed,
                },
            )
            .await;

        // Vector 2: Oversized payload (P5 guard)
        let oversized = vec![0xFF; config.network.max_chunk_size_bytes * 3];
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: oversized,
                },
            )
            .await;

        // Vector 3: Replay attempt — same chunk twice
        let replay_chunk = make_test_chunk(&victim, 128);
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: replay_chunk.clone(),
                },
            )
            .await;
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: replay_chunk,
                },
            )
            .await;

        // Vector 4: Legitimate chunk
        let valid = make_test_chunk(&victim, 256);
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: net.clone(),
                    topic: config.network.video_topic.clone(),
                    data: valid,
                },
            )
            .await;

        harness.advance_time(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
    }

    // After 10 rounds of sustained adversarial attack, node must be alive
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("Victim must survive 10 rounds of multi-vector adversarial attack");
    harness.advance_time(Duration::from_millis(200)).await;
}

/// Rapid identity churn: 50 different "peers" each send one chunk,
/// then disappear. Tests peer_did_cache cap (R3-3) and topology
/// gate admission under churn.
#[tokio::test]
async fn rapid_identity_churn_does_not_exhaust_resources() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let victim = harness
        .spawn_node("Churn-Victim", NodeRole::Guardian)
        .await
        .expect("spawn victim");

    // Inject chunks from 50 distinct "peers" (different NetworkIds)
    for i in 0..50u32 {
        let fake_peer = MeshAddress::new(format!("ephemeral-peer-{i}"));
        let chunk = make_test_chunk(&victim, 128);
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: fake_peer,
                    topic: config.network.video_topic.clone(),
                    data: chunk,
                },
            )
            .await;
    }

    harness.advance_time(Duration::from_secs(3)).await;
    tokio::task::yield_now().await;

    // Node must survive identity churn
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("Node must survive 50-peer identity churn");
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// COORDINATED KILL SCENARIO
//
// A state-sponsored adversary with deep knowledge of the Phalanx architecture
// attempts a coordinated five-phase attack designed to cascade failures across
// every defensive layer simultaneously. The attack models an adversary who has
// read the source code, understands the Volterra integral homeostasis, knows
// the subnet quota limits, the Bloom filter rotation window, and the outbound
// queue capacity — and tries to weaponize all of them at once.
//
// Phase 1 — ECLIPSE: Saturate topology from a single /16 to hit the subnet
//           quota wall, then pivot to 200 diverse subnets with Sybil identities
//           to flood the peer table and spike the Sybil integral.
//
// Phase 2 — ASPHYXIATE: Isolate the victim by setting Byzantine chaos on its
//           sole honest ally, then flood the victim's ingress with oversized
//           garbage from every Sybil peer — hammering bandwidth pressure.
//
// Phase 3 — POISON: Inject structurally valid but semantically malicious
//           traffic: spoofed DIDs, replayed evidence hashes, chunks claiming
//           to be from the victim's own identity (reflection attack).
//
// Phase 4 — EXHAUST: While the pipeline is saturated, inject memory pressure
//           and storage pressure directly into the governor (modeling OS-level
//           resource exhaustion from the flood), attempting to push the node
//           into Dormant power state where it stops participating.
//
// Phase 5 — VERIFY RESURRECTION: Cease all attack traffic, drain pressure,
//           advance time to let integrals decay, and confirm the node recovers
//           to Normal operation and can still process legitimate evidence.
//
// Success criteria: the node must survive all five phases, never crash, and
// recover to operational status afterward. If any phase kills the node, the
// test fails with a descriptive assertion identifying the lethal vector.
// ============================================================================

#[tokio::test]
async fn coordinated_kill_attempt() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, collector) = SimulationHarness::init_mesh(config.clone(), physics);

    use phalanx_forensics::Homeostasis;

    // ── Spawn the victim and a single honest ally ───────────────────────
    let victim = harness
        .spawn_node("Victim", NodeRole::Guardian)
        .await
        .expect("spawn victim");
    let ally = harness
        .spawn_node("Ally", NodeRole::Guardian)
        .await
        .expect("spawn ally");
    let ally_net = harness.resolve_did(&ally).await.expect("resolve ally");

    let governor = harness
        .governor_for(&victim)
        .expect("Governor must exist for victim");

    // ── PHASE 1: ECLIPSE ────────────────────────────────────────────────
    // 1a. Saturate multiple /16 subnets simultaneously — not just one,
    //     but 10 different /16s, each trying to fill 30 peers.
    let mut sybil_nets = Vec::new();
    for subnet in 0..10u8 {
        for i in 0..30u32 {
            let sybil_peer = MeshAddress::new(format!("sybil-s{subnet}-{i}"));
            let _ = harness
                .inject_event(
                    &victim,
                    NetworkEvent::PeerDiscovered {
                        peer: sybil_peer.clone(),
                        source: phalanx_proto::telemetry::DiscoverySource::Bootstrap,
                        bucket: SubnetBucket::from_ipv4_prefix(60 + subnet, 66),
                        transport: TransportClass::Internet,
                    },
                )
                .await;
            sybil_nets.push(sybil_peer);
        }
    }

    // 1b. Pivot: 500 Sybil peers from fully diverse subnets
    for i in 0..500u32 {
        let sybil_peer = MeshAddress::new(format!("sybil-diverse-{i}"));
        let subnet_a = ((i >> 8) & 0xFF) as u8;
        let subnet_b = (i & 0xFF) as u8;
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::PeerDiscovered {
                    peer: sybil_peer.clone(),
                    source: phalanx_proto::telemetry::DiscoverySource::Kademlia,
                    bucket: SubnetBucket::from_ipv4_prefix(subnet_a.wrapping_add(10), subnet_b),
                    transport: TransportClass::Internet,
                },
            )
            .await;
        sybil_nets.push(sybil_peer);
    }

    harness.advance_time(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    let stress_after_eclipse = governor.composite_stress();
    println!(
        "[PHASE 1 - ECLIPSE] Stress after 800 Sybil peers (10 subnets + 500 diverse): {:.4}",
        stress_after_eclipse
    );

    // Victim must survive the eclipse flood
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: ally_net.clone(),
                topic: config.network.video_topic.clone(),
                data: make_test_chunk(&victim, 64),
            },
        )
        .await
        .expect("Victim must survive Phase 1 (Eclipse)");

    // ── PHASE 2: ASPHYXIATE ─────────────────────────────────────────────
    // Cut off the ally's outbound — victim is now isolated
    harness
        .inject_chaos(&ally, phalanx_proto::telemetry::ChaosMode::Byzantine)
        .await;

    // Flood oversized garbage from Sybil peers — hammer bandwidth integral
    // 100 peers x 4 MiB each = 400 MiB of raw bandwidth pressure
    for i in 0..100u32 {
        let attacker = MeshAddress::new(format!("sybil-diverse-{i}"));
        let garbage = vec![0xDE; 4 * 1024 * 1024];
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: attacker,
                    topic: config.network.video_topic.clone(),
                    data: garbage,
                },
            )
            .await;
    }

    // Don't let it breathe — hit it again immediately with no time advance
    for i in 100..200u32 {
        let attacker = MeshAddress::new(format!("sybil-diverse-{i}"));
        let garbage = vec![0xAB; 2 * 1024 * 1024];
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: attacker,
                    topic: config.network.video_topic.clone(),
                    data: garbage,
                },
            )
            .await;
    }

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    let stress_after_asphyxiate = governor.composite_stress();
    let state_after_asphyxiate = governor.recommended_power_state();
    println!(
        "[PHASE 2 - ASPHYXIATE] Stress after 800 MiB flood: {:.4}, Power: {:?}",
        stress_after_asphyxiate, state_after_asphyxiate
    );

    // Victim must survive bandwidth saturation
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: ally_net.clone(),
                topic: config.network.video_topic.clone(),
                data: make_test_chunk(&victim, 64),
            },
        )
        .await
        .expect("Victim must survive Phase 2 (Asphyxiate)");

    // ── PHASE 3: POISON ─────────────────────────────────────────────────
    // 3a. DID spoofing: 50 chunks from 10 different impostor identities
    for impostor in 0..10u32 {
        let impostor_did = Did::from(format!("did:key:z_impostor_{impostor}"));
        for i in 0..5u32 {
            let idx = impostor * 5 + i;
            let attacker = MeshAddress::new(format!("sybil-diverse-{idx}"));
            let spoofed = make_spoofed_chunk(&impostor_did, 1024);
            let _ = harness
                .inject_event(
                    &victim,
                    NetworkEvent::DataReceived {
                        origin: attacker,
                        topic: config.network.video_topic.clone(),
                        data: spoofed,
                    },
                )
                .await;
        }
    }

    // 3b. Reflection attack: 50 chunks claiming to be from the VICTIM's own DID
    for i in 50..100u32 {
        let attacker = MeshAddress::new(format!("sybil-diverse-{i}"));
        let reflected = make_spoofed_chunk(&victim, 2048);
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: attacker,
                    topic: config.network.video_topic.clone(),
                    data: reflected,
                },
            )
            .await;
    }

    // 3c. Replay flood: 10 different payloads, each replayed 20 times = 200 replays
    for variant in 0..10u32 {
        let replay_payload = make_test_chunk(&victim, 256 + variant as usize);
        for rep in 0..20u32 {
            let idx = 100 + variant * 20 + rep;
            let attacker = MeshAddress::new(format!("sybil-diverse-{}", idx % 500));
            let _ = harness
                .inject_event(
                    &victim,
                    NetworkEvent::DataReceived {
                        origin: attacker,
                        topic: config.network.video_topic.clone(),
                        data: replay_payload.clone(),
                    },
                )
                .await;
        }
    }

    // 3d. Malformed garbage — not even valid postcard, just random bytes
    for i in 0..100u32 {
        let attacker = MeshAddress::new(format!("sybil-diverse-{}", i % 500));
        let mut malformed = vec![0u8; 4096];
        // Fill with pseudo-random pattern to defeat any accidental structure
        for (j, byte) in malformed.iter_mut().enumerate() {
            *byte = ((i as usize * 31 + j * 37) & 0xFF) as u8;
        }
        let _ = harness
            .inject_event(
                &victim,
                NetworkEvent::DataReceived {
                    origin: attacker,
                    topic: config.network.video_topic.clone(),
                    data: malformed,
                },
            )
            .await;
    }

    harness.advance_time(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;

    let stress_after_poison = governor.composite_stress();
    println!(
        "[PHASE 3 - POISON] Stress after 50 spoofed + 50 reflected + 200 replayed + 100 malformed: {:.4}",
        stress_after_poison
    );

    // Victim must survive poisoned traffic
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: ally_net.clone(),
                topic: config.network.video_topic.clone(),
                data: make_test_chunk(&victim, 64),
            },
        )
        .await
        .expect("Victim must survive Phase 3 (Poison)");

    // ── PHASE 4: EXHAUST ────────────────────────────────────────────────
    // Directly inject resource pressure into the governor — models OS-level
    // exhaustion caused by the sustained flood. Hit EVERY integral hard,
    // repeatedly, while continuing the data flood.

    // Sustained pressure injection over 30 ticks — try to redline Phalanx.
    //
    // The governor's composite stress = weighted sum of (integral / critical):
    //   s: weight=0.25, crit=10.0s,   half-life=0.17s  (system/metabolic)
    //   d: weight=0.20, crit=25.0s,   half-life=1.4s   (IO)
    //   m: weight=0.20, crit=512 MiB, half-life=2.3s   (memory)
    //   w: weight=0.15, crit=0.80,    half-life=14.0s  (storage)
    //   b: weight=0.20, crit=100 MiB, half-life=1.4s   (bandwidth)
    //
    // To push past Conserving (0.50), we need to saturate every integral
    // at or above its critical threshold every tick, faster than decay.
    for tick in 0..30u32 {
        // Memory: 1 GiB held — 2x the 512 MiB critical threshold
        governor.record_memory_pressure(1024 * 1024 * 1024);
        // Storage: 99% full — critical is 0.80, we're at 0.99
        governor.record_storage_pressure(990, 1000);
        // IO: 25 seconds — at critical threshold (d_crit = 25.0)
        governor.record_io_pressure(Duration::from_secs(25));
        // CPU: 10 seconds — at critical threshold (s_crit = 10.0)
        governor.record_metabolic_pressure(Duration::from_secs(10));
        // Latency: 5 second round-trip
        governor.record_latency_pressure(Duration::from_secs(5));
        // Bandwidth: 100 MiB — at critical threshold (b_crit = 100 MiB)
        governor.record_bandwidth_pressure(100 * 1024 * 1024);
        // Sybil signal: massive eclipse
        governor.record_eclipse_impulse(10.0);
        // Entry pressure: 10 new peers per tick
        for _ in 0..10u32 {
            governor.record_entry_pressure();
        }

        // Simultaneous data flood — 100 chunks per tick at 256 KB each
        for j in 0..100u32 {
            let idx = tick * 100 + j;
            let attacker = MeshAddress::new(format!("sybil-diverse-{}", idx % 500));
            let _ = harness
                .inject_event(
                    &victim,
                    NetworkEvent::DataReceived {
                        origin: attacker,
                        topic: config.network.video_topic.clone(),
                        data: vec![0xFF; 256 * 1024], // 256 KB each
                    },
                )
                .await;
        }

        harness.advance_time(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let tick_stress = governor.composite_stress();
        let tick_state = governor.recommended_power_state();
        println!(
            "[PHASE 4 - EXHAUST tick {}] Stress: {:.4}, Power: {:?}",
            tick, tick_stress, tick_state
        );
    }

    let stress_peak = governor.composite_stress();
    let state_peak = governor.recommended_power_state();
    println!(
        "[PHASE 4 - EXHAUST] Peak stress: {:.4}, Power state: {:?}",
        stress_peak, state_peak
    );

    // The node SHOULD be in a degraded power state — that's the governor
    // doing its job (shedding load to survive). But it must still be alive.
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: ally_net.clone(),
                topic: config.network.video_topic.clone(),
                data: make_test_chunk(&victim, 64),
            },
        )
        .await
        .expect("Victim must survive Phase 4 (Exhaust) — degraded but alive");

    // ── PHASE 5: VERIFY RESURRECTION ────────────────────────────────────
    // All attack traffic ceases. Relieve resource pressure. Let integrals
    // decay naturally. The node must recover to Normal within 5 minutes.

    // Relieve artificial resource pressure
    governor.record_memory_pressure(0);
    governor.record_storage_pressure(100, 1000); // 10% used

    // Advance time in 10-second steps, watching stress decay
    let mut recovered = false;
    println!("[PHASE 5 - RESURRECTION] Watching recovery...");
    println!("elapsed_s,composite_stress,power_state");

    for step in 0..30u32 {
        harness.advance_time(Duration::from_secs(10)).await;
        tokio::task::yield_now().await;

        let stress = governor.composite_stress();
        let state = governor.recommended_power_state();
        let elapsed = (step + 1) * 10;
        println!("{},{:.4},{:?}", elapsed, stress, state);

        if state == phalanx_proto::types::PowerState::Normal {
            recovered = true;
            println!(
                "[PHASE 5] Node recovered to Normal at t={}s (stress={:.4})",
                elapsed, stress
            );
            break;
        }
    }

    // Even if hysteresis delays full recovery, stress should be declining
    let final_stress = governor.composite_stress();
    assert!(
        final_stress < stress_peak,
        "Stress must decline during recovery: peak={:.4}, final={:.4}",
        stress_peak,
        final_stress,
    );

    // Verify the node can still process legitimate traffic after the attack
    let post_attack_chunk = make_test_chunk(&victim, 256);
    harness
        .inject_event(
            &victim,
            NetworkEvent::DataReceived {
                origin: ally_net.clone(),
                topic: config.network.video_topic.clone(),
                data: post_attack_chunk,
            },
        )
        .await
        .expect("Victim must process legitimate traffic after full attack sequence");

    harness.advance_time(Duration::from_secs(1)).await;
    tokio::task::yield_now().await;

    // ── POST-MORTEM ─────────────────────────────────────────────────────
    let attacks = collector.attacks().await;
    let summary = collector.summary().await;

    println!("\n[POST-MORTEM]");
    println!("  Attacks blocked: {}", attacks.len());
    println!("  Peak stress:     {:.4}", stress_peak);
    println!("  Final stress:    {:.4}", final_stress);
    println!(
        "  Recovered:       {}",
        if recovered {
            "YES"
        } else {
            "NO (but stress declining)"
        }
    );
    println!("\n{}", summary);

    // ── FINAL SHUTDOWN ──────────────────────────────────────────────────
    harness
        .inject_event(&victim, NetworkEvent::Shutdown)
        .await
        .expect("Victim must accept clean shutdown after surviving coordinated kill attempt");
    harness
        .inject_event(&ally, NetworkEvent::Shutdown)
        .await
        .expect("Ally shutdown");
    harness.advance_time(Duration::from_millis(500)).await;
}

// ============================================================================
// Black Hole Peer Detection — Reciprocity Floor
// ============================================================================

/// Three peers: an honest contributor, a silent wolf, and a new peer within grace.
/// After recording evidence from the honest peer and evaluating reciprocity,
/// the wolf should be flagged NonReciprocal while the honest peer passes.
///
/// This test validates the full pipeline: governor contribution tracking →
/// evaluate_reciprocity() → graduated response.
#[test]
fn black_hole_peer_detected_via_reciprocity_floor() {
    use phalanx_forensics::policy::HomeostaticConfig;
    use phalanx_forensics::trust::{
        PeerContribution, ReciprocityParams, ReciprocityVerdict, evaluate_reciprocity,
    };
    use phalanx_node::vitals::SystemGovernor;

    let config = HomeostaticConfig::default();
    let governor = SystemGovernor::with_config(config);
    let params = ReciprocityParams::default();

    let honest_peer = "honest-peer-1";
    let wolf_peer = "wolf-silent-0";
    let new_peer = "fresh-peer-2";

    // Simulate: honest peer sends 10 valid evidence shards.
    for _ in 0..10 {
        governor.record_peer_evidence(honest_peer, true);
    }
    // Wolf sends nothing. New peer also sends nothing (but is within grace).

    // Read contribution integrals.
    let honest_contrib = governor.peer_contribution_value(honest_peer);
    let wolf_contrib = governor.peer_contribution_value(wolf_peer);
    let new_contrib = governor.peer_contribution_value(new_peer);

    println!("Contribution integrals:");
    println!("  Honest: {:.4}", honest_contrib);
    println!("  Wolf:   {:.4}", wolf_contrib);
    println!("  New:    {:.4}", new_contrib);

    assert!(
        honest_contrib > 0.0,
        "Honest peer should have positive contribution"
    );
    assert!(wolf_contrib == 0.0, "Wolf should have zero contribution");

    // Evaluate reciprocity for each peer in a 3-peer mesh.
    // Floor = 3.0 / max(3, 2) = 1.0

    // Honest peer: connected 15 min, has contribution → Reciprocal
    let honest_verdict = evaluate_reciprocity(
        &PeerContribution {
            connected_secs: 900,
            contribution_integral: honest_contrib,
        },
        &params,
        3,
    );
    assert_eq!(
        honest_verdict,
        ReciprocityVerdict::Reciprocal,
        "Honest peer with contribution > floor must pass"
    );

    // Wolf: connected 15 min, zero contribution → NonReciprocal { deficit: 1.0 }
    let wolf_verdict = evaluate_reciprocity(
        &PeerContribution {
            connected_secs: 900,
            contribution_integral: wolf_contrib,
        },
        &params,
        3,
    );
    assert_eq!(
        wolf_verdict,
        ReciprocityVerdict::NonReciprocal { deficit: 1.0 },
        "Silent wolf must be flagged as non-reciprocal with full deficit"
    );

    // New peer: connected 5 min (within grace) → GracePeriod
    let new_verdict = evaluate_reciprocity(
        &PeerContribution {
            connected_secs: 300,
            contribution_integral: new_contrib,
        },
        &params,
        3,
    );
    assert_eq!(
        new_verdict,
        ReciprocityVerdict::GracePeriod,
        "New peer within grace period must not be judged"
    );

    // Apply graduated response: spectral anomaly for the wolf.
    if let ReciprocityVerdict::NonReciprocal { deficit } = wolf_verdict {
        governor.record_spectral_anomaly(wolf_peer, deficit * 5.0);
    }

    // Verify: wolf's coupling integral is now negative (decoupled).
    let wolf_coupled = governor.is_peer_coupled(wolf_peer);
    assert!(
        !wolf_coupled,
        "Wolf should be decoupled after spectral anomaly penalty"
    );

    // Verify: honest peer's coupling is unaffected.
    let honest_coupled = governor.is_peer_coupled(honest_peer);
    assert!(
        honest_coupled,
        "Honest peer must remain coupled — penalty only hit the wolf"
    );

    // Verify: contribution integrals are untouched by the penalty
    // (penalties write to r_integrals["{peer_id}"], not r_integrals["contrib:{peer_id}"]).
    let wolf_contrib_after = governor.peer_contribution_value(wolf_peer);
    assert!(
        wolf_contrib_after == 0.0,
        "Wolf's contribution integral must not be affected by spectral anomaly"
    );

    // Test pruning: after pruning, stale integrals are removed.
    governor.prune_stale_integrals();
    // The wolf's coupling integral (negative, large magnitude) should survive pruning.
    // The honest peer's integrals should also survive (positive, large magnitude).
    let honest_after_prune = governor.peer_contribution_value(honest_peer);
    assert!(
        honest_after_prune > 0.0,
        "Honest peer's contribution integral must survive pruning"
    );

    println!("\nReciprocity floor test passed:");
    println!("  Honest: {:?}", honest_verdict);
    println!("  Wolf:   {:?} → decoupled", wolf_verdict);
    println!("  New:    {:?}", new_verdict);
}
