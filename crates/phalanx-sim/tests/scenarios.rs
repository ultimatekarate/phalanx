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
// crates/phalanx-sim/tests/scenarios.rs
//
// Simulation scenarios for Volterra parameter tuning.
// Each scenario targets a specific question about the system's dynamic response
// and prints time-series data for manual inspection during parameter sweeps.

use phalanx_forensics::Homeostasis;
use phalanx_node::config::NodeConfig;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::evidence::{ChunkType, ShardChunk};
use phalanx_proto::identity::{NetworkId, NodeRole};
use phalanx_proto::network::NetworkEvent;
use phalanx_proto::prelude::{Did, EncodingSymbolId, PhalanxTimestamp, ShardId};
use phalanx_proto::types::PowerState;
use phalanx_sim::physics::PhalanxPhysics;
use phalanx_sim::SimulationHarness;

use std::sync::Arc;
use std::time::Duration;

// ============================================================================
// Test Utilities
// ============================================================================

/// Construct a valid postcard-serialized ShardChunk for injection tests.
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

/// Inject a single data chunk into a node's ingress pipeline.
async fn inject_chunk(
    harness: &phalanx_sim::SimulationHarness,
    target_did: &Did,
    origin_network_id: &NetworkId,
    config: &NodeConfig,
    payload_size: usize,
) {
    let chunk_data = make_test_chunk(target_did, payload_size);
    let _ = harness
        .inject_event(
            target_did,
            NetworkEvent::DataReceived {
                origin: origin_network_id.clone(),
                topic: config.network.video_topic.clone(),
                data: chunk_data,
            },
        )
        .await;
}

// ============================================================================
// Scenario 1: Sustained Load -> Power State Transition
// ============================================================================

/// Question: How long does continuous ingestion take to push a node
/// from Normal to Conserving to Leaf?
#[tokio::test]
async fn scenario_1_sustained_load_power_transition() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_a = harness
        .spawn_node("Sender-A", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Sender-A");
    let node_b = harness
        .spawn_node("Receiver-B", NodeRole::Guardian)
        .await
        .expect("Failed to spawn Receiver-B");

    let network_id_a = harness
        .resolve_did(&node_a)
        .await
        .expect("Failed to resolve node A");

    let governor_b = harness
        .governor_for(&node_b)
        .expect("Governor for node B should exist");

    println!("--- Scenario 1: Sustained Load -> Power State Transition ---");
    println!("elapsed_s,composite_stress,power_state");

    let mut elapsed_secs = 0u64;
    let mut saw_nonzero_stress = false;

    while elapsed_secs <= 120 {
        // Inject a chunk every time step
        inject_chunk(&harness, &node_b, &network_id_a, &config, 1024).await;

        harness.advance_time(Duration::from_secs(5)).await;
        tokio::task::yield_now().await;
        elapsed_secs += 5;

        let stress = governor_b.composite_stress();
        let state = governor_b.recommended_power_state();

        if stress > 0.0 {
            saw_nonzero_stress = true;
        }

        println!("{},{:.4},{:?}", elapsed_secs, stress, state);
    }

    // Tolerant assertion: injection should have produced some stress
    assert!(
        saw_nonzero_stress,
        "composite_stress should have risen above 0.0 at some point during sustained load"
    );

    // Clean up
    for did in [&node_a, &node_b] {
        let _ = harness.inject_event(did, NetworkEvent::Shutdown).await;
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Scenario 2: Burst Recovery
// ============================================================================

/// Question: After a 10-second burst of heavy traffic, how long does
/// the system take to recover to Normal?
#[tokio::test]
async fn scenario_2_burst_recovery() {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();

    let (mut harness, _collector) = SimulationHarness::init_mesh(config.clone(), physics);

    let node_a = harness
        .spawn_node("Burst-Sender", NodeRole::Guardian)
        .await
        .expect("Failed to spawn sender");
    let node_b = harness
        .spawn_node("Burst-Receiver", NodeRole::Guardian)
        .await
        .expect("Failed to spawn receiver");

    let network_id_a = harness
        .resolve_did(&node_a)
        .await
        .expect("Failed to resolve sender");

    let governor_b = harness
        .governor_for(&node_b)
        .expect("Governor for receiver should exist");

    println!("--- Scenario 2: Burst Recovery ---");
    println!("phase,elapsed_s,composite_stress,power_state");

    // Phase 1: Heavy burst — inject 10 chunks per second for 10 seconds
    for sec in 0..10 {
        for _ in 0..10 {
            inject_chunk(&harness, &node_b, &network_id_a, &config, 2048).await;
        }
        harness.advance_time(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let stress = governor_b.composite_stress();
        let state = governor_b.recommended_power_state();
        println!("burst,{},{:.4},{:?}", sec + 1, stress, state);
    }

    let peak_stress = governor_b.composite_stress();

    // Phase 2: Recovery — no traffic, advance 1s at a time for 60s
    for sec in 0..60 {
        harness.advance_time(Duration::from_secs(1)).await;
        tokio::task::yield_now().await;

        let stress = governor_b.composite_stress();
        let state = governor_b.recommended_power_state();
        println!("recovery,{},{:.4},{:?}", sec + 1, stress, state);
    }

    let final_stress = governor_b.composite_stress();

    // Tolerant assertion: stress should have decreased from peak
    assert!(
        final_stress <= peak_stress,
        "Stress should decrease during recovery: peak={:.4}, final={:.4}",
        peak_stress,
        final_stress
    );

    // Clean up
    for did in [&node_a, &node_b] {
        let _ = harness.inject_event(did, NetworkEvent::Shutdown).await;
    }
    harness.advance_time(Duration::from_millis(200)).await;
}

// ============================================================================
// Scenario 3: Individual Integral Isolation
// ============================================================================

/// Helper: spawn a single-node harness and return the governor.
async fn spawn_single_node() -> (SimulationHarness, Did, Arc<SystemGovernor>) {
    let config = NodeConfig::test_defaults();
    let physics = PhalanxPhysics::test_profile();
    let (mut harness, _collector) = SimulationHarness::init_mesh(config, physics);

    let did = harness
        .spawn_node("Isolated-Node", NodeRole::Guardian)
        .await
        .expect("Failed to spawn node");

    let governor = harness.governor_for(&did).expect("Governor should exist");

    (harness, did, governor)
}

/// 3a: System pressure (s) — weight 0.25
#[tokio::test]
async fn scenario_3a_system_pressure_isolation() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 3a: System Pressure Isolation (weight=0.25, s_crit=10.0) ---");

    // Inject known metabolic pressure
    governor.record_metabolic_pressure(Duration::from_secs(10));
    let stress = governor.composite_stress();
    println!(
        "After 10s metabolic impulse: composite_stress = {:.4}",
        stress
    );

    assert!(
        stress > 0.0,
        "System pressure should contribute to composite stress"
    );
    // Weight is 0.25, and s_crit is 10.0. A 10s impulse => s.value ~= 10.0,
    // so (s/s_crit).min(1.0) = 1.0, contribution = 0.25 * 1.0 = 0.25
    assert!(
        stress <= 0.25 + 0.01,
        "System-only stress should be <= 0.26 (weight=0.25), got {:.4}",
        stress
    );
}

/// 3b: IO pressure (d) — weight 0.20
#[tokio::test]
async fn scenario_3b_io_pressure_isolation() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 3b: IO Pressure Isolation (weight=0.20, d_crit=25.0) ---");

    // Inject known IO pressure (saturate to d_crit)
    governor.record_io_pressure(Duration::from_secs(25));
    let stress = governor.composite_stress();
    println!("After 25s IO impulse: composite_stress = {:.4}", stress);

    assert!(
        stress > 0.0,
        "IO pressure should contribute to composite stress"
    );
    assert!(
        stress <= 0.20 + 0.01,
        "IO-only stress should be <= 0.21 (weight=0.20), got {:.4}",
        stress
    );
}

/// 3c: Memory pressure (m) — weight 0.20
#[tokio::test]
async fn scenario_3c_memory_pressure_isolation() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 3c: Memory Pressure Isolation (weight=0.20, m_crit=512.0 MiB) ---");

    // Inject memory pressure at critical level (512 MiB)
    governor.record_memory_pressure(512 * 1024 * 1024);
    let stress = governor.composite_stress();
    println!(
        "After 512 MiB memory impulse: composite_stress = {:.4}",
        stress
    );

    assert!(
        stress > 0.0,
        "Memory pressure should contribute to composite stress"
    );
    assert!(
        stress <= 0.20 + 0.01,
        "Memory-only stress should be <= 0.21 (weight=0.20), got {:.4}",
        stress
    );
}

/// 3d: Storage pressure (w) — weight 0.15
#[tokio::test]
async fn scenario_3d_storage_pressure_isolation() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 3d: Storage Pressure Isolation (weight=0.15, w_crit=0.8) ---");

    // Inject storage pressure at critical ratio
    governor.record_storage_pressure(800, 1000);
    let stress = governor.composite_stress();
    println!(
        "After 80% storage impulse: composite_stress = {:.4}",
        stress
    );

    assert!(
        stress > 0.0,
        "Storage pressure should contribute to composite stress"
    );
    assert!(
        stress <= 0.15 + 0.01,
        "Storage-only stress should be <= 0.16 (weight=0.15), got {:.4}",
        stress
    );
}

/// 3e: Bandwidth pressure (b) — weight 0.20
#[tokio::test]
async fn scenario_3e_bandwidth_pressure_isolation() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 3e: Bandwidth Pressure Isolation (weight=0.20, b_crit=100.0 MiB) ---");

    // Inject bandwidth pressure at critical level (50 MiB)
    governor.record_bandwidth_pressure(50 * 1024 * 1024);
    let stress = governor.composite_stress();
    println!(
        "After 50 MiB bandwidth impulse: composite_stress = {:.4}",
        stress
    );

    assert!(
        stress > 0.0,
        "Bandwidth pressure should contribute to composite stress"
    );
    assert!(
        stress <= 0.20 + 0.01,
        "Bandwidth-only stress should be <= 0.21 (weight=0.20), got {:.4}",
        stress
    );
}

// ============================================================================
// Scenario 4: Sybil Attack -> Endowment Shrink
// ============================================================================

/// Question: Does the entry pressure integral correctly gate new peer
/// acceptance under Sybil attack?
#[tokio::test]
async fn scenario_4_sybil_attack_endowment_shrink() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 4: Sybil Attack -> Endowment Shrink ---");
    println!("phase,step,sybil_endowment");

    let initial_endowment = governor.sybil_endowment().0;
    println!("initial,0,{:.4}", initial_endowment);

    // Phase 1: Sybil burst — 50 entry pressure events in batches of 10
    for batch in 0..5 {
        for _ in 0..10 {
            governor.record_entry_pressure();
        }
        let endowment = governor.sybil_endowment().0;
        println!("attack,{},{:.4}", (batch + 1) * 10, endowment);
    }

    let post_attack_endowment = governor.sybil_endowment().0;

    // Phase 2: Recovery — advance 60 seconds, current_value() applies lazy decay
    for sec in 1..=60 {
        _harness.advance_time(Duration::from_secs(1)).await;
        let endowment = governor.sybil_endowment().0;
        if sec % 10 == 0 {
            println!("recovery,{},{:.4}", sec, endowment);
        }
    }

    let recovered_endowment = governor.sybil_endowment().0;

    // Assertions
    assert!(
        post_attack_endowment < initial_endowment,
        "Endowment should decrease during Sybil attack: initial={:.4}, post_attack={:.4}",
        initial_endowment,
        post_attack_endowment
    );
    assert!(
        recovered_endowment > post_attack_endowment,
        "Endowment should recover after attack stops: post_attack={:.4}, recovered={:.4}",
        post_attack_endowment,
        recovered_endowment
    );
}

// ============================================================================
// Scenario 5: Multi-Vector Stress
// ============================================================================

/// Question: Does combined pressure from multiple sources produce
/// additive composite stress?
#[tokio::test]
async fn scenario_5_multi_vector_stress() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 5: Multi-Vector Stress ---");

    // First, measure individual contributions in isolation (fresh governor for each would
    // be ideal, but we'll note the additive nature from known weights instead).
    // We inject into bandwidth, memory, and system simultaneously.
    governor.record_bandwidth_pressure(50 * 1024 * 1024); // ~50 MiB (b_crit = 100)
    governor.record_memory_pressure(512 * 1024 * 1024); // ~512 MiB (m_crit = 512)
    governor.record_metabolic_pressure(Duration::from_secs(10)); // 10s (s_crit = 10)

    let combined_stress = governor.composite_stress();
    println!("Combined (b+m+s) composite_stress = {:.4}", combined_stress);

    // Expected: ~0.10 (bw) + ~0.20 (mem) + ~0.25 (sys) = ~0.55
    // The actual value depends on DecayingIntegral timing, but it should be
    // significantly larger than any single contribution.
    assert!(
        combined_stress > 0.20,
        "Multi-vector stress should exceed any single weight, got {:.4}",
        combined_stress
    );
    // Should not exceed theoretical maximum of weights summed (0.25 + 0.20 + 0.20 = 0.65)
    // plus some epsilon for timing
    assert!(
        combined_stress <= 0.65 + 0.05,
        "Multi-vector stress should approximate sum of individual weights, got {:.4}",
        combined_stress
    );
}

// ============================================================================
// Scenario 6: Hysteresis Oscillation Resistance
// ============================================================================

/// Question: Does the system oscillate between Normal and Conserving
/// under fluctuating load?
#[tokio::test]
async fn scenario_6_hysteresis_oscillation_resistance() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 6: Hysteresis Oscillation Resistance ---");
    println!("cycle,phase,composite_stress,power_state");

    let mut states: Vec<PowerState> = Vec::new();

    for cycle in 0..10 {
        // Heavy load phase (5 seconds): inject large impulses
        for _ in 0..5 {
            governor.record_metabolic_pressure(Duration::from_secs(5));
            governor.record_bandwidth_pressure(30 * 1024 * 1024);
            governor.record_memory_pressure(300 * 1024 * 1024);
            _harness.advance_time(Duration::from_secs(1)).await;
            let stress = governor.composite_stress();
            let state = governor.recommended_power_state();
            println!("{}:load,{},{:.4},{:?}", cycle, states.len(), stress, state);
            states.push(state);
        }

        // Idle phase (5 seconds): current_value() applies lazy decay
        for _ in 0..5 {
            _harness.advance_time(Duration::from_secs(1)).await;
            let stress = governor.composite_stress();
            let state = governor.recommended_power_state();
            println!("{}:idle,{},{:.4},{:?}", cycle, states.len(), stress, state);
            states.push(state);
        }
    }

    // Count transitions
    let transitions: usize = states.windows(2).filter(|w| w[0] != w[1]).count();

    println!(
        "\nTotal state transitions: {} over {} observations",
        transitions,
        states.len()
    );

    // With hysteresis (3-tick and 5-tick counters), transitions should be
    // significantly fewer than the 10 oscillation cycles. Without hysteresis,
    // we'd expect ~20 transitions (up/down each cycle).
    // With hysteresis, the system should resist rapid switching.
    assert!(
        transitions < 20,
        "Hysteresis should limit transitions to fewer than 20, got {}",
        transitions
    );
}

// ============================================================================
// Scenario 8: Full Recovery from Critical
// ============================================================================

/// Question: Starting from maximum stress on all integrals, how long
/// does full recovery take?
#[tokio::test]
async fn scenario_8_full_recovery_from_critical() {
    let (_harness, _did, governor) = spawn_single_node().await;

    println!("--- Scenario 8: Full Recovery from Critical ---");

    // Phase 1: Saturate all integrals with large impulses
    for _ in 0..30 {
        governor.record_metabolic_pressure(Duration::from_secs(10));
        governor.record_io_pressure(Duration::from_secs(25));
        governor.record_memory_pressure(512 * 1024 * 1024);
        governor.record_storage_pressure(950, 1000);
        governor.record_bandwidth_pressure(50 * 1024 * 1024);
    }

    let initial_stress = governor.composite_stress();
    println!(
        "Saturated composite_stress = {:.4} (target > 0.85)",
        initial_stress
    );

    assert!(
        initial_stress > 0.85,
        "Should reach critical stress after saturation, got {:.4}",
        initial_stress
    );

    // Phase 2: Recovery — stop injecting, current_value() applies lazy decay
    println!("elapsed_s,s_value,d_value,m_value,w_value,b_value,composite_stress,power_state");

    let mut elapsed = 0u64;
    let mut recovered = false;

    while elapsed <= 300 {
        let stress = governor.composite_stress();
        let state = governor.recommended_power_state();

        // Read individual integral values for the decay curve
        let now = governor.now_secs();
        let (s_val, d_val, m_val, w_val, b_val) = governor.with_state(|s| {
            (
                s.s.current_value(now),
                s.d.current_value(now),
                s.m.current_value(now),
                s.w.current_value(now),
                s.b.current_value(now),
            )
        });

        println!(
            "{},{:.4},{:.4},{:.4},{:.4},{:.4},{:.4},{:?}",
            elapsed, s_val, d_val, m_val, w_val, b_val, stress, state
        );

        if stress < 0.30 && !recovered {
            recovered = true;
            println!("# Recovery to Normal threshold at {}s", elapsed);
        }

        _harness.advance_time(Duration::from_secs(5)).await;
        elapsed += 5;
    }

    let final_stress = governor.composite_stress();

    // Assert: stress should have decreased significantly
    assert!(
        final_stress < initial_stress,
        "Stress should decrease during recovery: initial={:.4}, final={:.4}",
        initial_stress,
        final_stress
    );

    // Ideally it should recover below 0.30 within 300s, but we use a tolerant assertion
    assert!(
        final_stress < 0.30,
        "Stress should recover below 0.30 within 300s, got {:.4}",
        final_stress
    );
}
