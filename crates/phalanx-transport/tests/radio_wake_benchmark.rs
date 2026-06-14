//! Radio wake pattern benchmark.
//!
//! Measures swarm maintenance overhead (gossipsub heartbeats, Kademlia walks,
//! AutoNAT probes, mDNS) with **zero application traffic**. Each test creates
//! 3 real libp2p swarms on localhost, lets mDNS discover peers, then samples
//! the swarm wake counter every second for 120 seconds.
//!
//! Run manually (not in CI):
//! ```sh
//! cargo test -p phalanx-transport -- radio_wake --ignored --nocapture
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation
)]

use std::sync::atomic::Ordering;
use std::time::Duration;

use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::network::IngressPort;
use phalanx_transport::adapters::libp2p::AdapterConfig;
use phalanx_transport::config::MeshTransportConfig;
use phalanx_transport::factory::build_mesh_transport;

/// Number of swarm nodes in the benchmark mesh.
const NODE_COUNT: usize = 3;
/// Seconds to wait for mDNS peer discovery before sampling.
const DISCOVERY_WAIT_SECS: u64 = 10;
/// Seconds to sample wake events.
const SAMPLE_DURATION_SECS: u64 = 120;

const BASE_PORT: u16 = 39100;

fn make_config(node_index: usize, poll_cadence: Option<Duration>) -> MeshTransportConfig {
    let port = BASE_PORT + node_index as u16;
    let mut bootstrap_peers = Vec::new();
    // All nodes bootstrap to node 0
    if node_index > 0 {
        bootstrap_peers.push(format!("/ip4/127.0.0.1/tcp/{BASE_PORT}"));
    }
    MeshTransportConfig {
        listen_addresses: vec![format!("/ip4/127.0.0.1/tcp/{port}")],
        bootstrap_peers,
        subscribe_topics: vec!["test/radio-wake".to_string()],
        adapter: AdapterConfig {
            enable_wake_log: true,
            poll_cadence,
            ..AdapterConfig::default()
        },
        ..MeshTransportConfig::default()
    }
}

/// Run the benchmark for `SAMPLE_DURATION_SECS`, printing CSV to stdout.
///
/// Returns total cumulative wakes across all nodes.
async fn run_benchmark(label: &str, poll_cadence: Option<Duration>) -> u64 {
    eprintln!("=== {label} (cadence: {poll_cadence:?}) ===");
    eprintln!("Creating {NODE_COUNT} swarm nodes with fixed ports (base: {BASE_PORT})...");

    // Build nodes sequentially — node 0 first, others bootstrap to it.
    let mut egresses = Vec::new();
    let mut ingresses = Vec::new();
    for i in 0..NODE_COUNT {
        let config = make_config(i, poll_cadence);
        let identity = PhalanxIdentity::new_ephemeral();
        let (ingress, egress) = build_mesh_transport(&identity, &config)
            .unwrap_or_else(|e| panic!("Node {i} failed to build: {e}"));
        egresses.push(egress);
        ingresses.push(ingress);
        if i == 0 {
            // Give node 0 time to start listening before others dial
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    eprintln!("Waiting {DISCOVERY_WAIT_SECS}s for connections to establish...");
    tokio::time::sleep(Duration::from_secs(DISCOVERY_WAIT_SECS)).await;

    // Connectivity check: drain ingress events and count peer discoveries
    let mut total_discoveries = 0usize;
    for (i, ingress) in ingresses.iter_mut().enumerate() {
        let mut node_discoveries = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_millis(100), ingress.next_event()).await {
                Ok(Some(phalanx_proto::network::NetworkEvent::PeerDiscovered { .. })) => {
                    node_discoveries += 1;
                }
                Ok(Some(_)) => {} // other events
                _ => break,       // timeout or channel closed
            }
        }
        eprintln!("Node {i}: {node_discoveries} peers discovered");
        total_discoveries += node_discoveries;
    }
    eprintln!("Total peer discoveries: {total_discoveries}");

    // Snapshot initial wake counts
    let counters: Vec<_> = egresses.iter().map(|e| e.swarm_wake_count()).collect();
    let initial: Vec<u64> = counters.iter().map(|c| c.load(Ordering::Relaxed)).collect();

    // I/O counters
    let io_bytes_sent: Vec<_> = egresses.iter().map(|e| e.socket_bytes_sent()).collect();
    let io_bytes_recv: Vec<_> = egresses.iter().map(|e| e.socket_bytes_received()).collect();
    let io_ops: Vec<_> = egresses.iter().map(|e| e.socket_io_ops()).collect();

    // Print CSV header
    println!(
        "timestamp_ms,cumulative_wakes,wakes_per_sec,bytes_sent,bytes_received,io_ops,io_ops_per_sec"
    );

    let start = tokio::time::Instant::now();
    let mut prev_total: u64 = 0;
    let mut prev_io_ops: u64 = 0;

    for _tick in 1..=SAMPLE_DURATION_SECS {
        tokio::time::sleep(Duration::from_secs(1)).await;

        let cumulative: u64 = counters
            .iter()
            .zip(initial.iter())
            .map(|(c, init)| c.load(Ordering::Relaxed) - init)
            .sum();

        let wakes_per_sec = cumulative - prev_total;
        prev_total = cumulative;

        let bytes_sent: u64 = io_bytes_sent
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let bytes_received: u64 = io_bytes_recv
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        let total_io_ops: u64 = io_ops.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        let io_ops_per_sec = total_io_ops - prev_io_ops;
        prev_io_ops = total_io_ops;

        let elapsed_ms = start.elapsed().as_millis();
        println!(
            "{elapsed_ms},{cumulative},{wakes_per_sec},{bytes_sent},{bytes_received},{total_io_ops},{io_ops_per_sec}"
        );
    }

    // Print wake log statistics if available
    for (i, egress) in egresses.iter().enumerate() {
        if let Some(log) = egress.swarm_wake_log() {
            let guard = log.lock().unwrap();
            let count = guard.len();
            if count > 1 {
                // Calculate inter-wake gaps
                let mut gaps: Vec<Duration> = Vec::with_capacity(count - 1);
                for pair in guard.windows(2) {
                    gaps.push(pair[1].duration_since(pair[0]));
                }
                gaps.sort();
                let median = gaps[gaps.len() / 2];
                let max_gap = gaps.last().unwrap();
                let min_gap = gaps.first().unwrap();

                // Wake clustering: count wakes within 100ms windows
                let mut clustered = 0usize;
                let mut scattered = 0usize;
                let window = Duration::from_millis(100);
                let mut window_start = guard[0];
                let mut window_count = 1usize;
                for ts in guard.iter().skip(1) {
                    if ts.duration_since(window_start) <= window {
                        window_count += 1;
                    } else {
                        if window_count > 1 {
                            clustered += window_count;
                        } else {
                            scattered += 1;
                        }
                        window_start = *ts;
                        window_count = 1;
                    }
                }
                // Flush last window
                if window_count > 1 {
                    clustered += window_count;
                } else {
                    scattered += 1;
                }

                eprintln!(
                    "Node {i}: {count} wakes | gap min={min_gap:?} median={median:?} max={max_gap:?} | clustered={clustered} scattered={scattered}"
                );
            } else {
                eprintln!("Node {i}: {count} wakes (insufficient data for gap analysis)");
            }
        }
    }

    // Diagnostic: final I/O counter values
    let final_bytes_sent: u64 = io_bytes_sent
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .sum();
    let final_bytes_recv: u64 = io_bytes_recv
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .sum();
    let final_io_ops: u64 = io_ops.iter().map(|c| c.load(Ordering::Relaxed)).sum();
    eprintln!(
        "I/O diagnostic: bytes_sent={final_bytes_sent} bytes_received={final_bytes_recv} io_ops={final_io_ops}"
    );

    prev_total
}

#[ignore] // Run manually: cargo test -p phalanx-transport -- radio_wake_baseline --ignored --nocapture
#[tokio::test]
async fn radio_wake_baseline() {
    let total = run_benchmark("Baseline (continuous poll)", None).await;
    eprintln!("Total wakes over {SAMPLE_DURATION_SECS}s: {total}");
}

#[ignore] // Run manually: cargo test -p phalanx-transport -- radio_wake_cadence_5s --ignored --nocapture
#[tokio::test]
async fn radio_wake_cadence_5s() {
    let total = run_benchmark("Cadence 5s", Some(Duration::from_secs(5))).await;
    eprintln!("Total wakes over {SAMPLE_DURATION_SECS}s: {total}");
}

#[ignore] // Run manually: cargo test -p phalanx-transport -- radio_wake_cadence_15s --ignored --nocapture
#[tokio::test]
async fn radio_wake_cadence_15s() {
    let total = run_benchmark("Cadence 15s", Some(Duration::from_secs(15))).await;
    eprintln!("Total wakes over {SAMPLE_DURATION_SECS}s: {total}");
}

#[ignore] // Run manually: cargo test -p phalanx-transport -- radio_wake_cadence_30s --ignored --nocapture
#[tokio::test]
async fn radio_wake_cadence_30s() {
    let total = run_benchmark("Cadence 30s", Some(Duration::from_secs(30))).await;
    eprintln!("Total wakes over {SAMPLE_DURATION_SECS}s: {total}");
}
