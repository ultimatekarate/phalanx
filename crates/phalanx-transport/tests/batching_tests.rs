//! Opportunistic-batching measurement tests.
//!
//! Five `#[ignore]`-gated benchmarks that exercise the IO-event log and
//! per-protocol wake counters added to the adapter. Each test brings up a
//! 3-node localhost mesh and samples for 120 seconds. CSV goes to stdout;
//! end-of-run blocks print distribution tables to stderr.
//!
//! The four KPIs these tests answer:
//!   1. Inter-IO gap distribution + wake→IO latency (io_timing_distributions)
//!   2. Per-substream IO attribution + per-protocol wake counts (protocol_and_substream_attribution)
//!   3. Outbound queue depth at IO time (all burst tests)
//!   4. Write-size distribution (all burst tests)
//!
//! Run manually (fixed ports + 120s windows require --test-threads=1 when
//! running more than one at a time):
//! ```sh
//! cargo test -p phalanx-transport --test batching_tests -- --ignored --nocapture --test-threads=1
//! ```
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::float_cmp,
    clippy::too_many_lines,
    clippy::while_let_loop,
    clippy::cognitive_complexity
)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::network::{EgressPort, IngressPort};
use phalanx_proto::topic::MeshTopic;
use phalanx_transport::adapters::libp2p::{AdapterConfig, Libp2pEgress, Libp2pIngress};
use phalanx_transport::config::MeshTransportConfig;
use phalanx_transport::counting::{IoKind, IoLogEntry};
use phalanx_transport::factory::build_mesh_transport;
use tokio::time::Instant;

const NODE_COUNT: usize = 3;
const DISCOVERY_WAIT_SECS: u64 = 10;
const SAMPLE_DURATION_SECS: u64 = 120;
const TOPIC: &str = "test/batching";
const PAYLOAD_BYTES: usize = 1024;

// Each test uses a disjoint 10-port window to avoid TCP TIME_WAIT / stale-socket
// collisions when running serially with --test-threads=1.
const PORT_IO_TIMING: u16 = 39200;
const PORT_PROTO_ATTR: u16 = 39210;
const PORT_CONSTANT: u16 = 39220;
const PORT_BURST: u16 = 39230;
const PORT_FLOOD: u16 = 39240;
const PORT_MEDIA_LOW: u16 = 39250;
const PORT_MEDIA_MEDIUM: u16 = 39260;
const PORT_MEDIA_HIGH: u16 = 39270;

// RaptorQ symbol size (matches phalanx_proto::types::SymbolSize::default()).
const SYMBOL_SIZE: usize = 1200;

// ── Helpers ──────────────────────────────────────────────────────────────

fn make_config(base_port: u16, node_index: usize) -> MeshTransportConfig {
    let port = base_port + node_index as u16;
    // Distinct loopback IPs per node (127.0.0.1/2/3) so gossipsub's
    // ip_colocation_factor penalty (threshold=3 in PeerScoreParams) never
    // engages. Same-IP localhost testing was ejecting peers from the mesh
    // within ~14s under media loads and corrupting measurements.
    let ip_octet = 1 + node_index as u8;
    let mut bootstrap_peers = Vec::new();
    if node_index > 0 {
        bootstrap_peers.push(format!("/ip4/127.0.0.1/tcp/{base_port}"));
    }
    MeshTransportConfig {
        listen_addresses: vec![format!("/ip4/127.0.0.{ip_octet}/tcp/{port}")],
        bootstrap_peers,
        // Normalize through MeshTopic so subscribe matches what `publish()` sends.
        // `MeshTopic::new("test/batching")` yields `/phalanx/test/batching`.
        subscribe_topics: vec![MeshTopic::new(TOPIC).to_string()],
        adapter: AdapterConfig {
            enable_wake_log: true,
            enable_io_log: true,
            poll_cadence: None,
            ..AdapterConfig::default()
        },
        ..MeshTransportConfig::default()
    }
}

/// Build 3 nodes on localhost, wait for discovery, assert peers were found.
/// Panics if total discoveries == 0 — otherwise tests silently produce garbage.
async fn setup_mesh(base_port: u16) -> (Vec<Libp2pEgress>, Vec<Libp2pIngress>) {
    eprintln!("Creating {NODE_COUNT} swarm nodes (base port: {base_port})...");
    let mut egresses = Vec::with_capacity(NODE_COUNT);
    let mut ingresses = Vec::with_capacity(NODE_COUNT);
    for i in 0..NODE_COUNT {
        let config = make_config(base_port, i);
        let identity = PhalanxIdentity::new_ephemeral();
        let (ingress, egress) = build_mesh_transport(&identity, &config)
            .unwrap_or_else(|e| panic!("Node {i} failed to build: {e}"));
        egresses.push(egress);
        ingresses.push(ingress);
        if i == 0 {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }

    eprintln!("Waiting {DISCOVERY_WAIT_SECS}s for peer discovery...");
    tokio::time::sleep(Duration::from_secs(DISCOVERY_WAIT_SECS)).await;

    let mut total_discoveries = 0usize;
    for (i, ingress) in ingresses.iter_mut().enumerate() {
        let mut node_discoveries = 0usize;
        loop {
            match tokio::time::timeout(Duration::from_millis(100), ingress.next_event()).await {
                Ok(Some(phalanx_proto::network::NetworkEvent::PeerDiscovered { .. })) => {
                    node_discoveries += 1;
                }
                Ok(Some(_)) => {}
                _ => break,
            }
        }
        eprintln!("Node {i}: {node_discoveries} peers discovered");
        total_discoveries += node_discoveries;
    }
    eprintln!("Total peer discoveries: {total_discoveries}");
    assert!(
        total_discoveries > 0,
        "mDNS discovery failed — tests would produce garbage. \
        Check that mDNS is allowed on localhost."
    );

    (egresses, ingresses)
}

/// Force gossipsub topic-mesh formation by publishing canaries until every
/// non-publisher ingress has received at least `NEEDED_PER_NODE` messages.
/// Without this, `publish()` calls return Ok but never reach peers because the
/// topic mesh (distinct from libp2p connections) hasn't stabilized.
///
/// Call this AFTER `setup_mesh()` and BEFORE the sampling loop. Counters
/// accumulated during warmup are captured in the initial snapshot taken by
/// `run_burst_test`, so warmup traffic is excluded from test metrics.
async fn warmup_gossipsub_mesh(
    egresses: &[Libp2pEgress],
    ingresses: &mut [Libp2pIngress],
    publisher_idx: usize,
) {
    const NEEDED_PER_NODE: usize = 3;
    const WARMUP_TIMEOUT_SECS: u64 = 30;
    const TICK_MS: u64 = 500;
    const CANARY: &[u8] = b"WARMUP";

    eprintln!(
        "Warming up gossipsub mesh (publisher={publisher_idx}, target≥{NEEDED_PER_NODE} per receiver)..."
    );
    let topic = MeshTopic::new(TOPIC);
    let warmup_start = Instant::now();
    let mut received = vec![0usize; ingresses.len()];

    while warmup_start.elapsed() < Duration::from_secs(WARMUP_TIMEOUT_SECS) {
        if let Err(e) = egresses[publisher_idx]
            .publish(&topic, CANARY.to_vec())
            .await
        {
            eprintln!("Warmup publish failed: {e}");
        }
        tokio::time::sleep(Duration::from_millis(TICK_MS)).await;

        for (i, ingress) in ingresses.iter_mut().enumerate() {
            loop {
                match tokio::time::timeout(Duration::from_millis(10), ingress.next_event()).await {
                    Ok(Some(phalanx_proto::network::NetworkEvent::DataReceived {
                        data, ..
                    })) if data.as_slice() == CANARY => {
                        received[i] += 1;
                    }
                    Ok(Some(_)) => {} // drain other events
                    _ => break,
                }
            }
        }

        let all_ready = received
            .iter()
            .enumerate()
            .all(|(i, &n)| i == publisher_idx || n >= NEEDED_PER_NODE);
        if all_ready {
            eprintln!(
                "Warmup complete in {:?}. Per-node received counts: {received:?}",
                warmup_start.elapsed()
            );
            return;
        }
    }
    panic!(
        "Gossipsub mesh warmup timed out after {WARMUP_TIMEOUT_SECS}s. \
        Per-node received counts: {received:?} (need ≥{NEEDED_PER_NODE} per non-publisher)"
    );
}

fn percentile(sorted: &[Duration], pct: f64) -> Duration {
    if sorted.is_empty() {
        return Duration::ZERO;
    }
    let idx = ((sorted.len() as f64 - 1.0) * pct).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

/// Bucket a byte-count into a 5-bucket histogram index.
/// Buckets: [0-100), [100-500), [500-2K), [2K-8K), [8K+).
fn write_size_bucket(bytes: u64) -> usize {
    match bytes {
        0..=99 => 0,
        100..=499 => 1,
        500..=2047 => 2,
        2048..=8191 => 3,
        _ => 4,
    }
}

const BUCKET_LABELS: [&str; 5] = ["[0-100)", "[100-500)", "[500-2K)", "[2K-8K)", "[8K+)"];

/// Print a labeled table of inter-IO gap percentiles.
fn print_gap_stats(label: &str, gaps: &mut Vec<Duration>) {
    if gaps.is_empty() {
        eprintln!("  {label}: (no gaps — fewer than 2 entries)");
        return;
    }
    gaps.sort();
    eprintln!(
        "  {label}: n={}, p50={:?}, p90={:?}, p99={:?}, max={:?}",
        gaps.len(),
        percentile(gaps, 0.50),
        percentile(gaps, 0.90),
        percentile(gaps, 0.99),
        percentile(gaps, 1.0),
    );
}

/// Drain all pending events (discovery drop, periodic PeerDiscovered from the
/// background swarm) so the ingress buffer doesn't overflow during long runs.
async fn drain_ingresses(ingresses: &mut [Libp2pIngress]) {
    for ingress in ingresses.iter_mut() {
        loop {
            match tokio::time::timeout(Duration::from_millis(1), ingress.next_event()).await {
                Ok(Some(_)) => continue,
                _ => break,
            }
        }
    }
}

/// Snapshot `io_log` contents for a node and clone into an owned Vec.
fn snapshot_io_log(egress: &Libp2pEgress) -> Vec<IoLogEntry> {
    egress
        .io_log()
        .map(|arc| arc.lock().unwrap().clone())
        .unwrap_or_default()
}

// ── Test 1: io_timing_distributions ──────────────────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- io_timing_distributions --ignored --nocapture
#[tokio::test]
async fn io_timing_distributions() {
    eprintln!("=== io_timing_distributions (idle mesh, {SAMPLE_DURATION_SECS}s) ===");
    let (egresses, mut ingresses) = setup_mesh(PORT_IO_TIMING).await;

    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(SAMPLE_DURATION_SECS) {
        drain_ingresses(&mut ingresses).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // ── Inter-IO gap analysis (primary) ──
    eprintln!("\n-- Inter-IO gap distribution --");
    for (i, egress) in egresses.iter().enumerate() {
        let mut log = snapshot_io_log(egress);
        if log.len() < 2 {
            eprintln!("Node {i}: insufficient IO entries ({})", log.len());
            continue;
        }
        eprintln!("Node {i}: {} IO events", log.len());

        // Aggregate gap (all entries, time-sorted)
        log.sort_by_key(|e| e.at);
        let mut aggregate: Vec<Duration> = log
            .windows(2)
            .map(|w| w[1].at.duration_since(w[0].at))
            .collect();
        print_gap_stats("aggregate", &mut aggregate);

        // Per-substream gap
        let mut by_stream: HashMap<u64, Vec<IoLogEntry>> = HashMap::new();
        for entry in &log {
            by_stream
                .entry(entry.substream_id)
                .or_default()
                .push(*entry);
        }
        let mut stream_ids: Vec<u64> = by_stream.keys().copied().collect();
        stream_ids.sort();
        for sid in stream_ids {
            let stream = by_stream.get(&sid).unwrap();
            if stream.len() < 2 {
                continue;
            }
            let mut gaps: Vec<Duration> = stream
                .windows(2)
                .map(|w| w[1].at.duration_since(w[0].at))
                .collect();
            print_gap_stats(&format!("substream #{sid} (n={})", stream.len()), &mut gaps);
        }
    }

    // ── Wake → IO latency (secondary) ──
    eprintln!("\n-- Wake→IO latency distribution --");
    let lookahead = Duration::from_millis(100);
    for (i, egress) in egresses.iter().enumerate() {
        let mut io_log = snapshot_io_log(egress);
        io_log.sort_by_key(|e| e.at);
        let wake_log = match egress.swarm_wake_log() {
            Some(log) => log.lock().unwrap().clone(),
            None => {
                eprintln!("Node {i}: no wake log");
                continue;
            }
        };

        let mut latencies: Vec<Duration> = Vec::new();
        let mut orphans: usize = 0;
        // io_log is sorted; for each wake, binary-search forward and linear-scan.
        for wake in &wake_log {
            let idx = io_log.partition_point(|e| e.at < *wake);
            if idx < io_log.len() {
                let latency = io_log[idx].at.duration_since(*wake);
                if latency <= lookahead {
                    latencies.push(latency);
                } else {
                    orphans += 1;
                }
            } else {
                orphans += 1;
            }
        }
        eprintln!(
            "Node {i}: {} wakes, {} had IO within {:?}, {} orphan",
            wake_log.len(),
            latencies.len(),
            lookahead,
            orphans,
        );
        print_gap_stats("latency", &mut latencies);
    }

    // Drop explicitly to shut down swarm tasks before returning.
    drop(egresses);
    drop(ingresses);
}

// ── Test 2: protocol_and_substream_attribution ───────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- protocol_and_substream_attribution --ignored --nocapture
#[tokio::test]
async fn protocol_and_substream_attribution() {
    eprintln!("=== protocol_and_substream_attribution (idle mesh, {SAMPLE_DURATION_SECS}s) ===");
    let (egresses, mut ingresses) = setup_mesh(PORT_PROTO_ATTR).await;

    // Aggregate per-node per-protocol counters across the whole mesh.
    let wake_handles: Vec<_> = egresses.iter().map(|e| e.swarm_wake_count()).collect();
    let proto_handles: Vec<_> = egresses.iter().map(|e| e.protocol_wakes()).collect();
    let initial_wakes: Vec<u64> = wake_handles
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();

    // CSV header
    println!(
        "timestamp_ms,total_wakes,gossipsub,kademlia,mdns,identify,autonat,\
dcutr,relay_server,relay_client,retrieval,connection,listener,other"
    );

    let start = Instant::now();
    for _tick in 1..=SAMPLE_DURATION_SECS {
        tokio::time::sleep(Duration::from_secs(1)).await;
        drain_ingresses(&mut ingresses).await;

        let total_wakes: u64 = wake_handles
            .iter()
            .zip(initial_wakes.iter())
            .map(|(c, init)| c.load(Ordering::Relaxed) - init)
            .sum();
        let sum = |sel: fn(
            &phalanx_transport::adapters::libp2p::ProtocolWakeCounters,
        ) -> &Arc<AtomicU64>|
         -> u64 {
            proto_handles
                .iter()
                .map(|p| sel(p).load(Ordering::Relaxed))
                .sum()
        };
        let gossipsub = sum(|p| &p.gossipsub);
        let kademlia = sum(|p| &p.kademlia);
        let mdns = sum(|p| &p.mdns);
        let identify = sum(|p| &p.identify);
        let autonat = sum(|p| &p.autonat);
        let dcutr = sum(|p| &p.dcutr);
        let relay_server = sum(|p| &p.relay_server);
        let relay_client = sum(|p| &p.relay_client);
        let retrieval = sum(|p| &p.retrieval);
        let connection = sum(|p| &p.connection);
        let listener = sum(|p| &p.listener);
        let other = sum(|p| &p.other);

        let elapsed_ms = start.elapsed().as_millis();
        println!(
            "{elapsed_ms},{total_wakes},{gossipsub},{kademlia},{mdns},{identify},\
{autonat},{dcutr},{relay_server},{relay_client},{retrieval},{connection},{listener},{other}"
        );
    }

    // ── Per-substream IO attribution ──
    eprintln!("\n-- Per-substream IO totals --");
    for (i, egress) in egresses.iter().enumerate() {
        let mut log = snapshot_io_log(egress);
        if log.is_empty() {
            eprintln!("Node {i}: empty io_log");
            continue;
        }
        log.sort_by_key(|e| e.at);
        let mut by_stream: HashMap<u64, (u64, u64, u64, Instant, Instant)> = HashMap::new();
        for entry in &log {
            let slot = by_stream
                .entry(entry.substream_id)
                .or_insert((0, 0, 0, entry.at, entry.at));
            match entry.kind {
                IoKind::Read => slot.0 += entry.bytes,
                IoKind::Write => slot.1 += entry.bytes,
            }
            slot.2 += 1;
            slot.3 = slot.3.min(entry.at);
            slot.4 = slot.4.max(entry.at);
        }
        let mut rows: Vec<_> = by_stream.into_iter().collect();
        rows.sort_by_key(|(_, (r, w, _, _, _))| std::cmp::Reverse(r + w));
        eprintln!("Node {i}: substream_id | bytes_read | bytes_written | io_ops | span_ms");
        for (sid, (r, w, ops, first, last)) in rows.iter().take(20) {
            let span_ms = last.duration_since(*first).as_millis();
            eprintln!("  {sid:4} | {r:>12} | {w:>12} | {ops:>6} | {span_ms:>8}");
        }
    }

    // ── Sanity: sum(12 protocol counters) == total wake count per node ──
    eprintln!("\n-- Per-protocol wake attribution sanity check --");
    for (i, (wake, proto)) in wake_handles.iter().zip(proto_handles.iter()).enumerate() {
        let total = wake.load(Ordering::Relaxed);
        let sum = proto.gossipsub.load(Ordering::Relaxed)
            + proto.kademlia.load(Ordering::Relaxed)
            + proto.mdns.load(Ordering::Relaxed)
            + proto.identify.load(Ordering::Relaxed)
            + proto.autonat.load(Ordering::Relaxed)
            + proto.dcutr.load(Ordering::Relaxed)
            + proto.relay_server.load(Ordering::Relaxed)
            + proto.relay_client.load(Ordering::Relaxed)
            + proto.retrieval.load(Ordering::Relaxed)
            + proto.connection.load(Ordering::Relaxed)
            + proto.listener.load(Ordering::Relaxed)
            + proto.other.load(Ordering::Relaxed);
        let diff = total.abs_diff(sum);
        eprintln!("Node {i}: total_wakes={total}, per_protocol_sum={sum}, diff={diff}");
        // Small racey drift is acceptable (the two reads happen in separate
        // atomic ops). A large diff means a SwarmEvent variant is unclassified.
        assert!(
            diff <= 16,
            "Node {i}: per-protocol sum drifted from total by {diff} — \
            a SwarmEvent variant is likely unclassified in handle_swarm_event!"
        );
    }

    drop(egresses);
    drop(ingresses);
}

// ── Tests 3-5 shared harness ─────────────────────────────────────────────

struct BurstRunResult {
    coarse_csv: Vec<String>,
    queue_samples: Vec<(Instant, u64)>,
}

/// Run a burst-shaped load test. The publisher closure is spawned as its own
/// task (gets a cloned egress + start instant). Main task samples at 1s
/// cadence while a concurrent task samples queue_depth at 10ms cadence.
async fn run_burst_test<F, Fut>(
    label: &str,
    egresses: Vec<Libp2pEgress>,
    mut ingresses: Vec<Libp2pIngress>,
    publisher: F,
) -> BurstRunResult
where
    F: FnOnce(Libp2pEgress, Instant) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    eprintln!("=== {label} ===");
    let start = Instant::now();

    // Fine queue-depth sampler: Node 1 (publisher).
    let queue_handle = egresses[1].outbound_queue_depth();
    let queue_samples: Arc<Mutex<Vec<(Instant, u64)>>> = Arc::new(Mutex::new(Vec::new()));
    let queue_samples_task = queue_samples.clone();
    let stop_flag = Arc::new(AtomicU64::new(0));
    let stop_flag_task = stop_flag.clone();
    let fine_sampler = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(10));
        while stop_flag_task.load(Ordering::Relaxed) == 0 {
            interval.tick().await;
            let depth = queue_handle.load(Ordering::Relaxed);
            queue_samples_task
                .lock()
                .unwrap()
                .push((Instant::now(), depth));
        }
    });

    // Publisher task
    let pub_egress = egresses[1].clone();
    let publisher_task = tokio::spawn(publisher(pub_egress, start));

    // Coarse sampling loop (main task)
    let wake_handles: Vec<_> = egresses.iter().map(|e| e.swarm_wake_count()).collect();
    let bytes_sent_h: Vec<_> = egresses.iter().map(|e| e.socket_bytes_sent()).collect();
    let bytes_recv_h: Vec<_> = egresses.iter().map(|e| e.socket_bytes_received()).collect();
    let io_ops_h: Vec<_> = egresses.iter().map(|e| e.socket_io_ops()).collect();
    let initial_wakes: Vec<u64> = wake_handles
        .iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect();

    let mut coarse_csv = Vec::with_capacity(SAMPLE_DURATION_SECS as usize + 1);
    coarse_csv.push(
        "timestamp_ms,cumulative_wakes,bytes_sent,bytes_received,io_ops,bytes_per_op,\
queue_depth_min,queue_depth_max,queue_depth_mean"
            .to_string(),
    );

    for _tick in 1..=SAMPLE_DURATION_SECS {
        let window_start = Instant::now();
        tokio::time::sleep(Duration::from_secs(1)).await;
        drain_ingresses(&mut ingresses).await;
        let window_end = Instant::now();

        let cumulative_wakes: u64 = wake_handles
            .iter()
            .zip(initial_wakes.iter())
            .map(|(c, init)| c.load(Ordering::Relaxed) - init)
            .sum();
        let bytes_sent: u64 = bytes_sent_h.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        let bytes_received: u64 = bytes_recv_h.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        let io_ops: u64 = io_ops_h.iter().map(|c| c.load(Ordering::Relaxed)).sum();
        let bytes_per_op = if io_ops == 0 {
            0.0
        } else {
            bytes_sent as f64 / io_ops as f64
        };

        // Queue-depth min/max/mean over the 1s window (from the 10ms sampler).
        let samples_guard = queue_samples.lock().unwrap();
        let in_window: Vec<u64> = samples_guard
            .iter()
            .filter(|(at, _)| *at >= window_start && *at <= window_end)
            .map(|(_, d)| *d)
            .collect();
        drop(samples_guard);
        let (qmin, qmax, qmean) = if in_window.is_empty() {
            (0, 0, 0.0)
        } else {
            let min = *in_window.iter().min().unwrap();
            let max = *in_window.iter().max().unwrap();
            let mean = in_window.iter().copied().sum::<u64>() as f64 / in_window.len() as f64;
            (min, max, mean)
        };

        let elapsed_ms = start.elapsed().as_millis();
        coarse_csv.push(format!(
            "{elapsed_ms},{cumulative_wakes},{bytes_sent},{bytes_received},{io_ops},\
{bytes_per_op:.2},{qmin},{qmax},{qmean:.2}"
        ));
    }

    // Shut down sampler + publisher.
    stop_flag.store(1, Ordering::Relaxed);
    let _ = fine_sampler.await;
    let _ = publisher_task.await;

    let queue_samples_out = queue_samples.lock().unwrap().clone();
    let result = BurstRunResult {
        coarse_csv,
        queue_samples: queue_samples_out,
    };

    // ── End-of-test blocks ──
    println!(
        "\n-- Coarse CSV ({label}) --\n{}",
        result.coarse_csv.join("\n")
    );

    // Write-size histogram (aggregated over all nodes). Bucketed view kept for
    // continuity with prior runs; the empirical CDF below is the data-derived
    // companion that doesn't depend on bucket choice.
    let mut buckets = [0u64; 5];
    let mut total_writes = 0u64;
    let mut all_write_sizes: Vec<u64> = Vec::new();
    for egress in &egresses {
        for e in snapshot_io_log(egress) {
            if e.kind == IoKind::Write {
                buckets[write_size_bucket(e.bytes)] += 1;
                total_writes += 1;
                all_write_sizes.push(e.bytes);
            }
        }
    }
    eprintln!("\n-- Write-size histogram (all nodes, n={total_writes}) --");
    for (i, label) in BUCKET_LABELS.iter().enumerate() {
        let pct = if total_writes == 0 {
            0.0
        } else {
            100.0 * buckets[i] as f64 / total_writes as f64
        };
        eprintln!("  {label:>10}: {:>8} ({pct:5.1}%)", buckets[i]);
    }

    // Empirical CDF of write sizes — derived from the data, no bucket choice.
    all_write_sizes.sort_unstable();
    if !all_write_sizes.is_empty() {
        let n = all_write_sizes.len();
        let last = n - 1;
        let percentile_at = |p: f64| -> u64 {
            let idx = ((last as f64) * p).round() as usize;
            all_write_sizes[idx.min(last)]
        };
        let sum: u128 = all_write_sizes.iter().map(|&b| b as u128).sum();
        let mean = sum as f64 / n as f64;
        eprintln!("\n-- Write-size empirical CDF (all nodes, n={n}) --");
        eprintln!("  min:    {:>7}", all_write_sizes[0]);
        eprintln!("  p10:    {:>7}", percentile_at(0.10));
        eprintln!("  p25:    {:>7}", percentile_at(0.25));
        eprintln!("  p50:    {:>7}", percentile_at(0.50));
        eprintln!("  p75:    {:>7}", percentile_at(0.75));
        eprintln!("  p90:    {:>7}", percentile_at(0.90));
        eprintln!("  p95:    {:>7}", percentile_at(0.95));
        eprintln!("  p99:    {:>7}", percentile_at(0.99));
        eprintln!("  p99.9:  {:>7}", percentile_at(0.999));
        eprintln!("  max:    {:>7}", all_write_sizes[last]);
        eprintln!("  mean:   {mean:>9.1}");
    }

    // Queue-depth-at-IO (publisher node only: match each Write entry to the
    // nearest queue-depth sample within ±5ms).
    eprintln!("\n-- Queue depth at publisher IO (Node 1, ±5ms correlation) --");
    let mut io_log = snapshot_io_log(&egresses[1]);
    io_log.sort_by_key(|e| e.at);
    let tolerance = Duration::from_millis(5);
    let mut matched_depths: Vec<u64> = Vec::new();
    let mut unmatched = 0usize;
    // For each Write entry, binary-search the queue samples.
    for entry in io_log.iter().filter(|e| e.kind == IoKind::Write) {
        let idx = result
            .queue_samples
            .partition_point(|(at, _)| *at < entry.at);
        let mut best: Option<(Duration, u64)> = None;
        for &(at, depth) in &result.queue_samples
            [idx.saturating_sub(1)..=idx.min(result.queue_samples.len().saturating_sub(1))]
        {
            let gap = if at >= entry.at {
                at.duration_since(entry.at)
            } else {
                entry.at.duration_since(at)
            };
            if gap <= tolerance && best.as_ref().is_none_or(|(g, _)| gap < *g) {
                best = Some((gap, depth));
            }
        }
        if let Some((_, depth)) = best {
            matched_depths.push(depth);
        } else {
            unmatched += 1;
        }
    }
    matched_depths.sort();
    eprintln!(
        "  matched={}, unmatched={} | p50={}, p90={}, p99={}, max={}",
        matched_depths.len(),
        unmatched,
        matched_depths
            .get(matched_depths.len() / 2)
            .copied()
            .unwrap_or(0),
        matched_depths
            .get(matched_depths.len() * 9 / 10)
            .copied()
            .unwrap_or(0),
        matched_depths
            .get(matched_depths.len() * 99 / 100)
            .copied()
            .unwrap_or(0),
        matched_depths.last().copied().unwrap_or(0),
    );

    // Per-substream IO totals (publisher node only).
    eprintln!("\n-- Per-substream IO totals (Node 1) --");
    let mut per_stream: HashMap<u64, (u64, u64, u64)> = HashMap::new();
    for e in &io_log {
        let slot = per_stream.entry(e.substream_id).or_insert((0, 0, 0));
        match e.kind {
            IoKind::Read => slot.0 += e.bytes,
            IoKind::Write => slot.1 += e.bytes,
        }
        slot.2 += 1;
    }
    let mut rows: Vec<_> = per_stream.into_iter().collect();
    rows.sort_by_key(|(_, (r, w, _))| std::cmp::Reverse(r + w));
    eprintln!("  substream_id | bytes_read | bytes_written | io_ops");
    for (sid, (r, w, ops)) in rows.iter().take(20) {
        eprintln!("  {sid:12} | {r:>10} | {w:>13} | {ops:>6}");
    }

    // Final queue depth (used by Test 3 for drift assertion).
    let final_depth = egresses[1].outbound_queue_depth().load(Ordering::Relaxed);
    eprintln!("\n-- Final outbound_queue_depth (Node 1): {final_depth} --");

    // Gossipsub publish errors per node (InsufficientPeers, MessageTooLarge, etc).
    // A non-zero publisher count means gossipsub silently rejected publishes
    // that the test harness thought succeeded at the TransportCommand level.
    eprintln!("\n-- Gossipsub publish errors --");
    for (i, egress) in egresses.iter().enumerate() {
        let errs = egress.gossipsub_publish_errors().load(Ordering::Relaxed);
        eprintln!("  Node {i}: {errs}");
    }

    drop(egresses);
    drop(ingresses);

    result
}

// ── Test 3: batching_constant_10_msgs ────────────────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- batching_constant_10_msgs --ignored --nocapture
#[tokio::test]
async fn batching_constant_10_msgs() {
    let (egresses, mut ingresses) = setup_mesh(PORT_CONSTANT).await;
    warmup_gossipsub_mesh(&egresses, &mut ingresses, 1).await;
    let queue_handle = egresses[1].outbound_queue_depth();

    run_burst_test(
        "batching_constant_10_msgs (10 msg/s × 120s = 1200 msgs)",
        egresses,
        ingresses,
        |egress, start| async move {
            let topic = MeshTopic::new(TOPIC);
            let payload = vec![0u8; PAYLOAD_BYTES];
            let mut interval = tokio::time::interval(Duration::from_millis(100));
            for seq in 0u64..1200 {
                interval.tick().await;
                if start.elapsed() >= Duration::from_secs(SAMPLE_DURATION_SECS) {
                    break;
                }
                let mut payload_with_seq = payload.clone();
                payload_with_seq[0..8].copy_from_slice(&seq.to_le_bytes());
                if let Err(e) = egress.publish(&topic, payload_with_seq).await {
                    eprintln!("publish #{seq} failed: {e}");
                }
            }
        },
    )
    .await;

    // Drift assertion: steady-state queue depth after 120s of constant load.
    let final_depth = queue_handle.load(Ordering::Relaxed);
    assert!(
        final_depth <= 10,
        "outbound_queue_depth drifted to {final_depth} after 1200 publishes — \
        likely a dec missing from one of the command_rx.recv() arms"
    );
}

// ── Test 4: batching_burst_50_every_10s ──────────────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- batching_burst_50_every_10s --ignored --nocapture
#[tokio::test]
async fn batching_burst_50_every_10s() {
    let (egresses, mut ingresses) = setup_mesh(PORT_BURST).await;
    warmup_gossipsub_mesh(&egresses, &mut ingresses, 1).await;

    run_burst_test(
        "batching_burst_50_every_10s (12 bursts of 50, 600 msgs total)",
        egresses,
        ingresses,
        |egress, start| async move {
            let topic = MeshTopic::new(TOPIC);
            let payload = vec![0u8; PAYLOAD_BYTES];
            let mut next_burst = Duration::from_secs(0);
            for burst in 0u64..12 {
                let wait = next_burst.saturating_sub(start.elapsed());
                if !wait.is_zero() {
                    tokio::time::sleep(wait).await;
                }
                for seq in 0u64..50 {
                    let mut p = payload.clone();
                    let tag = burst * 50 + seq;
                    p[0..8].copy_from_slice(&tag.to_le_bytes());
                    if let Err(e) = egress.publish(&topic, p).await {
                        eprintln!("burst {burst} #{seq} failed: {e}");
                    }
                }
                next_burst += Duration::from_secs(10);
            }
        },
    )
    .await;
}

// ── Test 5: batching_flood_500_at_30s ────────────────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- batching_flood_500_at_30s --ignored --nocapture
#[tokio::test]
async fn batching_flood_500_at_30s() {
    let (egresses, mut ingresses) = setup_mesh(PORT_FLOOD).await;
    warmup_gossipsub_mesh(&egresses, &mut ingresses, 1).await;

    run_burst_test(
        "batching_flood_500_at_30s (idle 30s, 500 msgs, idle to 120s)",
        egresses,
        ingresses,
        |egress, start| async move {
            let topic = MeshTopic::new(TOPIC);
            let payload = vec![0u8; PAYLOAD_BYTES];
            // Wait until t=30s
            let wait = Duration::from_secs(30).saturating_sub(start.elapsed());
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }
            eprintln!("flood: starting at elapsed={:?}", start.elapsed());
            for seq in 0u64..500 {
                let mut p = payload.clone();
                p[0..8].copy_from_slice(&seq.to_le_bytes());
                if let Err(e) = egress.publish(&topic, p).await {
                    eprintln!("flood #{seq} failed: {e}");
                }
            }
            eprintln!("flood: done at elapsed={:?}", start.elapsed());
        },
    )
    .await;
}

// ── Tests 6-8: realistic media-egress workloads ──────────────────────────
//
// Each video frame (30 fps) is RaptorQ-encoded into many 1200-byte symbols,
// and each symbol is a separate gossipsub.publish() (see
// `publish_fountain_symbols` in phalanx-node::actors::media_egress). These
// tests reproduce that geometry: a burst of N symbols every 33 ms for 120 s.
//
//   burst_size | source quality  | sustained publish rate
//   -----------+-----------------+------------------------
//   24         | ~500 kbps (cellular H.264)  | ~720 msg/s
//   90         | ~2 Mbps (typical mobile)    | ~2,700 msg/s
//   215        | ~5 Mbps (1080p)             | ~6,450 msg/s

/// Burst-per-frame publisher. Ticks at 30 Hz; each tick fires `burst_size`
/// publishes back-to-back. If libp2p's drain can't keep up, `publish().await`
/// backpressures against the 2048-capacity command channel — that is a valid
/// observation (queue depth hits its cap), not a test failure.
async fn media_burst_publisher(egress: Libp2pEgress, start: Instant, burst_size: usize) {
    let topic = MeshTopic::new(TOPIC);
    let payload = vec![0u8; SYMBOL_SIZE];
    let mut interval = tokio::time::interval(Duration::from_millis(33));
    let mut seq: u64 = 0;
    const FRAME_COUNT: u64 = 30 * SAMPLE_DURATION_SECS;
    for _frame in 0u64..FRAME_COUNT {
        interval.tick().await;
        if start.elapsed() >= Duration::from_secs(SAMPLE_DURATION_SECS) {
            break;
        }
        for _ in 0..burst_size {
            let mut p = payload.clone();
            p[0..8].copy_from_slice(&seq.to_le_bytes());
            if let Err(e) = egress.publish(&topic, p).await {
                eprintln!("publish seq={seq} failed: {e}");
                return;
            }
            seq += 1;
        }
    }
}

// ── Test 6: batching_media_low_cellular ──────────────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- batching_media_low_cellular --ignored --nocapture
#[tokio::test]
async fn batching_media_low_cellular() {
    let (egresses, mut ingresses) = setup_mesh(PORT_MEDIA_LOW).await;
    warmup_gossipsub_mesh(&egresses, &mut ingresses, 1).await;

    run_burst_test(
        "batching_media_low_cellular (24 msgs / 33ms × 120s, ~720 msg/s, 500 kbps H.264)",
        egresses,
        ingresses,
        |egress, start| async move {
            media_burst_publisher(egress, start, 24).await;
        },
    )
    .await;
}

// ── Test 7: batching_media_medium_mobile ─────────────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- batching_media_medium_mobile --ignored --nocapture
#[tokio::test]
async fn batching_media_medium_mobile() {
    let (egresses, mut ingresses) = setup_mesh(PORT_MEDIA_MEDIUM).await;
    warmup_gossipsub_mesh(&egresses, &mut ingresses, 1).await;

    run_burst_test(
        "batching_media_medium_mobile (90 msgs / 33ms × 120s, ~2700 msg/s, 2 Mbps)",
        egresses,
        ingresses,
        |egress, start| async move {
            media_burst_publisher(egress, start, 90).await;
        },
    )
    .await;
}

// ── Test 8: batching_media_high_1080p ────────────────────────────────────

#[ignore]
// cargo test -p phalanx-transport --test batching_tests -- batching_media_high_1080p --ignored --nocapture
#[tokio::test]
async fn batching_media_high_1080p() {
    let (egresses, mut ingresses) = setup_mesh(PORT_MEDIA_HIGH).await;
    warmup_gossipsub_mesh(&egresses, &mut ingresses, 1).await;

    run_burst_test(
        "batching_media_high_1080p (215 msgs / 33ms × 120s, ~6450 msg/s, 5 Mbps)",
        egresses,
        ingresses,
        |egress, start| async move {
            media_burst_publisher(egress, start, 215).await;
        },
    )
    .await;
}
