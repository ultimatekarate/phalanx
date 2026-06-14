//! Homeostasis Load Test — Tier 0 measurement.
//!
//! Tests whether the Volterra homeostasis loop closes on gossipsub rejection
//! through *existing* pressure signals (`bytes_sent`, `io_ops`) without any
//! explicit wiring of `gossipsub_publish_errors` into `transport_drops`.
//!
//! Setup: 3-node libp2p mesh on loopback. Node 1 is the publisher, with a
//! `SystemGovernor` whose IO counters are wired to its adapter. The publisher
//! task fires `SYMBOLS_PER_FRAME` 1200-byte symbols at the FPS dictated by
//! `target_fps(BASE_FPS, recommended_power_state())`. A vitals-update task
//! ticks at the governor's recommended interval (`vitals_polling_interval()`).
//!
//! Decision branch (per `~/.claude/plans/create-these-new-tests-flickering-petal.md`):
//!   1. Steady-state rejection rate (after t=30s) below RaptorQ's 33% recovery
//!      margin AND `current_fps` decreased from 30 → loop closes on existing
//!      signals; correctness concern is bounded; close.
//!   2. Steady-state rejection elevated despite `current_fps` not decreasing
//!      → loop does not close on proxies; Tier 2 (wire
//!      `gossipsub_publish_errors` into `SystemGovernor::transport_drops`)
//!      is the structural fix.
//!   3. Steady-state OK but transient peaks during PowerState transitions
//!      exceed the margin → Tier 1 (queue-cap bump) absorbs the overshoot
//!      during Volterra response time.
//!
//! Run:
//! ```sh
//! cargo test -p phalanx-node --test homeostasis_load_test -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Caveats:
//! - Loopback ≠ production network. This exercises gossipsub queue saturation
//!   under a sustained publish rate; it cannot reproduce production scenarios
//!   where the bottleneck is cellular/WiFi uplink bandwidth.
//! - Camera + media_egress actors are bypassed. Test directly drives publishes
//!   at the FPS-determined rate. Production has additional CPU/memory pressure
//!   contributions to `composite_stress` that this test does not capture.
//! - Per-recording loss is approximated by 5-second windows rather than tracked
//!   per recording_id. Distribution shape captures bursty vs. uniform but does
//!   not isolate any single recording's loss exactly.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use phalanx_node::hardware::camera::target_fps;
use phalanx_node::vitals::SystemGovernor;
use phalanx_proto::identity::PhalanxIdentity;
use phalanx_proto::network::{EgressPort, IngressPort};
use phalanx_proto::topic::MeshTopic;
use phalanx_proto::types::Fps;
use phalanx_transport::adapters::libp2p::{AdapterConfig, Libp2pEgress, Libp2pIngress};
use phalanx_transport::config::MeshTransportConfig;
use phalanx_transport::factory::build_mesh_transport;
use tokio::time::Instant;

const NODE_COUNT: usize = 3;
const DISCOVERY_WAIT_SECS: u64 = 10;
// Reduced from 240 → 60 for the bottleneck-attribution arc: the question is
// drain rate (which stabilizes well within 60s), not RaptorQ recovery margin
// over a long steady-state window. See `docs/bottleneck-attribution-arc.md`.
const SAMPLE_DURATION_SECS: u64 = 60;
const TOPIC: &str = "test/homeostasis";
// Un-bundled production-current parameters: 1200-byte RaptorQ symbols at
// 215 per frame × 30 fps target. The known cliff regime where gossipsub
// rejects ~99.9% of publishes after the mesh-prune cascade fires (see
// `docs/bundling-diagnostic-arc.md`). Used here to characterize the
// per-variant rejection breakdown via `PublishErrorCounters`.
const SYMBOL_SIZE: usize = 1200;
const SYMBOLS_PER_FRAME: usize = 215;
const BASE_FPS: u32 = 30;
const PUBLISHER_IDX: usize = 1;
const BASE_PORT: u16 = 39280;

// ── Helpers (copy-pasted from crates/phalanx-transport/tests/batching_tests.rs) ──

fn make_config(base_port: u16, node_index: usize) -> MeshTransportConfig {
    let port = base_port + node_index as u16;
    // Distinct loopback IPs per node (127.0.0.1/2/3) so gossipsub's
    // ip_colocation_factor penalty (threshold=3) never engages.
    let ip_octet = 1 + node_index as u8;
    let mut bootstrap_peers = Vec::new();
    if node_index > 0 {
        bootstrap_peers.push(format!("/ip4/127.0.0.1/tcp/{base_port}"));
    }
    MeshTransportConfig {
        listen_addresses: vec![format!("/ip4/127.0.0.{ip_octet}/tcp/{port}")],
        bootstrap_peers,
        subscribe_topics: vec![MeshTopic::new(TOPIC).to_string()],
        adapter: AdapterConfig {
            enable_wake_log: true,
            enable_io_log: true,
            enable_publish_timing: true,
            poll_cadence: None,
            ..AdapterConfig::default()
        },
        ..MeshTransportConfig::default()
    }
}

async fn setup_mesh(
    runtimes: &[tokio::runtime::Runtime],
    base_port: u16,
) -> (Vec<Libp2pEgress>, Vec<Libp2pIngress>) {
    eprintln!("Creating {NODE_COUNT} swarm nodes (base port: {base_port})...");
    let mut egresses = Vec::with_capacity(NODE_COUNT);
    let mut ingresses = Vec::with_capacity(NODE_COUNT);
    for i in 0..NODE_COUNT {
        let config = make_config(base_port, i);
        let identity = PhalanxIdentity::new_ephemeral();
        // Build inside this node's dedicated runtime context so the swarm
        // task (spawned internally by build_mesh_transport) runs on this
        // node's runtime — isolates from other nodes' tokio scheduling.
        let _guard = runtimes[i].enter();
        let (ingress, egress) = build_mesh_transport(&identity, &config)
            .unwrap_or_else(|e| panic!("Node {i} failed to build: {e}"));
        drop(_guard);
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
                    Ok(Some(_)) => {}
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

// ── The test ──

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn homeostasis_load_test() {
    // Narrowly-filtered tracing subscriber. Captures gossipsub's heartbeat
    // prune decisions (e.g., "HEARTBEAT: Prune peer with negative score") to
    // diagnose whether the publisher is being pruned from the topic mesh.
    // Everything outside libp2p_gossipsub is suppressed at warn level so the
    // 240s test doesn't spew unrelated debug noise. `try_init` so the test
    // co-exists with other tests in the same binary.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "warn,libp2p_gossipsub=debug",
        ))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();

    eprintln!(
        "=== homeostasis_load_test ({SAMPLE_DURATION_SECS}s, FPS={BASE_FPS} base, {SYMBOLS_PER_FRAME} symbols/frame) ==="
    );

    // Per-node dedicated tokio runtimes. Each node's swarm task and async
    // helpers run on its own runtime so tokio-scheduler-level contention
    // between nodes is eliminated. This isolates the test from the
    // single-process-runtime confound (drain rate appearing capped because
    // all nodes share one scheduler queue).
    eprintln!("Creating {NODE_COUNT} dedicated tokio runtimes (2 worker threads each)...");
    let runtimes: Vec<tokio::runtime::Runtime> = (0..NODE_COUNT)
        .map(|i| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .thread_name(format!("phalanx-node-{i}"))
                .build()
                .unwrap_or_else(|e| panic!("Failed to build runtime {i}: {e}"))
        })
        .collect();

    let (egresses, mut ingresses) = setup_mesh(&runtimes, BASE_PORT).await;
    warmup_gossipsub_mesh(&egresses, &mut ingresses, PUBLISHER_IDX).await;

    // Drain ingresses after warmup so accumulated traffic doesn't skew the
    // initial CSV samples.
    for ingress in ingresses.iter_mut() {
        while let Ok(Some(_)) =
            tokio::time::timeout(Duration::from_millis(1), ingress.next_event()).await
        {}
    }

    // The publisher's `SystemGovernor` wired to its adapter's `IoCounters`.
    // `dropped` is left as a fresh empty counter — the test specifically does
    // NOT wire `gossipsub_publish_errors` into `transport_drops`. The question
    // it answers is whether the loop closes on existing proxy signals
    // (`bytes_sent`, `io_ops`) without that wiring.
    let publisher_egress = &egresses[PUBLISHER_IDX];
    let dropped_unused = Arc::new(AtomicU64::new(0));
    let governor = SystemGovernor::new()
        .with_io_counters(
            publisher_egress.socket_bytes_sent(),
            publisher_egress.socket_bytes_received(),
            publisher_egress.socket_io_ops(),
            dropped_unused,
        )
        .with_queue_depth(publisher_egress.outbound_queue_depth());
    let governor = Arc::new(governor);

    // Counters
    let publish_attempts = Arc::new(AtomicU64::new(0));
    let publish_errors = publisher_egress.gossipsub_publish_errors();
    let bytes_sent_arc = publisher_egress.socket_bytes_sent();
    let bytes_recv_arc = publisher_egress.socket_bytes_received();
    let queue_depth_arc = publisher_egress.outbound_queue_depth();
    let io_ops_arc = publisher_egress.socket_io_ops();
    // Per-publish timing — present because `enable_publish_timing: true` was
    // set on the publisher's AdapterConfig in `make_config`. Drives the E1
    // dispositive measurement: R = mean_call_us × drain_rate / 1e6.
    let publish_timing = publisher_egress
        .publish_timing()
        .expect("publish_timing must be Some when enable_publish_timing=true");
    // Per-variant breakdown of gossipsub publish failures. Always-on; only
    // the failure path increments.
    let publish_error_breakdown = publisher_egress.publish_error_breakdown();

    // Vitals-update task: ticks at the governor's recommended interval
    // (5/15/30/60s depending on PowerState). Spawned on the publisher's
    // runtime so it shares a scheduler with the publisher loop.
    let stop = Arc::new(AtomicBool::new(false));
    let governor_for_vitals = governor.clone();
    let stop_for_vitals = stop.clone();
    let vitals_task = runtimes[PUBLISHER_IDX].spawn(async move {
        while !stop_for_vitals.load(Ordering::Relaxed) {
            governor_for_vitals.update_vitals();
            let interval = governor_for_vitals.vitals_polling_interval();
            tokio::time::sleep(interval).await;
        }
    });

    // Publisher task: fires `SYMBOLS_PER_FRAME` symbols per frame at the FPS
    // dictated by `target_fps(BASE_FPS, recommended_power_state())`. Spawned
    // on the publisher's dedicated runtime so it doesn't compete with the
    // receivers' tokio scheduling.
    let governor_for_publisher = governor.clone();
    let attempts_for_pub = publish_attempts.clone();
    let publisher_egress_clone = publisher_egress.clone();
    let stop_for_pub = stop.clone();
    let publisher_task = runtimes[PUBLISHER_IDX].spawn(async move {
        let topic = MeshTopic::new(TOPIC);
        let payload = vec![0u8; SYMBOL_SIZE];
        while !stop_for_pub.load(Ordering::Relaxed) {
            let power = governor_for_publisher.current_power_state();
            let fps = target_fps(Fps::new(BASE_FPS), power);
            if fps.get() == 0 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
            // Smooth output via cooperative yield between messages instead of
            // the original "215 in tight loop, then sleep" pattern. tokio's
            // sleep can't pace at the 155µs inter-message interval that
            // FPS=30 × 215 symbols/frame implies, so we use yield_now() —
            // which gives the receivers' tasks a chance to run between every
            // publish without the timer-wheel precision floor. The publisher
            // self-paces against the command channel's drain rate, but
            // interleaved with receiver work rather than 215-deep bursts.
            let _ = publisher_egress_clone
                .publish(&topic, payload.clone())
                .await;
            attempts_for_pub.fetch_add(1, Ordering::Relaxed);
            tokio::task::yield_now().await;
        }
    });

    // Receiver-drain tasks: each ingress must be drained or it overflows the
    // event channel. Spawned on each node's dedicated runtime.
    let mut ingress_handles = Vec::new();
    for (i, mut ingress) in ingresses.into_iter().enumerate() {
        let stop_for_ing = stop.clone();
        let h = runtimes[i].spawn(async move {
            while !stop_for_ing.load(Ordering::Relaxed) {
                let _ = tokio::time::timeout(Duration::from_millis(10), ingress.next_event()).await;
            }
        });
        ingress_handles.push(h);
    }

    // CSV header (stdout for piping; eprintln for status to stderr).
    // `bytes_recv_delta` is the diagnostic for graylisting: if peers stay
    // connected, gossipsub heartbeats keep this non-zero. If it flatlines
    // along with `bytes_sent_delta`, the publisher has been fully disconnected.
    // `mean_call_us` and `io_ops_per_publish` are the E1 dispositive metrics:
    // see `docs/bottleneck-attribution-arc.md`. `mean_call_us` is the per-window
    // mean wall-time of the swarm-task `gossipsub.publish()` call;
    // `io_ops_per_publish` is the swarm-side socket-op-to-publish-attempt ratio.
    // `err_*` columns are per-variant rejection-cause breakdowns. Sum to
    // `publish_errors_delta` (modulo small read races).
    println!(
        "t_sec,fps_target,power_state,composite_stress,publish_attempts_delta,publish_errors_delta,bytes_sent_delta,bytes_recv_delta,queue_depth,mean_call_us,io_ops_per_publish,err_all_queues_full,err_no_peers_subscribed,err_message_too_large,err_duplicate,err_signing,err_transform_failed"
    );

    // Per-second sampling loop on the test task.
    let test_start = Instant::now();
    let mut last_attempts = 0u64;
    let mut last_errors = 0u64;
    let mut last_bytes_sent = 0u64;
    let mut last_bytes_recv = 0u64;
    let mut last_io_ops = 0u64;
    let mut last_call_nanos_total = 0u64;
    let mut last_call_count = 0u64;
    let mut last_err_aqf = 0u64;
    let mut last_err_nps = 0u64;
    let mut last_err_mtl = 0u64;
    let mut last_err_dup = 0u64;
    let mut last_err_sig = 0u64;
    let mut last_err_xfm = 0u64;
    // (attempts_delta, errors_delta) per second — used for per-window analysis.
    let mut window_log: Vec<(u64, u64)> = Vec::new();

    let mut tick = tokio::time::interval(Duration::from_secs(1));
    tick.tick().await; // immediate first tick
    while test_start.elapsed() < Duration::from_secs(SAMPLE_DURATION_SECS) {
        tick.tick().await;
        let t_sec = test_start.elapsed().as_secs();
        let attempts = publish_attempts.load(Ordering::Relaxed);
        let errors = publish_errors.load(Ordering::Relaxed);
        let bytes_sent = bytes_sent_arc.load(Ordering::Relaxed);
        let bytes_recv = bytes_recv_arc.load(Ordering::Relaxed);
        let queue = queue_depth_arc.load(Ordering::Relaxed);
        let io_ops = io_ops_arc.load(Ordering::Relaxed);
        let call_nanos_total = publish_timing.call_nanos_total.load(Ordering::Relaxed);
        let call_count = publish_timing.call_count.load(Ordering::Relaxed);
        let err_aqf = publish_error_breakdown
            .all_queues_full
            .load(Ordering::Relaxed);
        let err_nps = publish_error_breakdown
            .no_peers_subscribed
            .load(Ordering::Relaxed);
        let err_mtl = publish_error_breakdown
            .message_too_large
            .load(Ordering::Relaxed);
        let err_dup = publish_error_breakdown.duplicate.load(Ordering::Relaxed);
        let err_sig = publish_error_breakdown
            .signing_error
            .load(Ordering::Relaxed);
        let err_xfm = publish_error_breakdown
            .transform_failed
            .load(Ordering::Relaxed);
        let attempts_delta = attempts.saturating_sub(last_attempts);
        let errors_delta = errors.saturating_sub(last_errors);
        let bytes_sent_delta = bytes_sent.saturating_sub(last_bytes_sent);
        let bytes_recv_delta = bytes_recv.saturating_sub(last_bytes_recv);
        let io_ops_delta = io_ops.saturating_sub(last_io_ops);
        let call_nanos_delta = call_nanos_total.saturating_sub(last_call_nanos_total);
        let call_count_delta = call_count.saturating_sub(last_call_count);
        let err_aqf_delta = err_aqf.saturating_sub(last_err_aqf);
        let err_nps_delta = err_nps.saturating_sub(last_err_nps);
        let err_mtl_delta = err_mtl.saturating_sub(last_err_mtl);
        let err_dup_delta = err_dup.saturating_sub(last_err_dup);
        let err_sig_delta = err_sig.saturating_sub(last_err_sig);
        let err_xfm_delta = err_xfm.saturating_sub(last_err_xfm);
        last_attempts = attempts;
        last_errors = errors;
        last_bytes_sent = bytes_sent;
        last_bytes_recv = bytes_recv;
        last_io_ops = io_ops;
        last_call_nanos_total = call_nanos_total;
        last_call_count = call_count;
        last_err_aqf = err_aqf;
        last_err_nps = err_nps;
        last_err_mtl = err_mtl;
        last_err_dup = err_dup;
        last_err_sig = err_sig;
        last_err_xfm = err_xfm;

        let power = governor.current_power_state();
        let stress = governor.composite_stress();
        let fps = target_fps(Fps::new(BASE_FPS), power);

        // mean_call_us = (call_nanos_delta / call_count_delta) / 1000.
        // Guarded against div-by-zero in the warmup tick where call_count_delta=0.
        let mean_call_us = if call_count_delta > 0 {
            (call_nanos_delta as f64) / (call_count_delta as f64) / 1000.0
        } else {
            0.0
        };
        let io_ops_per_publish = if call_count_delta > 0 {
            (io_ops_delta as f64) / (call_count_delta as f64)
        } else {
            0.0
        };

        println!(
            "{t_sec},{},{:?},{:.3},{attempts_delta},{errors_delta},{bytes_sent_delta},{bytes_recv_delta},{queue},{mean_call_us:.2},{io_ops_per_publish:.2},{err_aqf_delta},{err_nps_delta},{err_mtl_delta},{err_dup_delta},{err_sig_delta},{err_xfm_delta}",
            fps.get(),
            power,
            stress
        );

        window_log.push((attempts_delta, errors_delta));
    }

    // Stop background tasks.
    stop.store(true, Ordering::Relaxed);
    let _ = vitals_task.await;
    let _ = publisher_task.await;
    for h in ingress_handles {
        let _ = h.await;
    }

    // ── Analysis blocks ──

    eprintln!("\n-- Per-5s-window rejection-rate distribution --");
    let mut window_rates: Vec<f64> = Vec::new();
    for chunk in window_log.chunks(5) {
        let attempts: u64 = chunk.iter().map(|(a, _)| *a).sum();
        let errors: u64 = chunk.iter().map(|(_, e)| *e).sum();
        if attempts > 0 {
            window_rates.push(errors as f64 / attempts as f64);
        }
    }
    window_rates.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    if window_rates.is_empty() {
        eprintln!("  (no windows with publishes — the test may have run without a working mesh)");
    } else {
        let n = window_rates.len();
        let p50 = window_rates[n.saturating_sub(1) / 2];
        let p90 = window_rates[(n.saturating_sub(1) * 90) / 100];
        let p99 = window_rates[(n.saturating_sub(1) * 99) / 100];
        let max = *window_rates.last().unwrap();
        eprintln!("  windows={n}, p50={p50:.3}, p90={p90:.3}, p99={p99:.3}, max={max:.3}");
        let over_margin = window_rates.iter().filter(|&&r| r > 0.333).count();
        eprintln!(
            "  RaptorQ RepairRatio=1.5 recovery margin (33.3%): {over_margin} of {n} windows above"
        );
    }

    // Per-node totals — the diagnostic for whether traffic flowed at all.
    // If publisher's bytes_sent ≈ 0 and other nodes' bytes_received ≈ 0,
    // the publisher's peer connections were torn down (graylisting).
    // If the publisher's bytes_sent grew but rejection rate is still high,
    // gossipsub queue saturation is the real bottleneck.
    eprintln!("\n-- Per-node IO totals (cumulative over test) --");
    eprintln!("  node | bytes_sent | bytes_received | gossipsub_publish_errors");
    for (i, eg) in egresses.iter().enumerate() {
        let sent = eg.socket_bytes_sent().load(Ordering::Relaxed);
        let recv = eg.socket_bytes_received().load(Ordering::Relaxed);
        let errs = eg.gossipsub_publish_errors().load(Ordering::Relaxed);
        let role = if i == PUBLISHER_IDX { "(pub)" } else { "     " };
        eprintln!("  {i} {role} | {sent:>10} | {recv:>14} | {errs:>23}");
    }

    eprintln!("\n-- Steady-state summary (post-30s window aggregate) --");
    let skip = 30usize.min(window_log.len());
    let steady = &window_log[skip..];
    let total_attempts: u64 = steady.iter().map(|(a, _)| *a).sum();
    let total_errors: u64 = steady.iter().map(|(_, e)| *e).sum();
    if total_attempts > 0 {
        let rate = total_errors as f64 / total_attempts as f64;
        eprintln!(
            "  attempts={total_attempts}, errors={total_errors}, rate={rate:.3} \
             ({})",
            if rate > 0.333 {
                "ABOVE RaptorQ recovery margin — Tier 2 likely justified"
            } else {
                "below RaptorQ recovery margin — loop closes on existing signals"
            }
        );
    } else {
        eprintln!("  (no publishes in steady-state window — test likely failed to drive load)");
    }

    // Per-variant rejection breakdown (cumulative over the run). Diagnoses
    // *why* gossipsub.publish() rejected — see PublishErrorCounters in
    // crates/phalanx-transport/src/adapters/libp2p.rs.
    eprintln!("\n-- Publish-error variant breakdown (cumulative) --");
    let total_errs = publish_errors.load(Ordering::Relaxed);
    let aqf = publish_error_breakdown
        .all_queues_full
        .load(Ordering::Relaxed);
    let aqf_peers = publish_error_breakdown
        .all_queues_full_peers_attempted
        .load(Ordering::Relaxed);
    let nps = publish_error_breakdown
        .no_peers_subscribed
        .load(Ordering::Relaxed);
    let mtl = publish_error_breakdown
        .message_too_large
        .load(Ordering::Relaxed);
    let dup = publish_error_breakdown.duplicate.load(Ordering::Relaxed);
    let sig = publish_error_breakdown
        .signing_error
        .load(Ordering::Relaxed);
    let xfm = publish_error_breakdown
        .transform_failed
        .load(Ordering::Relaxed);
    let pct = |n: u64| -> String {
        if total_errs == 0 {
            "  -  ".to_string()
        } else {
            format!("{:5.1}%", 100.0 * n as f64 / total_errs as f64)
        }
    };
    eprintln!("  total_errors          = {total_errs}");
    eprintln!("  all_queues_full       = {aqf:>8}  ({})", pct(aqf));
    if aqf > 0 {
        let mean_n = aqf_peers as f64 / aqf as f64;
        eprintln!("    mean peers attempted at saturation = {mean_n:.2} (sum n = {aqf_peers})");
    }
    eprintln!("  no_peers_subscribed   = {nps:>8}  ({})", pct(nps));
    eprintln!("  message_too_large     = {mtl:>8}  ({})", pct(mtl));
    eprintln!("  duplicate             = {dup:>8}  ({})", pct(dup));
    eprintln!("  signing_error         = {sig:>8}  ({})", pct(sig));
    eprintln!("  transform_failed      = {xfm:>8}  ({})", pct(xfm));
    let breakdown_sum = aqf + nps + mtl + dup + sig + xfm;
    if breakdown_sum != total_errs {
        eprintln!(
            "  NOTE: breakdown sum ({breakdown_sum}) != total ({total_errs}) — small read race"
        );
    }

    eprintln!("\n=== homeostasis_load_test complete ===");

    // Shut runtimes down without blocking the outer (test) runtime — dropping
    // a Runtime from within an async context would panic in tokio's blocking
    // shutdown. shutdown_background returns immediately and lets the worker
    // threads finish on their own.
    for rt in runtimes {
        rt.shutdown_background();
    }
}
