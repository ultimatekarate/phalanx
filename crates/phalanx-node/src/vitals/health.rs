// crates/phalanx-node/src/vitals/health.rs
//
// Observability (telemetry initialization) and health tracking.
//
// ── Lock discipline ────────────────────────────────────────────────────────
// HealthTracker is shared across actors via `Arc<HealthTracker>`. Each field
// is wrapped in `std::sync::RwLock` so multiple actors can read concurrently
// without coarse mutex contention.
//
// **Poison handling:** lock acquisition uses `unwrap_or_else(|e| e.into_inner())`
// (matching SystemGovernor / ReputationProjection convention) so a panic in
// one actor cannot cascade into permanent unavailability for the rest. The
// data is recovered as-of the panic and operation continues.
//
// **NEVER hold a `RwLock` guard across an `.await`.** A single async task
// suspending while holding a write-lock will deadlock any other task
// attempting to acquire the same lock — including read-locks.
//
// CORRECT — acquire, copy/test, drop in one statement:
//
//     let peers: Vec<MeshAddress> = self.heartbeats
//         .read().unwrap_or_else(|e| e.into_inner())
//         .keys().cloned().collect();
//     // …iterate `peers` without holding the lock…
//
// WRONG — guard held across .await, deadlocks if anyone tries to write:
//
//     let guard = self.heartbeats.read().unwrap_or_else(|e| e.into_inner());
//     for peer in guard.keys() {
//         some_async_call(peer).await;
//     }
//
// All accessor methods on `HealthTracker` follow the correct pattern: they
// acquire the lock, do their work, and drop the guard before returning.
// Callers that need to compose their own logic should retrieve the data they
// need via these accessors rather than reaching for raw fields.

use std::collections::HashMap;
use std::sync::{Once, OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::Level;
use tracing_subscriber::{filter::Targets, fmt, prelude::*};

use phalanx_proto::identity::MeshAddress;
use phalanx_proto::prelude::PhalanxPhysics;
use phalanx_proto::telemetry::SimEvent;
use phalanx_proto::types::VitalityRate;
use phalanx_proto::vitals::{ControlMessage, StressLoad};

use super::spectral::SpectralObserver;

static TELEMETRY_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();
static INIT: Once = Once::new();

pub struct TelemetryHub {
    pub tx: broadcast::Sender<SimEvent>,
}

/// The shared per-target telemetry filter — used by the desktop subscriber here
/// and by the Android subscriber in `phalanx-ffi`, so both keep identical levels.
///
/// `phalanx_transport` is admitted at DEBUG so the `Libp2pAdapter::publish` span
/// is captured; the prior filter omitted it, leaving it at the INFO default.
pub fn telemetry_filter() -> Targets {
    Targets::new()
        .with_target("phalanx_node", Level::DEBUG)
        .with_target("phalanx_forensics", Level::DEBUG)
        .with_target("phalanx_transport", Level::DEBUG)
        .with_target("phalanx::forensics::collision", Level::TRACE)
        .with_default(Level::INFO)
}

pub fn init_observability() {
    INIT.call_once(|| {
        let file_appender = tracing_appender::rolling::daily("logs", "guardian.log");
        let (non_blocking_file, file_guard) = tracing_appender::non_blocking(file_appender);

        let _ = TELEMETRY_GUARD.set(file_guard);

        let registry = tracing_subscriber::registry()
            .with(telemetry_filter())
            .with(
                fmt::layer()
                    .with_target(true)
                    .with_thread_ids(true)
                    .with_span_events(fmt::format::FmtSpan::CLOSE),
            )
            .with(fmt::layer().with_writer(non_blocking_file).json());

        let _ = registry.try_init();
    });
}

/// Per-peer health and spectral observer state. Designed for `Arc<HealthTracker>`
/// sharing across actors. See the lock-discipline note at the top of this file.
pub struct HealthTracker {
    heartbeats: RwLock<HashMap<MeshAddress, Instant>>,
    capacities: RwLock<HashMap<MeshAddress, ControlMessage>>,
    peer_contracts: RwLock<HashMap<MeshAddress, VitalityRate>>,

    /// Shield Wall: spectral behavioral observer for Byzantine detection.
    spectral: RwLock<SpectralObserver>,
}

impl HealthTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            heartbeats: RwLock::new(HashMap::new()),
            capacities: RwLock::new(HashMap::new()),
            peer_contracts: RwLock::new(HashMap::new()),
            spectral: RwLock::new(SpectralObserver::new()),
        }
    }

    /// Record a heartbeat from a peer. Updates `heartbeats`, `peer_contracts`,
    /// `capacities`, and the spectral observer atomically (each lock briefly).
    pub fn register_activity(&self, msg: ControlMessage) {
        let peer_id = msg.sender.clone();
        self.heartbeats
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer_id.clone(), Instant::now());
        self.peer_contracts
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer_id.clone(), VitalityRate::new(msg.heartbeat_ms));

        // Shield Wall: record heartbeat for spectral consistency evaluation.
        self.spectral
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .record_heartbeat(peer_id.clone(), &msg);

        self.capacities
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(peer_id, msg);
    }

    /// Whether the peer has missed its heartbeat contract by more than the
    /// physics-derived grace period. Returns `true` for unknown peers.
    #[must_use]
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Duration jitter arithmetic.
    pub fn is_peer_stale(&self, peer_id: &MeshAddress, physics: &PhalanxPhysics) -> bool {
        let last_time = match self
            .heartbeats
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_id)
        {
            Some(t) => *t,
            None => return true,
        };

        let contract = self
            .peer_contracts
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| VitalityRate::new(5000));

        let jitter_multiplier = (physics.tau_rtt as u32 / 10).max(2);
        let grace_period = contract.as_duration() * jitter_multiplier;

        last_time.elapsed() > grace_period
    }

    /// Snapshot of all peers we have heard a heartbeat from. The lock is
    /// released before the returned `Vec` is constructed.
    #[must_use]
    pub fn peer_addresses(&self) -> Vec<MeshAddress> {
        self.heartbeats
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    /// Whether we have observed at least one heartbeat from `peer`.
    #[must_use]
    pub fn has_heartbeat(&self, peer: &MeshAddress) -> bool {
        self.heartbeats
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(peer)
    }

    // ── Spectral observer accessors ────────────────────────────────────────

    /// Record a data-volume sample for spectral consistency evaluation.
    pub fn record_data_received(&self, peer_id: MeshAddress, bytes: usize) {
        self.spectral
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .record_data_received(peer_id, bytes);
    }

    /// Run a spectral consistency evaluation against accumulated samples.
    /// Returns `None` until `min_observations` heartbeats have been recorded.
    #[must_use]
    pub fn evaluate_spectral(&self, peer_id: &MeshAddress) -> Option<f64> {
        self.spectral
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .evaluate(peer_id)
    }

    /// Threshold above which a residual triggers an anomaly impulse.
    #[must_use]
    pub fn spectral_anomaly_threshold(&self) -> f64 {
        self.spectral
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .anomaly_threshold
    }

    /// Drop all spectral observations for a peer (called on peer disconnect).
    pub fn remove_spectral_peer(&self, peer_id: &MeshAddress) {
        self.spectral
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove_peer(peer_id);
    }
}

impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// Significance gate for outbound heartbeats. Owned by the publisher
/// (the vitals task), not by `HealthTracker` — heartbeat publishing is
/// a publisher-side concern, not a peer-tracking concern.
///
/// A broadcast fires when either:
/// - load delta since the last broadcast exceeds 0.10, OR
/// - 30 seconds have elapsed since the last broadcast.
///
/// The first call always fires (`last_at = None`) so a fresh node
/// advertises its presence on the first vitals tick rather than
/// waiting up to 30s for the elapsed branch when load is stable.
pub struct BroadcastGate {
    last_load: StressLoad,
    last_at: Option<Instant>,
}

impl BroadcastGate {
    #[must_use]
    pub fn new() -> Self {
        Self {
            last_load: StressLoad(0.0),
            last_at: None,
        }
    }

    /// Returns `true` if a broadcast should fire now. Updates internal
    /// state only when returning `true` (a `false` leaves the gate
    /// unchanged so the next call sees the same baseline).
    pub fn should_broadcast(&mut self, current_load: StressLoad) -> bool {
        let fire = match self.last_at {
            None => true,
            Some(at) => {
                let load_delta = (current_load.as_f32() - self.last_load.as_f32()).abs();
                load_delta > 0.10 || at.elapsed() > Duration::from_secs(30)
            }
        };
        if fire {
            self.last_load = current_load;
            self.last_at = Some(Instant::now());
        }
        fire
    }
}

impl Default for BroadcastGate {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::float_cmp
)]
mod tests {
    use super::*;

    fn peer(name: &str) -> MeshAddress {
        MeshAddress::new(name.to_string())
    }

    #[test]
    fn broadcast_gate_first_call_always_fires() {
        // Fresh gate (`last_at = None`) advertises presence on the first
        // vitals tick rather than waiting up to 30s for the elapsed branch.
        let mut gate = BroadcastGate::new();
        assert!(gate.should_broadcast(StressLoad(0.0)));
    }

    #[test]
    fn broadcast_gate_fires_on_significant_load_change() {
        // Significance rule: load delta > 0.10 triggers a broadcast.
        let mut gate = BroadcastGate::new();
        // Burn the always-fires-first slot at baseline.
        let _ = gate.should_broadcast(StressLoad(0.10));
        // Delta 0.30 → exceeds 0.10 threshold.
        assert!(gate.should_broadcast(StressLoad(0.40)));
    }

    #[test]
    fn broadcast_gate_skips_when_load_stable_and_time_fresh() {
        // After the first call updates `last_at`, a stable load within
        // 30s must not re-fire.
        let mut gate = BroadcastGate::new();
        let _ = gate.should_broadcast(StressLoad(0.50));
        // Delta 0.05 < 0.10; elapsed < 1s < 30s → no broadcast.
        assert!(!gate.should_broadcast(StressLoad(0.55)));
    }

    #[test]
    fn broadcast_gate_records_state_on_fire() {
        // When a broadcast fires, the gate must record what it sent;
        // otherwise the next call re-fires against the same delta.
        let mut gate = BroadcastGate::new();
        // First call always fires (initial baseline 0.0 → 0.75).
        assert!(gate.should_broadcast(StressLoad(0.75)));
        // Second call with the same value: delta 0.0 < 0.10, elapsed << 30s.
        assert!(!gate.should_broadcast(StressLoad(0.75)));
    }

    #[test]
    fn is_peer_stale_returns_true_for_unknown_peer() {
        // An unknown peer has never heartbeated — must be treated as stale.
        // Any other behaviour would let silent peers coast indefinitely.
        let tracker = HealthTracker::new();
        let physics = PhalanxPhysics::default();
        assert!(tracker.is_peer_stale(&peer("ghost"), &physics));
    }

    #[test]
    fn is_peer_stale_returns_false_immediately_after_registration() {
        // Freshly registered peer — elapsed time is microseconds, grace
        // period is measured in seconds.
        let tracker = HealthTracker::new();
        let pid = peer("live");
        let msg = ControlMessage {
            sender: pid.clone(),
            load_factor: phalanx_proto::vitals::StressLoad(0.1),
            storage_remaining_mb: 1024,
            heartbeat_ms: 5_000,
            is_leaf: false,
            integral_summary: None,
        };
        tracker.register_activity(msg);

        let physics = PhalanxPhysics::default();
        assert!(
            !tracker.is_peer_stale(&pid, &physics),
            "fresh heartbeat must not be classified as stale"
        );
    }

    #[test]
    fn is_peer_stale_grace_period_scales_with_tau_rtt() {
        // Regression guard: the jitter_multiplier derivation is
        // `(tau_rtt / 10).max(2)`. If tau_rtt drops, the multiplier floor
        // of 2 must still protect us — otherwise fresh peers get flagged
        // as stale on networks with very low RTT.
        let tracker = HealthTracker::new();
        let pid = peer("low-rtt-peer");
        let msg = ControlMessage {
            sender: pid.clone(),
            load_factor: phalanx_proto::vitals::StressLoad(0.1),
            storage_remaining_mb: 1024,
            heartbeat_ms: 5_000,
            is_leaf: false,
            integral_summary: None,
        };
        tracker.register_activity(msg);

        let low_rtt_physics = PhalanxPhysics {
            tau_rtt: 1,
            ..PhalanxPhysics::default()
        };
        assert!(
            !tracker.is_peer_stale(&pid, &low_rtt_physics),
            "min-multiplier floor must prevent spurious staleness on low RTT"
        );
    }
}
