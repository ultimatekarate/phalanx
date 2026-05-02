// crates/phalanx-node/src/vitals/health.rs
//
// Observability (telemetry initialization) and health tracking.

use std::collections::HashMap;
use std::sync::{Once, OnceLock};
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

pub fn init_observability() {
    INIT.call_once(|| {
        let file_appender = tracing_appender::rolling::daily("logs", "guardian.log");
        let (non_blocking_file, file_guard) = tracing_appender::non_blocking(file_appender);

        let _ = TELEMETRY_GUARD.set(file_guard);

        let filter = Targets::new()
            .with_target("phalanx_node", Level::DEBUG)
            .with_target("phalanx_forensics", Level::DEBUG)
            .with_target("phalanx::forensics::collision", Level::TRACE)
            .with_default(Level::INFO);

        let registry = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(true).with_thread_ids(true))
            .with(fmt::layer().with_writer(non_blocking_file).json());

        let _ = registry.try_init();
    });
}

pub struct HealthTracker {
    pub heartbeats: HashMap<MeshAddress, Instant>,
    pub capacities: HashMap<MeshAddress, ControlMessage>,
    pub peer_contracts: HashMap<MeshAddress, VitalityRate>,

    /// Shield Wall: spectral behavioral observer for Byzantine detection.
    pub spectral: SpectralObserver,
}

impl HealthTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            heartbeats: HashMap::new(),
            capacities: HashMap::new(),
            peer_contracts: HashMap::new(),
            spectral: SpectralObserver::new(),
        }
    }

    pub fn register_activity(&mut self, msg: ControlMessage) {
        let peer_id = msg.sender.clone();
        self.heartbeats.insert(peer_id.clone(), Instant::now());
        self.peer_contracts
            .insert(peer_id.clone(), VitalityRate::new(msg.heartbeat_ms));

        // Shield Wall: record heartbeat for spectral consistency evaluation
        self.spectral.record_heartbeat(peer_id.clone(), &msg);

        self.capacities.insert(peer_id, msg);
    }

    #[must_use]
    #[allow(clippy::arithmetic_side_effects, clippy::cast_possible_truncation)] // Duration jitter arithmetic.
    pub fn is_peer_stale(&self, peer_id: &MeshAddress, physics: &PhalanxPhysics) -> bool {
        let last_time = match self.heartbeats.get(peer_id) {
            Some(t) => t,
            None => return true,
        };

        let contract = self
            .peer_contracts
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| VitalityRate::new(5000));

        let jitter_multiplier = (physics.tau_rtt as u32 / 10).max(2);
        let grace_period = contract.as_duration() * jitter_multiplier;

        last_time.elapsed() > grace_period
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
        let mut tracker = HealthTracker::new();
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
        let mut tracker = HealthTracker::new();
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
