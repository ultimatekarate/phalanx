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

use phalanx_proto::identity::NetworkId;
use phalanx_proto::prelude::PhalanxPhysics;
use phalanx_proto::telemetry::SimEvent;
use phalanx_proto::types::VitalityRate;
use phalanx_proto::vitals::ControlMessage;

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
    pub heartbeats: HashMap<NetworkId, Instant>,
    pub capacities: HashMap<NetworkId, ControlMessage>,
    pub peer_contracts: HashMap<NetworkId, VitalityRate>,

    pub last_sent_load: f32,
    pub last_sent_storage: u64,
    pub last_sent_at: Instant,

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
            last_sent_at: Instant::now(),
            last_sent_load: 0.0,
            last_sent_storage: 0,
            spectral: SpectralObserver::new(),
        }
    }

    pub fn should_broadcast_self(&mut self, current_load: f32, current_storage: u64) -> bool {
        let load_delta = (current_load - self.last_sent_load).abs();
        let time_since = self.last_sent_at.elapsed();

        // SIGNIFICANCE: Did my stress change by more than 10%?
        // STALENESS: Has it been 30 seconds since I checked in?
        if load_delta > 0.10 || time_since > Duration::from_secs(30) {
            self.last_sent_load = current_load;
            self.last_sent_storage = current_storage;
            self.last_sent_at = Instant::now();
            return true;
        }
        false
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
    pub fn is_peer_stale(&self, peer_id: &NetworkId, physics: &PhalanxPhysics) -> bool {
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
