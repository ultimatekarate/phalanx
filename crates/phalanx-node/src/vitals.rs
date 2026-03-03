use phalanx_proto::prelude::*;
use phalanx_proto::telemetry::SimEvent;
use phalanx_proto::types::SystemStress;
use phalanx_proto::types::TaskCost;
use phalanx_proto::types::VitalityRate;
use phalanx_proto::types::{PowerState, UnitInterval};
use phalanx_proto::vitals::ControlMessage;
use std::collections::HashMap;
use std::sync::{Once, OnceLock};
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::Level;
use tracing_subscriber::{filter::Targets, fmt, prelude::*};

static TELEMETRY_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();
static INIT: Once = Once::new();

pub struct SystemGovernor {
    // Cache the state to avoid expensive OS calls every millisecond
    current_state: std::sync::RwLock<SystemStress>,
}

impl SystemGovernor {
    pub fn check_permission(&self, task_cost: TaskCost) -> bool {
        let state = *self
            .current_state
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        match (state, task_cost) {
            (SystemStress::Nominal, _) => true,             // Do anything
            (SystemStress::Fair, TaskCost::Heavy) => false, // No FFTs
            (SystemStress::Fair, TaskCost::Light) => true,  // Signatures OK
            (SystemStress::Serious, _) => false,            // Only essential capture
            (SystemStress::Critical, _) => false,           // Survival mode
        }
    }

    // Call this every 5-10 seconds
    pub fn update_vitals(&self) {
        let thermal = self.get_thermal_status();
        let battery = self.get_battery_status();

        let new_state = std::cmp::max(thermal, battery);

        let mut guard = self
            .current_state
            .write()
            .unwrap_or_else(|poison| poison.into_inner());
        *guard = new_state;
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    fn get_thermal_status(&self) -> SystemStress {
        SystemStress::Nominal // Desktops/Strongholds rarely throttle
    }

    fn get_battery_status(&self) -> SystemStress {
        // Placeholder for cross-platform battery crate or native bridge
        SystemStress::Nominal
    }

    #[cfg(target_os = "android")]
    fn get_thermal_status(&self) -> SystemStress {
        // TODO: In Phase 3, we'll link this to a JNI call to PowerManager
        SystemStress::Nominal
    }

    #[cfg(target_os = "ios")]
    fn get_thermal_status(&self) -> SystemStress {
        // TODO: Map to NSProcessInfo.thermalState
        SystemStress::Nominal
    }
    // Platform-Specific Logic (Simplified)
    #[cfg(target_os = "android")]
    fn get_thermal_status(&self) -> SystemStress {
        // JNI call to PowerManager.getThermalStatus()
        // Returns 0 (NONE) to 6 (SHUTDOWN)
        // Map 0-1 -> Nominal, 2 -> Fair, 3 -> Serious, 4+ -> Critical
    }
}

/// The physical hub for routing events inside a running node.
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
            .with_default(Level::INFO);

        let registry = tracing_subscriber::registry()
            .with(filter)
            .with(fmt::layer().with_target(false).with_thread_ids(true))
            .with(fmt::layer().with_writer(non_blocking_file).json());

        let _ = registry.try_init();
    });
}

pub struct HealthTracker {
    pub heartbeats: HashMap<NetworkId, Instant>,
    pub capacities: HashMap<NetworkId, ControlMessage>,
    pub peer_contracts: HashMap<NetworkId, VitalityRate>,
}

impl HealthTracker {
    #[must_use]
    pub fn new() -> Self {
        Self {
            heartbeats: HashMap::new(),
            capacities: HashMap::new(),
            peer_contracts: HashMap::new(),
        }
    }

    pub fn register_activity(&mut self, msg: ControlMessage) {
        let peer_id = msg.sender;
        self.heartbeats.insert(peer_id, Instant::now());
        self.peer_contracts
            .insert(peer_id, VitalityRate::new(msg.heartbeat_ms));
        self.capacities.insert(peer_id, msg);
    }

    #[must_use]
    pub fn is_peer_stale(&self, peer_id: &NetworkId, physics: &PhalanxPhysics) -> bool {
        let last_time = match self.heartbeats.get(peer_id) {
            Some(t) => t,
            None => return true,
        };

        // Use the peer's reported interval, or fall back to physics default if unknown
        let default_load_factor = 0.0;
        let contract = self
            .peer_contracts
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| {
                VitalityRate::calculate(
                    physics,
                    PowerState::Normal,
                    UnitInterval::new(default_load_factor),
                )
            });

        // Apply physics jitter_factor to allow for network variance
        let grace_period = contract.as_duration() * physics.jitter_factor as u32;

        last_time.elapsed() > grace_period
    }
}

/// Standard default method.
impl Default for HealthTracker {
    fn default() -> Self {
        Self::new()
    }
}
