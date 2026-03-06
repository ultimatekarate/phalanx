// crates/phalanx-node/src/vitals.rs

use phalanx_proto::prelude::*;
use phalanx_proto::telemetry::SimEvent;
use phalanx_proto::types::SystemStress;
use phalanx_proto::types::TaskCost;
use phalanx_proto::types::VitalityRate;
use phalanx_proto::vitals::ControlMessage;
use std::collections::HashMap;
use std::sync::{Once, OnceLock};
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::Level;
use tracing_subscriber::{filter::Targets, fmt, prelude::*};
use std::fs;
use std::path::PathBuf;


static TELEMETRY_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();
static INIT: Once = Once::new();

pub struct SystemGovernor {
    current_state: std::sync::RwLock<SystemStress>,
    thermal_path: Option<PathBuf>,
    battery_path: Option<PathBuf>,
}

impl Default for SystemGovernor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemGovernor {
    pub fn new() -> Self {
        let (thermal, battery) = Self::discover_hardware();
        Self {
            current_state: std::sync::RwLock::new(SystemStress::Nominal),
            thermal_path: thermal,
            battery_path: battery,
        }
    }

    pub fn current_stress(&self) -> SystemStress {
        *self.current_state.read().unwrap_or_else(|poison| poison.into_inner())
    }
    
    pub fn check_permission(&self, task_cost: TaskCost) -> bool {
        let state = *self
            .current_state
            .read()
            .unwrap_or_else(|poison| poison.into_inner());
        match (state, task_cost) {
            (SystemStress::Nominal, _) => true,
            (SystemStress::Fair, TaskCost::Heavy) => false,
            (SystemStress::Fair, TaskCost::Light) => true,
            (SystemStress::Serious, _) => false,
            (SystemStress::Critical, _) => false,
        }
    }

    pub fn update_vitals(&self) {
        let t_stress = self.read_thermal();
        let b_stress = self.read_battery();

        let new_stress = std::cmp::max(t_stress, b_stress);
        
        if let Ok(mut state) = self.current_state.write() {
            *state = new_stress;
        }
    }

    // --- Hardware Discovery & Probes ---

    fn discover_hardware() -> (Option<PathBuf>, Option<PathBuf>) {
        let thermal = Self::find_path("/sys/class/thermal", "temp", &["cpu", "soc", "tsens"]);
        let battery = Self::find_path("/sys/class/power_supply", "capacity", &["battery"]);
        (thermal, battery)
    }

    fn read_thermal(&self) -> SystemStress {
        let raw = self.thermal_path.as_ref().and_then(|p| fs::read_to_string(p).ok());
        let temp = raw.and_then(|s| s.trim().parse::<i32>().ok()).unwrap_or(0) / 1000;

        match temp {
            t if t > 75 => SystemStress::Critical,
            t if t > 60 => SystemStress::Serious,
            t if t > 45 => SystemStress::Fair,
            _ => SystemStress::Nominal,
        }
    }

    fn read_battery(&self) -> SystemStress {
        let raw = self.battery_path.as_ref().and_then(|p| fs::read_to_string(p).ok());
        let cap = raw.and_then(|s| s.trim().parse::<i32>().ok()).unwrap_or(100);

        match cap {
            c if c < 5 => SystemStress::Critical,
            c if c < 15 => SystemStress::Serious,
            c if c < 50 => SystemStress::Fair,
            _ => SystemStress::Nominal,
        }
    }

    fn find_path(base: &str, file: &str, keys: &[&str]) -> Option<PathBuf> {
        let entries = fs::read_dir(base).ok()?;
        for entry in entries.flatten() {
            let path = entry.path();
            let type_str = fs::read_to_string(path.join("type")).ok()?.to_lowercase();
            if keys.iter().any(|k| type_str.contains(k)) {
                return Some(path.join(file));
            }
        }
        None
    }
}

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
            // Requires: tracing-subscriber = { version = "0.3", features = ["json"] }
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
        let peer_id = msg.sender.clone();
        // FIX: Clone peer_id so it can be used in multiple maps
        self.heartbeats.insert(peer_id.clone(), Instant::now());
        self.peer_contracts
            .insert(peer_id.clone(), VitalityRate::new(msg.heartbeat_ms));
        self.capacities.insert(peer_id, msg);
    }

    #[must_use]
    pub fn is_peer_stale(&self, peer_id: &NetworkId, physics: &PhalanxPhysics) -> bool {
        let last_time = match self.heartbeats.get(peer_id) {
            Some(t) => t,
            None => return true,
        };

        let contract = self
            .peer_contracts
            .get(peer_id)
            .cloned()
            .unwrap_or_else(|| {
                // FIX: Fallback to default VitalityRate instead of using non-existent calculate
                VitalityRate::new(5000)
            });

        // FIX: Derive jitter multiplier from tau_rtt instead of undefined jitter_factor property
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
