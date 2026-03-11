// crates/phalanx-node/src/vitals.rs

use phalanx_proto::prelude::*;
use phalanx_proto::telemetry::SimEvent;
use phalanx_proto::types::SystemStress;
use phalanx_proto::types::TaskCost;
use phalanx_proto::types::VitalityRate;
use phalanx_proto::vitals::ControlMessage;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Once, OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::Level;
use tracing_subscriber::{filter::Targets, fmt, prelude::*};

static TELEMETRY_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();
static INIT: Once = Once::new();

// =====================================================================
// API BOUNDARIES (Hardened Types)
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct IngestionScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FinalizationScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct SybilEndowment(pub f64);

impl IngestionScale {
    pub fn as_throttle_delay(&self, base_delay_ms: u64) -> Duration {
        if self.0 <= 0.01 {
            Duration::from_millis(base_delay_ms * 100)
        } else {
            let multiplier = (1.0 / self.0) - 1.0;
            Duration::from_millis((base_delay_ms as f64 * multiplier) as u64)
        }
    }
}

// =====================================================================
// HOMEOSTATIC CONFIGURATION & STATE
// =====================================================================

#[derive(Debug, Clone)]
pub struct HomeostaticConfig {
    pub lambda_sys: f64,
    pub s_crit: f64,
    pub lambda_io: f64,
    pub d_crit: f64,
    pub lambda_rep: f64,
    pub omega: f64,
    pub lambda_entry: f64,
    pub psi_max: f64,
    pub k_sybil: f64,
    pub base_temporal_drift: Duration,
}

impl HomeostaticConfig {
    pub fn pipeline_capacity(&self) -> usize {
        // We use s_crit (10.0) as the base.
        // A coefficient of 20.0 means we can buffer 200 concurrent 'units' of stress.
        (self.s_crit * 20.0) as usize
    }
}

impl Default for HomeostaticConfig {
    fn default() -> Self {
        Self {
            lambda_sys: 4.0,
            s_crit: 10.0,
            lambda_io: 0.5,
            d_crit: 25.0,
            lambda_rep: 0.01,
            omega: 100.0,
            lambda_entry: 0.1,
            psi_max: 50.0,
            k_sybil: 2.0,
            base_temporal_drift: Duration::from_millis(500),
        }
    }
}

pub struct IntegralState {
    pub s_integral: f64,
    pub d_integral: f64,
    pub e_integral: f64,
    pub l_integral: f64, // Latency (Network/Scheduling Age)
    pub r_integrals: HashMap<String, f64>,
    pub last_sys_tick: Instant,
}

pub trait Homeostasis {
    fn temporal_tolerance(&self) -> Duration;
    fn record_metabolic_pressure(&self, duration: Duration);
    fn record_latency_pressure(&self, duration: Duration);
    fn record_io_pressure(&self, duration: Duration);
    fn record_entry_pressure(&self);
    fn ingestion_scaler(&self) -> IngestionScale;
    fn finalization_scaler(&self) -> FinalizationScale;
    fn sybil_endowment(&self) -> SybilEndowment;
}

// =====================================================================
// THE SYSTEM GOVERNOR
// =====================================================================

pub struct SystemGovernor {
    current_state: RwLock<SystemStress>,
    thermal_path: Option<PathBuf>,
    battery_path: Option<PathBuf>,
    pub config: HomeostaticConfig,
    pub integrals: RwLock<IntegralState>,
}

impl Default for SystemGovernor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemGovernor {
    pub fn new() -> Self {
        Self::with_config(HomeostaticConfig::default())
    }

    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&IntegralState) -> R,
    {
        let state = self.integrals.read().unwrap_or_else(|e| e.into_inner());
        f(&state)
    }

    /// The "State Monad" helper for mutable state access.
    fn with_state_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut IntegralState) -> R,
    {
        let mut state = self.integrals.write().unwrap_or_else(|e| e.into_inner());
        f(&mut state)
    }

    pub fn with_config(config: HomeostaticConfig) -> Self {
        let (thermal, battery) = Self::discover_hardware();
        Self {
            current_state: RwLock::new(SystemStress::Nominal),
            thermal_path: thermal,
            battery_path: battery,
            config,
            integrals: RwLock::new(IntegralState {
                s_integral: 0.0,
                d_integral: 0.0,
                e_integral: 0.0,
                l_integral: 0.0,
                r_integrals: HashMap::new(),
                last_sys_tick: Instant::now(),
            }),
        }
    }

    pub fn current_stress(&self) -> SystemStress {
        *self
            .current_state
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
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

        let heat_penalty = match new_stress {
            SystemStress::Nominal => 0.0,
            SystemStress::Fair => 0.5,
            SystemStress::Serious => 2.0,
            SystemStress::Critical => 10.0,
        };

        if heat_penalty > 0.0 {
            let mut state = self.integrals.write().unwrap_or_else(|e| e.into_inner());
            let decay = Self::calculate_dt_and_decay(&mut state, self.config.lambda_sys);
            state.s_integral = heat_penalty + (state.s_integral * decay);
        }

        let mut state = self
            .current_state
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *state = new_stress;
    }

    fn calculate_dt_and_decay(state: &mut IntegralState, lambda: f64) -> f64 {
        let now = Instant::now();
        let dt = now.duration_since(state.last_sys_tick).as_secs_f64();
        state.last_sys_tick = now;
        (-lambda * dt).exp()
    }

    // --- Immune Integral (Reputation) ---

    pub fn record_peer_evidence(&self, peer_id: &str, is_valid: bool) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_rep);
            let current_r = s.r_integrals.get(peer_id).unwrap_or(&0.0) * decay;
            let delta = if is_valid { 1.0 } else { -self.config.omega };
            s.r_integrals.insert(peer_id.to_string(), current_r + delta);
        });
    }

    pub fn is_peer_coupled(&self, peer_id: &str) -> bool {
        self.with_state(|s| *s.r_integrals.get(peer_id).unwrap_or(&0.0) >= 0.0)
    }

    // --- Hardware Discovery & Probes ---

    fn discover_hardware() -> (Option<PathBuf>, Option<PathBuf>) {
        let thermal = Self::find_path("/sys/class/thermal", "temp", &["cpu", "soc", "tsens"]);
        let battery = Self::find_path("/sys/class/power_supply", "capacity", &["battery"]);
        (thermal, battery)
    }

    fn read_thermal(&self) -> SystemStress {
        let raw = self
            .thermal_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok());
        let temp = raw.and_then(|s| s.trim().parse::<i32>().ok()).unwrap_or(0) / 1000;

        match temp {
            t if t > 75 => SystemStress::Critical,
            t if t > 60 => SystemStress::Serious,
            t if t > 45 => SystemStress::Fair,
            _ => SystemStress::Nominal,
        }
    }

    fn read_battery(&self) -> SystemStress {
        let raw = self
            .battery_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok());
        let cap = raw
            .and_then(|s| s.trim().parse::<i32>().ok())
            .unwrap_or(100);

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

// =====================================================================
// THE HOMEOSTASIS IMPLEMENTATION
// =====================================================================

impl Homeostasis for SystemGovernor {
    fn record_metabolic_pressure(&self, duration: Duration) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_sys);
            s.s_integral = duration.as_secs_f64() + (s.s_integral * decay);
        });
    }

    fn record_latency_pressure(&self, duration: Duration) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_sys);
            s.l_integral = duration.as_secs_f64() + (s.l_integral * decay);
        });
    }

    fn record_io_pressure(&self, duration: Duration) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_io);
            s.d_integral = duration.as_secs_f64() + (s.d_integral * decay);
        });
    }

    fn record_entry_pressure(&self) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_entry);
            s.e_integral = 1.0 + (s.e_integral * decay);
        });
    }

    fn temporal_tolerance(&self) -> Duration {
        self.with_state(|s| {
            let base = self.config.base_temporal_drift;
            let expansion = Duration::from_secs_f64(s.l_integral);
            base + expansion
        })
    }

    fn ingestion_scaler(&self) -> IngestionScale {
        self.with_state(|s| IngestionScale((1.0 - (s.s_integral / self.config.s_crit)).max(0.0)))
    }

    fn finalization_scaler(&self) -> FinalizationScale {
        self.with_state(|s| FinalizationScale((1.0 - (s.d_integral / self.config.d_crit)).max(0.0)))
    }

    fn sybil_endowment(&self) -> SybilEndowment {
        self.with_state(|s| {
            SybilEndowment(self.config.psi_max / (1.0 + self.config.k_sybil * s.e_integral))
        })
    }
}

// =====================================================================
// OBSERVABILITY & HEALTH
// =====================================================================

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
        }
    }

    pub fn should_broadcast_self(&mut self, current_load: f32, current_storage: u64) -> bool {
        let load_delta = (current_load - self.last_sent_load).abs();
        let time_since = self.last_sent_at.elapsed();

        // 1. SIGNIFICANCE: Did my stress change by more than 10%?
        // 2. STALENESS: Has it been 30 seconds since I checked in?
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

// =====================================================================
// 6. TESTS
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use phalanx_proto::types::TaskCost;
    use std::fs;
    use tempfile::tempdir;

    fn setup_mock_sysfs(root: &std::path::Path) -> (PathBuf, PathBuf) {
        let thermal_dir = root.join("sys/class/thermal/thermal_zone0");
        let battery_dir = root.join("sys/class/power_supply/battery");

        fs::create_dir_all(&thermal_dir).unwrap();
        fs::create_dir_all(&battery_dir).unwrap();

        fs::write(thermal_dir.join("type"), "cpu-thermal\n").unwrap();
        fs::write(thermal_dir.join("temp"), "40000\n").unwrap();

        fs::write(battery_dir.join("type"), "Battery\n").unwrap();
        fs::write(battery_dir.join("capacity"), "80\n").unwrap();

        (thermal_dir.join("temp"), battery_dir.join("capacity"))
    }

    #[test]
    fn test_hardware_discovery_logic() {
        let dir = tempdir().unwrap();
        let root = dir.path();

        let thermal_path = SystemGovernor::find_path(
            &root.join("sys/class/thermal").to_string_lossy(),
            "temp",
            &["cpu"],
        );
        let battery_path = SystemGovernor::find_path(
            &root.join("sys/class/power_supply").to_string_lossy(),
            "capacity",
            &["battery"],
        );

        assert!(thermal_path.is_none());
        assert!(battery_path.is_none());
        setup_mock_sysfs(root);

        let thermal_path = SystemGovernor::find_path(
            &root.join("sys/class/thermal").to_string_lossy(),
            "temp",
            &["cpu"],
        )
        .expect("Should find CPU thermal");

        assert!(thermal_path.to_string_lossy().contains("thermal_zone0"));

        let battery_path = SystemGovernor::find_path(
            &root.join("sys/class/power_supply").to_string_lossy(),
            "capacity",
            &["battery"],
        )
        .expect("Should find battery supply");

        assert!(battery_path.to_string_lossy().contains("battery"));
    }

    #[test]
    fn test_permission_logic_matrix() {
        let gov = SystemGovernor::new();

        assert!(gov.check_permission(TaskCost::Light));
        assert!(gov.check_permission(TaskCost::Heavy));

        if let Ok(mut state) = gov.current_state.write() {
            *state = SystemStress::Fair;
        }
        assert!(gov.check_permission(TaskCost::Light));
        assert!(!gov.check_permission(TaskCost::Heavy));

        if let Ok(mut state) = gov.current_state.write() {
            *state = SystemStress::Critical;
        }
        assert!(!gov.check_permission(TaskCost::Light));
        assert!(!gov.check_permission(TaskCost::Heavy));
    }

    #[test]
    fn test_vitals_update_calculation() {
        let dir = tempdir().unwrap();
        let root = dir.path();
        let (t_file, b_file) = setup_mock_sysfs(root);

        let gov = SystemGovernor {
            current_state: RwLock::new(SystemStress::Nominal),
            thermal_path: Some(t_file.clone()),
            battery_path: Some(b_file.clone()),
            config: HomeostaticConfig::default(),
            integrals: RwLock::new(IntegralState {
                s_integral: 0.0,
                d_integral: 0.0,
                e_integral: 0.0,
                l_integral: 0.0,
                r_integrals: HashMap::new(),
                last_sys_tick: Instant::now(),
            }),
        };

        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Nominal);

        fs::write(&t_file, "80000\n").unwrap();
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Critical);

        fs::write(&t_file, "30000\n").unwrap();
        fs::write(&b_file, "10\n").unwrap();
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Serious);
    }
}
