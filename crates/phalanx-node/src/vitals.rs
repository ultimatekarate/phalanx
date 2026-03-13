// crates/phalanx-node/src/vitals.rs

use phalanx_proto::prelude::*;
use phalanx_proto::telemetry::SimEvent;
use phalanx_proto::types::PowerState;
use phalanx_proto::types::SystemStress;
use phalanx_proto::types::TaskCost;
use phalanx_proto::types::VitalityRate;
use phalanx_proto::vitals::ControlMessage;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Once, OnceLock, RwLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time::Instant;
use tracing::Level;
use tracing_subscriber::{filter::Targets, fmt, prelude::*};

static TELEMETRY_GUARD: OnceLock<tracing_appender::non_blocking::WorkerGuard> = OnceLock::new();
static INIT: Once = Once::new();

// =====================================================================
// PHASE 4: HARDWARE ABSTRACTION (Mobile Energy Guardian)
// =====================================================================

/// Battery charge level, 0-100. Clamped on construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BatteryLevel(u8);

impl BatteryLevel {
    #[must_use]
    pub fn new(pct: u8) -> Self {
        Self(pct.min(100))
    }

    #[must_use]
    pub fn get(&self) -> u8 {
        self.0
    }
}

/// Temperature in degrees Celsius.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Celsius(pub i32);

/// Platform-specific SoC thermal envelope thresholds.
/// Different SoCs have different thermal envelopes:
/// Snapdragon throttles ~42°C, Apple A-series ~40°C, desktop CPUs ~75°C.
#[derive(Debug, Clone, Copy)]
pub struct ThermalThresholds {
    pub fair: Celsius,
    pub serious: Celsius,
    pub critical: Celsius,
}

impl Default for ThermalThresholds {
    fn default() -> Self {
        Self::desktop()
    }
}

impl ThermalThresholds {
    /// Desktop/Linux defaults (existing hardcoded values).
    pub fn desktop() -> Self {
        Self {
            fair: Celsius(45),
            serious: Celsius(60),
            critical: Celsius(75),
        }
    }

    /// Mobile defaults (tighter thermal envelope).
    pub fn mobile() -> Self {
        Self {
            fair: Celsius(40),
            serious: Celsius(50),
            critical: Celsius(65),
        }
    }
}

/// App lifecycle events pushed by the mobile OS.
/// Desktop returns `None` from `lifecycle_events()` (no foreground/background concept).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleEvent {
    /// App moved to foreground — resume capture immediately.
    Foregrounded,
    /// App moved to background — transition to Dormant.
    Backgrounded,
}

/// Platform-abstracted hardware probing for battery, thermal, and lifecycle state.
///
/// `SysfsProbe` implements this for Linux/desktop (existing logic).
/// Mobile runtimes inject their own implementation via `phalanx-ffi`.
pub trait HardwareProbe: Send + Sync {
    /// Current battery charge level. Returns `None` if no battery (e.g., desktop AC).
    fn battery_level(&self) -> Option<BatteryLevel>;

    /// Current SoC/CPU temperature. Returns `None` if no thermal sensor available.
    fn thermal_reading(&self) -> Option<Celsius>;

    /// Whether the device is currently charging.
    fn is_charging(&self) -> bool;

    /// Whether the app is currently in the background (mobile only).
    fn is_background(&self) -> bool;

    /// Whether the platform allows camera capture in the background.
    /// Android (foreground service): true. iOS: false. Desktop: true.
    fn can_capture_in_background(&self) -> bool;

    /// Platform-specific thermal thresholds for this SoC.
    fn thermal_thresholds(&self) -> ThermalThresholds;

    /// Optional event channel for OS lifecycle transitions (foreground/background).
    /// Mobile implementations push callbacks into this channel.
    /// Desktop returns `None`.
    fn lifecycle_events(&self) -> Option<tokio::sync::mpsc::Receiver<LifecycleEvent>> {
        None
    }
}

/// Default hardware probe for Linux/desktop using sysfs.
/// Reads `/sys/class/thermal/` and `/sys/class/power_supply/`.
pub struct SysfsProbe {
    thermal_path: Option<PathBuf>,
    battery_path: Option<PathBuf>,
    thresholds: ThermalThresholds,
}

impl SysfsProbe {
    pub fn new() -> Self {
        let thermal = Self::find_path("/sys/class/thermal", "temp", &["cpu", "soc", "tsens"]);
        let battery = Self::find_path("/sys/class/power_supply", "capacity", &["battery"]);
        Self {
            thermal_path: thermal,
            battery_path: battery,
            thresholds: ThermalThresholds::desktop(),
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

impl Default for SysfsProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl HardwareProbe for SysfsProbe {
    fn battery_level(&self) -> Option<BatteryLevel> {
        let raw = self
            .battery_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())?;
        let pct = raw.trim().parse::<u8>().ok()?;
        Some(BatteryLevel::new(pct))
    }

    fn thermal_reading(&self) -> Option<Celsius> {
        let raw = self
            .thermal_path
            .as_ref()
            .and_then(|p| fs::read_to_string(p).ok())?;
        let millidegrees = raw.trim().parse::<i32>().ok()?;
        Some(Celsius(millidegrees / 1000))
    }

    fn is_charging(&self) -> bool {
        // Desktop: assume AC power (always charging / not battery-constrained)
        true
    }

    fn is_background(&self) -> bool {
        // Desktop: no foreground/background concept
        false
    }

    fn can_capture_in_background(&self) -> bool {
        // Desktop: always able to capture
        true
    }

    fn thermal_thresholds(&self) -> ThermalThresholds {
        self.thresholds
    }
}

// =====================================================================
// API BOUNDARIES (Hardened Types)
// =====================================================================

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct IngestionScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct FinalizationScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct SybilEndowment(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct MemoryScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct StorageScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct BandwidthScale(pub f64);

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct ConnectionScale(pub f64);

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
    // Resource pressure decay constants (Volterra kernel parameters)
    pub lambda_mem: f64,                  // Memory pressure decay rate
    pub m_crit: f64,                      // Memory critical threshold (MiB)
    pub lambda_wal: f64,                  // WAL/storage pressure decay rate
    pub w_crit: f64,                      // Storage critical ratio (0.0-1.0)
    pub lambda_bw: f64,                   // Bandwidth pressure decay rate
    pub b_crit: f64,                      // Bandwidth critical threshold (MiB)
    pub lambda_conn: f64,                 // Connection pressure decay rate
    pub c_crit: f64,                      // Connection critical ratio (0.0-1.0)
    pub max_temporal_tolerance: Duration, // Hard clamp on temporal_tolerance (T2 fix)
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
            lambda_mem: 0.3,
            m_crit: 512.0,
            lambda_wal: 0.05,
            w_crit: 0.8,
            lambda_bw: 0.5,
            b_crit: 50.0,
            lambda_conn: 0.2,
            c_crit: 0.9,
            max_temporal_tolerance: Duration::from_secs(10),
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
    // Volterra second-kind extensions for resource pressure feedback
    pub m_integral: f64, // Memory/buffer pressure (MiB held in reassembler + channels)
    pub w_integral: f64, // WAL/storage pressure (ratio of max capacity)
    pub b_integral: f64, // Bandwidth pressure (MiB ingress per event)
    pub c_integral: f64, // Connection pressure (ratio of max connections)
    pub conserving_trigger_count: u8, // Consecutive ticks above Conserving threshold (0.50)
    pub leaf_trigger_count: u8, // Consecutive vitals ticks above composite threshold (0.85)
    pub normal_trigger_count: u8, // Consecutive vitals ticks below recovery threshold (0.30)
    /// Phase 4f: Tracks the stress-driven power state independently of battery gate.
    /// Used as hysteresis fallback by `stress_recommendation()` so it doesn't
    /// inherit battery-gate-driven Dormant/Leaf states.
    pub stress_power_state: PowerState,
    // Phase 3: Internet connectivity detection
    /// Whether the node believes it has internet connectivity.
    /// Determined by tracking peer discovery sources: if ALL connected peers
    /// are mDNS-local for >30s, internet is considered unavailable.
    pub internet_available: bool,
    /// Number of peers discovered via mDNS (local network).
    pub local_peer_count: usize,
    /// Number of peers discovered via non-local means (Kademlia, Bootstrap, Relay).
    pub internet_peer_count: usize,
    /// When the last non-mDNS peer was seen. Used for the 30s grace period
    /// before declaring internet unavailable.
    pub last_internet_peer_seen: Instant,
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
    // Resource pressure integrals (Volterra extensions)
    fn record_memory_pressure(&self, bytes_held: usize);
    fn record_storage_pressure(&self, used_bytes: u64, max_bytes: u64);
    fn record_bandwidth_pressure(&self, bytes: usize);
    fn record_connection_pressure(&self, active: usize, max: usize);
    fn memory_scaler(&self) -> MemoryScale;
    fn storage_scaler(&self) -> StorageScale;
    fn bandwidth_scaler(&self) -> BandwidthScale;
    fn connection_scaler(&self) -> ConnectionScale;
}

// =====================================================================
// THE SYSTEM GOVERNOR
// =====================================================================

pub struct SystemGovernor {
    current_state: RwLock<SystemStress>,
    probe: Arc<dyn HardwareProbe>,
    pub config: HomeostaticConfig,
    pub integrals: RwLock<IntegralState>,
    pub recommended_state: RwLock<PowerState>,
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

    /// Create with a custom hardware probe (for mobile platforms).
    pub fn with_probe(config: HomeostaticConfig, probe: Arc<dyn HardwareProbe>) -> Self {
        Self {
            current_state: RwLock::new(SystemStress::Nominal),
            probe,
            config,
            integrals: RwLock::new(IntegralState {
                s_integral: 0.0,
                d_integral: 0.0,
                e_integral: 0.0,
                l_integral: 0.0,
                r_integrals: HashMap::new(),
                last_sys_tick: Instant::now(),
                m_integral: 0.0,
                w_integral: 0.0,
                b_integral: 0.0,
                c_integral: 0.0,
                conserving_trigger_count: 0,
                leaf_trigger_count: 0,
                normal_trigger_count: 0,
                stress_power_state: PowerState::Normal,
                internet_available: true,
                local_peer_count: 0,
                internet_peer_count: 0,
                last_internet_peer_seen: Instant::now(),
            }),
            recommended_state: RwLock::new(PowerState::Normal),
        }
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
        Self {
            current_state: RwLock::new(SystemStress::Nominal),
            probe: Arc::new(SysfsProbe::new()),
            config,
            integrals: RwLock::new(IntegralState {
                s_integral: 0.0,
                d_integral: 0.0,
                e_integral: 0.0,
                l_integral: 0.0,
                r_integrals: HashMap::new(),
                last_sys_tick: Instant::now(),
                m_integral: 0.0,
                w_integral: 0.0,
                b_integral: 0.0,
                c_integral: 0.0,
                conserving_trigger_count: 0,
                leaf_trigger_count: 0,
                normal_trigger_count: 0,
                stress_power_state: PowerState::Normal,
                internet_available: true,
                local_peer_count: 0,
                internet_peer_count: 0,
                last_internet_peer_seen: Instant::now(),
            }),
            recommended_state: RwLock::new(PowerState::Normal),
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

        // Phase 3: Periodic connectivity check (30s grace period)
        self.check_connectivity();

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

        // Automatic power state transition driven by composite integral stress
        let new_power = self.recommended_power_state();
        let mut power = self
            .recommended_state
            .write()
            .unwrap_or_else(|e| e.into_inner());
        *power = new_power;
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

    /// Per-peer bandwidth check via the r_integrals namespace.
    /// Peers accumulate +1.0 per event under a "bw:{peer_id}" key.
    /// Returns false when accumulated bandwidth pressure exceeds the sybil ceiling.
    pub fn is_peer_bandwidth_ok(&self, peer_id: &str) -> bool {
        let key = format!("bw:{}", peer_id);
        self.with_state(|s| {
            let pressure = s.r_integrals.get(&key).unwrap_or(&0.0);
            *pressure < self.config.psi_max
        })
    }

    /// Records per-peer bandwidth event into the r_integrals namespace.
    pub fn record_peer_bandwidth(&self, peer_id: &str) {
        let key = format!("bw:{}", peer_id);
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_rep);
            let current = s.r_integrals.get(&key).unwrap_or(&0.0) * decay;
            s.r_integrals.insert(key, current + 1.0);
        });
    }

    /// Weighted composite of all integral pressures for power state transitions.
    /// Returns 0.0 (idle) to 1.0+ (saturated).
    pub fn composite_stress(&self) -> f64 {
        self.with_state(|s| {
            let terms = [
                (0.25, s.s_integral / self.config.s_crit),
                (0.20, s.d_integral / self.config.d_crit),
                (0.20, s.m_integral / self.config.m_crit),
                (0.15, s.w_integral / self.config.w_crit),
                (0.20, s.b_integral / self.config.b_crit),
            ];
            terms.iter().map(|(w, n)| w * n.min(1.0)).sum()
        })
    }

    /// Phase 4f: Two-stage power state evaluation. Final state = max restriction wins.
    ///
    /// Stage 1: Battery gate (hard physical constraint, NO hysteresis — physical state is authoritative)
    /// Stage 2: Composite stress (software signal, existing hysteresis: 0.85/0.50/0.30 thresholds)
    ///
    /// `Dormant > Leaf > Conserving > Normal` in restrictiveness (PowerState derives Ord).
    pub fn recommended_power_state(&self) -> PowerState {
        // Stage 1: Battery gate (hard physical constraint)
        let battery = self.battery_gate();

        // Stage 2: Composite stress with hysteresis
        let stress = self.stress_recommendation();

        // Max restriction wins
        battery.max(stress)
    }

    /// Composite-stress-driven power state recommendation with hysteresis.
    /// 3 consecutive ticks above 0.85 → Leaf, 3 above 0.50 → Conserving, 5 below 0.30 → Normal.
    ///
    /// **Important:** Stress can only produce Normal/Conserving/Leaf — never Dormant.
    /// Dormant is exclusively a battery gate output (background state, not software stress).
    /// The hysteresis fallback clamps to Leaf to prevent inheriting battery-gate-driven Dormant.
    fn stress_recommendation(&self) -> PowerState {
        let composite = self.composite_stress();
        let mut integrals = self.integrals.write().unwrap_or_else(|e| e.into_inner());

        if composite > 0.85 {
            integrals.leaf_trigger_count = integrals.leaf_trigger_count.saturating_add(1);
            integrals.conserving_trigger_count = 0;
            integrals.normal_trigger_count = 0;
        } else if composite > 0.50 {
            integrals.conserving_trigger_count =
                integrals.conserving_trigger_count.saturating_add(1);
            integrals.leaf_trigger_count = 0;
            integrals.normal_trigger_count = 0;
        } else if composite < 0.3 {
            integrals.normal_trigger_count = integrals.normal_trigger_count.saturating_add(1);
            integrals.leaf_trigger_count = 0;
            integrals.conserving_trigger_count = 0;
        } else {
            integrals.leaf_trigger_count = 0;
            integrals.conserving_trigger_count = 0;
            integrals.normal_trigger_count = 0;
        }

        let stress_state = if integrals.leaf_trigger_count >= 3 {
            PowerState::Leaf
        } else if integrals.conserving_trigger_count >= 3 {
            PowerState::Conserving
        } else if integrals.normal_trigger_count >= 5 {
            PowerState::Normal
        } else {
            // Maintain stress-specific state during hysteresis window.
            // Uses stress_power_state (not recommended_state) to avoid inheriting
            // battery-gate-driven Dormant — stress never produces Dormant.
            integrals.stress_power_state
        };

        // Record stress output for next hysteresis fallback
        integrals.stress_power_state = stress_state;
        stress_state
    }

    /// Reads the current recommended power state (updated by update_vitals polling).
    pub fn current_power_state(&self) -> PowerState {
        *self
            .recommended_state
            .read()
            .unwrap_or_else(|e| e.into_inner())
    }

    // --- Phase 3: Internet Connectivity Detection ---

    /// Duration after the last internet peer was seen before declaring offline.
    const INTERNET_GRACE_PERIOD: Duration = Duration::from_secs(30);

    /// Update connectivity state based on a newly discovered peer and its discovery source.
    ///
    /// Detection strategy (from architectural plan):
    /// - If the node has connected non-mDNS peers (relay, Kademlia bootstrap), internet is available.
    /// - If ALL connected peers are mDNS-local for >30s, mark internet as unavailable.
    pub fn record_peer_discovery(&self, source: phalanx_proto::telemetry::DiscoverySource) {
        use phalanx_proto::telemetry::DiscoverySource;

        self.with_state_mut(|s| {
            match source {
                DiscoverySource::Mdns => {
                    s.local_peer_count = s.local_peer_count.saturating_add(1);
                }
                DiscoverySource::Bootstrap
                | DiscoverySource::Kademlia
                | DiscoverySource::Identify => {
                    s.internet_peer_count = s.internet_peer_count.saturating_add(1);
                    s.last_internet_peer_seen = Instant::now();
                    // Immediately mark internet as available
                    if !s.internet_available {
                        tracing::info!(
                            event = "internet_restored",
                            "Internet connectivity detected via {:?} peer",
                            source
                        );
                    }
                    s.internet_available = true;
                }
            }
        });
    }

    /// Record a peer departure (disconnect). Adjusts local/internet counts.
    pub fn record_peer_departure(&self, was_local: bool) {
        self.with_state_mut(|s| {
            if was_local {
                s.local_peer_count = s.local_peer_count.saturating_sub(1);
            } else {
                s.internet_peer_count = s.internet_peer_count.saturating_sub(1);
            }
        });
    }

    /// Periodic connectivity check — called by the vitals polling tick.
    /// If no internet peers have been seen for the grace period, marks internet as unavailable.
    pub fn check_connectivity(&self) {
        self.with_state_mut(|s| {
            if s.internet_peer_count == 0
                && s.last_internet_peer_seen.elapsed() > Self::INTERNET_GRACE_PERIOD
            {
                if s.internet_available {
                    tracing::warn!(
                        event = "internet_lost",
                        local_peers = s.local_peer_count,
                        grace_elapsed_secs = s.last_internet_peer_seen.elapsed().as_secs(),
                        "No internet peers for >30s — marking offline"
                    );
                }
                s.internet_available = false;
            }
        });
    }

    /// Returns whether the node believes it has internet connectivity.
    pub fn internet_available(&self) -> bool {
        self.with_state(|s| s.internet_available)
    }

    /// Returns the count of locally-discovered (mDNS) peers.
    pub fn local_peer_count(&self) -> usize {
        self.with_state(|s| s.local_peer_count)
    }

    // --- Hardware Probing (via HardwareProbe trait) ---

    fn read_thermal(&self) -> SystemStress {
        let thresholds = self.probe.thermal_thresholds();
        match self.probe.thermal_reading() {
            Some(temp) if temp > thresholds.critical => SystemStress::Critical,
            Some(temp) if temp > thresholds.serious => SystemStress::Serious,
            Some(temp) if temp > thresholds.fair => SystemStress::Fair,
            _ => SystemStress::Nominal,
        }
    }

    fn read_battery(&self) -> SystemStress {
        match self.probe.battery_level() {
            Some(level) if level.get() < 5 => SystemStress::Critical,
            Some(level) if level.get() < 15 => SystemStress::Serious,
            Some(level) if level.get() < 50 => SystemStress::Fair,
            _ => SystemStress::Nominal, // No battery sensor → assume AC power
        }
    }

    // --- Phase 4e: Battery gate (hard physical constraint, NOT composite_stress) ---

    /// Hard physical battery gate. A dead phone produces zero evidence.
    /// Battery is NOT a composite_stress weight — it short-circuits directly to PowerState.
    ///
    /// Charging bypasses the 20-50% gates (plugged in = no energy concern).
    fn battery_gate(&self) -> PowerState {
        if self.probe.is_background() {
            return PowerState::Dormant;
        }
        match self.probe.battery_level() {
            Some(level) if level.get() < 10 => PowerState::Leaf,
            Some(level) if level.get() < 50 && !self.probe.is_charging() => PowerState::Conserving,
            _ => PowerState::Normal, // No battery constraint (AC, charging, or >50%)
        }
    }

    /// Returns a reference to the hardware probe.
    pub fn probe(&self) -> &dyn HardwareProbe {
        &*self.probe
    }

    // --- Phase 4c: Adaptive Vitals Polling Interval ---

    /// Returns the vitals polling interval based on the current power state.
    /// Less restrictive states poll more frequently for faster adaptation.
    ///
    /// - Normal: 5s (fast response to load changes)
    /// - Conserving: 15s (balanced energy/responsiveness)
    /// - Leaf: 30s (minimal overhead, battery critical)
    /// - Dormant: 60s (background — battery/thermal readings only, no capture)
    pub fn vitals_polling_interval(&self) -> Duration {
        match self.current_power_state() {
            PowerState::Normal => Duration::from_secs(5),
            PowerState::Conserving => Duration::from_secs(15),
            PowerState::Leaf => Duration::from_secs(30),
            PowerState::Dormant => Duration::from_secs(60),
        }
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
            let total = base + expansion;
            total.min(self.config.max_temporal_tolerance) // T2: Hard clamp
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

    // --- Resource Pressure Recording (Volterra second-kind convolution) ---

    fn record_memory_pressure(&self, bytes_held: usize) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_mem);
            let mib = bytes_held as f64 / 1_048_576.0;
            s.m_integral = mib + (s.m_integral * decay);
        });
    }

    fn record_storage_pressure(&self, used_bytes: u64, max_bytes: u64) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_wal);
            let ratio = if max_bytes > 0 {
                used_bytes as f64 / max_bytes as f64
            } else {
                1.0
            };
            s.w_integral = ratio + (s.w_integral * decay);
        });
    }

    fn record_bandwidth_pressure(&self, bytes: usize) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_bw);
            let mib = bytes as f64 / 1_048_576.0;
            s.b_integral = mib + (s.b_integral * decay);
        });
    }

    fn record_connection_pressure(&self, active: usize, max: usize) {
        self.with_state_mut(|s| {
            let decay = Self::calculate_dt_and_decay(s, self.config.lambda_conn);
            let ratio = if max > 0 {
                active as f64 / max as f64
            } else {
                1.0
            };
            s.c_integral = ratio + (s.c_integral * decay);
        });
    }

    // --- Resource Scalers (1.0 = nominal, 0.0 = saturated) ---

    fn memory_scaler(&self) -> MemoryScale {
        self.with_state(|s| MemoryScale((1.0 - (s.m_integral / self.config.m_crit)).max(0.0)))
    }

    fn storage_scaler(&self) -> StorageScale {
        self.with_state(|s| StorageScale((1.0 - (s.w_integral / self.config.w_crit)).max(0.0)))
    }

    fn bandwidth_scaler(&self) -> BandwidthScale {
        self.with_state(|s| BandwidthScale((1.0 - (s.b_integral / self.config.b_crit)).max(0.0)))
    }

    fn connection_scaler(&self) -> ConnectionScale {
        self.with_state(|s| ConnectionScale((1.0 - (s.c_integral / self.config.c_crit)).max(0.0)))
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
    use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
    use tempfile::tempdir;

    // --- MockProbe: Configurable hardware probe for testing ---

    struct MockProbe {
        temperature: AtomicI32,
        battery: AtomicU8,
        charging: AtomicBool,
        background: AtomicBool,
        can_capture_bg: bool,
        thresholds: ThermalThresholds,
    }

    impl MockProbe {
        fn new() -> Self {
            Self {
                temperature: AtomicI32::new(30),
                battery: AtomicU8::new(100),
                charging: AtomicBool::new(true),
                background: AtomicBool::new(false),
                can_capture_bg: true,
                thresholds: ThermalThresholds::desktop(),
            }
        }

        fn set_temperature(&self, celsius: i32) {
            self.temperature.store(celsius, Ordering::Relaxed);
        }

        fn set_battery(&self, pct: u8) {
            self.battery.store(pct, Ordering::Relaxed);
        }

        fn set_charging(&self, charging: bool) {
            self.charging.store(charging, Ordering::Relaxed);
        }

        fn set_background(&self, bg: bool) {
            self.background.store(bg, Ordering::Relaxed);
        }
    }

    impl HardwareProbe for MockProbe {
        fn battery_level(&self) -> Option<BatteryLevel> {
            Some(BatteryLevel::new(self.battery.load(Ordering::Relaxed)))
        }

        fn thermal_reading(&self) -> Option<Celsius> {
            Some(Celsius(self.temperature.load(Ordering::Relaxed)))
        }

        fn is_charging(&self) -> bool {
            self.charging.load(Ordering::Relaxed)
        }

        fn is_background(&self) -> bool {
            self.background.load(Ordering::Relaxed)
        }

        fn can_capture_in_background(&self) -> bool {
            self.can_capture_bg
        }

        fn thermal_thresholds(&self) -> ThermalThresholds {
            self.thresholds
        }
    }

    fn make_governor_with_probe(probe: Arc<MockProbe>) -> SystemGovernor {
        SystemGovernor::with_probe(HomeostaticConfig::default(), probe)
    }

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

        let thermal_path = SysfsProbe::find_path(
            &root.join("sys/class/thermal").to_string_lossy(),
            "temp",
            &["cpu"],
        );
        let battery_path = SysfsProbe::find_path(
            &root.join("sys/class/power_supply").to_string_lossy(),
            "capacity",
            &["battery"],
        );

        assert!(thermal_path.is_none());
        assert!(battery_path.is_none());
        setup_mock_sysfs(root);

        let thermal_path = SysfsProbe::find_path(
            &root.join("sys/class/thermal").to_string_lossy(),
            "temp",
            &["cpu"],
        )
        .expect("Should find CPU thermal");

        assert!(thermal_path.to_string_lossy().contains("thermal_zone0"));

        let battery_path = SysfsProbe::find_path(
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
        let probe = Arc::new(MockProbe::new());
        probe.set_temperature(30); // Nominal
        probe.set_battery(80); // Nominal

        let gov = make_governor_with_probe(probe.clone());

        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Nominal);

        // Critical temperature
        probe.set_temperature(80);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Critical);

        // Low temperature, low battery → battery stress wins
        probe.set_temperature(30);
        probe.set_battery(10);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Serious);
    }

    #[test]
    fn test_memory_scaler_decay() {
        let gov = SystemGovernor::new();

        // Record 256 MiB of memory pressure
        gov.record_memory_pressure(256 * 1024 * 1024);
        let scale1 = gov.memory_scaler();
        // 256 MiB / 512 MiB crit = 0.5 ratio → scaler ≈ 0.5
        assert!(
            scale1.0 > 0.0 && scale1.0 < 1.0,
            "Scale should be between 0 and 1, got {}",
            scale1.0
        );

        // Wait briefly and record zero pressure — integral should decay
        std::thread::sleep(Duration::from_millis(50));
        gov.record_memory_pressure(0);
        let scale2 = gov.memory_scaler();
        assert!(
            scale2.0 > scale1.0,
            "After decay with zero forcing, scaler should increase (pressure drop)"
        );
    }

    #[test]
    fn test_storage_gate_rejects_when_full() {
        let gov = SystemGovernor::new();

        // Slam storage to 100% repeatedly to overwhelm the scaler
        for _ in 0..20 {
            gov.record_storage_pressure(1_000_000, 1_000_000); // 100% ratio
        }
        let scale = gov.storage_scaler();
        assert!(
            scale.0 < 0.05,
            "Storage scaler should be near zero at 100% usage, got {}",
            scale.0
        );
    }

    #[test]
    fn test_bandwidth_scaler_responds_to_load() {
        let gov = SystemGovernor::new();

        // Record 100 MiB bandwidth pressure repeatedly
        for _ in 0..20 {
            gov.record_bandwidth_pressure(100 * 1024 * 1024);
        }
        let scale = gov.bandwidth_scaler();
        assert!(
            scale.0 < 0.1,
            "Bandwidth scaler should be near zero under heavy load, got {}",
            scale.0
        );
    }

    #[test]
    fn test_temporal_tolerance_clamped() {
        let config = HomeostaticConfig {
            max_temporal_tolerance: Duration::from_secs(5),
            ..Default::default()
        };
        let gov = SystemGovernor::with_config(config);

        // Pump up latency integral to force tolerance expansion
        for _ in 0..50 {
            gov.record_latency_pressure(Duration::from_secs(10));
        }
        let tolerance = gov.temporal_tolerance();
        assert!(
            tolerance <= Duration::from_secs(5),
            "Tolerance {} should be clamped to 5s",
            tolerance.as_secs_f64()
        );
    }

    #[test]
    fn test_composite_stress_triggers_leaf() {
        let config = HomeostaticConfig {
            s_crit: 1.0,
            d_crit: 1.0,
            m_crit: 1.0,
            w_crit: 1.0,
            b_crit: 1.0,
            ..Default::default()
        };
        let gov = SystemGovernor::with_config(config);

        // Saturate all integrals (composite uses s, d, m, w, b)
        for _ in 0..30 {
            gov.record_metabolic_pressure(Duration::from_secs(5));
            gov.record_io_pressure(Duration::from_secs(5));
            gov.record_memory_pressure(10 * 1024 * 1024);
            gov.record_storage_pressure(900, 1000);
            gov.record_bandwidth_pressure(10 * 1024 * 1024);
        }

        let composite = gov.composite_stress();
        assert!(
            composite > 0.85,
            "Composite stress should exceed 0.85, got {}",
            composite
        );

        // Three consecutive calls should trigger Leaf
        let _p1 = gov.recommended_power_state();
        let _p2 = gov.recommended_power_state();
        let p3 = gov.recommended_power_state();
        assert_eq!(
            p3,
            PowerState::Leaf,
            "Should transition to Leaf after 3 ticks above threshold"
        );
    }

    #[test]
    fn test_per_peer_bandwidth_gate() {
        let config = HomeostaticConfig {
            psi_max: 5.0, // Low ceiling for testing
            ..Default::default()
        };
        let gov = SystemGovernor::with_config(config);

        let peer = "test_peer";
        assert!(gov.is_peer_bandwidth_ok(peer), "Fresh peer should be OK");

        // Exceed the bandwidth ceiling
        for _ in 0..10 {
            gov.record_peer_bandwidth(peer);
        }
        assert!(
            !gov.is_peer_bandwidth_ok(peer),
            "Peer should be throttled after exceeding ceiling"
        );
    }

    // --- Phase 3: Internet Connectivity Detection Tests ---

    #[test]
    fn test_connectivity_default_is_online() {
        let gov = SystemGovernor::new();
        assert!(
            gov.internet_available(),
            "Fresh governor should default to internet available"
        );
        assert_eq!(gov.local_peer_count(), 0);
    }

    #[test]
    fn test_internet_peer_keeps_online() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        // Discover a Kademlia peer — internet should stay available
        gov.record_peer_discovery(DiscoverySource::Kademlia);
        assert!(gov.internet_available());

        gov.with_state(|s| {
            assert_eq!(s.internet_peer_count, 1);
            assert_eq!(s.local_peer_count, 0);
        });
    }

    #[test]
    fn test_mdns_peer_increments_local_count() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        gov.record_peer_discovery(DiscoverySource::Mdns);
        gov.record_peer_discovery(DiscoverySource::Mdns);
        assert_eq!(gov.local_peer_count(), 2);

        gov.with_state(|s| {
            assert_eq!(s.internet_peer_count, 0);
        });
    }

    #[test]
    fn test_connectivity_transitions_to_offline() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        // Start with only mDNS peers, no internet peers ever seen
        gov.record_peer_discovery(DiscoverySource::Mdns);

        // Force last_internet_peer_seen to be >30s ago
        gov.with_state_mut(|s| {
            s.internet_peer_count = 0;
            s.last_internet_peer_seen = Instant::now() - Duration::from_secs(35);
        });

        // Connectivity check should detect offline
        gov.check_connectivity();
        assert!(
            !gov.internet_available(),
            "Should be offline after 30s grace with no internet peers"
        );
    }

    #[test]
    fn test_connectivity_restores_on_internet_peer() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        // Force offline state
        gov.with_state_mut(|s| {
            s.internet_available = false;
            s.internet_peer_count = 0;
            s.last_internet_peer_seen = Instant::now() - Duration::from_secs(60);
        });
        assert!(!gov.internet_available());

        // A Bootstrap peer arrives — should immediately restore
        gov.record_peer_discovery(DiscoverySource::Bootstrap);
        assert!(
            gov.internet_available(),
            "Internet should restore immediately on non-local peer discovery"
        );
    }

    #[test]
    fn test_peer_departure_adjusts_counts() {
        use phalanx_proto::telemetry::DiscoverySource;
        let gov = SystemGovernor::new();

        gov.record_peer_discovery(DiscoverySource::Mdns);
        gov.record_peer_discovery(DiscoverySource::Mdns);
        gov.record_peer_discovery(DiscoverySource::Kademlia);

        assert_eq!(gov.local_peer_count(), 2);
        gov.with_state(|s| assert_eq!(s.internet_peer_count, 1));

        // Depart one local peer
        gov.record_peer_departure(true);
        assert_eq!(gov.local_peer_count(), 1);

        // Depart the internet peer
        gov.record_peer_departure(false);
        gov.with_state(|s| assert_eq!(s.internet_peer_count, 0));
    }

    // --- Phase 4: Mobile Energy Guardian Tests ---

    #[test]
    fn test_battery_gate_low_battery_triggers_leaf() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(5);
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Leaf,
            "Battery <10% should trigger Leaf, got {:?}",
            state
        );
    }

    #[test]
    fn test_battery_gate_mid_battery_not_charging_triggers_conserving() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(30);
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Conserving,
            "Battery 30% not charging should trigger Conserving, got {:?}",
            state
        );
    }

    #[test]
    fn test_battery_gate_charging_bypasses_conserving() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(30);
        probe.set_charging(true); // Charging! Should bypass
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Normal,
            "Battery 30% while charging should remain Normal, got {:?}",
            state
        );
    }

    #[test]
    fn test_battery_gate_background_triggers_dormant() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(100);
        probe.set_charging(true);
        probe.set_background(true); // App backgrounded

        let gov = make_governor_with_probe(probe);
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Dormant,
            "Background app should trigger Dormant, got {:?}",
            state
        );
    }

    #[test]
    fn test_two_stage_max_restriction_battery_vs_stress() {
        // Low battery (Conserving) + high composite stress (Leaf) → Leaf wins
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(30);
        probe.set_charging(false);
        probe.set_background(false);

        let config = HomeostaticConfig {
            s_crit: 1.0,
            d_crit: 1.0,
            m_crit: 1.0,
            w_crit: 1.0,
            b_crit: 1.0,
            ..Default::default()
        };
        let gov = SystemGovernor::with_probe(config, probe);

        // Saturate all integrals to push composite above 0.85
        for _ in 0..30 {
            gov.record_metabolic_pressure(Duration::from_secs(5));
            gov.record_io_pressure(Duration::from_secs(5));
            gov.record_memory_pressure(10 * 1024 * 1024);
            gov.record_storage_pressure(900, 1000);
            gov.record_bandwidth_pressure(10 * 1024 * 1024);
        }

        // 3 ticks to trigger Leaf via stress recommendation
        let _p1 = gov.recommended_power_state();
        let _p2 = gov.recommended_power_state();
        let p3 = gov.recommended_power_state();

        // Battery gate says Conserving, stress says Leaf → max = Leaf
        assert_eq!(
            p3,
            PowerState::Leaf,
            "Max restriction should be Leaf (stress beats battery's Conserving), got {:?}",
            p3
        );
    }

    #[test]
    fn test_two_stage_battery_wins_over_normal_stress() {
        // Battery at 5% → Leaf gate. Stress is nominal → Normal.
        // Max(Leaf, Normal) = Leaf.
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(5);
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        // No stress applied → composite is near 0.0 → stress_recommendation returns Normal
        let state = gov.recommended_power_state();
        assert_eq!(
            state,
            PowerState::Leaf,
            "Battery gate (Leaf) should override stress (Normal), got {:?}",
            state
        );
    }

    #[test]
    fn test_simulated_battery_drain_transitions() {
        // Simulate 100% → 5%: verify Normal → Conserving → Leaf transitions
        let probe = Arc::new(MockProbe::new());
        probe.set_charging(false);
        probe.set_background(false);

        // 100% → Normal
        probe.set_battery(100);
        let gov = make_governor_with_probe(probe.clone());
        assert_eq!(gov.recommended_power_state(), PowerState::Normal);

        // 45% → Conserving (below 50, not charging)
        probe.set_battery(45);
        assert_eq!(gov.recommended_power_state(), PowerState::Conserving);

        // 8% → Leaf (below 10)
        probe.set_battery(8);
        assert_eq!(gov.recommended_power_state(), PowerState::Leaf);
    }

    #[test]
    fn test_battery_level_clamping() {
        // BatteryLevel should clamp to 100
        let level = BatteryLevel::new(255);
        assert_eq!(level.get(), 100);

        let level = BatteryLevel::new(0);
        assert_eq!(level.get(), 0);
    }

    #[test]
    fn test_thermal_thresholds_platform_variants() {
        let desktop = ThermalThresholds::desktop();
        let mobile = ThermalThresholds::mobile();

        // Mobile thresholds should be lower than desktop (tighter thermal envelope)
        assert!(mobile.fair.0 < desktop.fair.0);
        assert!(mobile.serious.0 < desktop.serious.0);
        assert!(mobile.critical.0 < desktop.critical.0);
    }

    #[test]
    fn test_hardware_probe_thermal_reading_drives_stress() {
        let probe = Arc::new(MockProbe::new());
        let gov = make_governor_with_probe(probe.clone());

        // Nominal temperature
        probe.set_temperature(30);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Nominal);

        // Fair threshold (desktop default = 45°C)
        probe.set_temperature(50);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Fair);

        // Serious threshold (desktop default = 60°C)
        probe.set_temperature(65);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Serious);

        // Critical threshold (desktop default = 75°C)
        probe.set_temperature(80);
        gov.update_vitals();
        assert_eq!(gov.current_stress(), SystemStress::Critical);
    }

    #[test]
    fn test_dormant_with_can_capture_background() {
        // Mock probe that reports can_capture_in_background = true (Android-like)
        let probe = Arc::new(MockProbe::new());
        probe.set_background(true);

        let gov = make_governor_with_probe(probe.clone());
        let state = gov.recommended_power_state();
        assert_eq!(state, PowerState::Dormant);
        // Verify the probe correctly reports capability
        assert!(gov.probe().can_capture_in_background());
    }

    // --- Phase 4c: Adaptive Vitals Polling Tests ---

    #[test]
    fn test_vitals_polling_interval_normal() {
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(100);
        probe.set_charging(true);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe);
        // Fresh governor defaults to Normal power state
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(5),
            "Normal should poll every 5s"
        );
    }

    #[test]
    fn test_vitals_polling_interval_adapts_to_power_state() {
        let probe = Arc::new(MockProbe::new());
        probe.set_charging(false);
        probe.set_background(false);

        let gov = make_governor_with_probe(probe.clone());

        // Force Conserving via battery gate (30%, not charging)
        probe.set_battery(30);
        gov.update_vitals();
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(15),
            "Conserving should poll every 15s"
        );

        // Force Leaf via battery gate (<10%)
        probe.set_battery(5);
        gov.update_vitals();
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(30),
            "Leaf should poll every 30s"
        );

        // Force Dormant via background
        probe.set_background(true);
        gov.update_vitals();
        assert_eq!(
            gov.vitals_polling_interval(),
            Duration::from_secs(60),
            "Dormant should poll every 60s"
        );
    }

    #[test]
    fn test_lifecycle_event_triggers_immediate_vitals_update() {
        // Verify that update_vitals() after a lifecycle event changes power state
        let probe = Arc::new(MockProbe::new());
        probe.set_battery(100);
        probe.set_charging(true);
        probe.set_background(true); // Start backgrounded → Dormant

        let gov = make_governor_with_probe(probe.clone());
        gov.update_vitals();
        assert_eq!(gov.current_power_state(), PowerState::Dormant);

        // Simulate foregrounding (in real app, the lifecycle_rx channel would fire)
        probe.set_background(false);
        gov.update_vitals(); // Immediate recalculation
        assert_eq!(
            gov.current_power_state(),
            PowerState::Normal,
            "Should transition to Normal immediately after foregrounding"
        );
    }
}
