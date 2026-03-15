// crates/phalanx-node/src/vitals/config.rs
//
// Homeostatic configuration, integral state, and the Homeostasis trait.

use std::collections::HashMap;
use std::time::Duration;
use tokio::time::Instant;

use phalanx_proto::types::PowerState;

use super::types::{
    BandwidthScale, ConnectionScale, FinalizationScale, IngestionScale, MemoryScale, StorageScale,
    SybilEndowment,
};

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
    pub lambda_lat: f64,                  // Latency pressure decay rate (independent of lambda_sys)
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
            lambda_lat: 1.0,
            max_temporal_tolerance: Duration::from_secs(10),
        }
    }
}

/// A single Volterra second-kind integral with its own time cursor.
/// Each integral decays independently: I(t+dt) = impulse + I(t) · exp(-λ·dt)
/// where dt is measured from THIS integral's last update, not a shared clock.
///
/// Before this fix, all integrals shared a single `last_sys_tick`. High-frequency
/// updates to one integral (e.g., bandwidth) would suppress decay in all others,
/// causing phantom cross-coupling and ~10x pressure inflation under load.
#[derive(Debug)]
pub struct DecayingIntegral {
    pub value: f64,
    last_update: Instant,
}

impl Default for DecayingIntegral {
    fn default() -> Self {
        Self::new()
    }
}

impl DecayingIntegral {
    pub fn new() -> Self {
        Self {
            value: 0.0,
            last_update: Instant::now(),
        }
    }

    /// Record an impulse, applying exponential decay since this integral's last update.
    pub fn record(&mut self, impulse: f64, lambda: f64) {
        let now = Instant::now();
        let dt = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.value = impulse + self.value * (-lambda * dt).exp();
    }
}

pub struct IntegralState {
    pub s: DecayingIntegral, // System/metabolic pressure
    pub d: DecayingIntegral, // I/O digestion pressure
    pub e: DecayingIntegral, // Entry/Sybil pressure
    pub l: DecayingIntegral, // Latency (Network/Scheduling Age)
    pub m: DecayingIntegral, // Memory/buffer pressure
    pub w: DecayingIntegral, // WAL/storage pressure
    pub b: DecayingIntegral, // Bandwidth pressure
    pub c: DecayingIntegral, // Connection pressure
    pub r_integrals: HashMap<String, DecayingIntegral>, // reputation integrals
    pub conserving_trigger_count: u8, // Consecutive ticks above Conserving threshold (0.50)
    pub leaf_trigger_count: u8, // Consecutive vitals ticks above composite threshold (0.85)
    pub normal_trigger_count: u8, // Consecutive vitals ticks below recovery threshold (0.30)
    /// Tracks the stress-driven power state independently of battery gate.
    /// Used as hysteresis fallback by `stress_recommendation()` so it doesn't
    /// inherit battery-gate-driven Dormant/Leaf states.
    pub stress_power_state: PowerState,
    // Internet connectivity detection
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

impl Default for IntegralState {
    fn default() -> Self {
        Self::new()
    }
}

impl IntegralState {
    pub fn new() -> Self {
        Self {
            s: DecayingIntegral::new(),
            d: DecayingIntegral::new(),
            e: DecayingIntegral::new(),
            l: DecayingIntegral::new(),
            m: DecayingIntegral::new(),
            w: DecayingIntegral::new(),
            b: DecayingIntegral::new(),
            c: DecayingIntegral::new(),
            r_integrals: HashMap::new(),
            conserving_trigger_count: 0,
            leaf_trigger_count: 0,
            normal_trigger_count: 0,
            stress_power_state: PowerState::Normal,
            internet_available: true,
            local_peer_count: 0,
            internet_peer_count: 0,
            last_internet_peer_seen: Instant::now(),
        }
    }
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
