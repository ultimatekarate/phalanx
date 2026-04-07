// crates/phalanx-stronghold/src/governor.rs
//
// StrongholdGovernor: Homeostasis implementation for desktop/server.
// Uses Volterra second-kind integrals from the Laboratory for resource management.
// No battery gate. No thermal probe. No mobile power state transitions.

use std::sync::RwLock;
use std::time::{Duration, Instant};

use phalanx_forensics::policy::{
    BandwidthScale, ConnectionScale, DecayingIntegral, FinalizationScale, Homeostasis,
    HomeostaticConfig, IngestionScale, MemoryScale, ResourceIntegrals, StorageScale,
    SybilEndowment,
};

/// The Stronghold's resource governor. Server-tuned Volterra integrals.
pub struct StrongholdGovernor {
    integrals: RwLock<ResourceIntegrals>,
    pub config: HomeostaticConfig,
    /// Monotonic epoch for DecayingIntegral time domain.
    /// Uses std::time::Instant (not tokio) — stronghold tests are `#[test]`.
    epoch: Instant,
}

impl StrongholdGovernor {
    pub fn new() -> Self {
        Self::with_config(Self::server_config())
    }

    /// Monotonic seconds since this governor's epoch.
    fn now_secs(&self) -> f64 {
        self.epoch.elapsed().as_secs_f64()
    }

    pub fn with_config(config: HomeostaticConfig) -> Self {
        let epoch = Instant::now();
        let integrals = ResourceIntegrals::from_config(&config, 0.0);
        Self {
            integrals: RwLock::new(integrals),
            config,
            epoch,
        }
    }

    /// Server safety margins (tighter than phone — more resources available).
    const SERVER_STORAGE_SAFETY_MARGIN: f64 = 0.10;
    const SERVER_CONNECTION_SAFETY_MARGIN: f64 = 0.05;

    /// Server-tuned thresholds. Expressed as ratios of the phone reference.
    fn server_config() -> HomeostaticConfig {
        let phone = HomeostaticConfig::default();
        HomeostaticConfig {
            m_crit: 8.0 * phone.m_crit,   // 8× phone (server has 8× RAM)
            b_crit: 5.0 * phone.b_crit,   // 5× phone (server has 5× bandwidth)
            psi_max: 4.0 * phone.psi_max, // 4× phone (server handles more peers)
            w_crit: 1.0 - Self::SERVER_STORAGE_SAFETY_MARGIN, // 10% margin (vs phone's 20%)
            c_crit: 1.0 - Self::SERVER_CONNECTION_SAFETY_MARGIN, // 5% margin (vs phone's 10%)
            ..phone
        }
    }

    fn with_state<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&ResourceIntegrals) -> R,
    {
        let state = self.integrals.read().unwrap_or_else(|e| e.into_inner());
        f(&state)
    }

    fn with_state_mut<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut ResourceIntegrals) -> R,
    {
        let mut state = self.integrals.write().unwrap_or_else(|e| e.into_inner());
        f(&mut state)
    }

    /// Per-peer bandwidth check via r_integrals.
    pub fn is_peer_bandwidth_ok(&self, peer_id: &str) -> bool {
        let now = self.now_secs();
        let key = format!("bw:{}", peer_id);
        self.with_state(|s| {
            s.r_integrals
                .get(&key)
                .is_none_or(|r| r.current_value(now) < self.config.psi_max)
        })
    }

    /// Record per-peer bandwidth event.
    pub fn record_peer_bandwidth(&self, peer_id: &str) {
        let now = self.now_secs();
        let key = format!("bw:{}", peer_id);
        self.with_state_mut(|s| {
            s.r_integrals
                .entry(key)
                .or_insert_with(|| DecayingIntegral::new(self.config.lambda_rep, now))
                .record(1.0, now);
        });
    }

    /// Weighted composite of all integral pressures.
    /// Returns 0.0 (idle) to 1.0+ (saturated).
    pub fn composite_stress(&self) -> f64 {
        let now = self.now_secs();
        let w = &self.config.stress_weights;
        self.with_state(|s| {
            let normalized = [
                s.s.current_value(now) / self.config.s_crit,
                s.d.current_value(now) / self.config.d_crit,
                s.m.current_value(now) / self.config.m_crit,
                s.w.current_value(now) / self.config.w_crit,
                s.b.current_value(now) / self.config.b_crit,
            ];
            w.iter()
                .zip(normalized.iter())
                .map(|(wi, ni)| wi * ni.min(1.0))
                .sum()
        })
    }
}

impl Default for StrongholdGovernor {
    fn default() -> Self {
        Self::new()
    }
}

impl Homeostasis for StrongholdGovernor {
    #[allow(clippy::arithmetic_side_effects)] // Duration addition — base + expansion, clamped by min().
    fn temporal_tolerance(&self) -> Duration {
        let now = self.now_secs();
        self.with_state(|s| {
            let base = self.config.base_temporal_drift;
            let expansion = Duration::from_secs_f64(s.l.current_value(now));
            let total = base + expansion;
            total.min(self.config.max_temporal_tolerance)
        })
    }

    fn record_metabolic_pressure(&self, duration: Duration) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.s.record(duration.as_secs_f64(), now));
    }

    fn record_latency_pressure(&self, duration: Duration) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.l.record(duration.as_secs_f64(), now));
    }

    fn record_io_pressure(&self, duration: Duration) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.d.record(duration.as_secs_f64(), now));
    }

    fn record_entry_pressure(&self) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.e.record(1.0, now));
    }

    fn record_eclipse_impulse(&self, magnitude: f64) {
        let now = self.now_secs();
        self.with_state_mut(|s| s.e.record(magnitude, now));
    }

    fn ingestion_scaler(&self) -> IngestionScale {
        let now = self.now_secs();
        self.with_state(|s| {
            IngestionScale((1.0 - (s.s.current_value(now) / self.config.s_crit)).max(0.0))
        })
    }

    fn finalization_scaler(&self) -> FinalizationScale {
        let now = self.now_secs();
        self.with_state(|s| {
            FinalizationScale((1.0 - (s.d.current_value(now) / self.config.d_crit)).max(0.0))
        })
    }

    fn sybil_endowment(&self) -> SybilEndowment {
        let now = self.now_secs();
        self.with_state(|s| {
            SybilEndowment(
                self.config.psi_max
                    / (1.0 + (self.config.k_sybil * s.e.current_value(now)).powi(2)),
            )
        })
    }

    fn record_memory_pressure(&self, bytes_held: usize) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let mib = bytes_held as f64 / 1_048_576.0;
            s.m.record(mib, now);
        });
    }

    fn record_storage_pressure(&self, used_bytes: u64, max_bytes: u64) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let ratio = if max_bytes > 0 {
                used_bytes as f64 / max_bytes as f64
            } else {
                1.0
            };
            s.w.record(ratio, now);
        });
    }

    fn record_bandwidth_pressure(&self, bytes: usize) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let mib = bytes as f64 / 1_048_576.0;
            s.b.record(mib, now);
        });
    }

    fn record_connection_pressure(&self, active: usize, max: usize) {
        let now = self.now_secs();
        self.with_state_mut(|s| {
            let ratio = if max > 0 {
                active as f64 / max as f64
            } else {
                1.0
            };
            s.c.record(ratio, now);
        });
    }

    fn memory_scaler(&self) -> MemoryScale {
        let now = self.now_secs();
        self.with_state(|s| {
            MemoryScale((1.0 - (s.m.current_value(now) / self.config.m_crit)).max(0.0))
        })
    }

    fn storage_scaler(&self) -> StorageScale {
        let now = self.now_secs();
        self.with_state(|s| {
            StorageScale((1.0 - (s.w.current_value(now) / self.config.w_crit)).max(0.0))
        })
    }

    fn bandwidth_scaler(&self) -> BandwidthScale {
        let now = self.now_secs();
        self.with_state(|s| {
            BandwidthScale((1.0 - (s.b.current_value(now) / self.config.b_crit)).max(0.0))
        })
    }

    fn connection_scaler(&self) -> ConnectionScale {
        let now = self.now_secs();
        self.with_state(|s| {
            ConnectionScale((1.0 - (s.c.current_value(now) / self.config.c_crit)).max(0.0))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn governor_starts_nominal() {
        let gov = StrongholdGovernor::new();
        assert!(
            gov.composite_stress() < 0.01,
            "Fresh governor should have near-zero stress"
        );
        assert!(
            gov.storage_scaler().0 > 0.99,
            "Fresh storage scaler should be near 1.0"
        );
        assert!(
            gov.ingestion_scaler().0 > 0.99,
            "Fresh ingestion scaler should be near 1.0"
        );
    }

    #[test]
    fn storage_scaler_degrades_under_pressure() {
        let gov = StrongholdGovernor::new();
        // Simulate heavy storage usage
        for _ in 0..20 {
            gov.record_storage_pressure(9, 10); // 90% full
        }
        let scaler = gov.storage_scaler();
        assert!(
            scaler.0 < 0.5,
            "Storage scaler should degrade under pressure, got {}",
            scaler.0
        );
    }

    #[test]
    fn peer_bandwidth_throttling() {
        let gov = StrongholdGovernor::new();
        assert!(
            gov.is_peer_bandwidth_ok("test-peer"),
            "Fresh peer should be ok"
        );
        // Flood the peer integral
        for _ in 0..500 {
            gov.record_peer_bandwidth("test-peer");
        }
        assert!(
            !gov.is_peer_bandwidth_ok("test-peer"),
            "Flooded peer should be throttled"
        );
    }
}
