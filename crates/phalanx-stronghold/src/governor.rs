// crates/phalanx-stronghold/src/governor.rs
//
// StrongholdGovernor: Homeostasis implementation for desktop/server.
// Uses Volterra second-kind integrals from the Laboratory for resource management.
// No battery gate. No thermal probe. No mobile power state transitions.

use std::sync::RwLock;
use std::time::Duration;

use phalanx_forensics::policy::{
    BandwidthScale, ConnectionScale, DecayingIntegral, FinalizationScale, Homeostasis,
    HomeostaticConfig, IngestionScale, MemoryScale, ResourceIntegrals, StorageScale,
    SybilEndowment,
};

/// The Stronghold's resource governor. Server-tuned Volterra integrals.
pub struct StrongholdGovernor {
    integrals: RwLock<ResourceIntegrals>,
    pub config: HomeostaticConfig,
}

impl StrongholdGovernor {
    pub fn new() -> Self {
        Self::with_config(Self::server_config())
    }

    pub fn with_config(config: HomeostaticConfig) -> Self {
        Self {
            integrals: RwLock::new(ResourceIntegrals::new()),
            config,
        }
    }

    /// Server-tuned thresholds. Higher ceilings than phone.
    fn server_config() -> HomeostaticConfig {
        HomeostaticConfig {
            // Memory: 4GB ceiling (vs phone's 512MB)
            lambda_mem: 0.3,
            m_crit: 4096.0,
            // Storage: 90% critical (vs phone's 80%)
            lambda_wal: 0.05,
            w_crit: 0.9,
            // Bandwidth: 500MB ceiling (vs phone's 50MB)
            lambda_bw: 0.5,
            b_crit: 500.0,
            // Sybil: higher per-peer ceiling (server handles more peers)
            psi_max: 200.0,
            k_sybil: 2.0,
            // Connection: higher capacity
            lambda_conn: 0.2,
            c_crit: 0.95,
            ..HomeostaticConfig::default()
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
        let key = format!("bw:{}", peer_id);
        self.with_state(|s| {
            s.r_integrals
                .get(&key)
                .is_none_or(|r| r.value < self.config.psi_max)
        })
    }

    /// Record per-peer bandwidth event.
    pub fn record_peer_bandwidth(&self, peer_id: &str) {
        let key = format!("bw:{}", peer_id);
        self.with_state_mut(|s| {
            s.r_integrals
                .entry(key)
                .or_insert_with(DecayingIntegral::new)
                .record(1.0, self.config.lambda_rep);
        });
    }

    /// Weighted composite of all integral pressures.
    /// Returns 0.0 (idle) to 1.0+ (saturated).
    pub fn composite_stress(&self) -> f64 {
        self.with_state(|s| {
            let terms = [
                (0.25, s.s.value / self.config.s_crit),
                (0.20, s.d.value / self.config.d_crit),
                (0.20, s.m.value / self.config.m_crit),
                (0.15, s.w.value / self.config.w_crit),
                (0.20, s.b.value / self.config.b_crit),
            ];
            terms.iter().map(|(w, n)| w * n.min(1.0)).sum()
        })
    }
}

impl Default for StrongholdGovernor {
    fn default() -> Self {
        Self::new()
    }
}

impl Homeostasis for StrongholdGovernor {
    fn temporal_tolerance(&self) -> Duration {
        self.with_state(|s| {
            let base = self.config.base_temporal_drift;
            let expansion = Duration::from_secs_f64(s.l.value);
            let total = base + expansion;
            total.min(self.config.max_temporal_tolerance)
        })
    }

    fn record_metabolic_pressure(&self, duration: Duration) {
        self.with_state_mut(|s| s.s.record(duration.as_secs_f64(), self.config.lambda_sys));
    }

    fn record_latency_pressure(&self, duration: Duration) {
        self.with_state_mut(|s| s.l.record(duration.as_secs_f64(), self.config.lambda_lat));
    }

    fn record_io_pressure(&self, duration: Duration) {
        self.with_state_mut(|s| s.d.record(duration.as_secs_f64(), self.config.lambda_io));
    }

    fn record_entry_pressure(&self) {
        self.with_state_mut(|s| s.e.record(1.0, self.config.lambda_entry));
    }

    fn record_eclipse_impulse(&self, magnitude: f64) {
        self.with_state_mut(|s| s.e.record(magnitude, self.config.lambda_entry));
    }

    fn ingestion_scaler(&self) -> IngestionScale {
        self.with_state(|s| IngestionScale((1.0 - (s.s.value / self.config.s_crit)).max(0.0)))
    }

    fn finalization_scaler(&self) -> FinalizationScale {
        self.with_state(|s| FinalizationScale((1.0 - (s.d.value / self.config.d_crit)).max(0.0)))
    }

    fn sybil_endowment(&self) -> SybilEndowment {
        self.with_state(|s| {
            SybilEndowment(self.config.psi_max / (1.0 + self.config.k_sybil * s.e.value))
        })
    }

    fn record_memory_pressure(&self, bytes_held: usize) {
        self.with_state_mut(|s| {
            let mib = bytes_held as f64 / 1_048_576.0;
            s.m.record(mib, self.config.lambda_mem);
        });
    }

    fn record_storage_pressure(&self, used_bytes: u64, max_bytes: u64) {
        self.with_state_mut(|s| {
            let ratio = if max_bytes > 0 {
                used_bytes as f64 / max_bytes as f64
            } else {
                1.0
            };
            s.w.record(ratio, self.config.lambda_wal);
        });
    }

    fn record_bandwidth_pressure(&self, bytes: usize) {
        self.with_state_mut(|s| {
            let mib = bytes as f64 / 1_048_576.0;
            s.b.record(mib, self.config.lambda_bw);
        });
    }

    fn record_connection_pressure(&self, active: usize, max: usize) {
        self.with_state_mut(|s| {
            let ratio = if max > 0 {
                active as f64 / max as f64
            } else {
                1.0
            };
            s.c.record(ratio, self.config.lambda_conn);
        });
    }

    fn memory_scaler(&self) -> MemoryScale {
        self.with_state(|s| MemoryScale((1.0 - (s.m.value / self.config.m_crit)).max(0.0)))
    }

    fn storage_scaler(&self) -> StorageScale {
        self.with_state(|s| StorageScale((1.0 - (s.w.value / self.config.w_crit)).max(0.0)))
    }

    fn bandwidth_scaler(&self) -> BandwidthScale {
        self.with_state(|s| BandwidthScale((1.0 - (s.b.value / self.config.b_crit)).max(0.0)))
    }

    fn connection_scaler(&self) -> ConnectionScale {
        self.with_state(|s| ConnectionScale((1.0 - (s.c.value / self.config.c_crit)).max(0.0)))
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
